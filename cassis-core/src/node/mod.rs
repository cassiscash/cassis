//! The node: coordinates the [`Network`] adapters of one Cassis node in
//! its three roles.
//!
//! * **Payer** ([`Node::pay`]): finds a route, PREPAREs every hop, funds
//!   the first HTLC, EXECUTEs the hops in order and COMMITs to the payee.
//! * **Router**: reserves hops on PREPARE, and on EXECUTE verifies the
//!   incoming HTLC before funding the outgoing one.
//! * **Payee**: on PREPARE checks it still expects the payment, on
//!   COMMIT verifies the final HTLC and claims it.
//!
//! Every HTLC this node funds or must claim is journaled in the
//! [`Store`] before or right after the network call, and a settlement
//! loop drives each to an end: claim the incoming side once the
//! preimage shows up downstream, refund the outgoing side once it
//! expires.

mod payee;
mod payer;
mod preimage_server;
mod router;
mod settle;

use crate::keys::NodeKeys;
use crate::network::{Htlc, HtlcTarget, Network, NetworkId};
use crate::primitives::{Bytes32, OperationId, XOnlyPubKey};
use crate::protocol::{Invoice, Prepare, Request, Response};
use crate::store::Store;
use crate::transport::{Handler, Transport};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tracing::{Instrument, Span};

pub use payee::create_invoice;
pub use preimage_server::{
    create_preimage_server_invoice, redeem_preimage_server_payments, PreimageServerInvoiceRecord,
    RedeemReport, PREIMAGE_SERVER_INVOICES,
};
pub use router::{PrepareVeto, RouteOffer, RoutingPolicy};

const INVOICES: &str = "invoices";
const PAYMENTS: &str = "payments";
const HOPS: &str = "hops";

/// How long EXECUTE and COMMIT work before answering
/// [`Response::Pending`] instead of the outcome.
const INLINE_WAIT: Duration = Duration::from_secs(5);
/// How often an incoming HTLC that is not final yet is verified again.
const VERIFY_RETRY_INTERVAL: Duration = Duration::from_secs(5);

/// An invoice this node issued, with its secret preimage.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InvoiceRecord {
    pub invoice: Invoice,
    pub preimage: Bytes32,
    pub status: InvoiceStatus,
    pub created_at: u64,
    pub settled_at: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvoiceStatus {
    Pending,
    Claimed,
    Expired,
}

/// A payment this node made: the HTLC it funded on its own network.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaymentRecord {
    pub invoice: Invoice,
    pub network: NetworkId,
    pub htlc: Htlc,
    pub status: PaymentStatus,
    /// Proof of payment, once known.
    pub preimage: Option<Bytes32>,
    pub created_at: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PaymentStatus {
    /// The HTLC is funded and neither claimed nor refunded yet.
    Pending,
    Completed,
    Refunded,
}

/// A hop this node routes: an incoming HTLC it may claim and the
/// outgoing HTLC it funded in exchange.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HopRecord {
    pub operation_id: OperationId,
    /// Iroh id of the payer that prepared and executed the hop.
    pub owner: String,
    pub prepare: Prepare,
    pub incoming: Htlc,
    /// Where EXECUTE asked to forward to.
    pub outgoing_target: HtlcTarget,
    pub outgoing: Option<Htlc>,
    pub state: HopState,
    /// Learned from downstream; claims `incoming`.
    pub preimage: Option<Bytes32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HopState {
    /// Waiting for the incoming HTLC to verify (to confirm, say).
    /// Nothing is funded yet.
    Verifying,
    /// Funding the outgoing HTLC.
    Funding,
    /// Outgoing HTLC funded; waiting for its preimage or its expiry.
    Forwarded,
    /// Incoming HTLC claimed.
    Settled,
    /// Outgoing HTLC refunded.
    Refunded,
    Failed(String),
}

pub struct NodeConfig {
    pub keys: NodeKeys,
    pub store: Arc<Store>,
    /// Span carrying the node's name; every task the node runs is
    /// instrumented with it.
    pub span: Span,
    /// Accept requests under the node's iroh identity: receive payments,
    /// route, and settle journaled HTLCs in the background. Without it
    /// the node can only pay, from an ephemeral endpoint.
    pub serve: bool,
}

/// Handle to a running node. Cheap to clone.
#[derive(Clone)]
pub struct Node(Arc<Inner>);

struct Inner {
    keys: NodeKeys,
    store: Arc<Store>,
    transport: Transport,
    span: Span,
    networks: RwLock<HashMap<NetworkId, Arc<dyn Network>>>,
    routing: RwLock<Option<RoutingPolicy>>,
    reservations: tokio::sync::Mutex<HashMap<OperationId, router::Reservation>>,
    /// Keys of records some task is currently acting on; others skip
    /// them instead of acting twice.
    busy: Mutex<HashSet<String>>,
    /// Claims started by COMMIT, by payment hash, until a repeated
    /// COMMIT collects their failure.
    commits: Mutex<HashMap<Bytes32, payee::CommitState>>,
    /// Background work, stopped by [`Node::shutdown`].
    tasks: Mutex<Vec<tokio::task::AbortHandle>>,
}

impl Node {
    pub async fn start(
        config: NodeConfig,
        networks: Vec<Arc<dyn Network>>,
    ) -> Result<Self, String> {
        let transport = Transport::bind(config.serve.then_some(config.keys.iroh)).await?;
        let node = Self(Arc::new(Inner {
            keys: config.keys,
            store: config.store,
            transport,
            span: config.span,
            networks: RwLock::new(
                networks
                    .into_iter()
                    .map(|network| (network.id(), network))
                    .collect(),
            ),
            routing: RwLock::new(None),
            reservations: Default::default(),
            busy: Default::default(),
            commits: Default::default(),
            tasks: Default::default(),
        }));
        if config.serve {
            node.resume_hops()?;
            let server = node.clone();
            let handler: Handler = Arc::new(move |request, peer| {
                let node = server.clone();
                Box::pin(async move { node.handle(request, peer).await })
            });
            let transport = node.0.transport.clone();
            node.spawn(async move { transport.serve(handler).await });
            node.spawn(node.clone().settle_loop());
        }
        Ok(node)
    }

    /// Run `task` in the background, under the node's span, until it
    /// ends or the node shuts down.
    fn spawn(&self, task: impl std::future::Future<Output = ()> + Send + 'static) {
        let handle = tokio::spawn(task.instrument(self.span()));
        let mut tasks = self.0.tasks.lock().unwrap_or_else(|e| e.into_inner());
        tasks.retain(|task| !task.is_finished());
        tasks.push(handle.abort_handle());
    }

    /// Stop serving, routing and settling, and close the endpoint. The
    /// journal stays in the store: a node started again on it resumes
    /// settling where this one stopped.
    pub async fn shutdown(&self) {
        for task in self
            .0
            .tasks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain(..)
        {
            task.abort();
        }
        self.0.transport.close().await;
    }

    /// Payments this node made, settled or not.
    pub fn payments(&self) -> Result<Vec<PaymentRecord>, String> {
        self.store().list(PAYMENTS)
    }

    pub fn span(&self) -> Span {
        self.0.span.clone()
    }

    pub fn store(&self) -> &Store {
        &self.0.store
    }

    pub fn node_pubkey(&self) -> XOnlyPubKey {
        self.0.keys.node.pubkey()
    }

    pub fn iroh_peer_id(&self) -> String {
        self.0.transport.peer_id()
    }

    pub fn add_network(&self, network: Arc<dyn Network>) {
        self.0
            .networks
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(network.id(), network);
    }

    pub fn network(&self, id: &NetworkId) -> Result<Arc<dyn Network>, String> {
        self.0
            .networks
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(id)
            .cloned()
            .ok_or_else(|| format!("network {id} is not enabled on this node"))
    }

    pub fn network_ids(&self) -> Vec<NetworkId> {
        let mut ids: Vec<_> = self
            .0
            .networks
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .cloned()
            .collect();
        ids.sort();
        ids
    }

    async fn handle(&self, request: Request, peer: String) -> Response {
        match request {
            Request::Prepare(prepare) => Response::Prepared(self.prepare(prepare, peer).await),
            Request::PreparePayee(prepare) => Response::PayeePrepared(self.prepare_payee(prepare)),
            Request::Execute(execute) => self.execute(execute, peer).await,
            Request::Discard(discard) => {
                self.discard(discard, peer).await;
                Response::Discarded
            }
            Request::Commit(commit) => self.commit(commit).await,
            Request::Settle(settle) => {
                self.settle_hop(settle, peer).await;
                Response::Settled
            }
            Request::PreimageInvoice
            | Request::PreimageSign(_)
            | Request::PreimagePayments { .. } => {
                Response::Error("this node is not a preimage server".into())
            }
        }
    }

    /// Mark `key` as being acted on; `None` if another task already is.
    fn busy(&self, key: String) -> Option<BusyGuard> {
        let mut busy = self.0.busy.lock().unwrap_or_else(|e| e.into_inner());
        busy.insert(key.clone()).then(|| BusyGuard {
            node: self.0.clone(),
            key,
        })
    }
}

struct BusyGuard {
    node: Arc<Inner>,
    key: String,
}

impl Drop for BusyGuard {
    fn drop(&mut self) {
        self.node
            .busy
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.key);
    }
}
