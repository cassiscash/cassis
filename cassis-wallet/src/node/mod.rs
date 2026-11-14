//! The node: coordinates the [`Network`] adapters of one wallet as a
//! payer and a payee.
//!
//! * **Payer** ([`Node::pay`]): finds a route, PREPAREs every hop, funds
//!   the first HTLC, EXECUTEs the hops in order and COMMITs to the payee.
//! * **Payee**: on PREPARE checks it still expects the payment, on
//!   COMMIT verifies the final HTLC and claims it.
//!
//! Routing is `cassis-routerd`'s: it hands this node the hop requests'
//! handler ([`Node::route_with`]) and drives its hops on this node's
//! networks and endpoint.
//!
//! Every HTLC this node funds is journaled in the [`Db`] as a
//! [`PendingPayment`](crate::db::PendingPayment) right after the network
//! call, and a settlement loop drives each to an end: a
//! [`Transaction`](crate::db::Transaction) once the payee claims it, a
//! refund once it expires.

mod offline;
mod payee;
mod payer;
mod settle;
mod verify;

use crate::db::Db;
use cassis_core::keys::NodeKeys;
use cassis_core::network::{Network, NetworkId};
use cassis_core::protocol::{Request, Response};
use cassis_core::transport::{Handler, Transport};
use cassis_core::{Bytes32, XOnlyPubKey};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tracing::{Instrument, Span};

pub use offline::{
    authorize_gateway, create_gateway_invoice, redeem_offline_payments, OfflineEndpoints,
    RedeemReport,
};
pub use payee::create_invoice;
pub use settle::{settle_outgoing, Outcome};
pub use verify::{verify_incoming, Unverified};

/// How long COMMIT works before answering [`Response::Pending`] instead
/// of the outcome.
pub const INLINE_WAIT: Duration = Duration::from_secs(5);
/// How often an incoming HTLC that does not verify yet is verified again.
pub const VERIFY_RETRY_INTERVAL: Duration = Duration::from_secs(5);

pub struct NodeConfig {
    pub keys: NodeKeys,
    pub db: Arc<Db>,
    /// Span carrying the node's name; every task the node runs is
    /// instrumented with it.
    pub span: Span,
    /// Accept requests under the node's iroh identity: receive payments,
    /// and settle journaled HTLCs in the background. Without it the node
    /// can only pay, from an ephemeral endpoint.
    pub serve: bool,
}

/// Handle to a running node. Cheap to clone.
#[derive(Clone)]
pub struct Node(Arc<Inner>);

struct Inner {
    keys: NodeKeys,
    db: Arc<Db>,
    transport: Transport,
    span: Span,
    networks: RwLock<HashMap<NetworkId, Arc<dyn Network>>>,
    /// Answers PREPARE, EXECUTE, DISCARD and SETTLE, when routing.
    router: RwLock<Option<Handler>>,
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
            db: config.db,
            transport,
            span: config.span,
            networks: RwLock::new(
                networks
                    .into_iter()
                    .map(|network| (network.id(), network))
                    .collect(),
            ),
            router: RwLock::new(None),
            busy: Default::default(),
            commits: Default::default(),
            tasks: Default::default(),
        }));
        if config.serve {
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
    pub fn spawn(&self, task: impl std::future::Future<Output = ()> + Send + 'static) {
        let handle = tokio::spawn(task.instrument(self.span()));
        let mut tasks = self.0.tasks.lock().unwrap_or_else(|e| e.into_inner());
        tasks.retain(|task| !task.is_finished());
        tasks.push(handle.abort_handle());
    }

    /// Stop serving, routing and settling, and close the endpoint. The
    /// journal stays in the database: a node started again on it resumes
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

    /// Answer the hop requests (PREPARE, EXECUTE, DISCARD, SETTLE) with
    /// `router` from now on.
    pub fn route_with(&self, router: Handler) {
        *self.0.router.write().unwrap_or_else(|e| e.into_inner()) = Some(router);
    }

    pub fn span(&self) -> Span {
        self.0.span.clone()
    }

    pub fn db(&self) -> &Db {
        &self.0.db
    }

    pub fn keys(&self) -> &NodeKeys {
        &self.0.keys
    }

    pub fn node_pubkey(&self) -> XOnlyPubKey {
        self.0.keys.node.pubkey()
    }

    pub fn iroh_peer_id(&self) -> String {
        self.0.transport.peer_id()
    }

    /// The node's endpoint: with its identity when it serves, so the
    /// offline flows (see [`create_gateway_invoice`]) can talk from it.
    pub fn transport(&self) -> &Transport {
        &self.0.transport
    }

    pub fn add_network(&self, network: Arc<dyn Network>) {
        self.0
            .networks
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(network.id(), network);
    }

    /// Stop using `id`, returning it. Tasks that hold it already keep
    /// it until they end.
    pub fn remove_network(&self, id: &NetworkId) -> Option<Arc<dyn Network>> {
        self.0
            .networks
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(id)
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

    /// Answer one request from `peer`.
    pub async fn handle(&self, request: Request, peer: String) -> Response {
        match request {
            Request::PreparePayee(prepare) => Response::PayeePrepared(self.prepare_payee(prepare)),
            Request::Commit(commit) => self.commit(commit).await,
            Request::Prepare(_)
            | Request::Execute(_)
            | Request::Discard(_)
            | Request::Settle(_) => {
                let router = self
                    .0
                    .router
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone();
                match router {
                    Some(router) => router(request, peer).await,
                    None => Response::Error("this node does not route".into()),
                }
            }
            Request::PreimageIssue { .. }
            | Request::PreimageRelease(_)
            | Request::PreimagePayments { .. } => {
                Response::Error("this node is not a preimage server".into())
            }
            Request::GatewayInvoice(_)
            | Request::GatewayAuthorize { .. }
            | Request::GatewayInvoiceFor(_) => Response::Error("this node is not a gateway".into()),
        }
    }

    /// Mark `key` as being acted on; `None` if another task already is.
    pub fn busy(&self, key: String) -> Option<BusyGuard> {
        let mut busy = self.0.busy.lock().unwrap_or_else(|e| e.into_inner());
        busy.insert(key.clone()).then(|| BusyGuard {
            node: self.0.clone(),
            key,
        })
    }
}

/// Held while a task acts on a record: see [`Node::busy`].
pub struct BusyGuard {
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

/// A database error, as the node reports errors.
pub(crate) fn db_error(error: orangedb::Error) -> String {
    format!("database: {error}")
}
