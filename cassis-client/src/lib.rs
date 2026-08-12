pub mod adapters;
pub mod netspec;
pub mod ops;
pub mod paths;
pub mod seed_store;
pub mod store;

use cassis_core::{
    AdapterError, Bytes32, HopCommit, HopCommitted, HopDiscard, HopExecute, HopPrepare,
    HtlcDescriptor, HtlcTarget, Invoice, InvoiceHandle, NetworkAdapter, NetworkId, OperationId,
    OutgoingPayment, OutgoingRequest, PaymentResult, PaymentStatus, RouteHop,
};
use cassis_iroh::{node_addr_from_announcement, node_addr_from_invoice, IrohClient};
use cassis_routing::{
    build_graph, compute_hop_expiries, fallback_transit_slack, fetch_announcements,
    find_route as find_route_in_graph,
};
use futures::future::join_all;
use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

use crate::store::{OutgoingPaymentStatus, PendingOutgoingPayment, Store};

#[derive(thiserror::Error, Debug)]
pub enum PayError {
    #[error("route error: {0}")]
    Route(String),
    #[error("io error: {0}")]
    Io(String),
    #[error("remote error (retryable={retryable}): {message}")]
    Remote { message: String, retryable: bool },
    #[error("hop rejected at index {index}: {reason}")]
    HopRejected { index: usize, reason: String },
    #[error("payee commit failed: {0}")]
    Commit(String),
    #[error("unimplemented")]
    Unimplemented,
}

impl From<cassis_iroh::IrohError> for PayError {
    fn from(e: cassis_iroh::IrohError) -> Self {
        match e {
            cassis_iroh::IrohError::Remote {
                message, retryable, ..
            } => PayError::Remote { message, retryable },
            other => PayError::Io(other.to_string()),
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ReceiveFlowError {
    #[error("network not registered: {0}")]
    UnknownNetwork(String),
    #[error("invoice reservation not found: {0}")]
    MissingReservation(String),
    #[error("receive error: {0}")]
    Adapter(#[from] AdapterError),
}

#[derive(Clone, Debug)]
pub struct ReceiveResult {
    pub payment_hash: Bytes32,
    pub preimage: Option<Bytes32>,
}

#[derive(thiserror::Error, Debug)]
pub enum RouteError {
    #[error("route error: {0}")]
    Route(cassis_routing::RouteError),
    #[error("nostr fetch error: {0}")]
    Fetch(String),
    #[error("unimplemented")]
    Unimplemented,
}

pub async fn find_route(
    relays: &[String],
    destination_network: &NetworkId,
    amount_msat: u64,
    sender_network: &NetworkId,
) -> Result<Vec<RouteHop>, RouteError> {
    let announcements = fetch_announcements(relays)
        .await
        .map_err(|err| RouteError::Fetch(err.to_string()))?;
    let graph = build_graph(announcements);
    graph.log();
    let route = find_route_in_graph(&graph, destination_network, amount_msat, sender_network)
        .map_err(RouteError::Route)?;
    let hops = route
        .into_iter()
        .map(|(node, incoming, outgoing)| RouteHop {
            node,
            incoming,
            outgoing,
        })
        .collect();
    Ok(hops)
}

/// Compute amount required at each hop. Each router subtracts its fee
/// from incoming amount and forwards remainder. Payer therefore locks
/// invoice amount plus all downstream fees on first hop.
fn route_amounts(invoice_amount_msat: u64, route: &[RouteHop]) -> Result<Vec<u64>, PayError> {
    let mut amounts = vec![0u64; route.len() + 1];
    amounts[route.len()] = invoice_amount_msat;
    for index in (0..route.len()).rev() {
        let downstream = amounts[index + 1];
        let node = &route[index].node;
        let proportional =
            (node.fee_ppm as u128).saturating_mul(downstream as u128) / 1_000_000u128;
        let fee = (node.fee_base_msat as u128)
            .saturating_add(proportional)
            .min(u64::MAX as u128) as u64;
        let amount = (downstream as u128)
            .checked_add(fee as u128)
            .ok_or_else(|| PayError::Route("route fee overflows amount".to_string()))?;
        if amount > u64::MAX as u128 {
            return Err(PayError::Route("route fee overflows amount".to_string()));
        }
        amounts[index] = amount as u64;
    }
    Ok(amounts)
}

pub struct CassisClient {
    pub adapters: HashMap<NetworkId, Arc<dyn NetworkAdapter>>,
    pub nostr_relays: Vec<String>,
    iroh_client: IrohClient,
    payment_store_path: PathBuf,
    invoice_handles: Arc<tokio::sync::Mutex<HashMap<Bytes32, InvoiceHandle>>>,
}

async fn create_outgoing_payment(
    adapter: &dyn NetworkAdapter,
    payment_hash: Bytes32,
    amount_msat: u64,
    target: &HtlcTarget,
    network: &NetworkId,
    expiry: u64,
) -> Result<OutgoingPayment, AdapterError> {
    adapter
        .create_outgoing(OutgoingRequest {
            operation_id: OperationId::random(),
            payment_hash,
            amount_msat,
            expiry,
            target: target.clone(),
            network: network.clone(),
        })
        .await
}

/// Keep payer-owned outgoing HTLC alive until it resolves. Routers have
/// the same responsibility for the outgoing HTLCs they executed; the
/// payer's first HTLC is not present in any router's execute table.
fn spawn_payment_guard(
    sender: Arc<dyn NetworkAdapter>,
    payment: OutgoingPayment,
    invoice: Invoice,
    store_path: PathBuf,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            if ops::unix_now() >= payment.expiry {
                break;
            }
            match sender.watch_outgoing(&payment, payment.expiry).await {
                Ok(preimage) => {
                    if let Err(error) = persist_payment_proof(&store_path, &invoice, preimage).await
                    {
                        warn!(target: "cassis_client", "failed to persist payment proof: {error}");
                    }
                    let _ = mark_outgoing_status(
                        &store_path,
                        &payment.operation_id,
                        OutgoingPaymentStatus::Completed,
                    )
                    .await;
                    return;
                }
                Err(AdapterError::DeadlineExceeded) if ops::unix_now() >= payment.expiry => {
                    break;
                }
                Err(AdapterError::Network(error)) | Err(AdapterError::Retryable(error)) => {
                    warn!(
                        target: "cassis_client",
                        "sender-side HTLC watch failed for {}: {error}; retrying",
                        payment.payment_hash.short()
                    );
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                Err(error) => {
                    warn!(
                        target: "cassis_client",
                        "sender-side HTLC watch failed for {}: {error}; entering refund path",
                        payment.payment_hash.short()
                    );
                    break;
                }
            }
        }

        loop {
            match sender.refund_outgoing(&payment).await {
                Ok(()) => {
                    let _ = mark_outgoing_status(
                        &store_path,
                        &payment.operation_id,
                        OutgoingPaymentStatus::Refunded,
                    )
                    .await;
                    break;
                }
                Err(AdapterError::Network(error)) | Err(AdapterError::Retryable(error)) => {
                    warn!(
                        target: "cassis_client",
                        "sender-side HTLC refund failed: {error}; retrying"
                    );
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
                Err(error) => {
                    warn!(target: "cassis_client", "sender-side HTLC refund failed: {error}");
                    break;
                }
            }
        }
    })
}

async fn persist_outgoing_payment(
    path: &std::path::Path,
    invoice: &Invoice,
    payment: &OutgoingPayment,
    sender_network: &NetworkId,
) -> Result<(), String> {
    let path = path.to_path_buf();
    let invoice = invoice.clone();
    let payment = payment.clone();
    let sender_network = sender_network.clone();
    tokio::task::spawn_blocking(move || {
        let mut store = Store::open(&path).map_err(|e| e.to_string())?;
        store
            .insert_outgoing_payment(&invoice, &payment, &sender_network)
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

async fn persist_payment_proof(
    path: &std::path::Path,
    invoice: &Invoice,
    preimage: Bytes32,
) -> Result<(), String> {
    let path = path.to_path_buf();
    let invoice = invoice.clone();
    tokio::task::spawn_blocking(move || {
        let mut store = Store::open(&path).map_err(|e| e.to_string())?;
        store
            .record_payment_proof(&invoice, preimage)
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

async fn mark_outgoing_status(
    path: &std::path::Path,
    operation_id: &OperationId,
    status: OutgoingPaymentStatus,
) -> Result<(), String> {
    let path = path.to_path_buf();
    let operation_id = operation_id.clone();
    tokio::task::spawn_blocking(move || {
        let mut store = Store::open(&path).map_err(|e| e.to_string())?;
        store
            .mark_outgoing_status(&operation_id, status)
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

impl CassisClient {
    pub async fn new(
        adapters: HashMap<NetworkId, Arc<dyn NetworkAdapter>>,
        nostr_relays: Vec<String>,
    ) -> Self {
        Self::with_store_path(
            adapters,
            nostr_relays,
            PathBuf::from("./cassis-client-store.db"),
        )
        .await
    }

    pub async fn with_store_path(
        adapters: HashMap<NetworkId, Arc<dyn NetworkAdapter>>,
        nostr_relays: Vec<String>,
        payment_store_path: PathBuf,
    ) -> Self {
        let endpoint = Endpoint::builder(presets::N0)
            .bind()
            .await
            .expect("failed to bind iroh endpoint for client");
        Self {
            adapters,
            nostr_relays,
            iroh_client: IrohClient::new(endpoint),
            payment_store_path,
            invoice_handles: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        }
    }

    pub fn iroh_client(&self) -> &IrohClient {
        &self.iroh_client
    }

    pub fn peer_id(&self) -> String {
        self.iroh_client.peer_id().to_string()
    }

    /// Resume every payer-owned outgoing HTLC persisted as pending. The
    /// adapter rebuilds its watcher state from the stored descriptor, then
    /// the same guard used by [`Self::pay`] watches for a preimage or waits
    /// for expiry before requesting a refund.
    pub async fn watch_pending(&self) -> Result<(), String> {
        let path = self.payment_store_path.clone();
        let pending: Vec<PendingOutgoingPayment> = tokio::task::spawn_blocking(move || {
            let mut store = Store::open(&path).map_err(|e| e.to_string())?;
            store.list_pending_outgoing().map_err(|e| e.to_string())
        })
        .await
        .map_err(|e| e.to_string())??;

        let mut guards = Vec::with_capacity(pending.len());
        for row in pending {
            let sender = self
                .adapters
                .get(&row.sender_network)
                .cloned()
                .ok_or_else(|| format!("sender adapter missing for {}", row.sender_network))?;
            sender.restore_outgoing(&row.payment).await.map_err(|e| {
                format!(
                    "cannot restore outgoing HTLC {} on {}: {e}",
                    row.payment.payment_hash, row.sender_network
                )
            })?;
            guards.push(spawn_payment_guard(
                sender,
                row.payment,
                row.invoice,
                self.payment_store_path.clone(),
            ));
        }
        join_all(guards).await;
        Ok(())
    }

    /// Drive the multi-hop PREPARE / EXECUTE / COMMIT protocol
    /// described in the user-facing docs:
    ///
    /// 1. PREPARE every router hop in order; abort if any rejects.
    /// 2. Create first outgoing HTLC on sender adapter.
    /// 3. Walk route: EXECUTE to hop `i` with descriptor returned by
    ///    hop `i-1` (or first outgoing payment).
    /// 4. After the last router, COMMIT directly to the payee's
    ///    iroh endpoint with the final descriptor and wait for
    ///    the preimage.
    pub async fn pay(
        &self,
        invoice: Invoice,
        sender_network: NetworkId,
    ) -> Result<PaymentResult, PayError> {
        let dest_network = invoice
            .networks
            .first()
            .ok_or_else(|| PayError::Route("invoice has no network".to_string()))?
            .clone();
        if sender_network == dest_network {
            return self
                .pay_same_network(&invoice, &dest_network, &sender_network)
                .await;
        }

        let route = self
            .find_route(&dest_network, invoice.amount_msat, sender_network.clone())
            .await
            .map_err(|err| PayError::Route(err.to_string()))?;

        if route.is_empty() {
            return self
                .pay_same_network(&invoice, &dest_network, &sender_network)
                .await;
        }

        // Validate the chain of networks before reserving capacity on
        // anyone. Each hop reports a claim identity that is only valid on
        // one network, so a break anywhere in this chain would have us
        // lock an HTLC to a key valid on a *different* network — the same
        // silent-divergence class this identity plumbing exists to
        // prevent. Cheaper to reject here than after PREPAREing everyone.
        validate_route_networks(&route, &sender_network, &dest_network)?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let hop_amounts = route_amounts(invoice.amount_msat, &route)?;
        let mut buffers: Vec<u64> = route
            .iter()
            .map(|hop| {
                let delta = if hop.node.incoming_delta_secs > 0 {
                    hop.node.incoming_delta_secs
                } else {
                    hop.incoming.default_incoming_delta()
                };
                let slack = if hop.node.transit_slack_secs > 0 {
                    hop.node.transit_slack_secs
                } else {
                    fallback_transit_slack(&hop.incoming)
                };
                delta.saturating_add(slack)
            })
            .collect();
        // The cascade needs a buffer for the final leg to the payee as
        // well: with only per-hop buffers it hands the last router an
        // outgoing expiry of exactly `now`, which adapters reject as
        // already expired. The cascade stays anchored at `now` — the
        // moment the payer decides to start — and every leg (the
        // routers plus the payee's claim window) stacks its buffer on
        // top of the previous one toward the sender.
        let payee_delta = dest_network.default_incoming_delta();
        let payee_slack = fallback_transit_slack(&dest_network);
        buffers.push(payee_delta.saturating_add(payee_slack));
        let expiries = compute_hop_expiries(now, &buffers);

        // Step 1: PREPARE every hop.
        let addrs: Vec<EndpointAddr> = route
            .iter()
            .map(|hop| {
                node_addr_from_announcement(&hop.node).map_err(|e| PayError::Io(e.to_string()))
            })
            .collect::<Result<Vec<_>, PayError>>()?;

        let attempt_ids: Vec<OperationId> =
            (0..route.len()).map(|_| OperationId::random()).collect();
        let all_hop_indices: Vec<usize> = (0..route.len()).collect();
        let prepares: Vec<(usize, HopPrepare)> = route
            .iter()
            .enumerate()
            .map(|(idx, hop)| {
                (
                    idx,
                    HopPrepare {
                        payment_hash: invoice.payment_hash,
                        operation_id: attempt_ids[idx].clone(),
                        amount_msat: hop_amounts[idx],
                        outgoing_amount_msat: hop_amounts[idx + 1],
                        incoming_network: hop.incoming.clone(),
                        outgoing_network: hop.outgoing.clone(),
                        incoming_deadline: expiries.get(idx).copied().unwrap_or(now),
                        outgoing_expiry: expiries.get(idx + 1).copied().unwrap_or(now),
                    },
                )
            })
            .collect();
        // All PREPAREs run concurrently. Every future is joined —
        // never cancelled mid-flight — because the only reliable set
        // of hops to DISCARD afterwards is "the ones whose reply was
        // actually read": a hop may have reserved while its reply died
        // in transport, and once a reply is lost that hop is
        // unreachable from here on.
        let prepared_futures = prepares.iter().cloned().map(|(idx, p)| {
            let peer = route[idx].node.node_pubkey;
            let addr = addrs[idx].clone();
            let route_len = route.len();
            info!(
                target: "cassis_client",
                "PREPARE hop {}/{route_len}: peer={peer} addr={addr:?} incoming={} outgoing={} \
                 amount_msat={} incoming_deadline={} outgoing_expiry={} payment_hash={}",
                idx+1,
                p.incoming_network,
                p.outgoing_network,
                p.amount_msat,
                p.incoming_deadline,
                p.outgoing_expiry,
                p.payment_hash,
            );
            async move {
                let reply = self.iroh_client.send_prepare(addr, p.clone()).await;
                match &reply {
                    Ok(ack) => info!(
                        target: "cassis_client",
                        "PREPARE hop {}/{route_len}: peer={peer} accepted={} reason={:?}",
                        idx+1,
                        ack.accepted,
                        ack.reason,
                    ),
                    Err(e) => info!(
                        target: "cassis_client",
                        "PREPARE hop {}/{route_len}: peer={peer} error={e}",
                        idx+1
                    ),
                }
                reply
            }
        });
        let replies = join_all(prepared_futures).await;

        // Reserve-list = hops that answered accepted=true; error = the
        // first failure in route order (rejection or transport). The
        // whole list is scanned even after a failure so late-accepting
        // hops are not forgotten when it is time to DISCARD.
        let mut acks: Vec<cassis_core::HopPrepared> = Vec::new();
        let mut reservation_ids: Vec<cassis_core::OperationId> = Vec::new();
        let mut first_failure: Option<PayError> = None;
        for (idx, reply) in replies.into_iter().enumerate() {
            match reply {
                Ok(ack) if ack.accepted => {
                    let operation_id = ack.operation_id.clone();
                    if operation_id != attempt_ids[idx] {
                        first_failure.get_or_insert(PayError::HopRejected {
                            index: idx,
                            reason: "PREPARE operation_id did not match payer attempt".to_string(),
                        });
                        continue;
                    }
                    reservation_ids.push(operation_id);
                    acks.push(ack);
                }
                Ok(ack) => {
                    let reason = ack.reason.clone().unwrap_or_else(|| "unknown".to_string());
                    first_failure.get_or_insert(PayError::HopRejected { index: idx, reason });
                }
                Err(err) => {
                    first_failure.get_or_insert(PayError::Io(err.to_string()));
                }
            }
        }
        if let Some(err) = first_failure {
            self.discard_reservations(&addrs, invoice.payment_hash, &all_hop_indices, &attempt_ids)
                .await;
            return Err(err);
        }

        // Resolve who each HTLC must be locked to. Every hop reports
        // the identity it claims its *incoming* HTLC with, so the party
        // upstream of it locks to that key; the payee's identity comes
        // from the invoice. `recipients[i]` is therefore the key the
        // HTLC funding hop `i` must be locked to, and `recipients[len]`
        // is the payee's.
        //
        // This is why `recipient` rides on EXECUTE rather than
        // PREPARE: the PREPAREs above run concurrently, so hop `i+1`'s
        // reply does not exist yet while hop `i`'s PREPARE is built.
        // Deriving it here, after every reply is in, also makes the
        // "lock to hop i instead of hop i+1" off-by-one unrepresentable.
        // A missing claim identity is a hard error rather than a
        // fallback to the announced node key: guessing is exactly what
        // caused HTLCs to be locked to unclaimable identities, and the
        // failure only surfaced on-chain after funds were committed.
        let mut htlc_targets = Vec::with_capacity(route.len() + 1);
        for (idx, ack) in acks.iter().enumerate() {
            match ack.htlc_target.clone() {
                Some(target) => htlc_targets.push(target),
                None => {
                    // Every hop accepted, so every hop is holding a
                    // reservation; none was executed yet.
                    self.discard_reservations(
                        &addrs,
                        invoice.payment_hash,
                        &all_hop_indices,
                        &attempt_ids,
                    )
                    .await;
                    return Err(PayError::HopRejected {
                        index: idx,
                        reason: "hop accepted the PREPARE but reported no addressing parameters"
                            .to_string(),
                    });
                }
            }
        }
        htlc_targets.push(invoice.address.clone());

        // Step 2: pay the first hop. The sender adapter creates
        // the first HTLC and returns the OutgoingPayment
        // descriptor (cashu proofs, etc.).
        let sender = match self.adapters.get(&sender_network) {
            Some(s) => s.clone(),
            None => {
                self.discard_reservations(
                    &addrs,
                    invoice.payment_hash,
                    &all_hop_indices,
                    &attempt_ids,
                )
                .await;
                return Err(PayError::Route(
                    "sender network adapter missing".to_string(),
                ));
            }
        };
        // The sender's outgoing HTLC is the first hop's *incoming*,
        // so it must not expire before the first hop's incoming
        // deadline (expiries[0]).
        let first_outgoing_expiry = expiries.first().copied().unwrap_or(now);
        // Lock to the first hop's self-reported claim identity, not to
        // its announced node key: those are different keys whenever the
        // network claims with a dedicated per-network key (rootstock).
        let first_target = &htlc_targets[0];
        let first_payment: OutgoingPayment = match create_outgoing_payment(
            sender.as_ref(),
            invoice.payment_hash,
            hop_amounts[0],
            first_target,
            &sender_network,
            first_outgoing_expiry,
        )
        .await
        {
            Ok(p) => p,
            Err(err) => {
                // Nothing funded yet on any hop; free every reservation.
                self.discard_reservations(
                    &addrs,
                    invoice.payment_hash,
                    &all_hop_indices,
                    &attempt_ids,
                )
                .await;
                return Err(PayError::Io(err.to_string()));
            }
        };
        let payment_guard = spawn_payment_guard(
            sender.clone(),
            first_payment.clone(),
            invoice.clone(),
            self.payment_store_path.clone(),
        );
        if let Err(error) = persist_outgoing_payment(
            &self.payment_store_path,
            &invoice,
            &first_payment,
            &sender_network,
        )
        .await
        {
            warn!(target: "cassis_client", "failed to persist outgoing HTLC: {error}");
        }
        // Descriptor travels with funded payment handle. No second
        // adapter map lookup or post-funding serialization window.
        let first_descriptor: HtlcDescriptor = first_payment.descriptor.clone();

        // Step 3: walk the route. `descriptor` carries the
        // HTLC info for the *incoming* side of the next hop.
        let mut descriptor = first_descriptor;
        for (i, hop) in route.iter().enumerate() {
            let execute = HopExecute {
                payment_hash: invoice.payment_hash,
                operation_id: reservation_ids[i].clone(),
                incoming_descriptor: descriptor,
                htlc_target: htlc_targets[i + 1].clone(),
            };
            let peer = hop.node.node_pubkey;
            let addr = addrs[i].clone();
            info!(
            target: "cassis_client",
             "EXECUTE hop {}/{}: peer={peer} addr={addr:?} incoming={} outgoing={} \
              amount_msat={} incoming_deadline={} outgoing_expiry={} addressing=<redacted> \
             payment_hash={} incoming_descriptor=<redacted>",
            i+1,
            route.len(),
            hop.incoming,
            hop.outgoing,
            invoice.amount_msat,
            expiries[i],
            expiries[i + 1],
            execute.payment_hash,
                        );
            debug!(
                target: "cassis_client",
                "  EXECUTE hop {}: in={} out={} amount={} msat",
                i+1,
                hop.incoming, hop.outgoing, invoice.amount_msat
            );
            let reply = match self.iroh_client.send_execute(addr, execute).await {
                Ok(r) => r,
                Err(e) => {
                    info!(
                        target: "cassis_client",
                        "EXECUTE hop {}/{}: peer={peer} error={e}",
                        i+1,
                        route.len(),
                    );
                    // Hops 0..i executed successfully (their
                    // reservations became funded HTLCs; DISCARD is a
                    // no-op there and is not sent). This hop may have
                    // consumed its reservation before failing — or not
                    // heard from us at all — so the safe set to free is
                    // this hop plus everything downstream.
                    self.discard_reservations(
                        &addrs,
                        invoice.payment_hash,
                        &all_hop_indices,
                        &attempt_ids,
                    )
                    .await;
                    return Err(PayError::Io(e.to_string()));
                }
            };
            if reply.payment_hash != invoice.payment_hash
                || reply.operation_id != reservation_ids[i]
            {
                self.discard_reservations(
                    &addrs,
                    invoice.payment_hash,
                    &all_hop_indices,
                    &attempt_ids,
                )
                .await;
                return Err(PayError::Io(format!(
                    "EXECUTE response correlation mismatch at hop {}",
                    i + 1
                )));
            }
            info!(
                target: "cassis_client",
                "EXECUTE hop {}/{}: peer={peer} outgoing_descriptor=<redacted>",
                i + 1,
                route.len(),
            );
            descriptor = reply.outgoing_descriptor;
        }

        // Step 4: COMMIT to the payee. The last `descriptor`
        // describes the HTLC deployed on the payee's incoming
        // network.
        let peer_id = invoice
            .iroh_peer_id
            .as_deref()
            .ok_or_else(|| PayError::Commit("invoice missing payee iroh_peer_id".to_string()))?;
        let payee_addr = node_addr_from_invoice(peer_id, invoice.iroh_relay.as_deref())
            .map_err(|e| PayError::Commit(format!("payee addr: {e}")))?;
        let commit = HopCommit {
            payment_hash: invoice.payment_hash,
            operation_id: OperationId::random(),
            amount_msat: invoice.amount_msat,
            network: dest_network.clone(),
            incoming_deadline: invoice.expires_at,
            incoming_descriptor: descriptor,
        };
        info!(
            target: "cassis_client",
            "sending COMMIT to payee for payment_hash={}",
            invoice.payment_hash.short(),
        );
        let committed = self.iroh_client.send_commit(payee_addr, commit).await?;
        let preimage = committed.preimage;
        // The payee's COMMIT reply is where the preimage enters this
        // process: from here on the payer can claim its own outgoing
        // HTLC, and so can every hop in between.
        info!(
            target: "cassis_client",
            "payee accepted COMMIT for payment_hash={} on {} (preimage received)",
            invoice.payment_hash.short(),
            dest_network,
        );
        if preimage.0 == [0u8; 32] {
            return Err(PayError::Commit(
                "payee returned zero preimage (misroute or commit handler missing)".to_string(),
            ));
        }

        // Step 5: verify the preimage actually matches the
        // payment hash before returning success. Cheap local
        // check; protects against accidental misroutes.
        if !preimage_matches(&preimage, &invoice.payment_hash) {
            return Err(PayError::Commit(format!(
                "payee preimage does not hash to payment hash {}",
                invoice.payment_hash
            )));
        }

        // Fan the revealed preimage out to every router hop so each can
        // claim its incoming HTLC now, rather than waiting for the poll
        // loop to observe the preimage on its downstream network.
        // Best-effort: a hop that misses the fanout still settles via
        // its own watch/refund loop.
        self.fanout_preimage(&addrs, &reservation_ids, invoice.payment_hash, preimage)
            .await;

        persist_payment_proof(&self.payment_store_path, &invoice, preimage)
            .await
            .map_err(PayError::Io)?;
        mark_outgoing_status(
            &self.payment_store_path,
            &first_payment.operation_id,
            OutgoingPaymentStatus::Completed,
        )
        .await
        .map_err(PayError::Io)?;
        payment_guard.abort();

        // The first-hop HTLC is what the sender adapter
        // already created. Its preimage should now be
        // available on the sender network; surface a
        // best-effort claim result. We do not block the
        // caller on the sender-side watch because the
        // preimage is already proven by the payee.
        match sender
            .watch_outgoing(&first_payment, first_payment.expiry)
            .await
        {
            Ok(_) => {}
            Err(AdapterError::DeadlineExceeded) => {
                warn!(
                    target: "cassis_client",
                    "  sender-side watch timed out (preimage already proven by COMMIT)"
                );
            }
            Err(err) => {
                warn!(
                    target: "cassis_client",
                    "  sender-side watch error: {err} (preimage already proven by COMMIT)"
                );
            }
        }

        Ok(PaymentResult {
            status: PaymentStatus::Completed,
            preimage: Some(preimage),
        })
    }

    /// Same-network shortcut: payer and payee share a network, so there
    /// are no router hops to PREPARE/EXECUTE. Create the HTLC directly
    /// on that network, COMMIT straight to the payee, and settle on the
    /// returned preimage. Mirrors steps 2/4/5 of [`Self::pay`] without
    /// the route walk.
    async fn pay_same_network(
        &self,
        invoice: &Invoice,
        dest_network: &NetworkId,
        sender_network: &NetworkId,
    ) -> Result<PaymentResult, PayError> {
        let sender = self
            .adapters
            .get(sender_network)
            .ok_or_else(|| PayError::Route("sender network adapter missing".to_string()))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let delta = dest_network.default_incoming_delta();
        let slack = fallback_transit_slack(dest_network);
        let outgoing_expiry = now.saturating_add(delta).saturating_add(slack);

        let htlc_target = invoice.address.clone();

        let first_payment = create_outgoing_payment(
            sender.as_ref(),
            invoice.payment_hash,
            invoice.amount_msat,
            &htlc_target,
            sender_network,
            outgoing_expiry,
        )
        .await
        .map_err(|e| PayError::Io(e.to_string()))?;
        let payment_guard = spawn_payment_guard(
            sender.clone(),
            first_payment.clone(),
            invoice.clone(),
            self.payment_store_path.clone(),
        );
        if let Err(error) = persist_outgoing_payment(
            &self.payment_store_path,
            invoice,
            &first_payment,
            sender_network,
        )
        .await
        {
            warn!(target: "cassis_client", "failed to persist outgoing HTLC: {error}");
        }

        let descriptor = first_payment.descriptor.clone();

        let peer_id = invoice
            .iroh_peer_id
            .as_deref()
            .ok_or_else(|| PayError::Commit("invoice missing payee iroh_peer_id".to_string()))?;
        let payee_addr = node_addr_from_invoice(peer_id, invoice.iroh_relay.as_deref())
            .map_err(|e| PayError::Commit(format!("payee addr: {e}")))?;
        let commit = HopCommit {
            payment_hash: invoice.payment_hash,
            operation_id: OperationId::random(),
            amount_msat: invoice.amount_msat,
            network: dest_network.clone(),
            incoming_deadline: invoice.expires_at,
            incoming_descriptor: descriptor,
        };
        info!(
            target: "cassis_client",
            "sending same-network COMMIT to payee for payment_hash={} on {}",
            invoice.payment_hash.short(),
            dest_network,
        );
        let committed = self.iroh_client.send_commit(payee_addr, commit).await?;
        let preimage = committed.preimage;
        if preimage.0 == [0u8; 32] {
            return Err(PayError::Commit(
                "payee returned zero preimage (misroute or commit handler missing)".to_string(),
            ));
        }
        if !preimage_matches(&preimage, &invoice.payment_hash) {
            return Err(PayError::Commit(format!(
                "payee preimage does not hash to payment hash {}",
                invoice.payment_hash
            )));
        }

        persist_payment_proof(&self.payment_store_path, invoice, preimage)
            .await
            .map_err(PayError::Io)?;
        mark_outgoing_status(
            &self.payment_store_path,
            &first_payment.operation_id,
            OutgoingPaymentStatus::Completed,
        )
        .await
        .map_err(PayError::Io)?;
        payment_guard.abort();

        match sender
            .watch_outgoing(&first_payment, first_payment.expiry)
            .await
        {
            Ok(_) => {}
            Err(AdapterError::DeadlineExceeded) => {
                warn!(
                    target: "cassis_client",
                    "  sender-side watch timed out (preimage already proven by COMMIT)"
                );
            }
            Err(err) => {
                warn!(
                    target: "cassis_client",
                    "  sender-side watch error: {err} (preimage already proven by COMMIT)"
                );
            }
        }

        Ok(PaymentResult {
            status: PaymentStatus::Completed,
            preimage: Some(preimage),
        })
    }

    /// Fire DISCARD at the given hops to release their PREPARE
    /// reservations, concurrently and best-effort: replies are logged
    /// (`released: false` covers already-consumed / aged-out /
    /// never-existed), failures do not alter the payment error. A hop
    /// that received no reply is simply unreachable; its reservation
    /// ages out on its own deadline.
    async fn discard_reservations(
        &self,
        addrs: &[EndpointAddr],
        payment_hash: Bytes32,
        hop_indices: &[usize],
        operation_ids: &[OperationId],
    ) {
        if operation_ids.is_empty() || hop_indices.len() != operation_ids.len() {
            return;
        }
        info!(
            target: "cassis_client",
            "payment aborted: sending DISCARD for {} reservation(s)",
            operation_ids.len(),
        );
        let futs = hop_indices
            .iter()
            .zip(operation_ids)
            .map(|(hop_index, operation_id)| {
                let Some(addr) = addrs.get(*hop_index).cloned() else {
                    return futures::future::Either::Left(async {});
                };
                let operation_id = operation_id.clone();
                futures::future::Either::Right(async move {
                    match self
                        .iroh_client
                        .send_discard(
                            addr,
                            HopDiscard {
                                payment_hash,
                                operation_id,
                            },
                        )
                        .await
                    {
                        Ok(ack) => debug!(
                            target: "cassis_client",
                            "DISCARD hop {}: released={}",
                            hop_index + 1,
                            ack.released,
                        ),
                        Err(e) => warn!(
                            target: "cassis_client",
                            "DISCARD hop {} failed (best effort): {e}",
                            hop_index + 1,
                        ),
                    }
                })
            });
        let futs: Vec<_> = futs.collect();
        join_all(futs).await;
    }

    /// Push an already-revealed preimage to every router hop, so each
    /// can claim its incoming HTLC without waiting for its poll loop to
    /// observe the preimage on the downstream network. Concurrent and
    /// best-effort: a hop that misses the fanout still settles via its
    /// own watch/refund loop, so failures only log here.
    async fn fanout_preimage(
        &self,
        addrs: &[EndpointAddr],
        operation_ids: &[OperationId],
        payment_hash: Bytes32,
        preimage: Bytes32,
    ) {
        if addrs.len() != operation_ids.len() {
            warn!(
                target: "cassis_client",
                "skip preimage fanout: {} addresses but {} operation ids",
                addrs.len(),
                operation_ids.len(),
            );
            return;
        }
        info!(
            target: "cassis_client",
            "fanning preimage out to {} hop(s) for payment_hash={}",
            addrs.len(),
            payment_hash.short(),
        );
        let futs = addrs.iter().enumerate().map(|(i, addr)| {
            let addr = addr.clone();
            let committed = HopCommitted {
                payment_hash,
                operation_id: operation_ids[i].clone(),
                preimage,
            };
            async move {
                match self.iroh_client.send_committed(addr, committed).await {
                    Ok(_) => debug!(
                        target: "cassis_client",
                        "COMMITTED fanout to hop {}: acknowledged",
                        i + 1,
                    ),
                    Err(e) => warn!(
                        target: "cassis_client",
                        "COMMITTED fanout to hop {} failed (best effort): {e}",
                        i + 1,
                    ),
                }
            }
        });
        join_all(futs).await;
    }

    pub async fn restore_invoice_handles(&self) -> Result<(), String> {
        let path = self.payment_store_path.clone();
        let handles = tokio::task::spawn_blocking(move || {
            let mut store = Store::open(&path).map_err(|e| e.to_string())?;
            store.list_invoice_handles().map_err(|e| e.to_string())
        })
        .await
        .map_err(|e| e.to_string())??;
        let mut memory = self.invoice_handles.lock().await;
        memory.extend(
            handles
                .into_iter()
                .map(|handle| (handle.invoice.payment_hash, handle)),
        );
        Ok(())
    }

    pub async fn find_route(
        &self,
        destination_network: &NetworkId,
        amount_msat: u64,
        sender_network: NetworkId,
    ) -> Result<Vec<RouteHop>, RouteError> {
        find_route(
            &self.nostr_relays,
            destination_network,
            amount_msat,
            &sender_network,
        )
        .await
    }

    fn receiver_for(
        &self,
        network: &NetworkId,
    ) -> Result<Arc<dyn NetworkAdapter>, ReceiveFlowError> {
        self.adapters
            .get(network)
            .cloned()
            .ok_or_else(|| ReceiveFlowError::UnknownNetwork(network.0.clone()))
    }

    pub async fn create_invoice_handle(
        &self,
        network: &NetworkId,
        amount_msat: u64,
        expiry: u64,
        description: Option<String>,
    ) -> Result<InvoiceHandle, ReceiveFlowError> {
        let receiver = self.receiver_for(network)?;
        let handle =
            cassis_core::create_invoice_handle(receiver.as_ref(), amount_msat, expiry, description)
                .await?;
        self.invoice_handles
            .lock()
            .await
            .insert(handle.invoice.payment_hash, handle.clone());
        let path = self.payment_store_path.clone();
        let stored_handle = handle.clone();
        tokio::task::spawn_blocking(move || {
            let mut store = Store::open(&path).map_err(|e| e.to_string())?;
            store
                .insert_invoice_handle(&stored_handle)
                .map_err(|e| e.to_string())
        })
        .await
        .map_err(|e| AdapterError::Network(e.to_string()))?
        .map_err(AdapterError::Network)?;
        Ok(handle)
    }

    pub async fn create_invoice(
        &self,
        network: &NetworkId,
        amount_msat: u64,
        expiry: u64,
        description: Option<String>,
    ) -> Result<Invoice, ReceiveFlowError> {
        Ok(self
            .create_invoice_handle(network, amount_msat, expiry, description)
            .await?
            .invoice)
    }

    pub async fn wait_for_incoming(
        &self,
        network: &NetworkId,
        payment_hash: Bytes32,
        deadline: u64,
    ) -> Result<Bytes32, ReceiveFlowError> {
        let receiver = self.receiver_for(network)?;
        let handle = self
            .invoice_handles
            .lock()
            .await
            .get(&payment_hash)
            .cloned();
        let Some(handle) = handle else {
            return Err(ReceiveFlowError::MissingReservation(format!(
                "payment_hash={}",
                payment_hash.short()
            )));
        };
        receiver
            .watch_incoming(&handle.reservation, deadline)
            .await?;
        Ok(handle.preimage)
    }

    pub async fn claim_invoice(
        &self,
        network: &NetworkId,
        payment_hash: Bytes32,
        preimage: Bytes32,
    ) -> Result<(), ReceiveFlowError> {
        let receiver = self.receiver_for(network)?;
        let handle = self
            .invoice_handles
            .lock()
            .await
            .get(&payment_hash)
            .cloned()
            .ok_or_else(|| {
                ReceiveFlowError::MissingReservation(format!(
                    "payment_hash={}",
                    payment_hash.short()
                ))
            })?;
        receiver
            .claim_reserved_incoming(&handle.reservation, preimage)
            .await?;
        Ok(())
    }

    pub async fn receive(
        &self,
        network: &NetworkId,
        amount_msat: u64,
        deadline: u64,
        description: Option<String>,
    ) -> Result<ReceiveResult, ReceiveFlowError> {
        let invoice = self
            .create_invoice(network, amount_msat, deadline, description)
            .await?;
        let payment_hash = invoice.payment_hash;
        let preimage = self
            .wait_for_incoming(network, payment_hash, deadline)
            .await?;
        self.claim_invoice(network, payment_hash, preimage).await?;
        Ok(ReceiveResult {
            payment_hash,
            preimage: Some(preimage),
        })
    }
}

/// Verify the route forms an unbroken chain of networks from the payer
/// to the payee.
///
/// Every HTLC in the chain is locked to a claim identity that is only
/// meaningful on one network: the payer's HTLC to hop 0's identity on
/// `route[0].incoming`, hop `i`'s to hop `i+1`'s on `route[i+1].incoming`,
/// and the last hop's to the payee's on the invoice's network. If any
/// adjacent pair disagreed we would lock funds to a key valid somewhere
/// else, which is exactly the silent, funds-stuck failure the claim
/// identity plumbing exists to prevent. Checked up front so a bad route
/// is rejected before any hop reserves capacity.
fn validate_route_networks(
    route: &[RouteHop],
    sender_network: &NetworkId,
    dest_network: &NetworkId,
) -> Result<(), PayError> {
    // Callers reject empty routes before reaching here.
    let first = &route[0];
    if first.incoming.0 == "spark" {
        return Err(PayError::Route(
            "Spark can be used as destination bridge, not route source".to_string(),
        ));
    }
    if &first.incoming != sender_network {
        return Err(PayError::Route(format!(
            "first hop receives on {} but we are sending on {sender_network}",
            first.incoming,
        )));
    }
    for (idx, pair) in route.windows(2).enumerate() {
        if pair[0].outgoing.0 == "spark" || pair[1].incoming.0 == "spark" {
            return Err(PayError::Route(format!(
                "Spark route leg {} has unsupported role direction: {} -> {}",
                idx + 1,
                pair[0].outgoing,
                pair[1].incoming,
            )));
        }
        if pair[0].outgoing != pair[1].incoming {
            return Err(PayError::Route(format!(
                "discontiguous route: hop {} sends on {} but hop {} receives on {}",
                idx + 1,
                pair[0].outgoing,
                idx + 2,
                pair[1].incoming,
            )));
        }
    }
    let last = &route[route.len() - 1];
    if &last.outgoing != dest_network {
        return Err(PayError::Route(format!(
            "last hop sends on {} but the invoice is payable on {dest_network}",
            last.outgoing,
        )));
    }
    Ok(())
}

/// Local helper: verify a candidate preimage hashes to the
/// expected payment hash. Cheap, local sanity check before
/// declaring the payment settled.
fn preimage_matches(preimage: &Bytes32, payment_hash: &Bytes32) -> bool {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(preimage.0);
    let out = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&out);
    hash == payment_hash.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use cassis_core::{RouteAnnouncement, XOnlyPubKey};

    fn hop(from: &str, to: &str, fee_base_msat: u64, fee_ppm: u64) -> RouteHop {
        RouteHop {
            node: RouteAnnouncement {
                node_pubkey: XOnlyPubKey([0u8; 32]),
                iroh_peer_id: String::new(),
                iroh_relay: None,
                from: NetworkId(from.into()),
                to: NetworkId(to.into()),
                fee_base_msat,
                fee_ppm,
                incoming_delta_secs: 0,
                transit_slack_secs: 0,
                relays: Vec::new(),
            },
            incoming: NetworkId(from.into()),
            outgoing: NetworkId(to.into()),
        }
    }

    #[test]
    fn route_amounts_add_each_hop_fee_to_upstream_amounts() {
        let route = vec![hop("a", "b", 100, 10_000), hop("b", "c", 100, 10_000)];
        let amounts = route_amounts(1_000, &route).expect("amounts fit");
        assert_eq!(amounts, vec![1_221, 1_110, 1_000]);
    }
}
