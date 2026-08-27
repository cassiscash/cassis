pub mod adapters;
pub mod netspec;
pub mod ops;
pub mod paths;
pub mod seed_store;
pub mod store;

use cassis_core::{
    Bytes32, HopCommit, HopDiscard, HopDispatch, HopPrepare, HtlcDescriptor, Invoice, NetworkId,
    NetworkReceiverAdapter, NetworkSenderAdapter, OutgoingPayment, PaymentResult, PaymentStatus,
    RouteHop, SendError,
};
use cassis_iroh::{node_addr_from_announcement, node_addr_from_invoice, IrohClient};
use cassis_routing::{
    build_graph, compute_hop_expiries, fallback_incoming_delta, fallback_transit_slack,
    fetch_announcements, find_route as find_route_in_graph,
};
use futures::future::join_all;
use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info, warn};

#[derive(thiserror::Error, Debug)]
pub enum PayError {
    #[error("route error: {0}")]
    Route(String),
    #[error("io error: {0}")]
    Io(String),
    #[error("hop rejected at index {index}: {reason}")]
    HopRejected { index: usize, reason: String },
    #[error("payee commit failed: {0}")]
    Commit(String),
    #[error("unimplemented")]
    Unimplemented,
}

impl From<cassis_iroh::IrohError> for PayError {
    fn from(e: cassis_iroh::IrohError) -> Self {
        PayError::Io(e.to_string())
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ReceiveFlowError {
    #[error("network not registered: {0}")]
    UnknownNetwork(String),
    #[error("receive error: {0}")]
    Receive(#[from] cassis_core::ReceiveError),
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

pub struct CassisClient {
    pub senders: HashMap<NetworkId, Arc<dyn NetworkSenderAdapter>>,
    pub receivers: HashMap<NetworkId, Arc<dyn NetworkReceiverAdapter>>,
    pub nostr_relays: Vec<String>,
    iroh_client: IrohClient,
}

impl CassisClient {
    pub async fn new(
        senders: HashMap<NetworkId, Arc<dyn NetworkSenderAdapter>>,
        nostr_relays: Vec<String>,
    ) -> Self {
        let endpoint = Endpoint::builder(presets::N0)
            .bind()
            .await
            .expect("failed to bind iroh endpoint for client");
        Self {
            senders,
            receivers: HashMap::new(),
            nostr_relays,
            iroh_client: IrohClient::new(endpoint),
        }
    }

    pub async fn with_receivers(
        senders: HashMap<NetworkId, Arc<dyn NetworkSenderAdapter>>,
        receivers: HashMap<NetworkId, Arc<dyn NetworkReceiverAdapter>>,
        nostr_relays: Vec<String>,
    ) -> Self {
        let endpoint = Endpoint::builder(presets::N0)
            .bind()
            .await
            .expect("failed to bind iroh endpoint for client");
        Self {
            senders,
            receivers,
            nostr_relays,
            iroh_client: IrohClient::new(endpoint),
        }
    }

    pub fn iroh_client(&self) -> &IrohClient {
        &self.iroh_client
    }

    pub fn peer_id(&self) -> String {
        self.iroh_client.peer_id().to_string()
    }

    /// Drive the multi-hop PREPARE / DISPATCH / COMMIT protocol
    /// described in the user-facing docs:
    ///
    /// 1. PREPARE every router hop in order; abort if any rejects.
    /// 2. Create the first HTLC on the sender's network
    ///    (the sender adapter's `pay_invoice`).
    /// 3. Walk the route: DISPATCH to hop `i` with the descriptor
    ///    returned by hop `i-1` (or by `pay_invoice` for the
    ///    first hop).
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
        let route = self
            .find_route(&dest_network, invoice.amount_msat, sender_network.clone())
            .await
            .map_err(|err| PayError::Route(err.to_string()))?;

        if route.is_empty() {
            // No router hops: payer == payee. Just send COMMIT
            // to the payee (ourselves or another cassis-cli
            // instance) and claim via the local receiver
            // adapter. The CLI side is responsible for setting
            // up the local receive flow; here we just pass the
            // invoice through.
            return Err(PayError::Route(
                "empty route: same-network pay not implemented; use the receiver adapter directly"
                    .to_string(),
            ));
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
        let mut buffers: Vec<u64> = route
            .iter()
            .map(|hop| {
                let delta = if hop.node.incoming_delta_secs > 0 {
                    hop.node.incoming_delta_secs
                } else {
                    fallback_incoming_delta(&hop.incoming)
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
        let payee_delta = fallback_incoming_delta(&dest_network);
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

        let prepares: Vec<(usize, HopPrepare)> = route
            .iter()
            .enumerate()
            .map(|(idx, hop)| {
                (
                    idx,
                    HopPrepare {
                        payment_hash: invoice.payment_hash,
                        amount_msat: invoice.amount_msat,
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
        let mut reserved_idx: Vec<usize> = Vec::new();
        let mut first_failure: Option<PayError> = None;
        for (idx, reply) in replies.into_iter().enumerate() {
            match reply {
                Ok(ack) if ack.accepted => {
                    reserved_idx.push(idx);
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
            self.discard_reservations(&addrs, invoice.payment_hash, &reserved_idx)
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
        // This is why `recipient` rides on DISPATCH rather than
        // PREPARE: the PREPAREs above run concurrently, so hop `i+1`'s
        // reply does not exist yet while hop `i`'s PREPARE is built.
        // Deriving it here, after every reply is in, also makes the
        // "lock to hop i instead of hop i+1" off-by-one unrepresentable.
        // A missing claim identity is a hard error rather than a
        // fallback to the announced node key: guessing is exactly what
        // caused HTLCs to be locked to unclaimable identities, and the
        // failure only surfaced on-chain after funds were committed.
        let mut recipients: Vec<cassis_core::PubKey> = Vec::with_capacity(route.len() + 1);
        for (idx, ack) in acks.iter().enumerate() {
            match ack.claim_pubkey {
                Some(k) => recipients.push(k),
                None => {
                    // Every hop accepted, so every hop is holding a
                    // reservation; none was DISPATCHed yet.
                    let reserved = (0..route.len()).collect::<Vec<usize>>();
                    self.discard_reservations(&addrs, invoice.payment_hash, &reserved)
                        .await;
                    return Err(PayError::HopRejected {
                        index: idx,
                        reason: "hop accepted the PREPARE but reported no claim identity"
                            .to_string(),
                    });
                }
            }
        }
        recipients.push(invoice.claim_pubkey_for(&dest_network));

        // From here until the first DISPATCH succeeds, every route hop
        // holds exactly one unused reservation. Any abort in this
        // window releases the full set.
        let all_hops: Vec<usize> = (0..route.len()).collect();

        // Step 2: pay the first hop. The sender adapter creates
        // the first HTLC and returns the OutgoingPayment
        // descriptor (cashu proofs, etc.).
        let sender = match self.senders.get(&sender_network) {
            Some(s) => s.clone(),
            None => {
                self.discard_reservations(&addrs, invoice.payment_hash, &all_hops)
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
        let first_recipient = recipients[0];
        let first_payment: OutgoingPayment = match sender
            .pay_invoice(
                invoice.payment_hash,
                invoice.amount_msat,
                first_recipient,
                // The HTLC is created on our own sending network, which
                // `validate_route_networks` proved is the first hop's
                // incoming network.
                &sender_network,
                first_outgoing_expiry,
            )
            .await
        {
            Ok(p) => p,
            Err(err) => {
                // Nothing funded yet on any hop; free every reservation.
                self.discard_reservations(&addrs, invoice.payment_hash, &all_hops)
                    .await;
                return Err(PayError::Io(err.to_string()));
            }
        };
        // The descriptor of the first HTLC is the descriptor
        // the sender adapter hands to the first router. We get
        // it via the router trait method; the blanket impl
        // does the lookup.
        let first_descriptor: HtlcDescriptor =
            match sender.outgoing_htlc_descriptor(invoice.payment_hash).await {
                Ok(d) => d,
                Err(e) => {
                    // The first HTLC exists (its own unwind stays with
                    // the sender adapter's refund path), but no router
                    // has been DISPATCHed: free their reservations.
                    self.discard_reservations(&addrs, invoice.payment_hash, &all_hops)
                        .await;
                    return Err(PayError::Io(e.to_string()));
                }
            };

        // Step 3: walk the route. `descriptor` carries the
        // HTLC info for the *incoming* side of the next hop.
        let mut descriptor = first_descriptor;
        for (i, hop) in route.iter().enumerate() {
            // `recipients[i + 1]` is the party downstream of hop `i`:
            // the next hop's claim identity, or the payee's for the last
            // hop.
            let recipient = recipients[i + 1];
            let dispatch = HopDispatch {
                payment_hash: invoice.payment_hash,
                incoming_descriptor: descriptor,
                recipient,
            };
            let peer = hop.node.node_pubkey;
            let addr = addrs[i].clone();
            info!(
                target: "cassis_client",
                "DISPATCH hop {}/{}: peer={peer} addr={addr:?} incoming={} outgoing={} \
                 amount_msat={} incoming_deadline={} outgoing_expiry={} recipient={} \
                 payment_hash={} incoming_descriptor={:?}",
                i+1,
                route.len(),
                hop.incoming,
                hop.outgoing,
                invoice.amount_msat,
                expiries[i],
                expiries[i + 1],
                recipient,
                dispatch.payment_hash,
                dispatch.incoming_descriptor,
            );
            debug!(
                target: "cassis_client",
                "  DISPATCH hop {}: in={} out={} amount={} msat",
                i+1,
                hop.incoming, hop.outgoing, invoice.amount_msat
            );
            let reply = match self.iroh_client.send_dispatch(addr, dispatch).await {
                Ok(r) => r,
                Err(e) => {
                    info!(
                        target: "cassis_client",
                        "DISPATCH hop {}/{}: peer={peer} error={e}",
                        i+1,
                        route.len(),
                    );
                    // Hops 0..i were DISPATCHed successfully (their
                    // reservations became funded HTLCs; DISCARD is a
                    // no-op there and is not sent). This hop may have
                    // consumed its reservation before failing — or not
                    // heard from us at all — so the safe set to free is
                    // this hop plus everything downstream.
                    let pending: Vec<usize> = (i..route.len()).collect();
                    self.discard_reservations(&addrs, invoice.payment_hash, &pending)
                        .await;
                    return Err(PayError::Io(e.to_string()));
                }
            };
            info!(
                target: "cassis_client",
                "DISPATCH hop {}/{}: peer={peer} outgoing_descriptor={:?}",
                i+1,
                route.len(),
                reply.outgoing_descriptor,
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
            "payee accepted COMMIT for payment_hash={} on {}: preimage={} \
             (received from payee)",
            invoice.payment_hash.short(),
            dest_network,
            preimage,
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

        // The first-hop HTLC is what the sender adapter
        // already created. Its preimage should now be
        // available on the sender network; surface a
        // best-effort claim result. We do not block the
        // caller on the sender-side watch because the
        // preimage is already proven by the payee.
        match sender
            .watch_payment(first_payment.clone(), first_payment.expiry)
            .await
        {
            Ok(_) => {}
            Err(SendError::DeadlineExceeded) => {
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
    ) {
        if hop_indices.is_empty() {
            return;
        }
        info!(
            target: "cassis_client",
            "payment aborted: sending DISCARD for payment_hash={} to {} hop(s)",
            payment_hash.short(),
            hop_indices.len(),
        );
        let futs = hop_indices.iter().map(|&i| {
            let addr = addrs[i].clone();
            async move {
                match self
                    .iroh_client
                    .send_discard(addr, HopDiscard { payment_hash })
                    .await
                {
                    Ok(ack) => debug!(
                        target: "cassis_client",
                        "DISCARD hop {}: released={}",
                        i + 1,
                        ack.released,
                    ),
                    Err(e) => warn!(
                        target: "cassis_client",
                        "DISCARD hop {} failed (best effort): {e}",
                        i + 1,
                    ),
                }
            }
        });
        join_all(futs).await;
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
    ) -> Result<Arc<dyn NetworkReceiverAdapter>, ReceiveFlowError> {
        self.receivers
            .get(network)
            .cloned()
            .ok_or_else(|| ReceiveFlowError::UnknownNetwork(network.0.clone()))
    }

    pub async fn create_invoice(
        &self,
        network: &NetworkId,
        amount_msat: u64,
        expiry: u64,
        description: Option<String>,
    ) -> Result<Invoice, ReceiveFlowError> {
        let receiver = self.receiver_for(network)?;
        let invoice = receiver
            .create_invoice(amount_msat, expiry, description)
            .await?;
        Ok(invoice)
    }

    pub async fn wait_for_incoming(
        &self,
        network: &NetworkId,
        payment_hash: Bytes32,
        deadline: u64,
    ) -> Result<Bytes32, ReceiveFlowError> {
        let receiver = self.receiver_for(network)?;
        let preimage = receiver.watch_incoming(payment_hash, deadline).await?;
        Ok(preimage)
    }

    pub async fn claim_invoice(
        &self,
        network: &NetworkId,
        payment_hash: Bytes32,
        preimage: Bytes32,
    ) -> Result<(), ReceiveFlowError> {
        let receiver = self.receiver_for(network)?;
        receiver.claim_incoming(payment_hash, preimage).await?;
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
    if &first.incoming != sender_network {
        return Err(PayError::Route(format!(
            "first hop receives on {} but we are sending on {sender_network}",
            first.incoming,
        )));
    }
    for (idx, pair) in route.windows(2).enumerate() {
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
