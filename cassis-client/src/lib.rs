use cassis_core::{
    Bytes32, HopCommit, HopDispatch, HopPrepare, HtlcDescriptor, Invoice, NetworkId,
    NetworkReceiverAdapter, NetworkSenderAdapter, OutgoingPayment, PaymentResult, PaymentStatus,
    RouteHop, SendError,
};
use cassis_iroh::{node_addr_from_announcement, node_addr_from_invoice, IrohClient};
use cassis_routing::{
    build_graph, compute_hop_expiries, fallback_incoming_delta, fallback_transit_slack,
    fetch_announcements, find_route as find_route_in_graph,
};
use futures::future::try_join_all;
use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr};
use log::{debug, warn};
use std::collections::HashMap;
use std::sync::Arc;

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

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let buffers: Vec<u64> = route
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
        let expiries = compute_hop_expiries(now, &buffers);

        // Step 1: PREPARE every hop.
        let addrs: Vec<EndpointAddr> = route
            .iter()
            .map(|hop| {
                node_addr_from_announcement(&hop.node).map_err(|e| PayError::Io(e.to_string()))
            })
            .collect::<Result<Vec<_>, PayError>>()?;

        let prepares: Vec<HopPrepare> = route
            .iter()
            .enumerate()
            .map(|(idx, hop)| HopPrepare {
                payment_hash: invoice.payment_hash,
                amount_msat: invoice.amount_msat,
                incoming_network: hop.incoming.clone(),
                outgoing_network: hop.outgoing.clone(),
                incoming_deadline: expiries.get(idx).copied().unwrap_or(now),
                outgoing_expiry: expiries.get(idx + 1).copied().unwrap_or(now),
                recipient: hop.node.node_pubkey.to_string(),
            })
            .collect();
        let prepared_futures = prepares
            .into_iter()
            .zip(addrs.iter().cloned())
            .map(|(p, addr)| self.iroh_client.send_prepare(addr, p));
        let prepared: Vec<cassis_core::HopPrepared> = try_join_all(prepared_futures).await?;
        for (i, ack) in prepared.iter().enumerate() {
            if !ack.accepted {
                return Err(PayError::HopRejected {
                    index: i,
                    reason: ack.reason.clone().unwrap_or_else(|| "unknown".to_string()),
                });
            }
        }

        // Step 2: pay the first hop. The sender adapter creates
        // the first HTLC and returns the OutgoingPayment
        // descriptor (cashu proofs, etc.).
        let first_hop = route
            .first()
            .ok_or_else(|| PayError::Route("route missing".to_string()))?;
        let sender = self
            .senders
            .get(&sender_network)
            .ok_or_else(|| PayError::Route("sender network adapter missing".to_string()))?
            .clone();
        let first_outgoing_expiry = expiries.get(1).copied().unwrap_or(now);
        let first_payment: OutgoingPayment = sender
            .pay_invoice(
                invoice.payment_hash,
                invoice.amount_msat,
                &first_hop.node.node_pubkey.to_string(),
                &first_hop.outgoing,
                first_outgoing_expiry,
            )
            .await
            .map_err(|err| PayError::Io(err.to_string()))?;
        // The descriptor of the first HTLC is the descriptor
        // the sender adapter hands to the first router. We get
        // it via the router trait method; the blanket impl
        // does the lookup.
        let first_descriptor: HtlcDescriptor = sender
            .outgoing_htlc_descriptor(invoice.payment_hash)
            .await
            .map_err(|e| PayError::Io(e.to_string()))?;

        // Step 3: walk the route. `descriptor` carries the
        // HTLC info for the *incoming* side of the next hop.
        let mut descriptor = first_descriptor;
        for (i, hop) in route.iter().enumerate() {
            let dispatch = HopDispatch {
                payment_hash: invoice.payment_hash,
                amount_msat: invoice.amount_msat,
                incoming_network: hop.incoming.clone(),
                outgoing_network: hop.outgoing.clone(),
                incoming_deadline: expiries.get(i).copied().unwrap_or(now),
                outgoing_expiry: expiries.get(i + 1).copied().unwrap_or(now),
                recipient: hop.node.node_pubkey.to_string(),
                incoming_descriptor: descriptor,
            };
            debug!(
                target: "cassis_client",
                "  DISPATCH hop {i}: in={} out={} amount={} msat",
                hop.incoming, hop.outgoing, invoice.amount_msat
            );
            let reply = self
                .iroh_client
                .send_dispatch(addrs[i].clone(), dispatch)
                .await?;
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
        let committed = self.iroh_client.send_commit(payee_addr, commit).await?;
        let preimage = committed.preimage;
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
