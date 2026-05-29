use cassis_core::{
    Bytes32, HopInstruction, Invoice, NetworkId, NetworkReceiverAdapter, NetworkSenderAdapter,
    PaymentResult, PaymentStatus, ReceiveError, RouteHop, SendError,
};
use cassis_iroh::{node_addr_from_announcement, IrohClient};
use cassis_routing::{
    build_graph, compute_hop_expiries, fallback_incoming_delta, fallback_transit_slack,
    fetch_announcements, find_route as find_route_in_graph,
};
use log::{debug, info};
use futures::future::try_join_all;
use iroh::Endpoint;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(thiserror::Error, Debug)]
pub enum PayError {
    #[error("route error: {0}")]
    Route(String),
    #[error("io error: {0}")]
    Io(String),
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
    Receive(#[from] ReceiveError),
}

/// Outcome of a one-shot `receive` call. Either the upstream funded
/// the invoice (and the receiver claimed it) or the call gave up.
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

/// Find a route to `destination` from `sender_network`, fetching route
/// announcements from the given Nostr relays and running Dijkstra.
///
/// This is a standalone function so callers that only need route lookup
/// (e.g. `cassis-cli`) don't have to construct a full `CassisClient` with
/// network adapters.
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

/// Pure-sender client: holds a map from `NetworkId` to a
/// `NetworkSenderAdapter` (the user-facing "pay invoice" trait). Any
/// `NetworkRouterAdapter` is automatically a sender via the blanket
/// impl in `cassis-core`, so router-style networks can be passed in
/// the same way.
pub struct CassisClient {
    pub senders: HashMap<NetworkId, Arc<dyn NetworkSenderAdapter>>,
    pub receivers: HashMap<NetworkId, Arc<dyn NetworkReceiverAdapter>>,
    pub nostr_relays: Vec<String>,
    iroh_client: IrohClient,
}

impl CassisClient {
    /// Build a sender-only client. Use this for pay-only flows.
    pub async fn new(
        senders: HashMap<NetworkId, Arc<dyn NetworkSenderAdapter>>,
        nostr_relays: Vec<String>,
    ) -> Self {
        let endpoint = Endpoint::builder()
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

    /// Build a client with both sender and receiver adapters. Use
    /// this for CLI-style flows that pay and receive.
    pub async fn with_receivers(
        senders: HashMap<NetworkId, Arc<dyn NetworkSenderAdapter>>,
        receivers: HashMap<NetworkId, Arc<dyn NetworkReceiverAdapter>>,
        nostr_relays: Vec<String>,
    ) -> Self {
        let endpoint = Endpoint::builder()
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

    pub async fn pay(
        &self,
        invoice: Invoice,
        sender_network: NetworkId,
    ) -> Result<PaymentResult, PayError> {
        let dest_network = invoice.networks.first().ok_or_else(|| {
            PayError::Route("invoice has no network".to_string())
        })?.clone();
        let route = self
            .find_route(
                &dest_network,
                invoice.amount_msat,
                sender_network.clone(),
            )
            .await
            .map_err(|err| PayError::Route(err.to_string()))?;

        if route.is_empty() {
            return Err(PayError::Route("empty route".to_string()));
        }

        // Per-hop incoming delta: prefer the value the operator published on
        // the announcement; fall back to a per-network default. Each hop
        // also receives a transit slack (published or fallback) to absorb
        // in-flight latency and clock skew between sender and that hop.
        // The effective buffer per hop is `delta + slack`. The cascade
        // grows off `now` per hop, independent of the invoice's
        // `expires_at`, so the sender's incoming_deadline is `now` plus
        // the sum of all effective buffers.
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
        info!(
            target: "cassis_client",
            "computing hop deadlines: now={now}, route_len={}, buffers={:?}",
            route.len(),
            buffers
        );
        let expiries = compute_hop_expiries(now, &buffers);
        info!(
            target: "cassis_client",
            "computed hop expiries (oldest first): {:?}",
            expiries
        );

        let instructions: Vec<(iroh::NodeAddr, HopInstruction)> = route
            .iter()
            .enumerate()
            .map(|(idx, hop)| {
                let addr = node_addr_from_announcement(&hop.node)
                    .map_err(|e| PayError::Io(e.to_string()))?;
                let incoming_deadline = expiries.get(idx).copied().unwrap_or(now);
                let outgoing_expiry = expiries.get(idx + 1).copied().unwrap_or(now);
                debug!(
                    target: "cassis_client",
                    "  hop {idx}: incoming_network={}, outgoing_network={}, \
                     incoming_deadline={incoming_deadline}, outgoing_expiry={outgoing_expiry}, \
                     recipient={}",
                    hop.incoming, hop.outgoing, hop.node.node_pubkey
                );
                let instruction = HopInstruction {
                    payment_hash: invoice.payment_hash,
                    amount_msat: invoice.amount_msat,
                    incoming_network: hop.incoming.clone(),
                    outgoing_network: hop.outgoing.clone(),
                    incoming_deadline,
                    outgoing_expiry,
                    recipient: hop.node.node_pubkey.to_string(),
                };
                Ok((addr, instruction))
            })
            .collect::<Result<Vec<_>, PayError>>()?;

        let ack_futures = instructions.into_iter().map(|(addr, instruction)| {
            self.iroh_client
                .send_instruction(addr, instruction)
        });
        let acks: Vec<cassis_core::HopAck> = try_join_all(ack_futures).await?;
        if acks.iter().any(|ack| !ack.accepted) {
            return Err(PayError::Route("hop rejected".to_string()));
        }

        let first_hop = route
            .first()
            .ok_or_else(|| PayError::Route("route missing".to_string()))?;
        let sender = self
            .senders
            .get(&sender_network)
            .ok_or_else(|| PayError::Route("sender network adapter missing".to_string()))?;

        let payment = sender
            .pay_invoice(
                invoice.payment_hash,
                invoice.amount_msat,
                &first_hop.node.node_pubkey.to_string(),
                &first_hop.outgoing,
                expiries.get(1).copied().unwrap_or(now),
            )
            .await
            .map_err(|err| PayError::Io(err.to_string()))?;

        match sender
            .watch_payment(payment.clone(), payment.expiry)
            .await
        {
            Ok(preimage) => Ok(PaymentResult {
                status: PaymentStatus::Completed,
                preimage: Some(preimage),
            }),
            Err(SendError::DeadlineExceeded) => {
                let _ = sender.refund_payment(payment).await;
                Ok(PaymentResult {
                    status: PaymentStatus::Refunded,
                    preimage: None,
                })
            }
            Err(err) => {
                let _ = sender.refund_payment(payment).await;
                Err(PayError::Io(err.to_string()))
            }
        }
    }

    pub async fn find_route(
        &self,
        destination_network: &NetworkId,
        amount_msat: u64,
        sender_network: NetworkId,
    ) -> Result<Vec<RouteHop>, RouteError> {
        find_route(&self.nostr_relays, destination_network, amount_msat, &sender_network).await
    }

    /// Look up the receiver adapter for `network`.
    fn receiver_for(&self, network: &NetworkId) -> Result<Arc<dyn NetworkReceiverAdapter>, ReceiveFlowError> {
        self.receivers
            .get(network)
            .cloned()
            .ok_or_else(|| ReceiveFlowError::UnknownNetwork(network.0.clone()))
    }

    /// Register an incoming invoice on `network` and return the
    /// network's `Invoice` (whose `payment_hash` is what the upstream
    /// will fund). The CLI is expected to persist a row tied to
    /// `payment_hash` before returning to the user; this method does
    /// not store anything.
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

    /// Block until the upstream hop funds the invoice (or the
    /// `deadline` expires) and return the preimage the network
    /// revealed. For "sells its own preimage" networks (fedimint)
    /// the preimage is owned by the network; the returned bytes are
    /// informational.
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

    /// Settle the invoice: release the preimage to the network and
    /// mark the incoming side paid.
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

    /// Convenience: `create_invoice` followed by `wait_for_incoming`
    /// (bounded by `deadline`) and `claim_invoice`. The caller is
    /// expected to have persisted the preimage before calling this
    /// — the client does not own the secret.
    pub async fn receive(
        &self,
        network: &NetworkId,
        amount_msat: u64,
        deadline: u64,
        description: Option<String>,
    ) -> Result<ReceiveResult, ReceiveFlowError> {
        let invoice = self.create_invoice(network, amount_msat, deadline, description).await?;
        let payment_hash = invoice.payment_hash;
        let preimage = self.wait_for_incoming(network, payment_hash, deadline).await?;
        self.claim_invoice(network, payment_hash, preimage).await?;
        Ok(ReceiveResult {
            payment_hash,
            preimage: Some(preimage),
        })
    }
}
