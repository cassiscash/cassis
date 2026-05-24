use cassis_core::{
    HopInstruction, Invoice, NetworkAdapter, NetworkId, PaymentResult, PaymentStatus,
    RouteHop, WatchError,
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

pub struct CassisClient {
    pub adapters: HashMap<NetworkId, Arc<dyn NetworkAdapter>>,
    pub nostr_relays: Vec<String>,
    iroh_client: IrohClient,
}

impl CassisClient {
    pub async fn new(
        adapters: HashMap<NetworkId, Arc<dyn NetworkAdapter>>,
        nostr_relays: Vec<String>,
    ) -> Self {
        let endpoint = Endpoint::builder()
            .bind()
            .await
            .expect("failed to bind iroh endpoint for client");
        Self {
            adapters,
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
        let adapter = self
            .adapters
            .get(&sender_network)
            .ok_or_else(|| PayError::Route("sender network adapter missing".to_string()))?;

        let outgoing_htlc = adapter
            .create_outgoing_htlc(
                invoice.payment_hash,
                invoice.amount_msat,
                expiries.get(1).copied().unwrap_or(now),
                &first_hop.node.node_pubkey.to_string(),
            )
            .await
            .map_err(|err| PayError::Io(err.to_string()))?;

        match adapter
            .watch_preimage(&outgoing_htlc, outgoing_htlc.expiry)
            .await
        {
            Ok(preimage) => Ok(PaymentResult {
                status: PaymentStatus::Completed,
                preimage: Some(preimage),
            }),
            Err(WatchError::DeadlineExceeded) => {
                let _ = adapter.refund_outgoing(&outgoing_htlc).await;
                Ok(PaymentResult {
                    status: PaymentStatus::Refunded,
                    preimage: None,
                })
            }
            Err(err) => {
                let _ = adapter.refund_outgoing(&outgoing_htlc).await;
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
}
