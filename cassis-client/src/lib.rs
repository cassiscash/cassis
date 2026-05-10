use cassis_core::{
    HopInstruction, Invoice, NetworkAdapter, NetworkId, NodePubkey, PaymentResult, PaymentStatus,
    RouteHop, WatchError,
};
use cassis_iroh::IrohClient;
use cassis_nostr::{build_graph, compute_hop_expiries, fetch_announcements, find_route as find_route_in_graph};
use futures::future::try_join_all;
use iroh::Endpoint;
use std::collections::HashMap;
use std::str::FromStr;
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
    Route(cassis_nostr::RouteError),
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
    destination: &NodePubkey,
    amount_msat: u64,
    sender_network: &NetworkId,
) -> Result<Vec<RouteHop>, RouteError> {
    let announcements = fetch_announcements(relays)
        .await
        .map_err(|err| RouteError::Fetch(err.to_string()))?;
    let graph = build_graph(announcements);
    graph.log();
    let route = find_route_in_graph(&graph, destination, amount_msat, sender_network)
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
        let destination = NodePubkey(invoice.payee);
        let route = self
            .find_route(
                &destination,
                invoice.amount_msat,
                sender_network.clone(),
            )
            .await
            .map_err(|err| PayError::Route(err.to_string()))?;

        if route.is_empty() {
            return Err(PayError::Route("empty route".to_string()));
        }

        let deltas = vec![0u64; route.len()];
        let expiries = compute_hop_expiries(invoice.expires_at, &deltas);

        let instructions: Vec<(iroh::PublicKey, HopInstruction)> = route
            .iter()
            .enumerate()
            .map(|(idx, hop)| {
                let peer_id = iroh::PublicKey::from_str(&hop.node.iroh_peer_id)
                    .map_err(|e| PayError::Io(e.to_string()))?;
                let instruction = HopInstruction {
                    payment_hash: invoice.payment_hash,
                    amount_msat: invoice.amount_msat,
                    incoming_network: hop.incoming.clone(),
                    outgoing_network: hop.outgoing.clone(),
                    incoming_deadline: expiries.get(idx).copied().unwrap_or(invoice.expires_at),
                    outgoing_expiry: expiries.get(idx + 1).copied().unwrap_or(invoice.expires_at),
                    recipient: hop.node.node_pubkey.to_string(),
                };
                Ok((peer_id, instruction))
            })
            .collect::<Result<Vec<_>, PayError>>()?;

        let ack_futures = instructions.into_iter().map(|(peer_id, instruction)| {
            self.iroh_client
                .send_instruction(peer_id, instruction)
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
                expiries.get(1).copied().unwrap_or(invoice.expires_at),
                &first_hop.node.node_pubkey.0,
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
        destination: &NodePubkey,
        amount_msat: u64,
        sender_network: NetworkId,
    ) -> Result<Vec<RouteHop>, RouteError> {
        find_route(&self.nostr_relays, destination, amount_msat, &sender_network).await
    }
}
