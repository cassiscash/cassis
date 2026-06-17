use cassis_core::{NetworkId, RouteAnnouncement};
use log::{debug, info};
use ritualistic::{Filter, Kind, Network, SubscriptionOptions, Timestamp};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};
use std::time::Duration;

mod delta_table;

pub use delta_table::{fallback_incoming_delta, fallback_transit_slack};

/// Maximum time we wait for Nostr relays to respond in
/// [`fetch_announcements`] before giving up.
const FETCH_ANNOUNCEMENTS_TIMEOUT: Duration = Duration::from_secs(10);

/// Only consider route-announcement events published in the last
/// day when building the routing graph. Stale announcements from
/// routers that went offline are ignored, so route computation
/// reflects nodes that are currently advertising.
const ANNOUNCEMENTS_MAX_AGE_SECS: u32 = 24 * 60 * 60;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeGraph {
    pub nodes: Vec<RouteAnnouncement>,
    #[serde(skip)]
    incoming_index: HashMap<NetworkId, Vec<usize>>,
}

impl NodeGraph {
    pub fn new(nodes: Vec<RouteAnnouncement>) -> Self {
        let mut incoming_index: HashMap<NetworkId, Vec<usize>> = HashMap::new();
        for (idx, node) in nodes.iter().enumerate() {
            incoming_index
                .entry(node.from.clone())
                .or_default()
                .push(idx);
        }
        for v in incoming_index.values_mut() {
            v.sort_unstable();
            v.dedup();
        }
        Self {
            nodes,
            incoming_index,
        }
    }

    fn nodes_for_network(&self, network: &NetworkId) -> impl Iterator<Item = usize> + '_ {
        self.incoming_index
            .get(network)
            .map(|nodes| nodes.iter().copied())
            .into_iter()
            .flatten()
    }

    pub fn log(&self) {
        debug!(target: "nostr", "--- graph ({} announcement(s)) ---", self.nodes.len());
        if self.nodes.is_empty() {
            debug!(target: "nostr", "  (empty)");
            return;
        }
        for (i, node) in self.nodes.iter().enumerate() {
            debug!(
                target: "nostr",
                "  route #{i}: {} {} -> {} fee={}/{}",
                node.node_pubkey, node.from, node.to, node.fee_base_msat, node.fee_ppm
            );
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum NostrError {
    #[error("network error: {0}")]
    Network(String),
    #[error("invalid event: {0}")]
    InvalidEvent(String),
    #[error("relay query timed out")]
    Timeout,
    #[error("unimplemented")]
    Unimplemented,
}

#[derive(thiserror::Error, Debug)]
pub enum RouteError {
    #[error("no route found")]
    NoRoute,
    #[error("invalid graph: {0}")]
    InvalidGraph(String),
    #[error("unimplemented")]
    Unimplemented,
}

#[derive(Clone, Debug)]
pub struct NostrAnnouncer {
    pub relays: Vec<String>,
}

impl NostrAnnouncer {
    pub fn new(relays: Vec<String>) -> Self {
        Self { relays }
    }

    pub async fn publish_once(&self, _announcement: &RouteAnnouncement) -> Result<(), NostrError> {
        Err(NostrError::Unimplemented)
    }

    pub async fn run_republish_loop(
        &self,
        _announcement: RouteAnnouncement,
        _interval_secs: u64,
    ) -> Result<(), NostrError> {
        Err(NostrError::Unimplemented)
    }
}

/// Nostr event kind for route announcements (Cassis).
const KIND_ROUTE_ANNOUNCEMENT: u16 = 35515;

/// Separator used in the `d` tag of route-announcement events: `<from>-><to>`.
const D_TAG_SEPARATOR: &str = "->";

/// Fetch route-announcement events (kind 35515) from the given Nostr relays
/// and build [`RouteAnnouncement`] structs from the directed route `d` tags
/// and fee/relay tags. Bounded by [`FETCH_ANNOUNCEMENTS_TIMEOUT`].
///
/// Each event's `d` tag has the form `<network_from>-><network_to>`.
/// Additional tags: `fee_base_msat`, `fee_ppm`, `relay`,
/// `incoming_delta_secs` (per-hop timelock budget in seconds; 0/absent
/// means callers should fall back to a per-network default).
pub async fn fetch_announcements(relays: &[String]) -> Result<Vec<RouteAnnouncement>, NostrError> {
    fetch_announcements_with_timeout(relays, FETCH_ANNOUNCEMENTS_TIMEOUT).await
}

/// Fetch route-announcement events with an explicit timeout. Exposed
/// so callers (and tests) can bound the relay query without depending
/// on the global constant.
pub async fn fetch_announcements_with_timeout(
    relays: &[String],
    timeout: Duration,
) -> Result<Vec<RouteAnnouncement>, NostrError> {
    if relays.is_empty() {
        return Err(NostrError::Network("no relays provided".into()));
    }

    let filter = Filter {
        kinds: Some(vec![Kind(KIND_ROUTE_ANNOUNCEMENT)]),
        since: Some(Timestamp(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as u32)
                .unwrap_or(0)
                .saturating_sub(ANNOUNCEMENTS_MAX_AGE_SECS),
        )),
        limit: Some(1000),
        ..Default::default()
    };

    let pool = Network::new();
    let events = match tokio::time::timeout(
        timeout,
        pool.query(relays, filter, SubscriptionOptions::default()),
    )
    .await
    {
        Ok(events) => events,
        Err(_) => return Err(NostrError::Timeout),
    };

    let mut announcements = Vec::new();

    for event in events {
        let mut from: Option<String> = None;
        let mut to: Option<String> = None;
        let mut iroh_peer_id: String = String::new();
        let mut iroh_relay: Option<String> = None;
        let mut fee_base_msat: u64 = 0;
        let mut fee_ppm: u64 = 0;
        let mut incoming_delta_secs: u64 = 0;
        let mut transit_slack_secs: u64 = 0;
        let mut relays: Vec<String> = Vec::new();

        for tag in event.tags.iter() {
            if tag.len() < 2 {
                continue;
            }
            match tag[0].as_str() {
                "d" => {
                    if let Some((f, t)) = parse_d_tag(&tag[1]) {
                        from = Some(f.to_string());
                        to = Some(t.to_string());
                    }
                }
                "iroh" => {
                    iroh_peer_id = tag[1].clone();
                    if tag.len() >= 3 && !tag[2].is_empty() {
                        iroh_relay = Some(tag[2].clone());
                    }
                }
                "fee_base_msat" => {
                    fee_base_msat = tag[1].parse().unwrap_or(0);
                }
                "fee_ppm" => {
                    fee_ppm = tag[1].parse().unwrap_or(0);
                }
                "incoming_delta_secs" => {
                    incoming_delta_secs = tag[1].parse().unwrap_or(0);
                }
                "transit_slack_secs" => {
                    transit_slack_secs = tag[1].parse().unwrap_or(0);
                }
                "relay" => {
                    relays.push(tag[1].clone());
                }
                _ => {}
            }
        }

        if let (Some(from), Some(to)) = (from, to) {
            announcements.push(RouteAnnouncement {
                node_pubkey: event.pubkey,
                iroh_peer_id,
                iroh_relay,
                from: NetworkId(from),
                to: NetworkId(to),
                fee_base_msat,
                fee_ppm,
                incoming_delta_secs,
                transit_slack_secs,
                relays,
            });
        }
    }

    Ok(announcements)
}

/// Parse a `d` tag value of the form `<network_from>-><network_to>`.
fn parse_d_tag(d: &str) -> Option<(&str, &str)> {
    d.split_once(D_TAG_SEPARATOR)
        .filter(|(from, to)| !from.is_empty() && !to.is_empty())
}

pub fn build_graph(announcements: Vec<RouteAnnouncement>) -> NodeGraph {
    NodeGraph::new(announcements)
}

pub fn find_route(
    graph: &NodeGraph,
    destination_network: &NetworkId,
    amount_msat: u64,
    sender_network: &NetworkId,
) -> Result<Vec<(RouteAnnouncement, NetworkId, NetworkId)>, RouteError> {
    info!(
        target: "nostr",
        "--- find_route: destination_network={destination_network}, amount_msat={amount_msat}, sender_network={sender_network}"
    );

    let mut heap: BinaryHeap<State> = BinaryHeap::new();
    let mut dist: HashMap<StateKey, u64> = HashMap::new();
    let mut prev: HashMap<StateKey, (StateKey, NetworkId)> = HashMap::new();

    for node_idx in graph.nodes_for_network(sender_network) {
        let node = &graph.nodes[node_idx];
        let fee = node_fee_msat(node, amount_msat);
        let key = StateKey {
            node_idx,
            incoming: sender_network.clone(),
        };
        debug!(
            target: "nostr",
            "  seed: route #{node_idx} ({}) <{sender_network} cost={fee} msat",
            node.node_pubkey
        );
        dist.insert(key.clone(), fee);
        heap.push(State { cost: fee, key });
    }

    let mut goal: Option<StateKey> = None;
    let mut step = 0u64;

    while let Some(State { cost, key }) = heap.pop() {
        step += 1;
        let node = &graph.nodes[key.node_idx];

        if let Some(best) = dist.get(&key) {
            if cost > *best {
                debug!(
                    target: "nostr",
                    "  step {step}: skip stale entry route #{} ({}) cost={cost} > best={best}",
                    key.node_idx,
                    node.node_pubkey
                );
                continue;
            }
        }

        debug!(
            target: "nostr",
            "  step {step}: visit route #{} ({}) via {} -> {} cost={cost} msat",
            key.node_idx,
            node.node_pubkey,
            key.incoming,
            node.to
        );

        if &node.to == destination_network {
            info!(
                target: "nostr",
                "  step {step}: destination network {destination_network} reached at route #{} ({})",
                key.node_idx,
                node.node_pubkey,
            );
            goal = Some(key.clone());
            break;
        }

        let outgoing = &node.to;

        debug!(target: "nostr", "    edge: {} -> {} (from {})", key.incoming, outgoing, node.node_pubkey);
        for next_idx in graph.nodes_for_network(outgoing) {
            if next_idx == key.node_idx {
                continue;
            }
            if graph.nodes[next_idx].node_pubkey == node.node_pubkey {
                continue;
            }
            let next_key = StateKey {
                node_idx: next_idx,
                incoming: outgoing.clone(),
            };
            let next_node = &graph.nodes[next_idx];
            let incoming_amount = amount_msat.saturating_sub(cost);
            let next_cost = cost.saturating_add(node_fee_msat(next_node, incoming_amount));
            let is_better = match dist.get(&next_key) {
                Some(existing) => next_cost < *existing,
                None => true,
            };
            if is_better {
                debug!(
                    target: "nostr",
                    "    relax: route #{next_idx} ({}) via {} new_cost={next_cost} msat",
                    next_node.node_pubkey, outgoing
                );
                dist.insert(next_key.clone(), next_cost);
                prev.insert(next_key.clone(), (key.clone(), outgoing.clone()));
                heap.push(State {
                    cost: next_cost,
                    key: next_key,
                });
            } else {
                debug!(
                    target: "nostr",
                    "    skip: route #{next_idx} ({}) via {} cost={next_cost} not better than {}",
                    next_node.node_pubkey,
                    outgoing,
                    dist.get(&next_key).copied().unwrap_or(0)
                );
            }
        }
    }

    let goal = goal.ok_or(RouteError::NoRoute)?;
    let mut hops_rev: Vec<(RouteAnnouncement, NetworkId, NetworkId)> = Vec::new();
    let mut current = goal.clone();
    let mut outgoing_for_current: Option<NetworkId> = Some(graph.nodes[goal.node_idx].to.clone());
    let mut hop_idx = 0u64;

    loop {
        let node = graph
            .nodes
            .get(current.node_idx)
            .ok_or_else(|| RouteError::InvalidGraph("node missing".to_string()))?;
        let incoming = current.incoming.clone();
        let outgoing = outgoing_for_current
            .clone()
            .unwrap_or_else(|| incoming.clone());
        debug!(
            target: "nostr",
            "  backtrack hop {hop_idx}: route #{} ({}) in={incoming} out={outgoing}",
            current.node_idx,
            node.node_pubkey
        );
        hop_idx += 1;
        hops_rev.push((node.clone(), incoming.clone(), outgoing.clone()));

        if let Some((prev_state, prev_outgoing)) = prev.get(&current) {
            current = prev_state.clone();
            outgoing_for_current = Some(prev_outgoing.clone());
        } else {
            break;
        }
    }

    hops_rev.reverse();
    Ok(hops_rev)
}

/// Compute cascading per-hop timelocks for a route.
///
/// `anchor` is the moment the payer decides to start the payment
/// (unix seconds). Callers pass one buffer per leg — each router hop
/// plus a final leg for the payee's own claim window. The returned
/// vector has `deltas.len() + 1` entries where `expiries[i]` is hop
/// `i`'s incoming deadline, `expiries[i + 1]` is hop `i`'s outgoing
/// expiry, and `expiries[deltas.len()]` is the payer's floor. The
/// cascade grows toward the sender off `anchor`, so the first hop's
/// incoming deadline is the most generous (`anchor` + sum of all
/// deltas) and the last router's outgoing expiry is `anchor` + the
/// payee leg's buffer.
///
/// Callers must include the payee's buffer in `deltas`: without it
/// the last router's outgoing expiry is exactly `anchor`, which every
/// adapter rejects as an already-expired locktime.
pub fn compute_hop_expiries(anchor: u64, deltas: &[u64]) -> Vec<u64> {
    let mut expiries = Vec::with_capacity(deltas.len() + 1);
    let mut cumulative: u64 = 0;
    for delta in deltas.iter().rev() {
        cumulative = cumulative.saturating_add(*delta);
        expiries.push(anchor.saturating_add(cumulative));
    }
    expiries.reverse();
    expiries.push(anchor);
    expiries
}

fn node_fee_msat(node: &RouteAnnouncement, amount_msat: u64) -> u64 {
    let fee_ppm = (node.fee_ppm as u128).saturating_mul(amount_msat as u128) / 1_000_000u128;
    let fee = node.fee_base_msat as u128 + fee_ppm;
    fee.min(u64::MAX as u128) as u64
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct StateKey {
    node_idx: usize,
    incoming: NetworkId,
}

#[derive(Clone, Debug)]
struct State {
    cost: u64,
    key: StateKey,
}

impl PartialEq for State {
    fn eq(&self, other: &Self) -> bool {
        self.cost == other.cost
    }
}

impl Eq for State {}

impl Ord for State {
    fn cmp(&self, other: &Self) -> Ordering {
        other.cost.cmp(&self.cost)
    }
}

impl PartialOrd for State {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cassis_core::NetworkId;

    fn route(pubkey: [u8; 32], from: &str, to: &str) -> RouteAnnouncement {
        RouteAnnouncement {
            node_pubkey: ritualistic::PubKey(pubkey),
            iroh_peer_id: String::new(),
            iroh_relay: None,
            from: NetworkId(from.to_string()),
            to: NetworkId(to.to_string()),
            fee_base_msat: 0,
            fee_ppm: 0,
            incoming_delta_secs: 0,
            transit_slack_secs: 0,
            relays: Vec::new(),
        }
    }

    fn key_x() -> [u8; 32] {
        [1u8; 32]
    }

    fn key_y() -> [u8; 32] {
        [2u8; 32]
    }

    #[test]
    fn single_event_a_to_b_finds_route() {
        let graph = build_graph(vec![route(key_x(), "A", "B")]);
        let route = find_route(&graph, &NetworkId("B".into()), 1000, &NetworkId("A".into()));
        assert!(route.is_ok(), "should find route A->B through nodeX");
        let hops = route.unwrap();
        assert_eq!(hops.len(), 1, "single-hop route");
        assert_eq!(hops[0].0.node_pubkey.0, key_x());
        assert_eq!(hops[0].1 .0, "A", "incoming is A");
        assert_eq!(hops[0].2 .0, "B", "outgoing is destination network B");
    }

    #[test]
    fn two_hop_route_a_to_c_via_b() {
        let graph = build_graph(vec![route(key_x(), "A", "B"), route(key_y(), "B", "C")]);
        let route = find_route(&graph, &NetworkId("C".into()), 1000, &NetworkId("A".into()));
        assert!(route.is_ok(), "should find route A->B->C");
        let hops = route.unwrap();
        assert_eq!(hops.len(), 2);
        assert_eq!(hops[0].0.node_pubkey.0, key_x());
        assert_eq!(hops[0].1 .0, "A");
        assert_eq!(hops[0].2 .0, "B");
        assert_eq!(hops[1].0.node_pubkey.0, key_y());
        assert_eq!(hops[1].1 .0, "B");
        assert_eq!(
            hops[1].2 .0, "C",
            "last hop's outgoing is the destination network"
        );
    }

    #[test]
    fn reverse_route_not_found_when_only_a_to_b_exists() {
        let graph = build_graph(vec![route(key_x(), "A", "B")]);
        let route = find_route(&graph, &NetworkId("A".into()), 1000, &NetworkId("B".into()));
        assert!(
            route.is_err(),
            "B->A should not exist when only A->B announced"
        );
    }

    #[test]
    fn bidirectional_routes_work() {
        let graph = build_graph(vec![
            route(key_x(), "A", "B"),
            route(key_x(), "B", "A"),
            route(key_y(), "B", "C"),
            route(key_y(), "C", "B"),
        ]);
        let route = find_route(&graph, &NetworkId("C".into()), 1000, &NetworkId("A".into()));
        assert!(route.is_ok(), "A->B->C forward route");
        let route = find_route(&graph, &NetworkId("A".into()), 1000, &NetworkId("C".into()));
        assert!(route.is_ok(), "C->B->A reverse route");
    }

    // ---- compute_hop_expiries (cascading timelock) tests ----

    #[test]
    fn compute_hop_expiries_empty_deltas() {
        // No hops means just the recipient's expiry (the anchor),
        // since no delta buffer accumulates.
        let expiries = compute_hop_expiries(1000, &[]);
        assert_eq!(expiries, vec![1000]);
    }

    #[test]
    fn compute_hop_expiries_zero_deltas() {
        // With all deltas zero, every entry equals the anchor. The
        // function returns N+1 entries for N hops so callers can index
        // `idx` (incoming_deadline) and `idx+1` (outgoing_expiry).
        let expiries = compute_hop_expiries(1000, &[0, 0, 0]);
        assert_eq!(expiries, vec![1000, 1000, 1000, 1000]);
    }

    #[test]
    fn compute_hop_expiries_cascade() {
        // deltas[i] is hop i's required buffer between receiving and
        // forwarding. The cascade grows toward the sender off the
        // anchor, so the first hop's incoming deadline is the most
        // generous (anchor + sum of all deltas) and the recipient's
        // expiry is exactly the anchor.
        let expiries = compute_hop_expiries(1000, &[10, 20, 30]);
        // expiries[3] = 1000 (recipient, no buffer remaining)
        // expiries[2] = 1000 + 30 = 1030
        // expiries[1] = 1030 + 20 = 1050
        // expiries[0] = 1050 + 10 = 1060
        assert_eq!(expiries, vec![1060, 1050, 1030, 1000]);
    }

    #[test]
    fn compute_hop_expiries_saturates_on_overflow() {
        // Adding u64::MAX should saturate rather than panic. The
        // recipient's entry (last) is anchored at the anchor, not at
        // the accumulated sum.
        let expiries = compute_hop_expiries(1000, &[u64::MAX, u64::MAX, u64::MAX]);
        assert_eq!(expiries.len(), 4);
        // Monotonically non-increasing from sender to recipient.
        // u64::MAX saturates, so the first three entries are equal.
        assert!(expiries[0] >= expiries[1]);
        assert!(expiries[1] >= expiries[2]);
        assert!(expiries[2] >= expiries[3]);
        assert_eq!(expiries[3], 1000);
    }

    // ---- fallback table tests ----

    #[test]
    fn fallback_known_networks() {
        assert_eq!(fallback_incoming_delta(&NetworkId("ark".into())), 10);
        assert_eq!(fallback_incoming_delta(&NetworkId("fedimint".into())), 30);
        assert_eq!(fallback_incoming_delta(&NetworkId("cashu".into())), 30);
        assert_eq!(fallback_incoming_delta(&NetworkId("liquid".into())), 300);
        assert_eq!(fallback_incoming_delta(&NetworkId("rootstock".into())), 600);
    }

    #[test]
    fn fallback_unknown_network_returns_default() {
        assert_eq!(fallback_incoming_delta(&NetworkId("mystery".into())), 30);
        assert_eq!(fallback_incoming_delta(&NetworkId("".into())), 30);
    }

    // ---- announcement schema tests ----

    #[test]
    fn route_announcement_carries_incoming_delta_secs() {
        // Constructing a RouteAnnouncement with the new field set and
        // round-tripping it through `build_graph` must preserve the
        // value (no serializer surprises, no NodeGraph::new clobber).
        let mut r = route(key_x(), "A", "B");
        r.incoming_delta_secs = 42;
        let graph = build_graph(vec![r.clone()]);
        assert_eq!(graph.nodes[0].incoming_delta_secs, 42);
    }

    #[test]
    fn route_announcement_carries_transit_slack_secs() {
        // Same round-trip property for the transit-slack field.
        let mut r = route(key_x(), "A", "B");
        r.transit_slack_secs = 60;
        let graph = build_graph(vec![r.clone()]);
        assert_eq!(graph.nodes[0].transit_slack_secs, 60);
    }

    // ---- relay-fetch timeout test ----

    #[tokio::test]
    #[ignore = "network-dependent; run with `cargo test -- --ignored`"]
    async fn fetch_announcements_is_bounded_by_timeout() {
        // Use an unroutable RFC 1918 address (10.255.255.1) so the
        // underlying connect would otherwise hang until the OS gives
        // up (tens of seconds). The wrap should bound the call to
        // roughly the requested timeout. We accept either Timeout or
        // an Ok(empty) because some relay pools treat immediate
        // connect-failure as "no events" and return within the
        // timer; what we *don't* accept is hanging for the OS TCP
        // timeout.
        let relays = vec!["wss://10.255.255.1:443".to_string()];
        let timeout = Duration::from_millis(200);
        let start = std::time::Instant::now();
        let result = fetch_announcements_with_timeout(&relays, timeout).await;
        let elapsed = start.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "fetch should be bounded by the wrap, took {elapsed:?}"
        );
        assert!(
            matches!(
                result,
                Ok(_) | Err(NostrError::Timeout) | Err(NostrError::Network(_))
            ),
            "unexpected variant: {result:?}"
        );
    }
}
