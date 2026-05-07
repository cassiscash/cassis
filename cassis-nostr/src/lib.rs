use cassis_core::{NetworkId, RouteAnnouncement};
use ritualistic::{Filter, Kind, Network, SubscriptionOptions};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};

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
        eprintln!("--- graph ({} announcement(s)) ---", self.nodes.len());
        if self.nodes.is_empty() {
            eprintln!("  (empty)");
            return;
        }
        for (i, node) in self.nodes.iter().enumerate() {
            eprintln!(
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

    pub async fn publish_once(
        &self,
        _announcement: &RouteAnnouncement,
    ) -> Result<(), NostrError> {
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
/// and fee/relay tags.
///
/// Each event's `d` tag has the form `<network_from>-><network_to>`.
/// Additional tags: `fee_base_msat`, `fee_ppm`, `relay`, `expires_at`.
pub async fn fetch_announcements(relays: &[String]) -> Result<Vec<RouteAnnouncement>, NostrError> {
    if relays.is_empty() {
        return Err(NostrError::Network("no relays provided".into()));
    }

    let filter = Filter {
        kinds: Some(vec![Kind(KIND_ROUTE_ANNOUNCEMENT)]),
        limit: Some(1000),
        ..Default::default()
    };

    let pool = Network::new();
    let events = pool
        .query(relays, filter, SubscriptionOptions::default())
        .await;

    let mut announcements = Vec::new();

    for event in events {
        let pubkey_hex = event.pubkey.to_hex();
        let mut from: Option<String> = None;
        let mut to: Option<String> = None;
        let mut fee_base_msat: u64 = 0;
        let mut fee_ppm: u64 = 0;
        let mut expires_at: u64 = 0;
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
                "fee_base_msat" => {
                    fee_base_msat = tag[1].parse().unwrap_or(0);
                }
                "fee_ppm" => {
                    fee_ppm = tag[1].parse().unwrap_or(0);
                }
                "expires_at" => {
                    expires_at = tag[1].parse().unwrap_or(0);
                }
                "relay" => {
                    relays.push(tag[1].clone());
                }
                _ => {}
            }
        }

        if let (Some(from), Some(to)) = (from, to) {
            announcements.push(RouteAnnouncement {
                node_pubkey: pubkey_hex,
                from: NetworkId(from),
                to: NetworkId(to),
                fee_base_msat,
                fee_ppm,
                expires_at,
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
    destination: &str,
    amount_msat: u64,
    sender_network: &NetworkId,
) -> Result<Vec<(RouteAnnouncement, NetworkId, NetworkId)>, RouteError> {
    eprintln!(
        "find_route: destination={destination}, amount_msat={amount_msat}, sender_network={sender_network}"
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
        eprintln!(
            "  seed: route #{node_idx} ({}) <{sender_network} cost={fee} msat",
            node.node_pubkey
        );
        dist.insert(key.clone(), fee);
        heap.push(State { cost: fee, key });
    }

    let mut goal: Option<StateKey> = None;
    let mut goal_outgoing: Option<NetworkId> = None;
    let mut step = 0u64;

    while let Some(State { cost, key }) = heap.pop() {
        step += 1;
        let node = &graph.nodes[key.node_idx];

        if let Some(best) = dist.get(&key) {
            if cost > *best {
                eprintln!(
                    "  step {step}: skip stale entry route #{} ({}) cost={cost} > best={best}",
                    key.node_idx,
                    node.node_pubkey
                );
                continue;
            }
        }

        eprintln!(
            "  step {step}: visit route #{} ({}) via {} cost={cost} msat",
            key.node_idx,
            node.node_pubkey,
            key.incoming
        );

        if node.node_pubkey == destination || node.to.0 == destination {
            eprintln!(
                "  step {step}: destination reached at route #{} ({}) via pubkey={} to={}",
                key.node_idx,
                node.node_pubkey,
                node.node_pubkey == destination,
                node.to.0 == destination,
            );
            if node.to.0 == destination {
                goal_outgoing = Some(node.to.clone());
            }
            goal = Some(key.clone());
            break;
        }

        let outgoing = &node.to;

        eprintln!("    edge: {} -> {} (from {})", key.incoming, outgoing, node.node_pubkey);
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
            let next_cost = cost.saturating_add(node_fee_msat(next_node, amount_msat));
            let is_better = match dist.get(&next_key) {
                Some(existing) => next_cost < *existing,
                None => true,
            };
            if is_better {
                eprintln!(
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
                eprintln!(
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
    let mut outgoing_for_current: Option<NetworkId> = None;
    let mut hop_idx = 0u64;

    loop {
        let node = graph
            .nodes
            .get(current.node_idx)
            .ok_or_else(|| RouteError::InvalidGraph("node missing".to_string()))?;
        let incoming = current.incoming.clone();
        let outgoing = outgoing_for_current.clone().or_else(|| goal_outgoing.clone()).unwrap_or_else(|| incoming.clone());
        eprintln!(
            "  backtrack hop {hop_idx}: route #{} ({}) in={incoming} out={outgoing}",
            current.node_idx,
            node.node_pubkey
        );
        hop_idx += 1;
        hops_rev.push((
            node.clone(),
            incoming.clone(),
            outgoing.clone(),
        ));

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

pub fn compute_hop_expiries(final_expiry: u64, deltas: &[u64]) -> Vec<u64> {
    let mut expiries = Vec::with_capacity(deltas.len() + 1);
    let mut current = final_expiry;
    expiries.push(current);
    for delta in deltas.iter().rev() {
        current = current.saturating_add(*delta);
        expiries.push(current);
    }
    expiries.reverse();
    expiries
}

fn node_fee_msat(node: &RouteAnnouncement, amount_msat: u64) -> u64 {
    let fee_ppm = (node.fee_ppm as u128)
        .saturating_mul(amount_msat as u128)
        / 1_000_000u128;
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

    fn route(pubkey: &str, from: &str, to: &str) -> RouteAnnouncement {
        RouteAnnouncement {
            node_pubkey: pubkey.to_string(),
            from: NetworkId(from.to_string()),
            to: NetworkId(to.to_string()),
            fee_base_msat: 0,
            fee_ppm: 0,
            expires_at: 0,
            relays: Vec::new(),
        }
    }

    #[test]
    fn single_event_a_to_b_finds_route() {
        let graph = build_graph(vec![route("nodeX", "A", "B")]);
        let route = find_route(&graph, "nodeX", 1000, &NetworkId("A".into()));
        assert!(route.is_ok(), "should find route A->B through nodeX");
        let hops = route.unwrap();
        assert_eq!(hops.len(), 1, "single-hop route");
        assert_eq!(hops[0].0.node_pubkey, "nodeX");
        assert_eq!(hops[0].1.0, "A", "incoming is A");
        assert_eq!(hops[0].2.0, "A", "outgoing for destination node is same as incoming");
    }

    #[test]
    fn two_hop_route_a_to_c_via_b() {
        let graph = build_graph(vec![
            route("nodeX", "A", "B"),
            route("nodeY", "B", "C"),
        ]);
        let route = find_route(&graph, "nodeY", 1000, &NetworkId("A".into()));
        assert!(route.is_ok(), "should find route A->B->C");
        let hops = route.unwrap();
        assert_eq!(hops.len(), 2);
        assert_eq!(hops[0].0.node_pubkey, "nodeX");
        assert_eq!(hops[0].1.0, "A");
        assert_eq!(hops[0].2.0, "B");
        assert_eq!(hops[1].0.node_pubkey, "nodeY");
        assert_eq!(hops[1].1.0, "B");
        assert_eq!(hops[1].2.0, "B");
    }

    #[test]
    fn reverse_route_not_found_when_only_a_to_b_exists() {
        let graph = build_graph(vec![route("nodeX", "A", "B")]);
        let route = find_route(&graph, "nodeX", 1000, &NetworkId("B".into()));
        assert!(route.is_err(), "B->A should not exist when only A->B announced");
    }

    #[test]
    fn bidirectional_routes_work() {
        let graph = build_graph(vec![
            route("nodeX", "A", "B"),
            route("nodeX", "B", "A"),
            route("nodeY", "B", "C"),
            route("nodeY", "C", "B"),
        ]);
        let route = find_route(&graph, "nodeY", 1000, &NetworkId("A".into()));
        assert!(route.is_ok(), "A->B->C forward route");
        let route = find_route(&graph, "nodeX", 1000, &NetworkId("C".into()));
        assert!(route.is_ok(), "C->B->A reverse route");
    }
}
