use cassis_core::{L2Tag, NetworkId, NodeAnnouncement, Route};
use ritualistic::{Filter, Kind, Network, SubscriptionOptions};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeGraph {
    pub nodes: Vec<NodeAnnouncement>,
    #[serde(skip)]
    incoming_index: HashMap<NetworkId, Vec<usize>>,
}

impl NodeGraph {
    pub fn new(nodes: Vec<NodeAnnouncement>) -> Self {
        let mut incoming_index: HashMap<NetworkId, Vec<usize>> = HashMap::new();
        for (idx, node) in nodes.iter().enumerate() {
            if !node.routes.is_empty() {
                // Directional: index only by the receiving side of each route.
                for route in &node.routes {
                    incoming_index
                        .entry(route.from.clone())
                        .or_default()
                        .push(idx);
                }
            } else {
                // Backward compat: no routes, use flat networks list.
                for network in &node.networks {
                    incoming_index
                        .entry(network.clone())
                        .or_default()
                        .push(idx);
                }
            }
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

    /// Nodes that can receive on the given network.
    fn nodes_for_network(&self, network: &NetworkId) -> impl Iterator<Item = usize> + '_ {
        self.incoming_index
            .get(network)
            .map(|nodes| nodes.iter().copied())
            .into_iter()
            .flatten()
    }

    /// Print the full graph contents to stderr.
    pub fn log(&self) {
        eprintln!("--- graph ({} node(s)) ---", self.nodes.len());
        if self.nodes.is_empty() {
            eprintln!("  (empty)");
            return;
        }
        for (i, node) in self.nodes.iter().enumerate() {
            eprintln!("  node #{i}: {}", node.node_pubkey);
            eprintln!("    fee: base={} ppm={}", node.fee_base_msat, node.fee_ppm);
            if node.routes.is_empty() {
                eprintln!("    networks: {:?}", node.networks);
            } else {
                for route in &node.routes {
                    eprintln!("    route: {} -> {}", route.from, route.to);
                }
            }
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
        _announcement: &NodeAnnouncement,
    ) -> Result<(), NostrError> {
        Err(NostrError::Unimplemented)
    }

    pub async fn run_republish_loop(
        &self,
        _announcement: NodeAnnouncement,
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
/// and build [`NodeAnnouncement`] structs from the directed route `d` tags.
///
/// Each event's `d` tag has the form `<network_from>-><network_to>`. Events
/// are grouped by pubkey — each unique pubkey is a node. The node's
/// `networks` field is the union of all networks appearing in its `d` tags.
pub async fn fetch_announcements(relays: &[String]) -> Result<Vec<NodeAnnouncement>, NostrError> {
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

    let mut announcements: HashMap<String, NodeAnnouncement> = HashMap::new();

    for event in events {
        let pubkey_hex = event.pubkey.to_hex();

        for tag in event.tags.iter() {
            if tag.len() >= 2 && tag[0] == "d" {
                if let Some((from, to)) = parse_d_tag(&tag[1]) {
                    let entry = announcements.entry(pubkey_hex.clone()).or_insert_with(|| {
                        NodeAnnouncement {
                            node_pubkey: pubkey_hex.clone(),
                            iroh_pubkey: String::new(),
                            networks: Vec::new(),
                            routes: Vec::new(),
                            fee_base_msat: 0,
                            fee_ppm: 0,
                            expires_at: 0,
                            relays: Vec::new(),
                        }
                    });

                    let from_net = NetworkId(from.to_string());
                    let to_net = NetworkId(to.to_string());

                    if !entry.networks.contains(&from_net) {
                        entry.networks.push(from_net.clone());
                    }
                    if !entry.networks.contains(&to_net) {
                        entry.networks.push(to_net.clone());
                    }

                    let route = Route {
                        from: from_net,
                        to: to_net,
                    };
                    if !entry.routes.contains(&route) {
                        entry.routes.push(route);
                    }
                }
            }
        }
    }

    Ok(announcements.into_values().collect())
}

/// Parse a `d` tag value of the form `<network_from>-><network_to>`.
fn parse_d_tag(d: &str) -> Option<(&str, &str)> {
    d.split_once(D_TAG_SEPARATOR)
        .filter(|(from, to)| !from.is_empty() && !to.is_empty())
}

pub fn build_graph(announcements: Vec<NodeAnnouncement>) -> NodeGraph {
    NodeGraph::new(announcements)
}

pub fn find_route(
    graph: &NodeGraph,
    destination: &str,
    amount_msat: u64,
    sender_network: &NetworkId,
) -> Result<Vec<(NodeAnnouncement, L2Tag, L2Tag)>, RouteError> {
    eprintln!(
        "find_route: destination={destination}, amount_msat={amount_msat}, sender_network={sender_network}"
    );

    let mut heap: BinaryHeap<State> = BinaryHeap::new();
    let mut dist: HashMap<StateKey, u64> = HashMap::new();
    let mut prev: HashMap<StateKey, (StateKey, NetworkId)> = HashMap::new();

    // Seed: all nodes that can receive on the sender's network.
    for node_idx in graph.nodes_for_network(sender_network) {
        let node = &graph.nodes[node_idx];
        let fee = node_fee_msat(node, amount_msat);
        let key = StateKey {
            node_idx,
            incoming: sender_network.clone(),
        };
        eprintln!(
            "  seed: node #{node_idx} ({}) reachable via {sender_network} cost={fee} msat",
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
                eprintln!(
                    "  step {step}: skip stale entry node #{} ({}) cost={cost} > best={best}",
                    key.node_idx,
                    node.node_pubkey
                );
                continue;
            }
        }

        eprintln!(
            "  step {step}: visit node #{} ({}) via {} cost={cost} msat",
            key.node_idx,
            node.node_pubkey,
            key.incoming
        );

        // Destination reached: this node's pubkey matches.
        if node.node_pubkey == destination {
            eprintln!(
                "  step {step}: destination reached at node #{} ({})",
                key.node_idx,
                node.node_pubkey
            );
            goal = Some(key.clone());
            break;
        }

        // Follow only directional routes: entered via `incoming`, exit via
        // each route whose `from` matches `incoming`.
        let outgoing_networks: Vec<&NetworkId> = if !node.routes.is_empty() {
            node.routes
                .iter()
                .filter(|r| r.from == key.incoming)
                .map(|r| &r.to)
                .collect()
        } else {
            // Backward compat: if no directional routes, use flat networks
            // but exclude the incoming network (can't exit where you entered).
            node.networks.iter().filter(|n| **n != key.incoming).collect()
        };

        for outgoing in outgoing_networks {
            eprintln!("    edge: {} -> {} (from {})", key.incoming, outgoing, node.node_pubkey);
            for next_idx in graph.nodes_for_network(outgoing) {
                if next_idx == key.node_idx {
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
                        "    relax: node #{next_idx} ({}) via {} new_cost={next_cost} msat",
                        next_node.node_pubkey,
                        outgoing
                    );
                    dist.insert(next_key.clone(), next_cost);
                    prev.insert(next_key.clone(), (key.clone(), outgoing.clone()));
                    heap.push(State {
                        cost: next_cost,
                        key: next_key,
                    });
                } else {
                    eprintln!(
                        "    skip: node #{next_idx} ({}) via {} cost={next_cost} not better than {}",
                        next_node.node_pubkey,
                        outgoing,
                        dist.get(&next_key).copied().unwrap_or(0)
                    );
                }
            }
        }
    }

    let goal = goal.ok_or(RouteError::NoRoute)?;
    let mut hops_rev: Vec<(NodeAnnouncement, L2Tag, L2Tag)> = Vec::new();
    let mut current = goal.clone();
    let mut outgoing_for_current: Option<NetworkId> = None;
    let mut hop_idx = 0u64;

    loop {
        let node = graph
            .nodes
            .get(current.node_idx)
            .ok_or_else(|| RouteError::InvalidGraph("node missing".to_string()))?;
        let incoming = current.incoming.clone();
        let outgoing = outgoing_for_current.clone().unwrap_or_else(|| incoming.clone());
        eprintln!(
            "  backtrack hop {hop_idx}: node #{} ({}) in={incoming} out={outgoing}",
            current.node_idx,
            node.node_pubkey
        );
        hop_idx += 1;
        hops_rev.push((
            node.clone(),
            L2Tag(incoming.0.clone()),
            L2Tag(outgoing.0.clone()),
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

fn node_fee_msat(node: &NodeAnnouncement, amount_msat: u64) -> u64 {
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

    fn node(pubkey: &str, routes: &[(&str, &str)]) -> NodeAnnouncement {
        NodeAnnouncement {
            node_pubkey: pubkey.to_string(),
            iroh_pubkey: String::new(),
            networks: routes
                .iter()
                .flat_map(|(f, t)| [NetworkId(f.to_string()), NetworkId(t.to_string())])
                .collect(),
            routes: routes
                .iter()
                .map(|(f, t)| Route {
                    from: NetworkId(f.to_string()),
                    to: NetworkId(t.to_string()),
                })
                .collect(),
            fee_base_msat: 0,
            fee_ppm: 0,
            expires_at: 0,
            relays: Vec::new(),
        }
    }

    #[test]
    fn single_event_a_to_b_finds_route() {
        let graph = build_graph(vec![node("nodeX", &[("A", "B")])]);
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
            node("nodeX", &[("A", "B")]),
            node("nodeY", &[("B", "C")]),
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
        let graph = build_graph(vec![node("nodeX", &[("A", "B")])]);
        let route = find_route(&graph, "nodeX", 1000, &NetworkId("B".into()));
        assert!(route.is_err(), "B->A should not exist when only A->B announced");
    }

    #[test]
    fn bidirectional_routes_work() {
        let graph = build_graph(vec![
            node("nodeX", &[("A", "B"), ("B", "A")]),
            node("nodeY", &[("B", "C"), ("C", "B")]),
        ]);
        let route = find_route(&graph, "nodeY", 1000, &NetworkId("A".into()));
        assert!(route.is_ok(), "A->B->C forward route");
        let route = find_route(&graph, "nodeX", 1000, &NetworkId("C".into()));
        assert!(route.is_ok(), "C->B->A reverse route");
    }
}
