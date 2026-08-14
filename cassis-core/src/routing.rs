//! Route discovery: Nostr route announcements, pathfinding, and the fee
//! and timelock arithmetic of a route.
//!
//! Routers announce every directed pair of networks they bridge as a
//! kind-35515 event whose `d` tag is `<from>-><to>`. Payers fetch the
//! recent ones, find the cheapest chain of hops from their network to
//! one the invoice accepts, and plan per-leg amounts and expiries.
//!
//! Kept free of the node runtime so it also builds for wasm.

use crate::network::NetworkId;
use crate::primitives::XOnlyPubKey;
use ritualistic::{EventTemplate, Filter, Kind, SubscriptionOptions, Tags, Timestamp};
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::time::Duration;
// The real `tokio` on native targets and a JS shim on wasm32.
use tokio_with_wasm::alias as tokio;

/// Nostr event kind of route announcements.
pub const ROUTE_ANNOUNCEMENT_KIND: u16 = 35515;

/// Announcements older than this are ignored: their router is assumed
/// offline. Routers republish well within it.
pub const ANNOUNCEMENT_MAX_AGE_SECS: u64 = 24 * 60 * 60;

/// Extra seconds per leg added to every timelock to absorb message
/// latency and clock skew, when a router does not announce its own.
pub const DEFAULT_TRANSIT_SLACK_SECS: u64 = 60;

pub const DEFAULT_NOSTR_RELAYS: &[&str] =
    &["wss://relay.damus.io", "wss://nos.lol", "wss://nostr.mom"];

const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// One directed hop a router offers: receive on `from`, send on `to`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteAnnouncement {
    pub node_pubkey: XOnlyPubKey,
    pub iroh_peer_id: String,
    pub iroh_relay: Option<String>,
    pub from: NetworkId,
    pub to: NetworkId,
    pub fee_base_msat: u64,
    pub fee_ppm: u64,
    /// Seconds the router needs between its outgoing and incoming
    /// expiry (see `Network::incoming_delta_secs`).
    pub incoming_delta_secs: u64,
    /// Seconds of slack the router asks payers to add per leg.
    pub transit_slack_secs: u64,
}

impl RouteAnnouncement {
    /// Fee this hop charges for forwarding `amount_msat`.
    pub fn fee_msat(&self, amount_msat: u64) -> u64 {
        fee_msat(self.fee_base_msat, self.fee_ppm, amount_msat)
    }

    /// Seconds the payer must leave between this hop's outgoing and
    /// incoming expiry.
    pub fn timelock_delta(&self) -> u64 {
        self.incoming_delta_secs
            .saturating_add(self.transit_slack_secs)
    }

    fn d_tag(&self) -> String {
        format!("{}->{}", self.from, self.to)
    }

    fn to_event_template(&self) -> EventTemplate {
        let mut iroh = vec!["iroh".to_string(), self.iroh_peer_id.clone()];
        iroh.extend(self.iroh_relay.clone());
        EventTemplate {
            created_at: Timestamp::now(),
            kind: Kind(ROUTE_ANNOUNCEMENT_KIND),
            tags: Tags(vec![
                vec!["d".to_string(), self.d_tag()],
                iroh,
                vec!["fee_base_msat".to_string(), self.fee_base_msat.to_string()],
                vec!["fee_ppm".to_string(), self.fee_ppm.to_string()],
                vec![
                    "incoming_delta_secs".to_string(),
                    self.incoming_delta_secs.to_string(),
                ],
                vec![
                    "transit_slack_secs".to_string(),
                    self.transit_slack_secs.to_string(),
                ],
            ]),
            content: String::new(),
        }
    }

    fn from_event(event: &ritualistic::Event) -> Option<Self> {
        let tag = |name: &str| {
            event
                .tags
                .iter()
                .find(|tag| tag.len() >= 2 && tag[0] == name)
        };
        let number = |name: &str| tag(name).and_then(|tag| tag[1].parse::<u64>().ok());
        let (from, to) = tag("d")?[1].split_once("->")?;
        let iroh = tag("iroh")?;
        let from = NetworkId::parse(from).ok()?;
        let to = NetworkId::parse(to).ok()?;
        Some(Self {
            node_pubkey: event.pubkey,
            iroh_peer_id: iroh[1].clone(),
            iroh_relay: iroh.get(2).filter(|relay| !relay.is_empty()).cloned(),
            fee_base_msat: number("fee_base_msat").unwrap_or(0),
            fee_ppm: number("fee_ppm").unwrap_or(0),
            incoming_delta_secs: number("incoming_delta_secs")
                .filter(|delta| *delta > 0)
                .unwrap_or_else(|| from.default_incoming_delta()),
            transit_slack_secs: number("transit_slack_secs")
                .filter(|slack| *slack > 0)
                .unwrap_or(DEFAULT_TRANSIT_SLACK_SECS),
            from,
            to,
        })
    }
}

pub fn fee_msat(base_msat: u64, ppm: u64, amount_msat: u64) -> u64 {
    let proportional = (ppm as u128).saturating_mul(amount_msat as u128) / 1_000_000;
    (base_msat as u128)
        .saturating_add(proportional)
        .min(u64::MAX as u128) as u64
}

/// Recent route announcements from `relays`, newest per router and
/// direction.
pub async fn fetch_announcements(relays: &[String]) -> Result<Vec<RouteAnnouncement>, String> {
    if relays.is_empty() {
        return Err("no nostr relays configured".into());
    }
    let filter = Filter {
        kinds: Some(vec![Kind(ROUTE_ANNOUNCEMENT_KIND)]),
        since: Some(Timestamp(
            crate::unix_now().saturating_sub(ANNOUNCEMENT_MAX_AGE_SECS) as u32,
        )),
        limit: Some(1000),
        ..Default::default()
    };
    let pool = ritualistic::Network::new();
    let events = tokio::time::timeout(
        FETCH_TIMEOUT,
        pool.query(relays, filter, SubscriptionOptions::default()),
    )
    .await
    .map_err(|_| "nostr relay query timed out".to_string())?;
    // `query` sorts newest first, so the first event per (router,
    // direction) is the current one.
    let mut announcements: Vec<RouteAnnouncement> = Vec::new();
    for event in &events {
        if !event.verify_signature() {
            continue;
        }
        let Some(announcement) = RouteAnnouncement::from_event(event) else {
            continue;
        };
        if !announcements.iter().any(|existing| {
            existing.node_pubkey == announcement.node_pubkey
                && existing.from == announcement.from
                && existing.to == announcement.to
        }) {
            announcements.push(announcement);
        }
    }
    Ok(announcements)
}

/// Sign and publish `announcements` with the router's node key.
/// Returns, per announcement, how many relays accepted it.
pub async fn publish_announcements(
    relays: &[String],
    node_key: &ritualistic::SecretKey,
    announcements: &[RouteAnnouncement],
) -> Vec<(String, usize)> {
    let mut pool = ritualistic::Network::new();
    let mut results = Vec::with_capacity(announcements.len());
    for announcement in announcements {
        let event = announcement.to_event_template().finalize(node_key);
        let mut replies = pool.publish_many(relays, event).await;
        let mut accepted = 0;
        while let Some(reply) = replies.recv().await {
            match reply.error {
                None => accepted += 1,
                Some(error) => tracing::debug!(
                    "relay {} rejected {}: {error}",
                    reply.relay_url,
                    announcement.d_tag()
                ),
            }
        }
        results.push((announcement.d_tag(), accepted));
    }
    results
}

/// Cheapest chain of hops carrying `amount_msat` from `from` to `to`.
/// Empty when `from == to`.
///
/// Searches backwards from the destination, where the amount is known,
/// so every hop's fee is computed on the amount it actually forwards.
pub fn find_route(
    announcements: &[RouteAnnouncement],
    from: &NetworkId,
    to: &NetworkId,
    amount_msat: u64,
) -> Result<Vec<RouteAnnouncement>, String> {
    if from == to {
        return Ok(Vec::new());
    }
    // Amount needed when entering a network to get `amount_msat` to
    // `to`, and the hop taken from there.
    let mut needed: HashMap<&NetworkId, u64> = HashMap::from([(to, amount_msat)]);
    let mut next_hop: HashMap<&NetworkId, &RouteAnnouncement> = HashMap::new();
    let mut queue = BinaryHeap::from([Reverse((amount_msat, to))]);
    while let Some(Reverse((amount, network))) = queue.pop() {
        if needed.get(network).is_some_and(|best| amount > *best) {
            continue;
        }
        if network == from {
            let mut route = Vec::new();
            let mut at = from;
            while at != to {
                let hop = next_hop[at];
                route.push(hop.clone());
                at = &hop.to;
            }
            let mut nodes: Vec<_> = route.iter().map(|hop| hop.node_pubkey).collect();
            nodes.sort_by_key(|key| *key.as_bytes());
            nodes.dedup();
            if nodes.len() != route.len() {
                // A router can only hold one hop per payment hash.
                return Err("cheapest route passes the same router twice".into());
            }
            return Ok(route);
        }
        for hop in announcements.iter().filter(|hop| hop.to == *network) {
            let Some(upstream) = amount.checked_add(hop.fee_msat(amount)) else {
                continue;
            };
            if needed.get(&hop.from).is_none_or(|best| upstream < *best) {
                needed.insert(&hop.from, upstream);
                next_hop.insert(&hop.from, hop);
                queue.push(Reverse((upstream, &hop.from)));
            }
        }
    }
    Err(format!("no route from {from} to {to}"))
}

/// Amounts and expiries of every leg of a route.
///
/// Leg `i < n` is the HTLC funding hop `i`; leg `n` is the HTLC
/// funding the payee. `amounts[i]` / `expiries[i]` belong to leg `i`,
/// so hop `i` receives `amounts[i]` until `expiries[i]` and forwards
/// `amounts[i + 1]` until `expiries[i + 1]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoutePlan {
    pub amounts: Vec<u64>,
    pub expiries: Vec<u64>,
}

/// Plan `route` delivering `amount_msat` to a payee who needs
/// `payee_delta_secs` to claim, starting at `now`.
///
/// Expiries decrease from payer to payee: each hop gets its announced
/// delta plus slack between its outgoing and incoming leg, and the
/// payee leg starts after every hop has had one slack period to
/// execute, so it is still claimable when the payee gets COMMIT.
pub fn plan_route(
    route: &[RouteAnnouncement],
    amount_msat: u64,
    payee_delta_secs: u64,
    now: u64,
) -> Result<RoutePlan, String> {
    let n = route.len();
    let mut amounts = vec![amount_msat; n + 1];
    for i in (0..n).rev() {
        amounts[i] = amounts[i + 1]
            .checked_add(route[i].fee_msat(amounts[i + 1]))
            .ok_or("route fees overflow")?;
    }
    let setup: u64 = route.iter().map(|hop| hop.transit_slack_secs).sum();
    let mut expiries = vec![0; n + 1];
    expiries[n] = now
        .saturating_add(setup)
        .saturating_add(payee_delta_secs)
        .saturating_add(DEFAULT_TRANSIT_SLACK_SECS);
    for i in (0..n).rev() {
        expiries[i] = expiries[i + 1].saturating_add(route[i].timelock_delta());
    }
    Ok(RoutePlan { amounts, expiries })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hop(node: u8, from: &str, to: &str, fee_base_msat: u64, fee_ppm: u64) -> RouteAnnouncement {
        RouteAnnouncement {
            node_pubkey: XOnlyPubKey([node; 32]),
            iroh_peer_id: String::new(),
            iroh_relay: None,
            from: NetworkId(from.into()),
            to: NetworkId(to.into()),
            fee_base_msat,
            fee_ppm,
            incoming_delta_secs: 30,
            transit_slack_secs: 60,
        }
    }

    fn route(graph: &[RouteAnnouncement], from: &str, to: &str) -> Result<Vec<u8>, String> {
        find_route(
            graph,
            &NetworkId(from.into()),
            &NetworkId(to.into()),
            1_000_000,
        )
        .map(|hops| hops.iter().map(|hop| hop.node_pubkey.0[0]).collect())
    }

    #[test]
    fn same_network_needs_no_hops() {
        assert_eq!(route(&[], "a", "a").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn finds_single_and_multi_hop_routes() {
        let graph = [hop(1, "a", "b", 0, 0), hop(2, "b", "c", 0, 0)];
        assert_eq!(route(&graph, "a", "b").unwrap(), vec![1]);
        assert_eq!(route(&graph, "a", "c").unwrap(), vec![1, 2]);
        assert!(route(&graph, "c", "a").is_err());
    }

    #[test]
    fn prefers_the_cheapest_route() {
        let graph = [
            hop(1, "a", "c", 10_000, 0),
            hop(2, "a", "b", 100, 0),
            hop(3, "b", "c", 100, 0),
        ];
        assert_eq!(route(&graph, "a", "c").unwrap(), vec![2, 3]);
    }

    #[test]
    fn rejects_routes_through_the_same_router_twice() {
        let graph = [
            hop(1, "a", "b", 0, 0),
            hop(2, "b", "c", 0, 0),
            hop(1, "c", "d", 0, 0),
        ];
        assert!(route(&graph, "a", "d").is_err());
    }

    #[test]
    fn plan_adds_fees_upstream_and_timelocks_decrease() {
        let graph = [hop(1, "a", "b", 100, 10_000), hop(2, "b", "c", 100, 10_000)];
        let plan = plan_route(&graph, 1_000, 30, 1_000).unwrap();
        assert_eq!(plan.amounts, vec![1_221, 1_110, 1_000]);
        // Payee leg: now + 2 * 60 setup + 30 delta + 60 slack.
        assert_eq!(plan.expiries, vec![1_390, 1_300, 1_210]);
    }

    #[test]
    fn plan_without_hops_only_has_the_payee_leg() {
        let plan = plan_route(&[], 5_000, 30, 1_000).unwrap();
        assert_eq!(plan.amounts, vec![5_000]);
        assert_eq!(plan.expiries, vec![1_090]);
    }
}
