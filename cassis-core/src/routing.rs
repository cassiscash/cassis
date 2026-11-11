//! Route discovery: Nostr route announcements, pathfinding, and the fee
//! and timelock arithmetic of a route.
//!
//! Routers announce every directed pair of networks they bridge as a
//! kind-35515 event whose `d` tag is `<from>-><to>`. Payers fetch the
//! recent ones, find the cheapest chain of hops from their network to
//! one the invoice accepts, and plan per-leg amounts and expiries.
//!
//! Routers moving test money (test mints, signet, testnets...) add a
//! [`TEST_MONEY_TAG`] tag, so explorers and payers can tell their
//! routes apart from real ones even on networks whose id does not say.
//!
//! Kept free of the node runtime so it also builds for wasm.

use crate::network::NetworkId;
use crate::primitives::XOnlyPubKey;
use ritualistic::{
    EventTemplate, Filter, Kind, PublishOptions, SubscriptionOptions, Tags, Timestamp,
};
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};
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

/// Relays route announcements are published to and fetched from.
pub const DEFAULT_NOSTR_RELAYS: &[&str] = &["wss://nostr.wine"];

/// Relays for nodes running on test money (mutinynet, signet, test
/// mints...), keeping their announcements off the default relays.
pub const TEST_NOSTR_RELAYS: &[&str] = &[
    "wss://nos.lol",
    "wss://relay.primal.net",
    "wss://relay.damus.io",
];

/// Name of the valueless tag marking an announcement as test money.
pub const TEST_MONEY_TAG: &str = "testmoney";

const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Bytes of a node key [`autoname`] encodes, away
/// from both ends so it does not echo the truncated hex shown in UIs.
const AUTONAME_BYTES: std::ops::Range<usize> = 8..12;

/// Bytes of a node key [`autohue`] derives from,
/// apart from [`AUTONAME_BYTES`] so names and colors vary independently.
const AUTOHUE_BYTES: std::ops::Range<usize> = 20..22;

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
    /// The router moves test money on this hop ([`TEST_MONEY_TAG`]).
    #[serde(default)]
    pub test_money: bool,
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

    /// The `name` in the node's kind-0 metadata, if it published one.
    pub async fn name(&self) -> Option<String> {
        let pool = ritualistic::Network::new();
        let profile = tokio::time::timeout(
            FETCH_TIMEOUT,
            ritualistic::Profile::from_metadata_fetch(&pool, self.node_pubkey),
        )
        .await
        .ok()?;
        profile
            .metadata
            .name
            .map(|name| name.trim().to_string())
            .filter(|name| !name.is_empty())
    }

    /// The router's [`autoname`].
    pub fn autoname(&self) -> String {
        autoname(&self.node_pubkey)
    }

    /// The router's [`autohue`].
    pub fn autohue(&self) -> u16 {
        autohue(&self.node_pubkey)
    }

    /// The `d` tag of this announcement: see [`route_d_tag`].
    pub fn d_tag(&self) -> String {
        route_d_tag(&self.from, &self.to)
    }

    fn to_event_template(&self) -> EventTemplate {
        let mut iroh = vec!["iroh".to_string(), self.iroh_peer_id.clone()];
        iroh.extend(self.iroh_relay.clone());
        let mut tags = vec![
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
        ];
        if self.test_money {
            tags.push(vec![TEST_MONEY_TAG.to_string()]);
        }
        EventTemplate {
            created_at: Timestamp::now(),
            kind: Kind(ROUTE_ANNOUNCEMENT_KIND),
            tags: Tags(tags),
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
            test_money: event
                .tags
                .iter()
                .any(|tag| tag.first().is_some_and(|name| name == TEST_MONEY_TAG)),
            from,
            to,
        })
    }
}

/// A memorable name derived from a node key, like
/// `misty-heron-quiet-willow`: two adjective/noun pairs, one byte of
/// [`AUTONAME_BYTES`] per word.
pub fn autoname(node_pubkey: &XOnlyPubKey) -> String {
    let [a, b, c, d] = node_pubkey.0[AUTONAME_BYTES]
        .try_into()
        .expect("AUTONAME_BYTES spans 4 bytes");
    format!(
        "{}-{}-{}-{}",
        ADJECTIVES[a as usize], NOUNS[b as usize], ADJECTIVES[c as usize], NOUNS[d as usize]
    )
}

/// A hue in degrees (`0..360`) derived from a node key, to tell nodes
/// apart at a glance in UIs.
pub fn autohue(node_pubkey: &XOnlyPubKey) -> u16 {
    let bytes = &node_pubkey.0[AUTOHUE_BYTES];
    let value = u16::from_be_bytes([bytes[0], bytes[1]]);
    (value as u32 * 360 / 65_536) as u16
}

/// The `d` tag a router announces the hop from `from` to `to` under,
/// which identifies it among the router's announcements.
pub fn route_d_tag(from: &NetworkId, to: &NetworkId) -> String {
    format!("{from}->{to}")
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
        let mut replies = pool
            .publish_many(relays, event, PublishOptions::default())
            .await;
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

/// One route announcement a relay keeps from a router.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Published {
    /// Which hop it announces: see [`route_d_tag`].
    pub d_tag: String,
    /// When it was signed, in unix seconds.
    pub created_at: u64,
}

/// Every route announcement `relay` keeps from `router`, however old,
/// the newest per `d` tag, sorted by it.
pub async fn fetch_published(relay: &str, router: XOnlyPubKey) -> Result<Vec<Published>, String> {
    let filter = Filter {
        kinds: Some(vec![Kind(ROUTE_ANNOUNCEMENT_KIND)]),
        authors: Some(vec![router]),
        limit: Some(1000),
        ..Default::default()
    };
    let pool = ritualistic::Network::new();
    let events = tokio::time::timeout(
        FETCH_TIMEOUT,
        pool.query([relay], filter, SubscriptionOptions::default()),
    )
    .await
    .map_err(|_| format!("{relay}: query timed out"))?;
    let mut published: Vec<Published> = Vec::new();
    for event in &events {
        if event.pubkey != router || !event.verify_signature() {
            continue;
        }
        let found = Published {
            d_tag: event.tags.get_d(),
            created_at: event.created_at.0 as u64,
        };
        match published.iter_mut().find(|p| p.d_tag == found.d_tag) {
            Some(known) => known.created_at = known.created_at.max(found.created_at),
            None => published.push(found),
        }
    }
    published.sort_by(|a, b| a.d_tag.cmp(&b.d_tag));
    Ok(published)
}

/// `d` tags of every route announcement `relay` keeps from `router`,
/// however old.
pub async fn fetch_own_routes(relay: &str, router: XOnlyPubKey) -> Result<Vec<String>, String> {
    Ok(fetch_published(relay, router)
        .await?
        .into_iter()
        .map(|published| published.d_tag)
        .collect())
}

/// Publish `name` as the router's profile (kind-0 metadata), which
/// payers and explorers show instead of its [`autoname`]; `None`
/// publishes an empty profile. Returns how many relays accepted it.
pub async fn publish_name(
    relays: &[String],
    node_key: &ritualistic::SecretKey,
    name: Option<&str>,
) -> usize {
    let content = match name {
        Some(name) => serde_json::json!({ "name": name }).to_string(),
        None => "{}".to_string(),
    };
    let event = EventTemplate {
        created_at: Timestamp::now(),
        kind: Kind(0),
        tags: Tags(Vec::new()),
        content,
    }
    .finalize(node_key);
    let mut pool = ritualistic::Network::new();
    let mut replies = pool
        .publish_many(relays, event, PublishOptions::default())
        .await;
    let mut accepted = 0;
    while let Some(reply) = replies.recv().await {
        match reply.error {
            None => accepted += 1,
            Some(error) => tracing::debug!("relay {} rejected a profile: {error}", reply.relay_url),
        }
    }
    accepted
}

/// Ask `relays` to delete the router's announcements under `d_tags`
/// (a NIP-09 deletion of their addresses). Returns how many relays
/// accepted the deletion.
pub async fn delete_announcements(
    relays: &[String],
    node_key: &ritualistic::SecretKey,
    d_tags: &[String],
) -> usize {
    let pubkey = node_key.pubkey().to_hex();
    let mut tags: Vec<Vec<String>> = d_tags
        .iter()
        .map(|d| {
            vec![
                "a".to_string(),
                format!("{ROUTE_ANNOUNCEMENT_KIND}:{pubkey}:{d}"),
            ]
        })
        .collect();
    tags.push(vec!["k".to_string(), ROUTE_ANNOUNCEMENT_KIND.to_string()]);
    let event = EventTemplate {
        created_at: Timestamp::now(),
        kind: Kind(5),
        tags: Tags(tags),
        content: "route no longer offered".to_string(),
    }
    .finalize(node_key);
    let mut pool = ritualistic::Network::new();
    let mut replies = pool
        .publish_many(relays, event, PublishOptions::default())
        .await;
    let mut accepted = 0;
    while let Some(reply) = replies.recv().await {
        match reply.error {
            None => accepted += 1,
            Some(error) => {
                tracing::debug!("relay {} rejected a deletion: {error}", reply.relay_url)
            }
        }
    }
    accepted
}

/// Cheapest chain of hops carrying `amount_msat` from `from` to `to`.
/// Empty when `from == to`. Hops of routers in `skip` (e.g. ones that
/// failed an earlier attempt) are never used.
///
/// Searches backwards from the destination, where the amount is known,
/// so every hop's fee is computed on the amount it actually forwards.
pub fn find_route(
    announcements: &[RouteAnnouncement],
    from: &NetworkId,
    to: &NetworkId,
    amount_msat: u64,
    skip: &HashSet<XOnlyPubKey>,
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
        for hop in announcements
            .iter()
            .filter(|hop| hop.to == *network && !skip.contains(&hop.node_pubkey))
        {
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

#[rustfmt::skip]
const ADJECTIVES: [&str; 256] = [
    "amber", "ancient", "autumn", "azure", "bitter", "black", "bold", "brave",
    "breezy", "bright", "brisk", "broken", "calm", "candid", "cedar", "chilly",
    "clear", "clever", "cloudy", "coastal", "cold", "cool", "copper", "coral",
    "cosmic", "crimson", "crisp", "curious", "damp", "dappled", "dark", "dawning",
    "deep", "dewy", "distant", "dreamy", "drifting", "dry", "dusky", "dusty",
    "eager", "early", "earthy", "east", "echoing", "elder", "empty", "faded",
    "fair", "falling", "fast", "feral", "fiery", "fleet", "floral", "foggy",
    "fragrant", "free", "fresh", "frosty", "gentle", "gilded", "glad", "gleaming",
    "glowing", "golden", "grand", "grassy", "gray", "green", "hallowed", "hazy",
    "hidden", "hollow", "honest", "humble", "hushed", "icy", "idle", "indigo",
    "ivory", "jade", "jolly", "keen", "kind", "lacy", "late", "lazy",
    "leafy", "light", "lilac", "little", "lively", "lone", "lonely", "long",
    "loud", "lucky", "lunar", "mellow", "merry", "midnight", "mild", "misty",
    "modest", "morning", "mossy", "muddy", "murky", "muted", "narrow", "nimble",
    "noble", "north", "odd", "olive", "opal", "pale", "patient", "peaceful",
    "pearl", "pine", "plain", "plucky", "polar", "proud", "purple", "quick",
    "quiet", "radiant", "rainy", "rapid", "rare", "restless", "rising", "robust",
    "rosy", "round", "royal", "ruby", "rugged", "russet", "rustic", "sacred",
    "salty", "sandy", "scarlet", "secret", "serene", "shady", "shaggy", "sharp",
    "shining", "shy", "silent", "silken", "silver", "simple", "sleepy", "slender",
    "slow", "small", "smoky", "smooth", "snowy", "soft", "solar", "solemn",
    "somber", "sonic", "south", "sparkling", "spring", "stark", "starry", "steady",
    "steep", "still", "stony", "stormy", "sturdy", "subtle", "summer", "sunny",
    "swift", "tall", "tame", "tawny", "tender", "thorny", "tidal", "tiny",
    "tranquil", "twilight", "urban", "velvet", "vernal", "violet", "vivid", "wandering",
    "warm", "wary", "watery", "wavy", "west", "whispering", "white", "wild",
    "windy", "winter", "wise", "wistful", "withered", "witty", "wooden", "woolly",
    "young", "zesty", "bashful", "blissful", "blooming", "blue", "bouncy", "brazen",
    "budding", "burly", "busy", "cheerful", "cozy", "dainty", "daring", "dazzling",
    "dizzy", "drowsy", "dutiful", "fancy", "fickle", "flinty", "fluffy", "fuzzy",
    "giddy", "glassy", "grumpy", "happy", "hardy", "jaunty", "jumpy", "knotty",
    "lanky", "lofty", "lush", "magic", "mighty", "nifty", "perky", "prickly",
];

#[rustfmt::skip]
const NOUNS: [&str; 256] = [
    "acorn", "alder", "anchor", "apple", "aspen", "aurora", "badger", "bamboo",
    "basin", "bay", "beacon", "bear", "bee", "beetle", "birch", "bird",
    "bison", "bloom", "blossom", "boulder", "brook", "breeze", "brush", "butterfly",
    "canyon", "cardinal", "cave", "cedar", "cherry", "cliff", "cloud", "clover",
    "comet", "coral", "cove", "crane", "creek", "cricket", "crow", "dawn",
    "deer", "delta", "dew", "dove", "dragonfly", "dune", "dusk", "eagle",
    "echo", "elm", "ember", "falcon", "fern", "field", "finch", "fir",
    "firefly", "flame", "flower", "fog", "forest", "fox", "frog", "frost",
    "gale", "garden", "glacier", "glade", "glen", "grove", "gull", "harbor",
    "hare", "hawk", "hazel", "heath", "hedge", "heron", "hill", "hollow",
    "horizon", "iris", "island", "ivy", "jay", "juniper", "kestrel", "lagoon",
    "lake", "lantern", "lark", "laurel", "leaf", "lily", "lotus", "lynx",
    "maple", "marsh", "meadow", "mesa", "mist", "moon", "moose", "moss",
    "moth", "mountain", "night", "oak", "ocean", "orchid", "otter", "owl",
    "palm", "peak", "pebble", "pine", "plain", "plum", "pond", "poppy",
    "prairie", "puffin", "quail", "rain", "raven", "reed", "reef", "ridge",
    "river", "robin", "rock", "rose", "sage", "salmon", "sand", "sea",
    "shadow", "shell", "shore", "sky", "slope", "snow", "sparrow", "spring",
    "spruce", "star", "stone", "storm", "stream", "summit", "sun", "swan",
    "thistle", "thorn", "thrush", "thunder", "tide", "tiger", "trail", "tree",
    "tulip", "valley", "violet", "vine", "wave", "willow", "wind", "wolf",
    "wren", "yew", "zephyr", "abyss", "arch", "arrow", "ash", "atlas",
    "autumn", "badland", "bark", "barley", "basil", "berry", "blaze", "bluff",
    "bramble", "breaker", "brine", "burrow", "cactus", "cairn", "canopy", "cascade",
    "cinder", "citrus", "clay", "cobble", "cocoa", "condor", "crag", "crest",
    "crystal", "current", "cypress", "daisy", "dale", "den", "dingo", "dolphin",
    "drift", "drizzle", "elk", "estuary", "fawn", "feather", "fjord", "flint",
    "flurry", "fountain", "gecko", "geyser", "ginger", "glimmer", "gorge", "granite",
    "grass", "grotto", "gust", "haze", "heather", "hemlock", "husk", "ibis",
    "inlet", "jasmine", "kelp", "knoll", "koi", "lichen", "linden", "loon",
    "magpie", "mango", "mantis", "marble", "mire", "monsoon", "nectar", "nettle",
    "newt", "oasis", "orbit", "osprey", "panda", "pansy", "pasture", "petal",
];

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
            test_money: false,
        }
    }

    fn route(graph: &[RouteAnnouncement], from: &str, to: &str) -> Result<Vec<u8>, String> {
        route_skipping(graph, from, to, &[])
    }

    fn route_skipping(
        graph: &[RouteAnnouncement],
        from: &str,
        to: &str,
        skip: &[u8],
    ) -> Result<Vec<u8>, String> {
        find_route(
            graph,
            &NetworkId(from.into()),
            &NetworkId(to.into()),
            1_000_000,
            &skip.iter().map(|node| XOnlyPubKey([*node; 32])).collect(),
        )
        .map(|hops| hops.iter().map(|hop| hop.node_pubkey.0[0]).collect())
    }

    #[test]
    fn announcements_round_trip_through_events() {
        let key = ritualistic::SecretKey::generate();
        for test_money in [false, true] {
            let announcement = RouteAnnouncement {
                node_pubkey: key.pubkey(),
                iroh_relay: Some("https://relay.example".into()),
                test_money,
                ..hop(0, "cashu::mint.example", "liquid::testnet", 10, 20)
            };
            let event = announcement.to_event_template().finalize(&key);
            assert_eq!(RouteAnnouncement::from_event(&event), Some(announcement));
        }
    }

    #[test]
    fn autoname_words_are_distinct() {
        for words in [&ADJECTIVES, &NOUNS] {
            let unique: HashSet<_> = words.iter().collect();
            assert_eq!(unique.len(), words.len());
        }
    }

    #[test]
    fn autoname_and_autohue_read_their_own_bytes() {
        let mut node = hop(0, "a", "b", 0, 0);
        assert_eq!(node.autoname(), "amber-acorn-amber-acorn");
        assert_eq!(node.autohue(), 0);
        node.node_pubkey.0[AUTONAME_BYTES].copy_from_slice(&[255, 1, 2, 255]);
        assert_eq!(node.autoname(), "prickly-alder-autumn-petal");
        assert_eq!(node.autohue(), 0);
        node.node_pubkey.0[AUTOHUE_BYTES].copy_from_slice(&[0xff, 0xff]);
        assert_eq!(node.autohue(), 359);
        assert_eq!(node.autoname(), "prickly-alder-autumn-petal");
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
    fn avoids_skipped_routers() {
        let graph = [
            hop(1, "a", "c", 0, 0),
            hop(2, "a", "b", 100, 0),
            hop(3, "b", "c", 100, 0),
        ];
        assert_eq!(route_skipping(&graph, "a", "c", &[1]).unwrap(), vec![2, 3]);
        assert!(route_skipping(&graph, "a", "c", &[1, 3]).is_err());
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

    /// fedimint -> router -> cashu -> router -> arkade, with the default
    /// margins and no transit slack: each hop adds the margin of its
    /// incoming network, so the payer's HTLC expires last.
    #[test]
    fn expiries_grow_by_each_incoming_margin() {
        let id = |spec: &str| NetworkId(spec.into());
        let (fedimint, cashu, arkade) = (id("fedimint::fed1q"), id("cashu::mint"), id("arkade"));
        let announce = |from: &NetworkId, to: &NetworkId| RouteAnnouncement {
            incoming_delta_secs: from.default_incoming_delta(),
            transit_slack_secs: 0,
            ..hop(1, &from.0, &to.0, 0, 0)
        };
        let route = [announce(&fedimint, &cashu), announce(&cashu, &arkade)];
        let plan = plan_route(&route, 1_000, arkade.default_incoming_delta(), 0).unwrap();
        // The payee's leg also gets one default slack, for COMMIT.
        let payee = 20 * 60 + DEFAULT_TRANSIT_SLACK_SECS;
        assert_eq!(
            plan.expiries,
            vec![payee + (5 + 40) * 60, payee + 5 * 60, payee]
        );
    }
}
