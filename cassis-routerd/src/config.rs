//! `<data dir>/config.toml`: everything the router does. Written with a
//! fresh mnemonic and no routes on first start, then read, and edited by
//! the admin interface through [`edit`], which keeps its comments.
//!
//! ```toml
//! mnemonic = "twelve words ..."    # identity keys derive from it, unless set below
//! # iroh_secret = "<hex>"          # identity of the cassis-hop endpoint
//! # nostr_secret = "nsec1..."      # node key: signs route announcements
//! # name = "My router"             # published as its profile; else its autoname
//! nostr_relays = ["wss://nostr.wine"]  # where routes are announced
//!
//! [networks."cashu::mint.example"]
//! secret = "<hex>"                 # wallet key on this network, written when added
//!
//! [networks.lightning]
//! secret = "<hex>"
//! lnd = { rest_url = "https://127.0.0.1:8080", tls_cert_path = "...", macaroon_path = "..." }
//! # or: bark = {}                  # Second's server, or { server_url, esplora_url }
//!
//! [[routes]]
//! from = "cashu::mint.example"
//! to = "lightning"
//! fee_base_msat = 1000             # on top of what claiming on `from` costs
//! fee_ppm = 500
//! # transit_slack_secs = 60
//! # test_money = true
//!
//! [admin]
//! # listen = "127.0.0.1:7979"      # open admin page over HTTP; "" turns it off
//! # iroh = true                    # admin page over iroh, for `peers`
//! # peers = ["<64 hex>"]           # iroh keys of renderers let in
//! ```

use cassis_admin::config::write_private;
pub use cassis_admin::AdminConfig;
use cassis_core::keys::{generate_mnemonic, NodeKeys};
use cassis_core::routing::{DEFAULT_NOSTR_RELAYS, DEFAULT_TRANSIT_SLACK_SECS};
use cassis_core::NetworkId;
use cassis_routerd::router::{RouteOffer, RoutingPolicy};
use cassis_wallet::config::parse_secret;
pub use cassis_wallet::config::NetworkConfig;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;
use toml_edit::DocumentMut;

pub const FILE: &str = "config.toml";

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub mnemonic: String,
    /// Hex secret of the iroh endpoint, instead of the mnemonic's.
    pub iroh_secret: Option<String>,
    /// Node key (`nsec1...` or hex), instead of the mnemonic's.
    pub nostr_secret: Option<String>,
    /// Published as the router's profile name; without it, payers and
    /// explorers show its autoname.
    pub name: Option<String>,
    /// Relays every route is announced on.
    #[serde(default = "default_relays")]
    pub nostr_relays: Vec<String>,
    #[serde(default = "default_max_reservations")]
    pub max_reservations: usize,
    /// Longest an incoming HTLC may run from its PREPARE.
    #[serde(default = "default_max_htlc_secs")]
    pub max_htlc_secs: u64,
    #[serde(default)]
    pub networks: BTreeMap<String, NetworkConfig>,
    #[serde(default)]
    pub routes: Vec<RouteConfig>,
    #[serde(default)]
    pub admin: AdminConfig,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    pub from: String,
    pub to: String,
    pub fee_base_msat: u64,
    pub fee_ppm: u64,
    #[serde(default = "default_transit_slack")]
    pub transit_slack_secs: u64,
    /// Mark the route's announcement as test money.
    #[serde(default)]
    pub test_money: bool,
}

fn default_max_reservations() -> usize {
    RoutingPolicy::default().max_reservations
}

fn default_max_htlc_secs() -> u64 {
    RoutingPolicy::default().max_htlc_secs
}

fn default_transit_slack() -> u64 {
    DEFAULT_TRANSIT_SLACK_SECS
}

fn default_relays() -> Vec<String> {
    DEFAULT_NOSTR_RELAYS
        .iter()
        .map(|relay| relay.to_string())
        .collect()
}

impl Config {
    /// Read `<dir>/config.toml`, writing a fresh one first if there is
    /// none.
    pub fn load_or_create(dir: &Path) -> Result<Self, String> {
        let path = dir.join(FILE);
        if !path.exists() {
            write_new(&path)?;
            tracing::warn!(
                "wrote a new config to {}: back up its mnemonic, then add networks and routes",
                path.display()
            );
        }
        warn_if_readable_by_others(&path);
        Self::load(dir)
    }

    /// Read `<dir>/config.toml`.
    pub fn load(dir: &Path) -> Result<Self, String> {
        let path = dir.join(FILE);
        let text =
            std::fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
        Self::parse(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    fn parse(text: &str) -> Result<Self, String> {
        let config: Self = toml::from_str(text).map_err(|e| e.to_string())?;
        config.check()?;
        Ok(config)
    }

    fn check(&self) -> Result<(), String> {
        self.keys()?;
        self.admin.listen_addr()?;
        if self.nostr_relays.is_empty() {
            return Err("nostr_relays: routes need a relay to be announced on".into());
        }
        for (at, relay) in self.nostr_relays.iter().enumerate() {
            if !(relay.starts_with("wss://") || relay.starts_with("ws://")) {
                return Err(format!("nostr_relays {relay}: expected a wss:// URL"));
            }
            if self.nostr_relays[..at].contains(relay) {
                return Err(format!("nostr_relays {relay}: listed twice"));
            }
        }
        for peer in &self.admin.peers {
            parse_secret(peer).map_err(|e| format!("admin.peers {peer}: {e}"))?;
        }
        let networks = self.network_ids()?;
        for route in &self.routes {
            let (from, to) = (NetworkId::parse(&route.from)?, NetworkId::parse(&route.to)?);
            if from == to {
                return Err(format!("route {from} -> {to} goes nowhere"));
            }
            let same = self.routes.iter().filter(|other| {
                (other.from.as_str(), other.to.as_str()) == (route.from.as_str(), route.to.as_str())
            });
            if same.count() > 1 {
                return Err(format!("route {from} -> {to} is listed twice"));
            }
            for end in [&from, &to] {
                if !networks.contains(end) {
                    return Err(format!(
                        "route {from} -> {to}: {end} is not under [networks]"
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn network_ids(&self) -> Result<Vec<NetworkId>, String> {
        self.networks
            .keys()
            .map(|spec| NetworkId::parse(spec))
            .collect()
    }

    pub fn keys(&self) -> Result<NodeKeys, String> {
        let mut keys = NodeKeys::from_mnemonic(&self.mnemonic).map_err(|e| e.to_string())?;
        if let Some(hex) = &self.iroh_secret {
            keys.iroh = parse_secret(hex).map_err(|e| format!("iroh_secret: {e}"))?;
        }
        if let Some(secret) = &self.nostr_secret {
            keys.node = secret.parse().map_err(|e| format!("nostr_secret: {e:?}"))?;
        }
        Ok(keys)
    }

    pub fn routing_policy(&self) -> Result<RoutingPolicy, String> {
        let routes = self
            .routes
            .iter()
            .map(|route| {
                Ok(RouteOffer {
                    from: NetworkId::parse(&route.from)?,
                    to: NetworkId::parse(&route.to)?,
                    fee_base_msat: route.fee_base_msat,
                    fee_ppm: route.fee_ppm,
                    transit_slack_secs: route.transit_slack_secs,
                    nostr_relays: self.nostr_relays.clone(),
                    test_money: route.test_money,
                })
            })
            .collect::<Result<_, String>>()?;
        Ok(RoutingPolicy {
            routes,
            cleanup_relays: self.nostr_relays.clone(),
            max_reservations: self.max_reservations,
            max_htlc_secs: self.max_htlc_secs,
            ..RoutingPolicy::default()
        })
    }
}

/// Apply `change` to `<dir>/config.toml` as it is on disk now, keeping
/// its comments and layout, and write it back if the result is a valid
/// config, which is returned.
pub fn edit(
    dir: &Path,
    change: impl FnOnce(&mut DocumentMut) -> Result<(), String>,
) -> Result<Config, String> {
    let path = dir.join(FILE);
    let text =
        std::fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let mut doc: DocumentMut = text
        .parse()
        .map_err(|e| format!("{}: {e}", path.display()))?;
    change(&mut doc)?;
    let text = doc.to_string();
    let config = Config::parse(&text)?;
    write_private(&path, &text)?;
    Ok(config)
}

/// A config with a fresh mnemonic and nothing to route yet, readable by
/// its owner only.
fn write_new(path: &Path) -> Result<(), String> {
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(path)
        .map_err(|e| format!("create {}: {e}", path.display()))?;
    let template = format!(
        r#"# cassis-routerd config, also edited by the admin interface, which
# keeps comments. The router's identity derives from the mnemonic below
# unless overridden, and every network has a key of its own, written
# when it is added: back this file up, it controls the router's funds.
#
# iroh_secret = "<64 hex>"
# nostr_secret = "nsec1..."
#
# The name published as the router's profile (else it goes by the
# autoname derived from its key):
# name = "My router"
#
# One table per network to open, with its wallet key, e.g.:
# [networks."cashu::mint.example"]
# secret = "<64 hex>"
# [networks.lightning]
# secret = "<64 hex>"
# lnd = {{ rest_url = "https://127.0.0.1:8080", tls_cert_path = "/path/tls.cert", macaroon_path = "/path/admin.macaroon" }}
#
# One entry per hop to offer and announce, e.g.:
# [[routes]]
# from = "cashu::mint.example"
# to = "arkade"
# fee_base_msat = 1000
# fee_ppm = 500
# test_money = true
#
# The admin interface: open over HTTP on loopback, and over iroh to the
# renderers listed in peers (or paired with the link printed on start).
# [admin]
# listen = "127.0.0.1:7979"
# iroh = true
# peers = []

# Relays every route is announced on.
nostr_relays = [{relays}]
mnemonic = "{mnemonic}"
"#,
        relays = DEFAULT_NOSTR_RELAYS
            .iter()
            .map(|relay| format!("{relay:?}"))
            .collect::<Vec<_>>()
            .join(", "),
        mnemonic = generate_mnemonic()
    );
    file.write_all(template.as_bytes())
        .map_err(|e| format!("write {}: {e}", path.display()))
}

fn warn_if_readable_by_others(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = std::fs::metadata(path) {
            if metadata.permissions().mode() & 0o077 != 0 {
                tracing::warn!(
                    "{} holds secrets but others can read it: chmod 600 it",
                    path.display()
                );
            }
        }
    }
}
