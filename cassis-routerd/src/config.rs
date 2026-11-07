//! `<data dir>/config.toml`: everything the router does. Written with a
//! fresh mnemonic and no routes on first start, then read, and edited by
//! the admin interface through [`edit`], which keeps its comments.
//!
//! ```toml
//! mnemonic = "twelve words ..."    # every key derives from it, unless set below
//! # iroh_secret = "<hex>"          # identity of the cassis-hop endpoint
//! # nostr_secret = "nsec1..."      # node key: signs route announcements
//! # name = "My router"             # published as its profile; else its autoname
//! nostr_relays = ["wss://nostr.wine"]  # where routes are announced
//!
//! [networks."cashu::mint.example"]
//! # secret = "<hex>"               # wallet key on this network
//!
//! [networks.lightning]
//! lnd = { rest_url = "https://127.0.0.1:8080", tls_cert_path = "...", macaroon_path = "..." }
//! # or: bark = {}                  # Second's server, or { server_url, esplora_url }
//!
//! [[routes]]
//! from = "cashu::mint.example"
//! to = "lightning"
//! fee_base_msat = 1000
//! fee_ppm = 500
//! # transit_slack_secs = 60
//! # max_incoming_lifetime_secs = 3600  # below what the `from` network allows
//! # test_money = true
//!
//! [admin]
//! # listen = "127.0.0.1:7979"      # open admin page over HTTP; "" turns it off
//! # iroh = true                    # admin page over iroh, for `peers`
//! # peers = ["<64 hex>"]           # iroh keys of renderers let in
//! ```

use cassis_core::keys::{generate_mnemonic, NodeKeys};
use cassis_core::node::{RouteOffer, RoutingPolicy};
use cassis_core::routing::{DEFAULT_NOSTR_RELAYS, DEFAULT_TRANSIT_SLACK_SECS};
use cassis_core::NetworkId;
use cassis_networks::NetworkSettings;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use toml_edit::DocumentMut;

pub const FILE: &str = "config.toml";
pub const DEFAULT_ADMIN_LISTEN: &str = "127.0.0.1:7979";

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
    #[serde(default)]
    pub networks: BTreeMap<String, NetworkConfig>,
    #[serde(default)]
    pub routes: Vec<RouteConfig>,
    #[serde(default)]
    pub admin: AdminConfig,
}

#[derive(Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminConfig {
    /// Loopback address of the admin page over HTTP, open to anyone on
    /// this machine; empty turns it off.
    #[serde(default = "default_admin_listen")]
    pub listen: String,
    /// Serve the admin page over iroh, to `peers` only.
    #[serde(default = "yes")]
    pub iroh: bool,
    /// Hex iroh keys of the renderers let in over iroh.
    #[serde(default)]
    pub peers: Vec<String>,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            listen: default_admin_listen(),
            iroh: true,
            peers: Vec::new(),
        }
    }
}

impl AdminConfig {
    pub fn listen_addr(&self) -> Result<Option<SocketAddr>, String> {
        if self.listen.is_empty() {
            return Ok(None);
        }
        let addr: SocketAddr = self
            .listen
            .parse()
            .map_err(|e| format!("admin.listen {}: {e}", self.listen))?;
        if !addr.ip().is_loopback() {
            return Err(format!(
                "admin.listen {addr}: the HTTP admin page is open, so it only listens on loopback"
            ));
        }
        Ok(Some(addr))
    }
}

#[derive(Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    /// Hex wallet key on this network, instead of the mnemonic's.
    pub secret: Option<String>,
    /// Chain API of `arkade` and `bitcoin`, instead of the public one.
    pub esplora_url: Option<String>,
    /// The LND node of a `lightning` network.
    pub lnd: Option<LndConfig>,
    /// The Ark server of a `lightning` network going through bark.
    pub bark: Option<BarkConfig>,
}

#[derive(Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(not(feature = "lightning"), allow(dead_code))]
pub struct LndConfig {
    pub rest_url: String,
    pub tls_cert_path: Option<PathBuf>,
    pub macaroon_path: Option<PathBuf>,
}

#[derive(Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(not(feature = "bark-lightning"), allow(dead_code))]
pub struct BarkConfig {
    /// Second's server for mainnet and signet when unset.
    pub server_url: Option<String>,
    pub esplora_url: Option<String>,
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
    /// Longest an incoming HTLC may run, when shorter than what the
    /// `from` network allows.
    pub max_incoming_lifetime_secs: Option<u64>,
    /// Mark the route's announcement as test money.
    #[serde(default)]
    pub test_money: bool,
}

fn default_max_reservations() -> usize {
    RoutingPolicy::default().max_reservations
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

fn default_admin_listen() -> String {
    DEFAULT_ADMIN_LISTEN.to_string()
}

fn yes() -> bool {
    true
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
                    max_incoming_lifetime_secs: route.max_incoming_lifetime_secs,
                    test_money: route.test_money,
                })
            })
            .collect::<Result<_, String>>()?;
        Ok(RoutingPolicy {
            routes,
            cleanup_relays: self.nostr_relays.clone(),
            max_reservations: self.max_reservations,
            ..RoutingPolicy::default()
        })
    }

    /// What opening `network` takes, its wallet kept under `dir`.
    #[allow(unused_variables)]
    pub fn network_settings(
        &self,
        network: &NetworkId,
        keys: &NodeKeys,
        dir: &Path,
    ) -> Result<NetworkSettings, String> {
        let config = &self.networks[&network.to_string()];
        let secret = match &config.secret {
            Some(hex) => parse_secret(hex).map_err(|e| format!("{network} secret: {e}"))?,
            None => keys.network_secret(network),
        };
        #[cfg(not(feature = "lightning"))]
        if config.lnd.is_some() {
            return Err(format!("{network}: this build has no LND support"));
        }
        #[cfg(not(feature = "bark-lightning"))]
        if config.bark.is_some() {
            return Err(format!("{network}: this build has no bark support"));
        }
        #[cfg(feature = "bark-lightning")]
        let bark = match &config.bark {
            None => None,
            Some(bark) => {
                let default = cassis_networks::bark_lightning::BarkConfig::default_for(network);
                Some(cassis_networks::bark_lightning::BarkConfig {
                    server_url: bark
                        .server_url
                        .clone()
                        .or_else(|| default.as_ref().map(|d| d.server_url.clone()))
                        .ok_or_else(|| format!("{network} has no default Ark server"))?,
                    esplora_url: bark
                        .esplora_url
                        .clone()
                        .or_else(|| default.as_ref().map(|d| d.esplora_url.clone()))
                        .ok_or_else(|| format!("{network} has no default Esplora"))?,
                })
            }
        };
        Ok(NetworkSettings {
            secret,
            dir: cassis_networks::network_dir(dir, network),
            max_incoming_lifetime_secs: None,
            esplora_url: config.esplora_url.clone(),
            #[cfg(feature = "lightning")]
            lnd: config.lnd.as_ref().map(|lnd| {
                cassis_networks::lnd::LndConfig::new(
                    lnd.rest_url.clone(),
                    lnd.tls_cert_path.clone(),
                    lnd.macaroon_path.clone(),
                )
            }),
            #[cfg(feature = "bark-lightning")]
            bark,
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

/// Replace `path` with `text` at once, readable by its owner only.
fn write_private(path: &Path, text: &str) -> Result<(), String> {
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension("toml.tmp");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(&tmp)
        .map_err(|e| format!("create {}: {e}", tmp.display()))?;
    file.write_all(text.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("replace {}: {e}", path.display()))
}

fn parse_secret(hex: &str) -> Result<[u8; 32], String> {
    let mut bytes = [0u8; 32];
    lowercase_hex::decode_to_slice(hex.trim(), &mut bytes)
        .map_err(|e| format!("expected 64 hex characters: {e}"))?;
    Ok(bytes)
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
# keeps comments. Every key derives from the mnemonic below unless
# overridden: back it up, it controls the router's funds.
#
# iroh_secret = "<64 hex>"
# nostr_secret = "nsec1..."
#
# The name published as the router's profile (else it goes by the
# autoname derived from its key):
# name = "My router"
#
# One table per network to open, e.g.:
# [networks."cashu::mint.example"]
# [networks.arkade]
# [networks.lightning]
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
