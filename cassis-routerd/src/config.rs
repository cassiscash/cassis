//! `<data dir>/config.toml`: everything the router does. Written with a
//! fresh mnemonic and no routes on first start, then only read.
//!
//! ```toml
//! mnemonic = "twelve words ..."    # every key derives from it, unless set below
//! # iroh_secret = "<hex>"          # identity of the cassis-hop endpoint
//! # nostr_secret = "nsec1..."      # node key: signs route announcements
//! nostr_relays = ["wss://nostr.wine"]  # for routes that name none
//! test_money = false               # default of every route
//!
//! [networks."cashu::mint.example"]
//! # secret = "<hex>"               # wallet key on this network
//! # max_incoming_lifetime_secs = 3600
//! # maintenance = false            # skip the wallet's upkeep
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
//! # nostr_relays = ["wss://relay.example"]
//! # test_money = true
//! ```

use cassis_core::keys::{generate_mnemonic, NodeKeys};
use cassis_core::node::{RouteOffer, RoutingPolicy};
use cassis_core::routing::{DEFAULT_NOSTR_RELAYS, DEFAULT_TRANSIT_SLACK_SECS, TEST_NOSTR_RELAYS};
use cassis_core::NetworkId;
use cassis_networks::NetworkSettings;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub const FILE: &str = "config.toml";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub mnemonic: String,
    /// Hex secret of the iroh endpoint, instead of the mnemonic's.
    pub iroh_secret: Option<String>,
    /// Node key (`nsec1...` or hex), instead of the mnemonic's.
    pub nostr_secret: Option<String>,
    /// Relays of routes that name none; the test relays when
    /// `test_money` and unset, else the default ones.
    pub nostr_relays: Option<Vec<String>>,
    #[serde(default)]
    pub test_money: bool,
    #[serde(default = "default_max_reservations")]
    pub max_reservations: usize,
    #[serde(default)]
    pub networks: BTreeMap<String, NetworkConfig>,
    #[serde(default)]
    pub routes: Vec<RouteConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    /// Hex wallet key on this network, instead of the mnemonic's.
    pub secret: Option<String>,
    pub max_incoming_lifetime_secs: Option<u64>,
    /// Chain API of `arkade` and `bitcoin`, instead of the public one.
    pub esplora_url: Option<String>,
    /// Run the wallet's upkeep (e.g. refreshing arkade VTXOs).
    #[serde(default = "yes")]
    pub maintenance: bool,
    /// The LND node of a `lightning` network.
    pub lnd: Option<LndConfig>,
    /// The Ark server of a `lightning` network going through bark.
    pub bark: Option<BarkConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(not(feature = "lightning"), allow(dead_code))]
pub struct LndConfig {
    pub rest_url: String,
    pub tls_cert_path: Option<PathBuf>,
    pub macaroon_path: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(not(feature = "bark-lightning"), allow(dead_code))]
pub struct BarkConfig {
    /// Second's server for mainnet and signet when unset.
    pub server_url: Option<String>,
    pub esplora_url: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    pub from: String,
    pub to: String,
    pub fee_base_msat: u64,
    pub fee_ppm: u64,
    #[serde(default = "default_transit_slack")]
    pub transit_slack_secs: u64,
    pub nostr_relays: Option<Vec<String>>,
    pub test_money: Option<bool>,
}

fn default_max_reservations() -> usize {
    RoutingPolicy::default().max_reservations
}

fn default_transit_slack() -> u64 {
    DEFAULT_TRANSIT_SLACK_SECS
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
        let text =
            std::fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let config: Self = toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        config.check()?;
        Ok(config)
    }

    fn check(&self) -> Result<(), String> {
        let networks = self.network_ids()?;
        for route in &self.routes {
            let (from, to) = (NetworkId::parse(&route.from)?, NetworkId::parse(&route.to)?);
            if from == to {
                return Err(format!("route {from} -> {to} goes nowhere"));
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

    /// Relays of routes that name none.
    pub fn default_relays(&self) -> Vec<String> {
        self.nostr_relays.clone().unwrap_or_else(|| {
            let relays = if self.test_money {
                TEST_NOSTR_RELAYS
            } else {
                DEFAULT_NOSTR_RELAYS
            };
            relays.iter().map(|relay| relay.to_string()).collect()
        })
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
                    nostr_relays: route
                        .nostr_relays
                        .clone()
                        .unwrap_or_else(|| self.default_relays()),
                    test_money: route.test_money.unwrap_or(self.test_money),
                })
            })
            .collect::<Result<_, String>>()?;
        Ok(RoutingPolicy {
            routes,
            cleanup_relays: self.default_relays(),
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
            max_incoming_lifetime_secs: config.max_incoming_lifetime_secs,
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
        r#"# cassis-routerd config. Every key derives from the mnemonic unless
# overridden here: back it up, it controls the router's funds.
mnemonic = "{mnemonic}"
# iroh_secret = "<64 hex>"
# nostr_secret = "nsec1..."

# Relays of routes that name none (default: wss://nostr.wine, or the
# test relays with test_money). The router also deletes its stale
# announcements from them.
# nostr_relays = ["wss://nostr.wine"]
# test_money = false

# One table per network to open, e.g.:
# [networks."cashu::mint.example"]
# [networks.arkade]
# [networks.lightning]
# lnd = {{ rest_url = "https://127.0.0.1:8080", tls_cert_path = "/path/tls.cert", macaroon_path = "/path/admin.macaroon" }}

# One entry per hop to offer and announce, e.g.:
# [[routes]]
# from = "cashu::mint.example"
# to = "arkade"
# fee_base_msat = 1000
# fee_ppm = 500
"#,
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
