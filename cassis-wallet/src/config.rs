//! `<home>/config.toml`: the wallet's keys and its networks. Written with
//! a fresh mnemonic and no networks on first use, then edited by
//! `enable` and `disable`, which keep its comments.
//!
//! ```toml
//! mnemonic = "twelve words ..."    # the node's identity keys derive from it
//!
//! [networks."cashu::mint.example"]
//! secret = "<64 hex>"              # wallet key on this network
//!
//! [networks.arkade]
//! secret = "<64 hex>"
//! # esplora_url = "https://..."    # chain API of arkade and bitcoin
//!
//! [networks.lightning]
//! lnd = { rest_url = "https://127.0.0.1:8080", tls_cert_path = "...", macaroon_path = "..." }
//! # or: bark = {}                  # Second's server, or { server_url, esplora_url }
//! ```
//!
//! Every network has a key of its own, written when it is enabled:
//! nothing derives it, so back this file up.

use cassis_core::keys::{generate_mnemonic, new_network_secret, NodeKeys};
use cassis_core::NetworkId;
use cassis_networks::NetworkSettings;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use toml_edit::DocumentMut;

pub const FILE: &str = "config.toml";

/// The wallet's part of a config: a router's or a gateway's has more,
/// which the wallet leaves alone.
#[derive(Clone, Deserialize)]
pub struct WalletConfig {
    pub mnemonic: String,
    #[serde(default)]
    pub networks: BTreeMap<String, NetworkConfig>,
}

/// How to open one network.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    /// Hex wallet key on this network (see [`new_secret`]).
    pub secret: Option<String>,
    /// Chain API of `arkade` and `bitcoin`, instead of the public one.
    pub esplora_url: Option<String>,
    /// The LND node of a `lightning` network.
    pub lnd: Option<LndConfig>,
    /// The Ark server of a `lightning` network going through bark.
    pub bark: Option<BarkConfig>,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(not(feature = "lightning"), allow(dead_code))]
pub struct LndConfig {
    pub rest_url: String,
    pub tls_cert_path: Option<PathBuf>,
    pub macaroon_path: Option<PathBuf>,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(not(feature = "bark-lightning"), allow(dead_code))]
pub struct BarkConfig {
    /// Second's server for mainnet and signet when unset.
    pub server_url: Option<String>,
    pub esplora_url: Option<String>,
}

impl WalletConfig {
    /// Read `<dir>/config.toml`, writing a fresh one first if there is
    /// none.
    pub fn load_or_create(dir: &Path) -> Result<Self, String> {
        let path = dir.join(FILE);
        if !path.exists() {
            write_private(&path, &template(&generate_mnemonic()))?;
            eprintln!(
                "wrote a new config to {}: back it up, it holds every key of this wallet",
                path.display()
            );
        }
        Self::load(dir)
    }

    pub fn load(dir: &Path) -> Result<Self, String> {
        let path = dir.join(FILE);
        let text =
            std::fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
        Self::parse(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    fn parse(text: &str) -> Result<Self, String> {
        let config: Self = toml::from_str(text).map_err(|e| e.to_string())?;
        config.keys()?;
        config.network_ids()?;
        Ok(config)
    }

    pub fn keys(&self) -> Result<NodeKeys, String> {
        NodeKeys::from_mnemonic(&self.mnemonic).map_err(|e| e.to_string())
    }

    pub fn network_ids(&self) -> Result<Vec<NetworkId>, String> {
        self.networks
            .keys()
            .map(|spec| NetworkId::parse(spec))
            .collect()
    }

    pub fn network(&self, network: &NetworkId) -> Result<&NetworkConfig, String> {
        self.networks
            .get(&network.0)
            .ok_or_else(|| format!("{network} is not enabled; see `cassis-wallet enable`"))
    }
}

impl NetworkConfig {
    /// The wallet key on `network`.
    pub fn secret(&self, network: &NetworkId) -> Result<[u8; 32], String> {
        let hex = self
            .secret
            .as_deref()
            .ok_or_else(|| format!("networks.\"{network}\" has no secret"))?;
        parse_secret(hex).map_err(|e| format!("{network} secret: {e}"))
    }

    /// What opening `network` takes, its wallet kept under `dir`.
    #[allow(unused_variables)]
    pub fn settings(&self, network: &NetworkId, dir: &Path) -> Result<NetworkSettings, String> {
        let secret = self.secret(network)?;
        #[cfg(not(feature = "lightning"))]
        if self.lnd.is_some() {
            return Err(format!("{network}: this build has no LND support"));
        }
        #[cfg(not(feature = "bark-lightning"))]
        if self.bark.is_some() {
            return Err(format!("{network}: this build has no bark support"));
        }
        #[cfg(feature = "bark-lightning")]
        let bark = match &self.bark {
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
            esplora_url: self.esplora_url.clone(),
            #[cfg(feature = "lightning")]
            lnd: self.lnd.as_ref().map(|lnd| {
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

/// A fresh wallet key, as hex (see [`new_network_secret`]).
pub fn new_secret() -> String {
    lowercase_hex::encode(new_network_secret())
}

pub fn parse_secret(hex: &str) -> Result<[u8; 32], String> {
    let mut bytes = [0u8; 32];
    lowercase_hex::decode_to_slice(hex.trim(), &mut bytes)
        .map_err(|e| format!("expected 64 hex characters: {e}"))?;
    Ok(bytes)
}

/// Apply `change` to `<dir>/config.toml` as it is on disk now, keeping
/// its comments and layout, and write it back if the result is a valid
/// config, which is returned.
pub fn edit(
    dir: &Path,
    change: impl FnOnce(&mut DocumentMut) -> Result<(), String>,
) -> Result<WalletConfig, String> {
    let path = dir.join(FILE);
    let text =
        std::fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let mut doc: DocumentMut = text
        .parse()
        .map_err(|e| format!("{}: {e}", path.display()))?;
    change(&mut doc)?;
    let text = doc.to_string();
    let config = WalletConfig::parse(&text)?;
    write_private(&path, &text)?;
    Ok(config)
}

/// The table of `network` in `doc`, made with a fresh secret if
/// missing.
pub fn network_table<'a>(
    doc: &'a mut DocumentMut,
    network: &NetworkId,
) -> Result<&'a mut toml_edit::Table, String> {
    let networks = doc
        .entry("networks")
        .or_insert_with(|| {
            let mut table = toml_edit::Table::new();
            table.set_implicit(true);
            toml_edit::Item::Table(table)
        })
        .as_table_mut()
        .ok_or("networks is not a table")?;
    let table = networks
        .entry(&network.0)
        .or_insert_with(toml_edit::table)
        .as_table_mut()
        .ok_or_else(|| format!("networks.\"{network}\" is not a table"))?;
    if !table.contains_key("secret") {
        table.insert("secret", toml_edit::value(new_secret()));
    }
    Ok(table)
}

/// Write `text` to `path`, readable by its owner only.
pub fn write_private(path: &Path, text: &str) -> Result<(), String> {
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let temporary = path.with_extension("toml.tmp");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(&temporary)
        .map_err(|e| format!("create {}: {e}", temporary.display()))?;
    file.write_all(text.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("write {}: {e}", temporary.display()))?;
    std::fs::rename(&temporary, path).map_err(|e| format!("write {}: {e}", path.display()))
}

fn template(mnemonic: &str) -> String {
    format!(
        r#"# cassis-wallet config, also edited by `enable` and `disable`, which
# keep comments. The node's identity derives from the mnemonic; every
# network has a key of its own below. Back this file up: it controls
# the wallet's funds.
mnemonic = "{mnemonic}"

# One table per network, with its wallet key, e.g.:
# [networks."cashu::mint.example"]
# secret = "<64 hex>"
# [networks.arkade]
# secret = "<64 hex>"
# esplora_url = "https://..."
# [networks.lightning]
# secret = "<64 hex>"
# lnd = {{ rest_url = "https://127.0.0.1:8080", tls_cert_path = "/path/tls.cert", macaroon_path = "/path/admin.macaroon" }}
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enabling_writes_a_secret_once() {
        let mut doc: DocumentMut = template(&generate_mnemonic()).parse().unwrap();
        let network = NetworkId::parse("arkade").unwrap();
        let secret = network_table(&mut doc, &network).unwrap()["secret"]
            .as_str()
            .unwrap()
            .to_string();
        network_table(&mut doc, &network).unwrap();
        let config = WalletConfig::parse(&doc.to_string()).unwrap();
        let entry = config.network(&network).unwrap();
        assert_eq!(entry.secret.as_deref(), Some(secret.as_str()));
        assert_eq!(
            entry.secret(&network).unwrap(),
            parse_secret(&secret).unwrap()
        );
    }
}
