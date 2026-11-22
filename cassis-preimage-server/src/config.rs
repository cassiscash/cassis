//! `<dir>/config.toml`: what the server does, written with nothing in it
//! on first start, then read, and followed as it changes. The admin
//! interface edits its admin section, keeping comments; its networks are
//! edited by hand. Its keys stay in `<dir>/seed`.
//!
//! ```toml
//! [networks."cashu::mint.example"]
//! [networks.arkade]
//! # esplora_url = "https://..."    # chain API of arkade and bitcoin
//!
//! [admin]
//! # listen = "127.0.0.1:7981"      # open admin page over HTTP; "" turns it off
//! # iroh = true                    # admin page over iroh, for `peers`
//! # peers = ["<64 hex>"]           # iroh keys of renderers let in
//! ```

use cassis_admin::config::put;
use cassis_admin::networks::NetworkConfig;
use cassis_admin::{AdminSection, ConfigFile, DaemonConfig};
use cassis_core::keys::generate_mnemonic;
use cassis_core::NetworkId;
use serde::Deserialize;
use std::collections::BTreeMap;

/// Where the admin page listens by default, next to a router's and a
/// gateway's.
pub const DEFAULT_LISTEN: &str = "127.0.0.1:7981";

pub const TEMPLATE: &str = r#"# cassis-preimage-server config, followed as it changes. The admin interface
# edits the admin section, keeping comments. Its keys are in the seed file.

# One table per network to verify HTLCs to payees on, e.g.:
# [networks."cashu::mint.example"]
# [networks.arkade]
# esplora_url = "https://..."
[networks]

# The admin interface: open over HTTP on loopback, and over iroh to the
# renderers listed in peers (or paired with the link printed on start):
# listen = "127.0.0.1:7981"
# iroh = true
# peers = []
[admin]
"#;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub networks: BTreeMap<String, NetworkConfig>,
    #[serde(default)]
    pub admin: AdminSection,
}

impl DaemonConfig for Config {
    fn check(&self) -> Result<(), String> {
        self.admin.resolve(DEFAULT_LISTEN).check()?;
        for id in self.networks.keys() {
            NetworkId::parse(id)?;
        }
        Ok(())
    }
}

/// Write a fresh mnemonic to every network of `file` that has none.
pub fn fill_mnemonics(file: &ConfigFile<Config>) -> Result<(), String> {
    if file
        .get()
        .networks
        .values()
        .all(|network| network.mnemonic.is_some())
    {
        return Ok(());
    }
    file.edit(|doc| {
        let Some(networks) = doc
            .get_mut("networks")
            .and_then(|networks| networks.as_table_like_mut())
        else {
            return Ok(());
        };
        for (id, network) in networks.iter_mut() {
            let Some(network) = network.as_table_like_mut() else {
                continue;
            };
            if !network.contains_key("mnemonic") {
                put(network, "mnemonic", Some(generate_mnemonic().into()));
                tracing::info!("gave {} a fresh mnemonic", id.get());
            }
        }
        Ok(())
    })
}
