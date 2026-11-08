//! `<dir>/config.toml`: what the server does, written with nothing in it
//! on first start, then read, and edited by the admin interface, which
//! applies changes right away and keeps comments. Its keys stay in
//! `<dir>/seed`.
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

use cassis_admin::networks::NetworkConfig;
use cassis_admin::{AdminSection, DaemonConfig};
use cassis_core::NetworkId;
use serde::Deserialize;
use std::collections::BTreeMap;

/// Where the admin page listens by default, next to a router's and a
/// gateway's.
pub const DEFAULT_LISTEN: &str = "127.0.0.1:7981";

pub const TEMPLATE: &str = r#"# cassis-preimage-server config, also edited by the admin interface, which
# keeps comments and applies changes right away. Its keys are in the seed file.

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
