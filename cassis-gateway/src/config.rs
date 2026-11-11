//! `<dir>/config.toml`: what the gateway does, written with a fresh
//! mnemonic and nothing else on first start, then read, and edited by
//! the admin interface, which applies changes right away and keeps
//! comments. It is also a wallet config (see [`cassis_wallet::config`]),
//! so `cassis-wallet --home <dir>` manages the gateway's funds.
//!
//! ```toml
//! mnemonic = "twelve words ..."    # the gateway's identity derives from it
//!
//! [networks."cashu::mint.example"]
//! secret = "<64 hex>"              # wallet key on this network, written when added
//! [networks.arkade]
//! secret = "<64 hex>"
//! # esplora_url = "https://..."    # chain API of arkade and bitcoin
//!
//! [terms]                          # all optional, in seconds
//! # max_final_timeout_secs = 2592000
//! # max_authorization_secs = 31622400
//! # default_invoice_expiry_secs = 3600
//! # forward_slack_secs = 3600
//! # final_slack_secs = 3600
//!
//! [admin]
//! # listen = "127.0.0.1:7980"      # open admin page over HTTP; "" turns it off
//! # iroh = true                    # admin page over iroh, for `peers`
//! # peers = ["<64 hex>"]           # iroh keys of renderers let in
//! ```

use crate::GatewayPolicy;
use cassis_admin::networks::NetworkConfig;
use cassis_admin::{AdminSection, DaemonConfig};
use cassis_core::keys::NodeKeys;
use cassis_core::NetworkId;
use serde::Deserialize;
use std::collections::BTreeMap;

/// Where the admin page listens by default, next to a router's.
pub const DEFAULT_LISTEN: &str = "127.0.0.1:7980";

/// A fresh config, with `mnemonic`.
pub fn template(mnemonic: &str) -> String {
    format!(
        r#"# cassis-gateway config, also edited by the admin interface, which keeps
# comments and applies changes right away. The gateway's identity derives
# from the mnemonic, and every network has a key of its own, written when
# it is added: back this file up, it controls the gateway's funds.
mnemonic = "{mnemonic}"

# One table per network to be paid on and to pay payees on, with its
# wallet key, e.g.:
# [networks."cashu::mint.example"]
# secret = "<64 hex>"
# [networks.arkade]
# secret = "<64 hex>"
# esplora_url = "https://..."
[networks]

# The terms it accepts from payees, in seconds, each with this default:
# max_final_timeout_secs = 2592000      # longest final timeout a payee may ask for
# max_authorization_secs = 31622400     # longest a standing authorization may run
# default_invoice_expiry_secs = 3600    # of invoices under one, when the asker names none
# forward_slack_secs = 3600             # margin asked of payers
# final_slack_secs = 3600               # margin on top of the payee's final timeout
[terms]

# The admin interface: open over HTTP on loopback, and over iroh to the
# renderers listed in peers (or paired with the link printed on start):
# listen = "127.0.0.1:7980"
# iroh = true
# peers = []
[admin]
"#
    )
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub mnemonic: String,
    #[serde(default)]
    pub networks: BTreeMap<String, NetworkConfig>,
    #[serde(default)]
    pub terms: GatewayPolicy,
    #[serde(default)]
    pub admin: AdminSection,
}

impl Config {
    pub fn keys(&self) -> Result<NodeKeys, String> {
        NodeKeys::from_mnemonic(&self.mnemonic).map_err(|e| e.to_string())
    }
}

impl DaemonConfig for Config {
    fn check(&self) -> Result<(), String> {
        self.keys()?;
        self.admin.resolve(DEFAULT_LISTEN).check()?;
        for id in self.networks.keys() {
            NetworkId::parse(id)?;
        }
        let terms = &self.terms;
        for (key, secs) in [
            ("max_final_timeout_secs", terms.max_final_timeout_secs),
            ("max_authorization_secs", terms.max_authorization_secs),
            (
                "default_invoice_expiry_secs",
                terms.default_invoice_expiry_secs,
            ),
            ("forward_slack_secs", terms.forward_slack_secs),
            ("final_slack_secs", terms.final_slack_secs),
        ] {
            // The slacks are time forwards need: without them, an HTLC is
            // refused or refundable as soon as it is funded.
            if secs == 0 {
                return Err(format!("terms.{key} cannot be 0"));
            }
        }
        Ok(())
    }
}
