//! `<dir>/config.toml`: what the gateway does, written with nothing in it
//! on first start, then read, and edited by the admin interface, which
//! applies changes right away and keeps comments. Its keys stay in
//! `<dir>/seed`.
//!
//! ```toml
//! [networks."cashu::mint.example"]
//! [networks.arkade]
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
use cassis_core::NetworkId;
use serde::Deserialize;
use std::collections::BTreeMap;

/// Where the admin page listens by default, next to a router's.
pub const DEFAULT_LISTEN: &str = "127.0.0.1:7980";

pub const TEMPLATE: &str = r#"# cassis-gateway config, also edited by the admin interface, which keeps
# comments and applies changes right away. Its keys are in the seed file.

# One table per network to be paid on and to pay payees on, e.g.:
# [networks."cashu::mint.example"]
# [networks.arkade]
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
"#;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub networks: BTreeMap<String, NetworkConfig>,
    #[serde(default)]
    pub terms: GatewayPolicy,
    #[serde(default)]
    pub admin: AdminSection,
}

impl DaemonConfig for Config {
    fn check(&self) -> Result<(), String> {
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
