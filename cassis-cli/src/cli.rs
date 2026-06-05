use cassis_core::{cashu_mint_url, cashu_network_id, fedimint_network_id, NetworkId};
use clap::{Parser, Subcommand};

const DEFAULT_NOSTR_RELAYS: &[&str] = &["wss://relay.damus.io", "wss://nos.lol", "wss://nostr.mom"];

pub fn default_nostr_relays() -> Vec<String> {
    DEFAULT_NOSTR_RELAYS.iter().map(|s| s.to_string()).collect()
}

#[derive(Parser, Debug)]
#[command(name = "cassis-cli")]
#[command(about = "Cassis command-line interface (pay, receive, manage)")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Pay an invoice from a given network
    Pay {
        #[arg(long)]
        invoice: String,
        #[arg(long)]
        from: String,
        /// Nostr relays to query for route announcements.
        #[arg(long, action = clap::ArgAction::Append, value_name = "URL")]
        nostr_relay: Vec<String>,
    },
    /// Create an invoice and persist the preimage locally. With
    /// `--wait`, block until the upstream funds and the invoice is
    /// claimed.
    Invoice {
        #[arg(long)]
        amount: u64,
        #[arg(long)]
        network: String,
        #[arg(long)]
        payee: Option<String>,
        #[arg(long)]
        description: Option<String>,
        #[arg(long)]
        expires_at: Option<u64>,
        /// Block until the invoice is funded and claimed, then print
        /// the preimage. Requires `--network` to have a registered
        /// receiver adapter (CLI must be built with the matching
        /// cargo feature).
        #[arg(long)]
        wait: bool,
        /// Wait timeout in seconds. Defaults to 600.
        #[arg(long, default_value_t = 600)]
        timeout: u64,
    },
    /// Long-running mode: claim incoming payments on the registered
    /// networks. Holds the registered receivers open and writes to
    /// the local store as invoices settle.
    Receive,
    /// List invoices persisted in the local store.
    Invoices {
        #[command(subcommand)]
        command: InvoicesCommands,
    },
    /// Look up a route to a destination
    Route {
        #[arg(long = "to")]
        destination_pubkey: String,
        #[arg(long)]
        amount: u64,
        #[arg(long)]
        from: String,
        #[arg(long, action = clap::ArgAction::Append, value_name = "URL")]
        nostr_relay: Vec<String>,
    },
    /// Inspect the local node
    Node {
        #[command(subcommand)]
        command: NodeCommands,
    },
    /// Seed management
    Seed {
        #[command(subcommand)]
        command: SeedCommands,
    },
    /// Register a network to participate in. The argument format
    /// mirrors `cassis-router`: `cashu::host`, `fedimint::invite`,
    /// `liquid`, `ark`, `rootstock`. Used to seed the local store
    /// and (for `receive`) the list of adapters to keep open.
    Register {
        #[arg(long, action = clap::ArgAction::Append, value_name = "SPEC")]
        network: Vec<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum InvoicesCommands {
    /// List invoices, optionally filtered by status.
    List {
        #[arg(long)]
        status: Option<String>,
    },
    /// Show full details of one invoice, identified by its payment
    /// hash.
    Show {
        #[arg(long)]
        payment_hash: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum NodeCommands {
    /// Show information about the local node
    Info,
}

#[derive(Subcommand, Debug)]
pub enum SeedCommands {
    /// Generate a new 12-word BIP39 mnemonic and write it to
    /// `~/.cassis/seed` (mode 0600). Refuses to overwrite without
    /// `--force`.
    Init {
        #[arg(long)]
        force: bool,
    },
    /// Print the stored mnemonic to stdout. Sensitive: callers
    /// should treat the output like a private key.
    Show,
}

/// A parsed `--network` spec, mirroring `cassis-router`'s format.
#[derive(Clone, Debug)]
pub enum NetSpec {
    #[cfg(feature = "cashu")]
    Cashu { mint_url: String, host: String },
    #[cfg(feature = "fedimint")]
    Fedimint { address: String },
    #[cfg(feature = "liquid")]
    Liquid,
    #[cfg(feature = "ark")]
    Ark,
    #[cfg(feature = "rootstock")]
    Rootstock,
}

impl NetSpec {
    pub fn parse(spec: &str) -> Result<Self, String> {
        let (kind, param) = split_canonical_spec(spec);
        match kind {
            #[cfg(feature = "cashu")]
            "cashu" => {
                let host = param.ok_or_else(|| {
                    "network 'cashu' requires a host, e.g. cashu::mint.example.com".to_string()
                })?;
                if host.is_empty() {
                    return Err(
                        "network 'cashu' requires a non-empty host, e.g. cashu::mint.example.com"
                            .to_string(),
                    );
                }
                if host.contains("://") {
                    return Err("network 'cashu' must not include a scheme; \
                         drop the http:// or https:// prefix and use cashu::<host> instead"
                        .to_string());
                }
                let network_id = cashu_network_id(host);
                let mint_url =
                    cashu_mint_url(&network_id).map_err(|e| format!("cashu mint url: {e}"))?;
                Ok(NetSpec::Cashu {
                    mint_url,
                    host: host.to_string(),
                })
            }
            #[cfg(feature = "fedimint")]
            "fedimint" => {
                let address = param.ok_or_else(|| {
                    "network 'fedimint' requires an invite code, \
                     e.g. fedimint::fed1qgqrg5c3plq3tts70rt7q3l4yy2v9m9te5t..."
                        .to_string()
                })?;
                if address.is_empty() {
                    return Err("network 'fedimint' requires a non-empty invite code".to_string());
                }
                Ok(NetSpec::Fedimint {
                    address: address.to_string(),
                })
            }
            #[cfg(feature = "liquid")]
            "liquid" => {
                if param.is_some() {
                    return Err("network 'liquid' does not take a parameter".into());
                }
                Ok(NetSpec::Liquid)
            }
            #[cfg(feature = "ark")]
            "ark" => {
                if param.is_some() {
                    return Err("network 'ark' does not take a parameter".into());
                }
                Ok(NetSpec::Ark)
            }
            #[cfg(feature = "rootstock")]
            "rootstock" => {
                if param.is_some() {
                    return Err("network 'rootstock' does not take a parameter".into());
                }
                Ok(NetSpec::Rootstock)
            }
            other => Err(format!(
                "unsupported network kind '{other}' (compile cassis-cli with the matching feature)"
            )),
        }
    }

    pub fn kind_name(&self) -> &'static str {
        match self {
            #[cfg(feature = "cashu")]
            NetSpec::Cashu { .. } => "cashu",
            #[cfg(feature = "fedimint")]
            NetSpec::Fedimint { .. } => "fedimint",
            #[cfg(feature = "liquid")]
            NetSpec::Liquid => "liquid",
            #[cfg(feature = "ark")]
            NetSpec::Ark => "ark",
            #[cfg(feature = "rootstock")]
            NetSpec::Rootstock => "rootstock",
            #[allow(unreachable_patterns)]
            _ => "unknown",
        }
    }

    pub fn network_id(&self) -> NetworkId {
        match self {
            #[cfg(feature = "cashu")]
            NetSpec::Cashu { host, .. } => cashu_network_id(host),
            #[cfg(feature = "fedimint")]
            NetSpec::Fedimint { address } => fedimint_network_id(address),
            #[cfg(feature = "liquid")]
            NetSpec::Liquid => NetworkId("liquid".to_string()),
            #[cfg(feature = "ark")]
            NetSpec::Ark => NetworkId("ark".to_string()),
            #[cfg(feature = "rootstock")]
            NetSpec::Rootstock => NetworkId("rootstock".to_string()),
            #[allow(unreachable_patterns)]
            _ => NetworkId("unknown".to_string()),
        }
    }
}

/// Split a `--network` spec into `(kind, param)`. Requires the canonical
/// `::` separator; any other form is rejected.
fn split_canonical_spec(spec: &str) -> (&str, Option<&str>) {
    match spec.split_once("::") {
        Some((kind, param)) => (kind, Some(param)),
        None => (spec, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cassis_core::{
        canonicalize_network_id, CASHU_NETWORK_ID_PREFIX, FEDIMINT_NETWORK_ID_PREFIX,
    };

    #[test]
    fn parse_canonical_cashu_spec_uses_canonical_form() {
        let spec = NetSpec::parse("cashu::mint.example.com").unwrap();
        assert_eq!(spec.network_id().0, "cashu::mint.example.com");
        let NetSpec::Cashu { mint_url, host } = spec else {
            panic!("expected Cashu variant");
        };
        assert_eq!(host, "mint.example.com");
        assert_eq!(mint_url, "https://mint.example.com");
    }

    #[test]
    fn parse_canonical_cashu_loopback_uses_canonical_form() {
        let spec = NetSpec::parse("cashu::localhost:3338").unwrap();
        assert_eq!(spec.network_id().0, "cashu::localhost:3338");
        let NetSpec::Cashu { mint_url, host } = spec else {
            panic!("expected Cashu variant");
        };
        assert_eq!(host, "localhost:3338");
        assert_eq!(mint_url, "http://localhost:3338");
    }

    #[test]
    fn parse_canonical_fedimint_spec_uses_canonical_form() {
        let spec = NetSpec::parse("fedimint::fed1qabc").unwrap();
        assert_eq!(spec.network_id().0, "fedimint::fed1qabc");
    }

    #[test]
    fn parse_rejects_legacy_single_colon() {
        assert!(NetSpec::parse("cashu:localhost:3338").is_err());
        assert!(NetSpec::parse("fedimint:fed1qabc").is_err());
    }

    #[test]
    fn parse_rejects_explicit_scheme() {
        assert!(NetSpec::parse("cashu:https://mint.example.com").is_err());
        assert!(NetSpec::parse("cashu:http://localhost:3338").is_err());
        assert!(NetSpec::parse("cashu::https://mint.example.com").is_err());
    }

    #[test]
    fn parse_rejects_empty_cashu() {
        assert!(NetSpec::parse("cashu::").is_err());
    }

    #[test]
    fn parse_rejects_empty_fedimint() {
        assert!(NetSpec::parse("fedimint::").is_err());
    }

    #[test]
    fn prefixes_match_core_constants() {
        assert_eq!(NetSpec::parse("cashu::x").unwrap().kind_name(), "cashu");
        assert_eq!(
            NetSpec::parse("fedimint::x").unwrap().kind_name(),
            "fedimint"
        );
        assert_eq!(CASHU_NETWORK_ID_PREFIX, "cashu::");
        assert_eq!(FEDIMINT_NETWORK_ID_PREFIX, "fedimint::");
    }

    #[test]
    fn canonicalize_passes_through_canonical() {
        let cases = [
            "cashu::localhost:3338",
            "cashu::mint.example.com",
            "fedimint::fed1qabc",
            "liquid",
            "ark",
        ];
        for raw in cases {
            let id = NetworkId(raw.to_string());
            assert_eq!(canonicalize_network_id(&id).0, raw);
        }
    }
}
