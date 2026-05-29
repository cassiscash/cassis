use cassis_core::NetworkId;
use clap::{Parser, Subcommand};

const DEFAULT_NOSTR_RELAYS: &[&str] = &[
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://nostr.mom",
];

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
    /// mirrors `cassis-router`: `cashu:host`, `fedimint:invite`,
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
    Cashu { mint_url: String },
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
        let (kind, param) = match spec.split_once(':') {
            Some((k, p)) => (k, Some(p)),
            None => (spec, None),
        };
        let _ = param;
        match kind {
            #[cfg(feature = "cashu")]
            "cashu" => {
                let raw = param.ok_or_else(|| {
                    "network 'cashu' requires a host or URL, \
                     e.g. cashu:mint.example.com"
                        .to_string()
                })?;
                let mint_url = normalize_cashu_mint_url(raw);
                Ok(NetSpec::Cashu { mint_url })
            }
            #[cfg(feature = "fedimint")]
            "fedimint" => {
                let address = param.ok_or_else(|| {
                    "network 'fedimint' requires an invite code, \
                     e.g. fedimint:fed1qgqrg5c3plq3tts70rt7q3l4yy2v9m9te5t..."
                        .to_string()
                })?;
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
            NetSpec::Cashu { mint_url } => NetworkId(format!("cashu:{mint_url}")),
            #[cfg(feature = "fedimint")]
            NetSpec::Fedimint { address } => NetworkId(format!("fedimint:{address}")),
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

#[cfg_attr(
    not(feature = "cashu"),
    allow(dead_code, unused_variables, unused_imports)
)]
fn normalize_cashu_mint_url(host_or_url: &str) -> String {
    if host_or_url.contains("://") {
        return host_or_url.to_string();
    }
    let host: &str = if let Some(rest) = host_or_url.strip_prefix('[') {
        match rest.find(']') {
            Some(end) => &rest[..end],
            None => host_or_url,
        }
    } else if host_or_url == "::1" || host_or_url.starts_with("::1:") {
        "::1"
    } else {
        host_or_url.split(':').next().unwrap_or(host_or_url)
    };
    let is_loopback = matches!(host, "localhost" | "127.0.0.1" | "::1");
    let scheme = if is_loopback { "http" } else { "https" };
    format!("{scheme}://{host_or_url}")
}
