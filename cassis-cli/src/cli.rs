use clap::{Parser, Subcommand};

const DEFAULT_NOSTR_RELAYS: &[&str] = &["wss://relay.damus.io", "wss://nos.lol", "wss://nostr.mom"];

pub fn default_nostr_relays() -> Vec<String> {
    DEFAULT_NOSTR_RELAYS.iter().map(|s| s.to_string()).collect()
}

#[derive(Parser, Debug)]
#[command(name = "cassis-cli")]
#[command(about = "Cassis command-line interface (pay, receive, manage)")]
pub struct Cli {
    /// Override the cassis config directory. Defaults to
    /// `$CASSIS_HOME` if set, otherwise `$HOME/.cassis`.
    #[arg(long, global = true, value_name = "DIR")]
    pub home: Option<String>,

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
    /// Create an invoice and persist the preimage locally.
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
        #[arg(long)]
        wait: bool,
        #[arg(long, default_value_t = 600)]
        timeout: u64,
    },
    /// Long-running mode: claim incoming payments on the registered networks.
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
    /// Local cashu wallet.
    Cashu {
        #[command(subcommand)]
        command: CashuCommands,
    },
    /// Manage a node's Arkade funds.
    Arkade {
        /// Network spec, `arkade` (default) or `arkade::testnet`.
        #[arg(long, default_value = "arkade")]
        network: String,
        #[command(subcommand)]
        command: ArkadeCommands,
    },
    /// Manage a node's Liquid (LWK) funds.
    Liquid {
        /// Network spec, `liquid` (default) or `liquid::testnet`.
        #[arg(long, default_value = "liquid")]
        network: String,
        #[command(subcommand)]
        command: LiquidCommands,
    },
    /// Register a network to participate in. The argument format
    /// mirrors `cassis-router`: `cashu::host`, `rootstock`,
    /// `rootstock::testnet`.
    Register {
        #[arg(long, action = clap::ArgAction::Append, value_name = "SPEC")]
        network: Vec<String>,
    },
    /// On-chain Rootstock operations.
    Rootstock {
        /// Network spec, `rootstock` (default) or `rootstock::testnet`.
        #[arg(long, default_value = "rootstock")]
        network: String,
        #[command(subcommand)]
        command: RootstockCommands,
    },
    /// Run the multi-network routing daemon. Replaced by the GUI.
    Router {
        #[arg(long, action = clap::ArgAction::Append, value_name = "SPEC")]
        network: Vec<String>,
        #[arg(long, action = clap::ArgAction::Append, value_name = "URL")]
        nostr_relay: Vec<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum CashuCommands {
    Send {
        #[arg(long)]
        network: String,
        #[arg(long)]
        amount: u64,
    },
    Receive {
        #[arg(long = "proof")]
        proof: String,
    },
    Balance {
        #[arg(long)]
        network: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum LiquidCommands {
    /// Show the node's L-BTC balance.
    Balance,
    /// Print the confidential deposit address.
    Deposit,
    /// Send L-BTC to another confidential address.
    Send {
        /// Destination Liquid address.
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount_msat: u64,
    },
}

#[derive(Subcommand, Debug)]
pub enum ArkadeCommands {
    /// Show the node's offchain Arkade balance.
    Balance,
    /// Submit confirmed boarding outputs to the next batch swap.
    Onboard,
    /// Print deposit addresses (boarding / on-chain / arkade).
    Deposit,
    /// Send VTXOs to another Arkade address.
    Send {
        /// Destination Arkade address (`ark1...` / `tark1...`).
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount_msat: u64,
    },
}

#[derive(Subcommand, Debug)]
pub enum RootstockCommands {
    Send {
        #[arg(long)]
        to: String,
        #[arg(long, default_value_t = 0)]
        amount_msat: u64,
        #[arg(long)]
        data: Option<String>,
        #[arg(long)]
        args: Option<String>,
    },
    Info,
    Read {
        #[arg(long)]
        to: String,
        #[arg(long)]
        data: String,
        #[arg(long)]
        args: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum InvoicesCommands {
    List {
        #[arg(long)]
        status: Option<String>,
    },
    Show {
        #[arg(long)]
        payment_hash: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum NodeCommands {
    Info,
}

#[derive(Subcommand, Debug)]
pub enum SeedCommands {
    Init {
        #[arg(long)]
        force: bool,
    },
    Show,
}

// The NetSpec enum and its parser previously lived here. They moved to
// `cassis_client::netspec` so the CLI and the GUI share the same parsing
// logic. See `cassis-client/src/netspec.rs`.
