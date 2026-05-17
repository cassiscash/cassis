use cassis_core::{HopInstruction, Invoice, NetworkId};
use cassis_iroh::{node_addr_from_announcement, IrohClient};
use cassis_onchain::{generate_preimage, hash_preimage};
use clap::{Parser, Subcommand};
use futures::future::try_join_all;
use log::{debug, error, info};

const DEFAULT_NOSTR_RELAYS: &[&str] = &[
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://nostr.mom",
];

#[derive(Parser)]
#[command(name = "cassis-cli")]
#[command(about = "Cassis command-line interface")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Pay an invoice from a given network
    Pay {
        #[arg(long)]
        invoice: String,
        #[arg(long)]
        from: String,
        /// Nostr relays to query for route announcements.
        /// Defaults to a built-in list when none are provided.
        #[arg(long, action = clap::ArgAction::Append, value_name = "URL")]
        nostr_relay: Vec<String>,
    },
    /// Create an invoice
    Invoice {
        #[arg(long)]
        amount: u64,
        #[arg(long)]
        network: String,
        #[arg(long)]
        payee: String,
        #[arg(long)]
        description: Option<String>,
        #[arg(long)]
        expires_at: Option<u64>,
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
}

#[derive(Subcommand)]
enum NodeCommands {
    /// Show information about the local node
    Info,
}

#[tokio::main]
async fn main() {
    cassis_core::logging::init_logging();

    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install default rustls crypto provider");

    let cli = Cli::parse();
    match cli.command {
        Commands::Pay { invoice, from, nostr_relay } => cmd_pay(invoice, from, nostr_relay).await,
        Commands::Invoice {
            amount,
            network,
            payee,
            description,
            expires_at,
        } => cmd_invoice(amount, network, payee, description, expires_at),
        Commands::Route {
            destination_pubkey,
            amount,
            from,
            nostr_relay,
        } => cmd_route(destination_pubkey, amount, from, nostr_relay).await,
        Commands::Node { command } => match command {
            NodeCommands::Info => cmd_node_info(),
        },
    }
}

async fn cmd_pay(invoice_str: String, from: String, nostr_relays: Vec<String>) {
    let invoice: Invoice = match serde_json::from_str(&invoice_str) {
        Ok(invoice) => invoice,
        Err(err) => {
            error!(target: "cassis_cli", "invalid invoice: {err}");
            std::process::exit(1);
        }
    };

    let sender_network = NetworkId(from);

    let dest_network = match invoice.networks.first() {
        Some(n) => n.clone(),
        None => {
            error!(target: "cassis_cli", "invoice has no network hints");
            std::process::exit(1);
        }
    };
    info!(
        target: "cassis_cli",
        "routing to network {dest_network} (payee {})",
        invoice.payee,
    );

    let relays: Vec<String> = if nostr_relays.is_empty() {
        DEFAULT_NOSTR_RELAYS.iter().map(|s| s.to_string()).collect()
    } else {
        nostr_relays
    };

    let route = match cassis_client::find_route(&relays, &dest_network, invoice.amount_msat, &sender_network).await {
        Ok(r) => r,
        Err(cassis_client::RouteError::Fetch(err)) => {
            error!(target: "cassis_cli", "error fetching announcements: {err}");
            std::process::exit(1);
        }
        Err(cassis_client::RouteError::Route(cassis_nostr::RouteError::NoRoute)) => {
            error!(target: "cassis_cli", "no route found");
            std::process::exit(1);
        }
        Err(err) => {
            error!(target: "cassis_cli", "route error: {err}");
            std::process::exit(1);
        }
    };

    if route.is_empty() {
        error!(target: "cassis_cli", "empty route");
        std::process::exit(1);
    }

    info!(
        target: "cassis_cli",
        "paying {} msat via {} hop(s) from {}",
        invoice.amount_msat,
        route.len(),
        sender_network,
    );

    info!(target: "cassis_cli", "binding iroh endpoint...");
    let client = IrohClient::bind().await.expect("failed to bind iroh endpoint");
    info!(target: "cassis_cli", "iroh endpoint bound");

    let deltas = vec![0u64; route.len()];
    let expiries = crate::compute_hop_expiries(invoice.expires_at, &deltas);

    let instructions: Vec<(iroh::NodeAddr, HopInstruction)> = route
        .iter()
        .enumerate()
        .map(|(idx, hop)| {
            let addr = node_addr_from_announcement(&hop.node)
                .unwrap_or_else(|e| {
                    error!(target: "cassis_cli", "invalid iroh addr for hop {idx}: {e}");
                    std::process::exit(1);
                });
            let instruction = HopInstruction {
                payment_hash: invoice.payment_hash,
                amount_msat: invoice.amount_msat,
                incoming_network: hop.incoming.clone(),
                outgoing_network: hop.outgoing.clone(),
                incoming_deadline: expiries.get(idx).copied().unwrap_or(invoice.expires_at),
                outgoing_expiry: expiries.get(idx + 1).copied().unwrap_or(invoice.expires_at),
                recipient: hop.node.node_pubkey.to_string(),
            };
            debug!(
                target: "cassis_cli",
                "  hop {}: sending instruction to {} (amount={}, incoming={}, outgoing={}, recipient={})",
                idx + 1,
                hop.node.node_pubkey,
                instruction.amount_msat,
                instruction.incoming_network.0,
                instruction.outgoing_network.0,
                instruction.recipient,
            );
            (addr, instruction)
        })
        .collect();

    info!(target: "cassis_cli", "sending {} hop instruction(s) in parallel...", instructions.len());
    let ack_futures = instructions.into_iter().map(|(addr, instruction)| {
        client.send_instruction(addr, instruction)
    });

    let acks = match try_join_all(ack_futures).await {
        Ok(acks) => acks,
        Err(err) => {
            error!(target: "cassis_cli", "iroh error: {err}");
            std::process::exit(1);
        }
    };
    info!(target: "cassis_cli", "all {} response(s) received", acks.len());

    for (i, ack) in acks.iter().enumerate() {
        if ack.accepted {
            info!(target: "cassis_cli", "hop {} accepted", i + 1);
        } else {
            error!(target: "cassis_cli", "hop {} rejected: {:?}", i + 1, ack.signature);
            std::process::exit(1);
        }
    }

    info!(target: "cassis_cli", "all hops prepared");
}

fn cmd_invoice(
    amount: u64,
    network: String,
    payee: String,
    description: Option<String>,
    expires_at: Option<u64>,
) {
    let preimage = generate_preimage();
    let payment_hash = hash_preimage(preimage);
    let invoice = Invoice {
        payment_hash,
        amount_msat: amount,
        payee,
        expires_at: expires_at.unwrap_or(0),
        networks: vec![NetworkId(network)],
        description,
    };
    let invoice_json = serde_json::to_string(&invoice).unwrap_or_default();
    println!("invoice: {invoice_json}");
    println!("preimage: {}", lowercase_hex::encode(preimage));
}

async fn cmd_route(
    destination_pubkey: String,
    amount: u64,
    from: String,
    nostr_relays: Vec<String>,
) {
    let sender_network = NetworkId(from);
    let dest_network = NetworkId(destination_pubkey);

    let relays: Vec<String> = if nostr_relays.is_empty() {
        DEFAULT_NOSTR_RELAYS.iter().map(|s| s.to_string()).collect()
    } else {
        nostr_relays
    };

    info!(target: "cassis_cli", "fetching route announcements from {} relay(s)...", relays.len());

    let route = match cassis_client::find_route(&relays, &dest_network, amount, &sender_network).await {
        Ok(r) => r,
        Err(cassis_client::RouteError::Fetch(err)) => {
            error!(target: "cassis_cli", "error fetching announcements: {err}");
            std::process::exit(1);
        }
        Err(cassis_client::RouteError::Route(cassis_nostr::RouteError::NoRoute)) => {
            error!(target: "cassis_cli", "no route found");
            std::process::exit(1);
        }
        Err(err) => {
            error!(target: "cassis_cli", "route error: {err}");
            std::process::exit(1);
        }
    };

    if route.is_empty() {
        error!(target: "cassis_cli", "empty route");
        std::process::exit(1);
    }

    println!("route found ({} hop(s)):", route.len());
    for (i, hop) in route.iter().enumerate() {
        println!(
            "  hop {}: {} | {} -> {}",
            i + 1,
            hop.node.node_pubkey,
            hop.incoming.0,
            hop.outgoing.0,
        );
    }
}

fn compute_hop_expiries(final_expiry: u64, deltas: &[u64]) -> Vec<u64> {
    let mut expiries = Vec::with_capacity(deltas.len() + 1);
    let mut current = final_expiry;
    expiries.push(current);
    for delta in deltas.iter().rev() {
        current = current.saturating_add(*delta);
        expiries.push(current);
    }
    expiries.reverse();
    expiries
}

fn cmd_node_info() {
    println!("node info not wired yet; configure cassisd to expose this");
}
