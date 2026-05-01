use cassis_core::{Invoice, NetworkId};
use cassis_onchain::{generate_preimage, hash_preimage};
use clap::{Parser, Subcommand};

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
    },
    /// Create an invoice
    Invoice {
        #[arg(long)]
        amount: u64,
        #[arg(long)]
        network: String,
        #[arg(long)]
        destination_pubkey: String,
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

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Pay { invoice, from } => cmd_pay(invoice, from),
        Commands::Invoice {
            amount,
            network,
            destination_pubkey,
            description,
            expires_at,
        } => cmd_invoice(amount, network, destination_pubkey, description, expires_at),
        Commands::Route {
            destination_pubkey,
            amount,
            from,
        } => cmd_route(destination_pubkey, amount, from),
        Commands::Node { command } => match command {
            NodeCommands::Info => cmd_node_info(),
        },
    }
}

fn cmd_pay(invoice: String, from: String) {
    let _from = NetworkId(from);
    let invoice: Invoice = match serde_json::from_str(&invoice) {
        Ok(invoice) => invoice,
        Err(err) => {
            eprintln!("invalid invoice: {err}");
            std::process::exit(1);
        }
    };
    println!("payment requested for {} msat", invoice.amount_msat);
    println!("payment flow not wired yet; use cassis-client in your app");
}

fn cmd_invoice(
    amount: u64,
    network: String,
    destination_pubkey: String,
    description: Option<String>,
    expires_at: Option<u64>,
) {
    let preimage = generate_preimage();
    let payment_hash = hash_preimage(preimage);
    let invoice = Invoice {
        payment_hash,
        amount_msat: amount,
        destination_pubkey,
        expires_at: expires_at.unwrap_or(0),
        route_hints: vec![NetworkId(network)],
        description,
    };
    let invoice_json = serde_json::to_string(&invoice).unwrap_or_default();
    println!("invoice: {invoice_json}");
    println!("preimage: {}", hex::encode(preimage));
}

fn cmd_route(destination_pubkey: String, amount: u64, from: String) {
    let _from = NetworkId(from);
    println!("route lookup requested for {destination_pubkey} amount {amount} msat");
    println!("route lookup not wired yet; use cassis-client in your app");
}

fn cmd_node_info() {
    println!("node info not wired yet; configure cassisd to expose this");
}
