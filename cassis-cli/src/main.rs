//! `cassis-cli`: one Cassis node, living in a home directory (see
//! [`home`]). It pays, receives, routes between its networks, and
//! manages each network's funds under a subcommand of its own. Each
//! network is compiled in by the cargo feature of the same name.

#[cfg(not(any(
    feature = "arkade",
    feature = "bitcoin",
    feature = "cashu",
    feature = "fedimint",
    feature = "lightning",
    feature = "liquid",
    feature = "rootstock"
)))]
compile_error!("cassis-cli needs at least one network feature, e.g. `--features cashu`");

mod home;
mod wallets;

use cassis_core::node::{
    create_invoice, HopRecord, InvoiceRecord, Node, NodeConfig, PaymentRecord, RoutingPolicy,
};
use cassis_core::routing::{self, DEFAULT_NOSTR_RELAYS};
use cassis_core::{unix_now, Invoice, NetworkId};
use clap::{Parser, Subcommand};
use home::Home;
use std::path::PathBuf;
use std::time::Duration;
use tracing::{info, info_span, Span};

#[derive(Parser)]
#[command(name = "cassis-cli", about = "Cassis node: pay, receive, route")]
struct Cli {
    /// Node directory. Defaults to `$CASSIS_HOME`, else `~/.cassis`.
    #[arg(long, global = true, value_name = "DIR")]
    home: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print the seed phrase.
    Seed,
    /// Print the node identity and its networks.
    Info,
    /// Add networks this node participates in, e.g. `cashu::mint.host`,
    /// `liquid`, `arkade::mutinynet`, `lightning`.
    Enable {
        #[arg(required = true)]
        networks: Vec<String>,
        /// LND REST URL, when enabling `lightning`.
        #[arg(long)]
        lnd_rest_url: Option<String>,
        #[arg(long)]
        lnd_tls_cert: Option<PathBuf>,
        #[arg(long)]
        lnd_macaroon: Option<PathBuf>,
    },
    /// Remove networks from this node.
    Disable {
        #[arg(required = true)]
        networks: Vec<String>,
    },
    /// Run the node until interrupted: claim payments to its invoices,
    /// settle and refund its HTLCs, and with `--route` route between
    /// its networks.
    Run {
        #[arg(long)]
        route: bool,
        #[arg(long, default_value_t = 1000)]
        fee_base_msat: u64,
        #[arg(long, default_value_t = 500)]
        fee_ppm: u64,
        #[arg(long = "nostr-relay", value_name = "URL")]
        nostr_relays: Vec<String>,
    },
    /// Create an invoice. A running node (`run`) claims it when paid.
    Invoice {
        #[arg(long)]
        amount_msat: u64,
        /// Networks it can be paid on; all of the node's by default.
        #[arg(long = "network")]
        networks: Vec<String>,
        #[arg(long)]
        description: Option<String>,
        #[arg(long, default_value_t = 3600)]
        expires_in: u64,
        /// Serve the node here until the invoice is paid or expires.
        #[arg(long)]
        wait: bool,
    },
    /// Pay an invoice (JSON) from one of this node's networks.
    Pay {
        #[arg(long)]
        invoice: String,
        #[arg(long)]
        from: String,
        #[arg(long = "nostr-relay", value_name = "URL")]
        nostr_relays: Vec<String>,
    },
    /// Show the cheapest announced route between two networks.
    Route {
        #[arg(long)]
        from: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount_msat: u64,
        #[arg(long = "nostr-relay", value_name = "URL")]
        nostr_relays: Vec<String>,
    },
    /// List the invoices this node issued.
    Invoices,
    /// List the payments this node made.
    Payments,
    /// List the hops this node routed.
    Hops,
    #[command(flatten)]
    Wallet(wallets::Command),
}

#[tokio::main]
async fn main() {
    cassis_core::logging::init_logging();
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let cli = Cli::parse();
    if let Err(error) = run(cli).await {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<(), String> {
    let home = Home::open(cli.home)?;
    let span = info_span!("node", node = "cassis");
    match cli.command {
        Command::Seed => println!("{}", home.mnemonic()?),
        Command::Info => {
            println!("node pubkey: {}", home.keys.node.pubkey().to_hex());
            println!("networks:");
            for network in home.networks()? {
                println!("  {network}");
            }
        }
        Command::Enable {
            networks,
            lnd_rest_url,
            lnd_tls_cert,
            lnd_macaroon,
        } => {
            let mut enabled = home.networks()?;
            for spec in &networks {
                let network = NetworkId::parse(spec)?;
                if network.kind() == "lightning" {
                    configure_lnd(
                        &home,
                        lnd_rest_url.clone(),
                        lnd_tls_cert.clone(),
                        lnd_macaroon.clone(),
                    )?;
                }
                // Fail early on networks this binary cannot open.
                home.open_network(&network, &span).await?;
                if !enabled.contains(&network) {
                    enabled.push(network);
                }
            }
            home.set_networks(&enabled)?;
        }
        Command::Disable { networks } => {
            let remove = networks
                .iter()
                .map(|spec| NetworkId::parse(spec))
                .collect::<Result<Vec<_>, _>>()?;
            let mut enabled = home.networks()?;
            enabled.retain(|network| !remove.contains(network));
            home.set_networks(&enabled)?;
        }
        Command::Run {
            route,
            fee_base_msat,
            fee_ppm,
            nostr_relays,
        } => {
            let node = serve(&home, &span).await?;
            if route {
                node.start_routing(RoutingPolicy {
                    fee_base_msat,
                    fee_ppm,
                    nostr_relays: relays(nostr_relays),
                    ..RoutingPolicy::default()
                });
            }
            info!("running as {}; Ctrl-C to stop", node.iroh_peer_id());
            tokio::signal::ctrl_c().await.ok();
        }
        Command::Invoice {
            amount_msat,
            networks,
            description,
            expires_in,
            wait,
        } => {
            let networks = if networks.is_empty() {
                home.networks()?
            } else {
                networks
                    .iter()
                    .map(|spec| NetworkId::parse(spec))
                    .collect::<Result<_, _>>()?
            };
            let expires_at = unix_now() + expires_in;
            let invoice = if wait {
                let node = serve(&home, &span).await?;
                node.create_invoice(&networks, amount_msat, expires_at, description)
                    .await?
            } else {
                let opened = home.open_networks(&networks, &span).await?;
                create_invoice(
                    &home.store,
                    &home.keys,
                    None,
                    &opened,
                    amount_msat,
                    expires_at,
                    description,
                )
                .await?
            };
            println!(
                "{}",
                serde_json::to_string(&invoice).map_err(|e| e.to_string())?
            );
            if wait {
                wait_for_claim(&home, &invoice).await?;
            }
        }
        Command::Pay {
            invoice,
            from,
            nostr_relays,
        } => {
            let invoice: Invoice =
                serde_json::from_str(&invoice).map_err(|e| format!("invalid invoice: {e}"))?;
            let from = NetworkId::parse(&from)?;
            let sender = home.open_network(&from, &span).await?;
            let node = Node::start(
                NodeConfig {
                    keys: home.keys.clone(),
                    store: home.store.clone(),
                    span,
                    serve: false,
                },
                vec![sender],
            )
            .await?;
            let preimage = node.pay(&invoice, &from, &relays(nostr_relays)).await?;
            println!("paid; preimage {preimage}");
        }
        Command::Route {
            from,
            to,
            amount_msat,
            nostr_relays,
        } => {
            let announcements = routing::fetch_announcements(&relays(nostr_relays)).await?;
            let route = routing::find_route(
                &announcements,
                &NetworkId::parse(&from)?,
                &NetworkId::parse(&to)?,
                amount_msat,
            )?;
            let plan = routing::plan_route(&route, amount_msat, 0, 0)?;
            println!("{} msat over {} hop(s)", plan.amounts[0], route.len());
            for (i, hop) in route.iter().enumerate() {
                println!(
                    "  {}: {} -> {} via {} (forwards {} msat)",
                    i + 1,
                    hop.from,
                    hop.to,
                    hop.node_pubkey.to_hex(),
                    plan.amounts[i + 1]
                );
            }
        }
        Command::Invoices => {
            for record in home.store.list::<InvoiceRecord>("invoices")? {
                println!(
                    "{} {:>12} msat {:?} expires {}",
                    record.invoice.payment_hash,
                    record.invoice.amount_msat,
                    record.status,
                    record.invoice.expires_at
                );
            }
        }
        Command::Payments => {
            for record in home.store.list::<PaymentRecord>("payments")? {
                println!(
                    "{} {:>12} msat on {} {:?}",
                    record.invoice.payment_hash,
                    record.htlc.amount_msat,
                    record.network,
                    record.status
                );
            }
        }
        Command::Hops => {
            for record in home.store.list::<HopRecord>("hops")? {
                println!(
                    "{} {} -> {} {:>12} msat {:?}",
                    record.prepare.payment_hash,
                    record.prepare.incoming_network,
                    record.prepare.outgoing_network,
                    record.prepare.amount_msat,
                    record.state
                );
            }
        }
        Command::Wallet(command) => wallets::run(&home, command, &span).await?,
    }
    Ok(())
}

/// Start the node, serving under its identity, with all its networks.
async fn serve(home: &Home, span: &Span) -> Result<Node, String> {
    let networks = home.open_networks(&home.networks()?, span).await?;
    if networks.is_empty() {
        return Err("no networks enabled; see `cassis-cli enable`".into());
    }
    Node::start(
        NodeConfig {
            keys: home.keys.clone(),
            store: home.store.clone(),
            span: span.clone(),
            serve: true,
        },
        networks,
    )
    .await
}

async fn wait_for_claim(home: &Home, invoice: &Invoice) -> Result<(), String> {
    let key = invoice.payment_hash.to_string();
    loop {
        let record: InvoiceRecord = home
            .store
            .get("invoices", &key)?
            .ok_or("invoice disappeared")?;
        match record.status {
            cassis_core::node::InvoiceStatus::Claimed => {
                println!("claimed");
                return Ok(());
            }
            cassis_core::node::InvoiceStatus::Expired => return Err("invoice expired".into()),
            cassis_core::node::InvoiceStatus::Pending => {
                tokio::time::sleep(Duration::from_secs(1)).await
            }
        }
    }
}

fn relays(relays: Vec<String>) -> Vec<String> {
    if relays.is_empty() {
        DEFAULT_NOSTR_RELAYS.iter().map(|r| r.to_string()).collect()
    } else {
        relays
    }
}

#[allow(unused_variables)]
fn configure_lnd(
    home: &Home,
    rest_url: Option<String>,
    tls_cert: Option<PathBuf>,
    macaroon: Option<PathBuf>,
) -> Result<(), String> {
    #[cfg(feature = "lightning")]
    if let Some(rest_url) = rest_url {
        home.set_lnd_config(&cassis_lnd::LndConfig::new(rest_url, tls_cert, macaroon))?;
    }
    Ok(())
}
