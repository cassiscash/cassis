//! `cassis-wallet`: a Cassis wallet, living in a home directory (see
//! [`home`]). It pays and receives Cassis invoices on its networks and
//! manages each network's funds under a subcommand of its own. Each
//! network is compiled in by the cargo feature of the same name.
//! Routing is `cassis-routerd`'s job.

#[cfg(not(any(
    feature = "arkade",
    feature = "bark-lightning",
    feature = "bitcoin",
    feature = "cashu",
    feature = "fedimint",
    feature = "lightning",
    feature = "liquid",
    feature = "rootstock"
)))]
compile_error!("cassis-wallet needs at least one network feature, e.g. `--features cashu`");

mod home;
mod order_demo;
mod wallets;

use cassis_core::node::{
    create_invoice, create_preimage_server_invoice, redeem_preimage_server_payments, InvoiceRecord,
    InvoiceStatus, Node, NodeConfig, PaymentRecord, PreimageServerInvoiceRecord,
    PREIMAGE_SERVER_INVOICES,
};
use cassis_core::routing::{self, DEFAULT_NOSTR_RELAYS, TEST_NOSTR_RELAYS};
use cassis_core::transport::PeerAddr;
use cassis_core::{unix_now, Invoice, NetworkId};
use clap::{Parser, Subcommand};
use home::Home;
use std::path::PathBuf;
use std::time::Duration;
use tracing::{info, info_span, Span};

#[derive(Parser)]
#[command(name = "cassis-wallet", about = "Cassis wallet: pay and receive")]
struct Cli {
    /// Node directory. Defaults to `$CASSIS_HOME`, else `~/.cassis`.
    #[arg(long, global = true, value_name = "DIR")]
    home: Option<PathBuf>,
    /// Nostr relay to announce and discover routes on, instead of the
    /// defaults (nostr.wine). Repeatable, or comma-separated in
    /// `$CASSIS_NOSTR_RELAYS`.
    #[arg(
        long = "nostr-relay",
        global = true,
        value_name = "URL",
        env = "CASSIS_NOSTR_RELAYS",
        value_delimiter = ','
    )]
    nostr_relays: Vec<String>,
    /// Use the relays for test money (nos.lol, relay.primal.net,
    /// relay.damus.io) instead of the defaults.
    #[arg(
        long,
        global = true,
        env = "CASSIS_TEST_RELAYS",
        conflicts_with = "nostr_relays"
    )]
    test_relays: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print the seed phrase.
    Seed,
    /// Print the node identity and its networks.
    Info,
    /// Add networks this wallet holds funds on, e.g. `cashu::mint.host`,
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
        /// Go through a bark wallet at an Ark server instead of LND, when
        /// enabling `lightning`: Second's server for mainnet and signet,
        /// unless `--bark-server` names another.
        #[arg(long)]
        bark: bool,
        /// Ark server URL, with `--bark`.
        #[arg(long, value_name = "URL", requires = "bark")]
        bark_server: Option<String>,
        /// Esplora API of the Ark server's chain, with `--bark`.
        #[arg(long, value_name = "URL", requires = "bark")]
        bark_esplora: Option<String>,
        /// Longest an HTLC received on these networks may run, instead
        /// of what the network derives (e.g. from an arkade operator's
        /// batch lifetime).
        #[arg(long, value_name = "SECS")]
        max_incoming_lifetime: Option<u64>,
    },
    /// Remove networks from this wallet.
    Disable {
        #[arg(required = true)]
        networks: Vec<String>,
    },
    /// Serve the wallet until interrupted: claim payments to its
    /// invoices and settle and refund its HTLCs.
    Run,
    /// Create an invoice to receive a payment. A running wallet (`run`)
    /// claims it when paid.
    #[command(visible_alias = "invoice")]
    Receive {
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
        #[arg(long, conflicts_with = "preimage_server")]
        wait: bool,
        /// Iroh id of a preimage server to answer payers instead of this
        /// node, which can then stay offline. It picks the payment hash
        /// and the metadata; claim with `redeem` afterwards.
        #[arg(long = "preimage-server", visible_alias = "ps", value_name = "ID")]
        preimage_server: Option<String>,
        /// Home relay of the preimage server.
        #[arg(
            long = "preimage-server-relay",
            visible_alias = "ps-relay",
            value_name = "URL",
            requires = "preimage_server"
        )]
        preimage_server_relay: Option<String>,
        /// With `--preimage-server`: how long this node may stay offline
        /// after a payment before `redeem` must claim it. Payers and
        /// routers lock their HTLCs that much longer.
        #[arg(long, value_name = "SECS", default_value_t = 24 * 3600, requires = "preimage_server")]
        claim_window: u64,
    },
    /// Fetch the payments preimage servers logged for this node's
    /// invoices and claim them, before their HTLCs expire.
    Redeem {
        /// Only this preimage server; by default every one with an
        /// unclaimed invoice.
        #[arg(long = "preimage-server", visible_alias = "ps", value_name = "ID")]
        preimage_server: Option<String>,
        #[arg(
            long = "preimage-server-relay",
            visible_alias = "ps-relay",
            value_name = "URL",
            requires = "preimage_server"
        )]
        preimage_server_relay: Option<String>,
        /// Only payments logged since this unix time.
        #[arg(long, default_value_t = 0)]
        since: u64,
    },
    /// Pay an invoice (JSON) from one of this node's networks.
    Pay {
        #[arg(long)]
        invoice: String,
        #[arg(long)]
        from: String,
    },
    /// Show the cheapest announced route between two networks.
    Route {
        #[arg(long)]
        from: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount_msat: u64,
    },
    /// Serve a demo Cassis Order Protocol flow (a coffee counter) with
    /// this node as the payee, printing its `cop:` URI.
    OrderDemo {
        #[arg(long, default_value = "Cassis Coffee")]
        name: String,
    },
    /// List the invoices this node issued.
    Invoices,
    /// List the payments this node made.
    Payments,
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
    let relays = relays(&cli);
    let home = Home::open(cli.home)?;
    let span = info_span!("node", node = "wallet");
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
            bark,
            bark_server,
            bark_esplora,
            max_incoming_lifetime,
        } => {
            let mut enabled = home.networks()?;
            for spec in &networks {
                let network = NetworkId::parse(spec)?;
                if network.kind() == "lightning" && bark {
                    configure_bark(&home, &network, bark_server.clone(), bark_esplora.clone())?;
                } else if network.kind() == "lightning" {
                    configure_lnd(
                        &home,
                        lnd_rest_url.clone(),
                        lnd_tls_cert.clone(),
                        lnd_macaroon.clone(),
                    )?;
                }
                if let Some(secs) = max_incoming_lifetime {
                    home.set_max_incoming_lifetime(&network, secs)?;
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
        Command::Run => {
            let node = serve(&home, &span).await?;
            info!("running as {}; Ctrl-C to stop", node.iroh_peer_id());
            tokio::signal::ctrl_c().await.ok();
            node.shutdown().await;
        }
        Command::Receive {
            amount_msat,
            networks,
            description,
            expires_in,
            wait,
            preimage_server,
            preimage_server_relay,
            claim_window,
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
            let mut serving = None;
            let invoice = if let Some(id) = preimage_server {
                let opened = home.open_networks(&networks, &span).await?;
                create_preimage_server_invoice(
                    &home.store,
                    &home.keys,
                    PeerAddr {
                        id,
                        relay: preimage_server_relay,
                    },
                    &opened,
                    amount_msat,
                    expires_at,
                    description,
                    claim_window,
                )
                .await?
            } else if wait {
                let node = serve(&home, &span).await?;
                let invoice = node
                    .create_invoice(&networks, amount_msat, expires_at, description, None)
                    .await?;
                serving = Some(node);
                invoice
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
                    None,
                )
                .await?
            };
            println!(
                "{}",
                serde_json::to_string(&invoice).map_err(|e| e.to_string())?
            );
            if wait {
                // Some network clients install their own SIGINT handler,
                // so Ctrl-C would not end the process by itself.
                let claimed = tokio::select! {
                    claimed = wait_for_claim(&home, &invoice) => claimed,
                    _ = tokio::signal::ctrl_c() => Err("interrupted".into()),
                };
                if let Err(error) = claimed {
                    if let Some(node) = serving {
                        node.shutdown().await;
                    }
                    return Err(error);
                }
                // A payer that got `Pending` from COMMIT polls again every
                // 5s. Keep the node serving for one more round trip: exiting
                // immediately leaves the payment Pending forever when the
                // payer never receives the preimage.
                tokio::time::sleep(CLAIM_GRACE).await;
                if let Some(node) = serving {
                    node.shutdown().await;
                }
            }
        }
        Command::Redeem {
            preimage_server,
            preimage_server_relay,
            since,
        } => redeem(&home, &span, preimage_server, preimage_server_relay, since).await?,
        Command::Pay { invoice, from } => {
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
            let preimage = node.pay(&invoice, &from, &relays).await;
            node.shutdown().await;
            println!("paid; preimage {}", preimage?);
        }
        Command::Route {
            from,
            to,
            amount_msat,
        } => {
            let announcements = routing::fetch_announcements(&relays).await?;
            let to = NetworkId::parse(&to)?;
            let route = routing::find_route(
                &announcements,
                &NetworkId::parse(&from)?,
                &to,
                amount_msat,
                &Default::default(),
            )?;
            let plan = routing::plan_route(
                &route,
                amount_msat,
                to.default_incoming_delta(),
                None,
                cassis_core::unix_now(),
            )?;
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
        Command::OrderDemo { name } => {
            let node = serve(&home, &span).await?;
            order_demo::run(node, home.keys.order_endpoint_secret(), &name).await?;
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
            for record in home
                .store
                .list::<PreimageServerInvoiceRecord>(PREIMAGE_SERVER_INVOICES)?
            {
                println!(
                    "{} {:>12} msat {:?} expires {} via preimage server {}",
                    record.invoice.payment_hash,
                    record.invoice.amount_msat,
                    record.status,
                    record.invoice.expires_at,
                    record.server.id
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
        Command::Wallet(command) => wallets::run(&home, command, &span).await?,
    }
    Ok(())
}

/// Start the node, serving under its identity, with all its networks.
async fn serve(home: &Home, span: &Span) -> Result<Node, String> {
    let networks = home.open_networks(&home.networks()?, span).await?;
    if networks.is_empty() {
        return Err("no networks enabled; see `cassis-wallet enable`".into());
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

/// How long `invoice --wait` keeps serving after a claim so the payer
/// can collect the preimage from a COMMIT it was told was still pending.
const CLAIM_GRACE: Duration = Duration::from_secs(30);

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

/// `redeem`: claim what preimage servers logged, on the networks of the
/// invoices still unclaimed through each.
async fn redeem(
    home: &Home,
    span: &Span,
    preimage_server: Option<String>,
    preimage_server_relay: Option<String>,
    since: u64,
) -> Result<(), String> {
    let unclaimed: Vec<PreimageServerInvoiceRecord> = home
        .store
        .list::<PreimageServerInvoiceRecord>(PREIMAGE_SERVER_INVOICES)?
        .into_iter()
        .filter(|record| record.status == InvoiceStatus::Pending)
        .collect();
    let mut servers: Vec<PeerAddr> = Vec::new();
    match preimage_server {
        Some(id) => servers.push(PeerAddr {
            id,
            relay: preimage_server_relay,
        }),
        None => {
            for record in &unclaimed {
                if !servers.iter().any(|r| r.id == record.server.id) {
                    servers.push(record.server.clone());
                }
            }
        }
    }
    if servers.is_empty() {
        println!("no unclaimed invoices through a preimage server");
        return Ok(());
    }
    for preimage_server in servers {
        let mut networks: Vec<NetworkId> = Vec::new();
        for record in unclaimed
            .iter()
            .filter(|r| r.server.id == preimage_server.id)
        {
            for entry in &record.invoice.networks {
                if !networks.contains(&entry.network) {
                    networks.push(entry.network.clone());
                }
            }
        }
        let opened = home.open_networks(&networks, span).await?;
        let report = redeem_preimage_server_payments(
            &home.store,
            &home.keys,
            &preimage_server,
            &opened,
            since,
        )
        .await?;
        for (hash, network, amount_msat) in &report.claimed {
            println!("claimed {hash} {amount_msat:>12} msat on {network}");
        }
        for (hash, reason) in &report.pending {
            println!("pending {hash}: {reason}");
        }
        for (hash, reason) in &report.failed {
            println!("failed  {hash}: {reason}");
        }
    }
    Ok(())
}

/// `--nostr-relay`s if given, else the test or default relays.
fn relays(cli: &Cli) -> Vec<String> {
    if !cli.nostr_relays.is_empty() {
        return cli.nostr_relays.clone();
    }
    let defaults = if cli.test_relays {
        TEST_NOSTR_RELAYS
    } else {
        DEFAULT_NOSTR_RELAYS
    };
    defaults.iter().map(|relay| relay.to_string()).collect()
}

#[allow(unused_variables, unreachable_code)]
fn configure_bark(
    home: &Home,
    network: &NetworkId,
    server: Option<String>,
    esplora: Option<String>,
) -> Result<(), String> {
    #[cfg(feature = "bark-lightning")]
    {
        let default = cassis_networks::bark_lightning::BarkConfig::default_for(network);
        let config = cassis_networks::bark_lightning::BarkConfig {
            server_url: server
                .or_else(|| default.as_ref().map(|d| d.server_url.clone()))
                .ok_or_else(|| {
                    format!("{network} has no default Ark server: pass --bark-server")
                })?,
            esplora_url: esplora
                .or_else(|| default.as_ref().map(|d| d.esplora_url.clone()))
                .ok_or_else(|| format!("{network} has no default Esplora: pass --bark-esplora"))?,
        };
        return home.set_bark_config(network, &config);
    }
    Err("this cassis-wallet was built without the 'bark-lightning' feature".into())
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
        home.set_lnd_config(&cassis_networks::lnd::LndConfig::new(
            rest_url, tls_cert, macaroon,
        ))?;
    }
    Ok(())
}
