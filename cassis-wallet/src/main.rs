//! `cassis-wallet`: a Cassis wallet, living in a home directory (see
//! [`home`]). It pays and receives Cassis invoices on its networks and
//! manages each network's funds under a subcommand of its own. Each
//! network is compiled in by the cargo feature of the same name.
//! Routing is `cassis-routerd`'s job.
//!
//! The wallet is stateless between commands: nothing runs in the
//! background. Every command that opens a network first runs its routine
//! checks (see [`home::routine_checks`]); `sync` does only that, and
//! settles the HTLCs this wallet funded.

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

mod order_demo;
mod wallets;

use cassis_core::offline::{
    endpoint_public_key, ReceiveAuthorization, DEFAULT_MIN_FINAL_TIMEOUT_SECS,
};
use cassis_core::protocol::{GatewayInvoiceFor, Request, Response};
use cassis_core::routing::{self, DEFAULT_NOSTR_RELAYS, TEST_NOSTR_RELAYS};
use cassis_core::transport::{PeerAddr, Transport};
use cassis_core::{unix_now, Invoice, NetworkId};
use cassis_wallet::db::{Direction, InvoiceHash, InvoiceState};
use cassis_wallet::node::{
    authorize_gateway, create_gateway_invoice, redeem_offline_payments, OfflineEndpoints,
};
use cassis_wallet::{Home, Node, NodeConfig};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::time::Duration;
use tracing::{info_span, Span};

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
    /// Print the seed phrase the node's identity derives from.
    Seed,
    /// Print the node identity and its networks.
    Info,
    /// Add networks this wallet holds funds on, e.g. `cashu::mint.host`,
    /// `liquid`, `arkade::mutinynet`, `lightning`, each with a fresh key
    /// written to its config.
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
        /// Chain API of `arkade` and `bitcoin` networks, instead of the
        /// public one.
        #[arg(long, value_name = "URL")]
        esplora_url: Option<String>,
    },
    /// Remove networks, and their keys, from this wallet's config.
    Disable {
        #[arg(required = true)]
        networks: Vec<String>,
    },
    /// Run the routine checks of every enabled network and settle the
    /// HTLCs of this wallet's payments (refunding expired ones), and
    /// nothing else.
    Sync,
    /// Create an invoice to receive a payment, and serve the node until
    /// it is paid or expires; with `--gateway`, return at once and claim
    /// with `redeem` later.
    #[command(visible_alias = "invoice")]
    Receive {
        #[arg(long)]
        amount_msat: u64,
        /// Networks it can be paid on (with `--gateway`: the gateway pays
        /// this node on); all of the node's by default.
        #[arg(long = "network")]
        networks: Vec<String>,
        #[arg(long)]
        description: Option<String>,
        #[arg(long, default_value_t = 3600)]
        expires_in: u64,
        #[command(flatten)]
        offline: OfflineArgs,
        /// With `--gateway`: how long the gateway's HTLC to this node
        /// must stay unrefundable after the preimage is released, i.e.
        /// how long this node may stay offline before `redeem`.
        #[arg(long, value_name = "SECS", default_value_t = DEFAULT_MIN_FINAL_TIMEOUT_SECS)]
        min_final_timeout: u64,
    },
    /// Let a gateway issue invoices in this node's name while it is
    /// offline, for hashes a preimage server issues; claim with `redeem`.
    Authorize {
        #[command(flatten)]
        offline: OfflineArgs,
        /// Networks the gateway pays this node on; all of the node's by
        /// default.
        #[arg(long = "network")]
        networks: Vec<String>,
        /// How long the gateway may issue invoices, from now.
        #[arg(long, value_name = "SECS", default_value_t = 30 * 24 * 3600)]
        valid_for: u64,
        #[arg(long, default_value_t = 1000)]
        min_amount_msat: u64,
        #[arg(long)]
        max_amount_msat: u64,
        /// If given, every invoice the gateway issues must say this.
        #[arg(long)]
        description: Option<String>,
        /// How long the gateway's HTLC to this node must stay
        /// unrefundable after the preimage is released.
        #[arg(long, value_name = "SECS", default_value_t = DEFAULT_MIN_FINAL_TIMEOUT_SECS)]
        min_final_timeout: u64,
    },
    /// Ask a gateway for an invoice paying an offline payee that
    /// authorized it (see `authorize`).
    RequestInvoice {
        /// Iroh id of the gateway.
        #[arg(long, value_name = "ID")]
        gateway: String,
        #[arg(long, value_name = "URL")]
        gateway_relay: Option<String>,
        /// The payee's key, its iroh id (see `info`).
        #[arg(long, value_name = "KEY")]
        payee: String,
        #[arg(long)]
        amount_msat: u64,
        #[arg(long)]
        description: Option<String>,
        /// The gateway's default when absent.
        #[arg(long)]
        expires_in: Option<u64>,
    },
    /// Fetch the HTLCs gateways funded to this node from the preimage
    /// servers that logged them, and claim them before they expire.
    Redeem {
        /// Only this preimage server; by default every one this node
        /// receives through.
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
    /// List the money that moved in and out of this wallet, and the
    /// payments still in flight.
    Payments,
    #[command(flatten)]
    Wallet(wallets::Command),
}

/// The gateway and preimage server to receive offline through.
#[derive(clap::Args)]
struct OfflineArgs {
    /// Iroh id of a gateway to be paid in this node's place, so this
    /// node can stay offline. It pays this node on with an HTLC once
    /// paid.
    #[arg(long, value_name = "ID", requires = "preimage_server")]
    gateway: Option<String>,
    #[arg(long, value_name = "URL", requires = "gateway")]
    gateway_relay: Option<String>,
    /// Iroh id of the preimage server that picks the payment hash and
    /// releases the preimage to the gateway once it paid this node.
    #[arg(
        long = "preimage-server",
        visible_alias = "ps",
        value_name = "ID",
        requires = "gateway"
    )]
    preimage_server: Option<String>,
    #[arg(
        long = "preimage-server-relay",
        visible_alias = "ps-relay",
        value_name = "URL",
        requires = "preimage_server"
    )]
    preimage_server_relay: Option<String>,
}

impl OfflineArgs {
    fn endpoints(self) -> Option<OfflineEndpoints> {
        Some(OfflineEndpoints {
            gateway: PeerAddr {
                id: self.gateway?,
                relay: self.gateway_relay,
            },
            preimage_server: PeerAddr {
                id: self.preimage_server?,
                relay: self.preimage_server_relay,
            },
        })
    }
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
    let mut home = Home::open(cli.home)?;
    let span = info_span!("node", node = "wallet");
    match cli.command {
        Command::Seed => println!("{}", home.mnemonic()),
        Command::Info => {
            println!("node pubkey: {}", home.keys.node.pubkey().to_hex());
            println!(
                "payee key (iroh id): {}",
                endpoint_public_key(&home.keys.iroh)
            );
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
            esplora_url,
        } => {
            for spec in &networks {
                let network = NetworkId::parse(spec)?;
                home.enable(&network, |table| {
                    if let Some(url) = &esplora_url {
                        table.insert("esplora_url", toml_edit::value(url.as_str()));
                    }
                    if network.kind() == "lightning" && bark {
                        let mut config = toml_edit::InlineTable::new();
                        if let Some(server) = &bark_server {
                            config.insert("server_url", server.as_str().into());
                        }
                        if let Some(esplora) = &bark_esplora {
                            config.insert("esplora_url", esplora.as_str().into());
                        }
                        table.insert("bark", toml_edit::value(config));
                    } else if network.kind() == "lightning" {
                        if let Some(rest_url) = &lnd_rest_url {
                            let mut config = toml_edit::InlineTable::new();
                            config.insert("rest_url", rest_url.as_str().into());
                            for (key, path) in [
                                ("tls_cert_path", &lnd_tls_cert),
                                ("macaroon_path", &lnd_macaroon),
                            ] {
                                if let Some(path) = path {
                                    config.insert(key, path.display().to_string().into());
                                }
                            }
                            table.insert("lnd", toml_edit::value(config));
                        }
                    }
                    Ok(())
                })?;
                // Fail early on networks this binary cannot open.
                home.open_network(&network, &span).await?;
            }
        }
        Command::Disable { networks } => {
            let remove = networks
                .iter()
                .map(|spec| NetworkId::parse(spec))
                .collect::<Result<Vec<_>, _>>()?;
            home.disable(&remove)?;
        }
        Command::Sync => {
            let networks = home.open_networks(&home.networks()?, &span).await?;
            let node = Node::start(
                NodeConfig {
                    keys: home.keys.clone(),
                    db: home.db.clone(),
                    span,
                    serve: false,
                },
                networks,
            )
            .await?;
            node.settle_once().await;
            node.shutdown().await;
        }
        Command::Receive {
            amount_msat,
            networks,
            description,
            expires_in,
            offline,
            min_final_timeout,
        } => {
            let networks = parse_networks(&home, &networks)?;
            let expires_at = unix_now() + expires_in;
            if let Some(endpoints) = offline.endpoints() {
                let opened = home.open_networks(&networks, &span).await?;
                let transport = Transport::bind_client(home.keys.iroh).await?;
                let invoice = create_gateway_invoice(
                    &home.db,
                    &home.keys,
                    &transport,
                    endpoints,
                    &opened,
                    amount_msat,
                    expires_at,
                    description,
                    None,
                    min_final_timeout,
                )
                .await;
                transport.close().await;
                print_invoice(&invoice?)?;
                return Ok(());
            }
            let node = serve(&home, &span).await?;
            let invoice = node
                .create_invoice(&networks, amount_msat, expires_at, description, None)
                .await?;
            print_invoice(&invoice)?;
            // Some network clients install their own SIGINT handler,
            // so Ctrl-C would not end the process by itself.
            let claimed = tokio::select! {
                claimed = wait_for_claim(&home, &invoice) => claimed,
                _ = tokio::signal::ctrl_c() => Err("interrupted".into()),
            };
            if claimed.is_ok() {
                // A payer that got `Pending` from COMMIT polls again every
                // 5s. Keep the node serving for one more round trip: exiting
                // immediately leaves the payment Pending forever when the
                // payer never receives the preimage.
                tokio::time::sleep(CLAIM_GRACE).await;
            }
            node.shutdown().await;
            claimed?;
        }
        Command::Authorize {
            offline,
            networks,
            valid_for,
            min_amount_msat,
            max_amount_msat,
            description,
            min_final_timeout,
        } => {
            let endpoints = offline
                .endpoints()
                .ok_or("authorize needs --gateway and --preimage-server")?;
            let networks = parse_networks(&home, &networks)?;
            let opened = home.open_networks(&networks, &span).await?;
            let now = unix_now();
            let transport = Transport::bind_client(home.keys.iroh).await?;
            let authorization = authorize_gateway(
                &home.db,
                &home.keys,
                &transport,
                endpoints,
                &opened,
                now,
                now + valid_for,
                min_amount_msat,
                max_amount_msat,
                min_final_timeout,
                description,
            )
            .await;
            transport.close().await;
            let authorization = authorization?;
            println!(
                "{}",
                serde_json::to_string(&authorization).map_err(|e| e.to_string())?
            );
        }
        Command::RequestInvoice {
            gateway,
            gateway_relay,
            payee,
            amount_msat,
            description,
            expires_in,
        } => {
            let transport = Transport::bind(None).await?;
            let request = Request::GatewayInvoiceFor(GatewayInvoiceFor {
                payee: payee
                    .trim()
                    .parse()
                    .map_err(|e| format!("payee key {payee}: {e}"))?,
                amount_msat,
                expires_at: expires_in.map(|secs| unix_now() + secs),
                description,
                metadata: None,
            });
            let answer = transport
                .request(
                    &PeerAddr {
                        id: gateway,
                        relay: gateway_relay,
                    },
                    &request,
                )
                .await;
            transport.close().await;
            let invoice = match answer? {
                Response::GatewayInvoice(Ok(invoice)) => invoice,
                Response::GatewayInvoice(Err(reason)) | Response::Error(reason) => {
                    return Err(format!("gateway refused: {reason}"))
                }
                other => return Err(format!("unexpected answer from gateway: {other:?}")),
            };
            invoice.verify()?;
            print_invoice(&invoice)?;
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
                    db: home.db.clone(),
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
            for invoice in home.db.invoices().all().map_err(|e| e.to_string())? {
                let via = invoice
                    .delegation
                    .as_ref()
                    .map(|delegation| format!(" via gateway {}", delegation.gateway))
                    .unwrap_or_default();
                println!(
                    "{} {:>12} msat {:?} expires {}{via}",
                    invoice.payment_hash.0, invoice.amount_msat, invoice.state, invoice.expires_at
                );
            }
            for delegation in home
                .db
                .full_delegations()
                .all()
                .map_err(|e| e.to_string())?
            {
                let authorization = &delegation.authorization;
                println!(
                    "standing: {}..{} msat until {} via gateway {}",
                    authorization.min_amount_msat,
                    authorization.max_amount_msat,
                    authorization.valid_until,
                    delegation.gateway
                );
            }
        }
        Command::Payments => {
            for transaction in home.db.transactions().all().map_err(|e| e.to_string())? {
                let direction = match transaction.direction {
                    Direction::Incoming => "in ",
                    Direction::Outgoing => "out",
                };
                println!(
                    "{} {direction} {:>12} msat on {} at {}",
                    transaction.payment_hash.0,
                    transaction.amount_msat,
                    transaction.network,
                    transaction.at
                );
            }
            for payment in home
                .db
                .pending_payments()
                .all()
                .map_err(|e| e.to_string())?
            {
                println!(
                    "{} out {:>12} msat on {} pending until {}",
                    payment.payment_hash.0,
                    payment.htlc.amount_msat,
                    payment.network,
                    payment.htlc.expiry
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
            db: home.db.clone(),
            span: span.clone(),
            serve: true,
        },
        networks,
    )
    .await
}

fn print_invoice(invoice: &Invoice) -> Result<(), String> {
    println!(
        "{}",
        serde_json::to_string(invoice).map_err(|e| e.to_string())?
    );
    Ok(())
}

/// How long `receive` keeps serving after a claim so the payer
/// can collect the preimage from a COMMIT it was told was still pending.
const CLAIM_GRACE: Duration = Duration::from_secs(30);

async fn wait_for_claim(home: &Home, invoice: &Invoice) -> Result<(), String> {
    let key = InvoiceHash(invoice.body.payment_hash.to_string());
    loop {
        let record = home
            .db
            .invoices()
            .get(key.clone())
            .map_err(|e| e.to_string())?
            .ok_or("invoice disappeared")?;
        match record.state {
            InvoiceState::Settled => {
                println!("claimed");
                return Ok(());
            }
            InvoiceState::Expired => return Err("invoice expired".into()),
            InvoiceState::Waiting => tokio::time::sleep(Duration::from_secs(1)).await,
        }
    }
}

/// `redeem`: claim what preimage servers logged, on the networks this
/// node named to gateways under each.
async fn redeem(
    home: &Home,
    span: &Span,
    preimage_server: Option<String>,
    preimage_server_relay: Option<String>,
    since: u64,
) -> Result<(), String> {
    // Every preimage server this node receives through, with the
    // networks it was paid on there: those of its delegated invoices
    // still waiting, and of its full delegations.
    let mut servers: Vec<(PeerAddr, Vec<NetworkId>)> = Vec::new();
    let mut add = |server: PeerAddr, authorization: ReceiveAuthorization| {
        let index = match servers.iter().position(|(known, _)| known.id == server.id) {
            Some(index) => index,
            None => {
                servers.push((server, Vec::new()));
                servers.len() - 1
            }
        };
        for destination in authorization.destinations {
            if !servers[index].1.contains(destination.network()) {
                servers[index].1.push(destination.network().clone());
            }
        }
    };
    let invoices = home
        .db
        .invoices()
        .range_by_to_check_on_preimage_server(..)
        .map_err(|e| e.to_string())?;
    for delegation in invoices
        .into_iter()
        .filter_map(|invoice| invoice.delegation)
    {
        let authorization: ReceiveAuthorization = (&delegation.authorization).try_into()?;
        add(
            PeerAddr {
                id: delegation.preimage_server,
                relay: authorization.preimage_server_relay.clone(),
            },
            authorization,
        );
    }
    for delegation in home
        .db
        .full_delegations()
        .all()
        .map_err(|e| e.to_string())?
    {
        let authorization: ReceiveAuthorization = (&delegation.authorization).try_into()?;
        add(
            PeerAddr {
                id: delegation.preimage_server,
                relay: authorization.preimage_server_relay.clone(),
            },
            authorization,
        );
    }
    if let Some(id) = preimage_server {
        servers.retain(|(server, _)| server.id == id);
        match servers.first_mut() {
            Some((server, _)) => server.relay = preimage_server_relay.or(server.relay.take()),
            None => servers.push((
                PeerAddr {
                    id,
                    relay: preimage_server_relay,
                },
                home.networks()?,
            )),
        }
    }
    if servers.is_empty() {
        println!("this node receives through no preimage server");
        return Ok(());
    }
    let transport = Transport::bind_client(home.keys.iroh).await?;
    let result = redeem_from(home, &transport, servers, since, span).await;
    transport.close().await;
    result
}

/// Claim what each of `servers` logged for this node since `since`.
async fn redeem_from(
    home: &Home,
    transport: &Transport,
    servers: Vec<(PeerAddr, Vec<NetworkId>)>,
    since: u64,
    span: &Span,
) -> Result<(), String> {
    for (preimage_server, networks) in servers {
        let opened = home.open_networks(&networks, span).await?;
        let report = redeem_offline_payments(
            &home.db,
            &home.keys,
            transport,
            &preimage_server,
            &opened,
            since,
        )
        .await?;
        for (hash, network, amount_msat) in &report.claimed {
            println!("claimed {hash} {amount_msat:>12} msat on {network}");
        }
        for (hash, metadata) in &report.metadata {
            println!(
                "        {hash} metadata {}",
                serde_json::to_string(metadata).map_err(|e| e.to_string())?
            );
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

/// `specs` parsed, or every network of the node when empty.
fn parse_networks(home: &Home, specs: &[String]) -> Result<Vec<NetworkId>, String> {
    if specs.is_empty() {
        return home.networks();
    }
    specs.iter().map(|spec| NetworkId::parse(spec)).collect()
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
