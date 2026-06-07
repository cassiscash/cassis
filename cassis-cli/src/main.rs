mod adapters;
mod cli;
mod paths;
mod seed_store;
mod store;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use cassis_client::ReceiveFlowError;
use cassis_core::{Bytes32, Invoice, NetworkId, NetworkReceiverAdapter, PaymentStatus};
use cassis_iroh::{Frame, IrohServer};
use cassis_keys as keys;
use clap::Parser;
use log::{error, info, warn};
use rand::RngCore;
use sha2::{Digest, Sha256};

#[cfg(feature = "cashu")]
use cli::CashuCommands;
use cli::{Cli, Commands, InvoicesCommands, NetSpec, SeedCommands};
#[cfg(feature = "cashu")]
use store::CashuProofRow;
use store::{InvoiceRow, InvoiceStatus, Store, StoreError};

#[tokio::main]
async fn main() {
    cassis_core::logging::init_logging();

    if let Err(e) = rustls::crypto::aws_lc_rs::default_provider().install_default() {
        error!(target: "cassis_cli", "failed to install rustls provider: {e:?}");
        std::process::exit(2);
    }

    let cli = Cli::parse();
    let result: Result<(), String> = match cli.command {
        Commands::Pay {
            invoice,
            from,
            nostr_relay,
        } => cmd_pay(invoice, from, nostr_relay).await,
        Commands::Invoice {
            amount,
            network,
            payee,
            description,
            expires_at,
            wait,
            timeout,
        } => {
            cmd_invoice(
                amount,
                network,
                payee,
                description,
                expires_at,
                wait,
                timeout,
            )
            .await
        }
        Commands::Receive => cmd_receive().await,
        Commands::Invoices { command } => match command {
            InvoicesCommands::List { status } => cmd_invoices_list(status),
            InvoicesCommands::Show { payment_hash } => cmd_invoices_show(payment_hash),
        },
        Commands::Route {
            destination_pubkey,
            amount,
            from,
            nostr_relay,
        } => cmd_route(destination_pubkey, amount, from, nostr_relay).await,
        Commands::Node { command } => match command {
            cli::NodeCommands::Info => {
                println!("node info: use `cassis-cli seed show` and `cassis-cli invoices list`");
                Ok(())
            }
        },
        Commands::Seed { command } => match command {
            SeedCommands::Init { force } => cmd_seed_init(force),
            SeedCommands::Show => cmd_seed_show(),
        },
        Commands::Register { network } => cmd_register(network),
        #[cfg(feature = "cashu")]
        Commands::Cashu { command } => match command {
            CashuCommands::Send { network, amount } => cmd_cashu_send(network, amount).await,
            CashuCommands::Receive { network, proof } => cmd_cashu_receive(network, proof).await,
            CashuCommands::Balance { network } => cmd_cashu_balance(network).await,
        },
    };
    if let Err(e) = result {
        error!(target: "cassis_cli", "{e}");
        std::process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn open_store() -> Result<Store, String> {
    let path = paths::store_path();
    Store::open(&path).map_err(|e| format!("opening store at {}: {e}", path.display()))
}

fn load_mnemonic() -> Result<String, String> {
    let path = paths::cassis_home().join(seed_store::SEED_FILENAME);
    if !path.exists() {
        return Err(format!(
            "no seed file at {}; run `cassis-cli seed init` first",
            path.display()
        ));
    }
    seed_store::read_mnemonic(&path)
        .map_err(|e| format!("reading seed from {}: {e}", path.display()))
}

fn derive_for(mnemonic: &str, specs: &[NetSpec]) -> Result<keys::DerivedKeys, String> {
    let ids: Vec<NetworkId> = specs.iter().map(|s| s.network_id()).collect();
    keys::derive_keys(mnemonic, ids).map_err(|e| format!("deriving keys: {e}"))
}

fn map_store_err(e: StoreError) -> String {
    e.to_string()
}

fn map_sql_err(e: minisqlite::Error) -> String {
    e.to_string()
}

fn map_recv_err(e: ReceiveFlowError) -> String {
    e.to_string()
}

// ---------------------------------------------------------------------------
// pay
// ---------------------------------------------------------------------------

async fn cmd_pay(
    invoice_str: String,
    from: String,
    nostr_relays: Vec<String>,
) -> Result<(), String> {
    let invoice: Invoice =
        serde_json::from_str(&invoice_str).map_err(|e| format!("invalid invoice JSON: {e}"))?;
    let sender_network = NetworkId(from.clone());
    let dest_network = invoice
        .networks
        .first()
        .cloned()
        .ok_or_else(|| "invoice has no network hints".to_string())?;
    info!(
        target: "cassis_cli",
        "routing to network {dest_network} (payee {})",
        invoice.payee,
    );
    let relays = if nostr_relays.is_empty() {
        cli::default_nostr_relays()
    } else {
        nostr_relays
    };
    let route =
        cassis_client::find_route(&relays, &dest_network, invoice.amount_msat, &sender_network)
            .await
            .map_err(|e| format!("route lookup: {e}"))?;
    if route.is_empty() {
        return Err("empty route".to_string());
    }
    info!(
        target: "cassis_cli",
        "paying {} msat via {} hop(s) from {}",
        invoice.amount_msat,
        route.len(),
        sender_network,
    );
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

    let net_spec = NetSpec::parse(&from)?;
    let specs = vec![net_spec];
    let mnemonic = load_mnemonic()?;
    let derived = derive_for(&mnemonic, &specs)?;
    let senders = adapters::build_senders(&specs, &derived).await?;
    let client = cassis_client::CassisClient::new(senders, relays).await;
    info!(
        target: "cassis_cli",
        "PREPARE/DISPATCH/COMMIT for payment_hash={}",
        invoice.payment_hash,
    );
    let result = client
        .pay(invoice, sender_network)
        .await
        .map_err(|e| format!("pay: {e}"))?;
    match result.status {
        PaymentStatus::Completed => {
            println!("status:       completed");
            if let Some(preimage) = result.preimage {
                println!("preimage:     {preimage}");
            }
        }
        PaymentStatus::Refunded => {
            println!("status:       refunded (deadline exceeded)");
        }
        PaymentStatus::Failed => {
            println!("status:       failed");
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// invoice
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn cmd_invoice(
    amount: u64,
    network: String,
    payee: Option<String>,
    description: Option<String>,
    expires_at: Option<u64>,
    wait: bool,
    timeout: u64,
) -> Result<(), String> {
    let net_spec = NetSpec::parse(&network)?;
    let network_id = net_spec.network_id();
    let preimage = generate_preimage();
    let payment_hash = hash_preimage(preimage);
    let now = unix_now();
    let ttl = 600u64;
    let invoice_expiry = expires_at.unwrap_or(now + ttl);

    // Derive the iroh endpoint info so the payer can dial
    // the COMMIT directly. Empty network id is fine when the
    // CLI doesn't need to publish an iroh endpoint (e.g.
    // single-process tests) but for production flows we
    // always include it.
    let mnemonic = load_mnemonic()?;
    let specs = vec![net_spec.clone()];
    let derived = derive_for(&mnemonic, &specs)?;
    let (iroh_peer_id, iroh_relay) = iroh_endpoint_info(&derived.iroh).await?;

    let mut store = open_store()?;
    let row = InvoiceRow {
        payment_hash: Bytes32(payment_hash),
        preimage,
        amount_msat: amount,
        network_id: network_id.clone(),
        payee: payee.clone(),
        description: description.clone(),
        expires_at: invoice_expiry,
        status: InvoiceStatus::Pending,
        created_at: now,
        claimed_at: None,
    };
    store.insert_invoice(&row).map_err(map_store_err)?;
    let invoice = Invoice {
        payment_hash: Bytes32(payment_hash),
        amount_msat: amount,
        payee: payee.unwrap_or_else(|| network_id.0.clone()),
        expires_at: invoice_expiry,
        networks: vec![network_id.clone()],
        description,
        iroh_peer_id: Some(iroh_peer_id),
        iroh_relay: Some(iroh_relay),
    };
    println!("payment_hash: {}", Bytes32(payment_hash));
    println!("preimage:     {}", lowercase_hex::encode(preimage));
    println!("network:      {network_id}");
    println!("amount_msat:  {amount}");
    println!("expires_at:   {invoice_expiry}");
    println!("status:       pending (persisted)");
    if let Ok(json) = serde_json::to_string(&invoice) {
        println!("invoice_json: {json}");
    }
    if !wait {
        return Ok(());
    }
    info!(target: "cassis_cli", "waiting for COMMIT or upstream fund (timeout={timeout}s)...");
    let receivers = adapters::build_receivers(&specs, &derived).await?;
    let client = cassis_client::CassisClient::with_receivers(
        HashMap::new(),
        receivers,
        cli::default_nostr_relays(),
    )
    .await;
    let deadline = now.saturating_add(timeout);
    let preimage_seen = client
        .wait_for_incoming(&network_id, Bytes32(payment_hash), deadline)
        .await
        .map_err(map_recv_err)?;
    client
        .claim_invoice(&network_id, Bytes32(payment_hash), preimage_seen)
        .await
        .map_err(map_recv_err)?;
    store
        .mark_status(&Bytes32(payment_hash), InvoiceStatus::Claimed)
        .map_err(map_store_err)?;
    println!("status:       claimed");
    Ok(())
}

/// Bind an iroh endpoint with the same identity the node will
/// later use as a COMMIT receiver, and return its public peer
/// id and home relay. Used to populate [`Invoice::iroh_peer_id`]
/// and [`Invoice::iroh_relay`].
async fn iroh_endpoint_info(secret: &iroh::SecretKey) -> Result<(String, String), String> {
    let (server, _) = IrohServer::new(secret.clone())
        .await
        .map_err(|e| format!("bind iroh endpoint: {e}"))?;
    let peer_id = server.peer_id().to_string();
    let relay = server
        .home_relay()
        .map(|s| s.to_string())
        .unwrap_or_else(|| cassis_iroh::DEFAULT_IROH_RELAY.to_string());
    // Drop the server; we just wanted the identity / relay.
    Ok((peer_id, relay))
}

fn generate_preimage() -> [u8; 32] {
    let mut preimage = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut preimage);
    preimage
}

fn hash_preimage(preimage: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(preimage);
    let out = hasher.finalize();
    let mut out32 = [0u8; 32];
    out32.copy_from_slice(&out);
    out32
}

fn parse_payment_hash(s: &str) -> Result<Bytes32, String> {
    let s = s.trim();
    if s.len() != 64 {
        return Err(format!(
            "payment hash must be 64 hex chars, got {}",
            s.len()
        ));
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hex = std::str::from_utf8(chunk).map_err(|e| e.to_string())?;
        out[i] = u8::from_str_radix(hex, 16).map_err(|e| e.to_string())?;
    }
    Ok(Bytes32(out))
}

// ---------------------------------------------------------------------------
// receive (long-running)
// ---------------------------------------------------------------------------

async fn cmd_receive() -> Result<(), String> {
    let mnemonic = load_mnemonic()?;
    let mut store = open_store()?;

    let registered = load_registered_networks(&mut store)?;
    if registered.is_empty() {
        return Err(
            "no networks registered; run `cassis-cli register --network <spec>` first".to_string(),
        );
    }

    let specs: Vec<NetSpec> = registered
        .iter()
        .map(|raw| NetSpec::parse(raw))
        .collect::<Result<Vec<_>, _>>()?;
    let ids: Vec<NetworkId> = specs.iter().map(|s| s.network_id()).collect();
    let derived = keys::derive_keys(&mnemonic, ids).map_err(|e| e.to_string())?;
    let receivers = adapters::build_receivers(&specs, &derived).await?;
    let pending: Vec<InvoiceRow> = store
        .list(Some(InvoiceStatus::Pending))
        .map_err(map_store_err)?
        .into_iter()
        .filter(|r| specs.iter().any(|s| s.network_id() == r.network_id))
        .collect();
    info!(
        target: "cassis_cli",
        "receive: {} network(s), {} pending invoice(s)",
        receivers.len(),
        pending.len()
    );

    let receiver_map: Arc<HashMap<NetworkId, Arc<dyn NetworkReceiverAdapter>>> =
        Arc::new(receivers);

    // Run the COMMIT-handler iroh server in the background.
    // It owns its own copy of the receiver map.
    let commit_receivers = receiver_map.clone();
    let commit_secret = derived.iroh.clone();
    let (iroh_server, iroh_secret) = IrohServer::new(commit_secret)
        .await
        .map_err(|e| format!("bind iroh endpoint: {e}"))?;
    let iroh_peer_id = iroh_secret.public().to_string();
    let iroh_relay = iroh_server
        .home_relay()
        .map(|s| s.to_string())
        .unwrap_or_else(|| cassis_iroh::DEFAULT_IROH_RELAY.to_string());
    info!(
        target: "cassis_cli",
        "receive: listening for COMMIT on iroh peer_id={iroh_peer_id} relay={iroh_relay}"
    );
    let commit_handler_receivers = commit_receivers.clone();
    let commit_handler_store_path = paths::store_path();
    tokio::spawn(async move {
        let handler = Arc::new(move |frame: Frame| {
            let receivers = commit_handler_receivers.clone();
            let store_path = commit_handler_store_path.clone();
            Box::pin(async move { handle_commit_frame(frame, receivers, store_path).await })
                as std::pin::Pin<
                    Box<
                        dyn std::future::Future<Output = Result<Frame, cassis_iroh::IrohError>>
                            + Send,
                    >,
                >
        });
        if let Err(e) = iroh_server.run(handler).await {
            error!(target: "cassis_cli", "iroh server error: {e}");
        }
    });

    // Also claim any pending invoices via the legacy
    // watch_incoming path (single-process / direct-sender
    // case). The COMMIT flow covers the multi-hop case.
    let mut tasks = Vec::new();
    for row in pending {
        let receiver_map = receiver_map.clone();
        let store_path = paths::store_path();
        tasks.push(tokio::spawn(async move {
            if let Err(e) = claim_one(&store_path, &receiver_map, row).await {
                warn!(target: "cassis_cli", "claim failed: {e}");
            }
        }));
    }
    for t in tasks {
        let _ = t.await;
    }
    println!("receive: ready (peer_id={iroh_peer_id}); use Ctrl-C to stop");
    println!("receive: COMMIT handler running in background; pending invoices processed");
    // Block until Ctrl-C: the COMMIT handler keeps the
    // process alive via the spawned iroh server task.
    tokio::signal::ctrl_c().await.ok();
    info!(target: "cassis_cli", "shutting down");
    Ok(())
}

/// COMMIT handler used by `cmd_receive`. On a Commit frame:
/// look up the local invoice, verify the descriptor is for
/// the right payment hash, claim the incoming HTLC on the
/// receiver adapter with the stored preimage, mark the
/// invoice claimed, and return a Committed frame.
async fn handle_commit_frame(
    frame: Frame,
    receivers: Arc<HashMap<NetworkId, Arc<dyn NetworkReceiverAdapter>>>,
    store_path: std::path::PathBuf,
) -> Result<Frame, cassis_iroh::IrohError> {
    let commit = match frame {
        Frame::Commit(c) => c,
        other => {
            return Err(cassis_iroh::IrohError::Protocol(format!(
                "payee expected Commit, got {:?}",
                other
            )))
        }
    };
    info!(
        target: "cassis_cli",
        "COMMIT received: payment_hash={} amount={} msat network={}",
        commit.payment_hash, commit.amount_msat, commit.network
    );
    // Open the store, do the synchronous lookup, and close
    // before any async work — the underlying minisqlite
    // engine is not Send, so we can't hold the Store across
    // an await. Captured only what we need: the stored
    // preimage.
    let preimage = {
        let mut store = Store::open(&store_path)
            .map_err(|e| cassis_iroh::IrohError::Protocol(format!("opening store: {e}")))?;
        let row = store.get(&commit.payment_hash).map_err(|e| {
            cassis_iroh::IrohError::Protocol(format!(
                "no local invoice for {}: {e}",
                commit.payment_hash
            ))
        })?;
        if row.network_id != commit.network {
            return Err(cassis_iroh::IrohError::Protocol(format!(
                "COMMIT network mismatch: invoice says {}, COMMIT says {}",
                row.network_id, commit.network
            )));
        }
        if row.amount_msat != commit.amount_msat {
            return Err(cassis_iroh::IrohError::Protocol(format!(
                "COMMIT amount mismatch: invoice says {}, COMMIT says {}",
                row.amount_msat, commit.amount_msat
            )));
        }
        row.preimage
    };
    let receiver = receivers.get(&commit.network).ok_or_else(|| {
        cassis_iroh::IrohError::Protocol(format!("no receiver adapter for {}", commit.network))
    })?;
    // Hand the descriptor to the adapter so it can find the
    // HTLC; then claim with the locally-stored preimage.
    receiver
        .accept_incoming_via_descriptor(
            commit.payment_hash,
            &commit.incoming_descriptor,
            commit.incoming_deadline,
        )
        .await
        .map_err(|e| cassis_iroh::IrohError::Protocol(format!("accept incoming htlc: {e}")))?;
    receiver
        .claim_incoming(commit.payment_hash, Bytes32(preimage))
        .await
        .map_err(|e| cassis_iroh::IrohError::Protocol(format!("claim_incoming: {e}")))?;
    // Mark claimed in a fresh short-lived store handle.
    let mut store = Store::open(&store_path)
        .map_err(|e| cassis_iroh::IrohError::Protocol(format!("reopen store: {e}")))?;
    store
        .mark_status(&commit.payment_hash, InvoiceStatus::Claimed)
        .map_err(|e| cassis_iroh::IrohError::Protocol(format!("store: {e}")))?;
    info!(
        target: "cassis_cli",
        "COMMIT handled: claimed {} on {}",
        commit.payment_hash, commit.network
    );
    Ok(Frame::Committed(cassis_core::HopCommitted {
        payment_hash: commit.payment_hash,
        preimage: Bytes32(preimage),
    }))
}

async fn claim_one(
    store_path: &std::path::Path,
    receivers: &HashMap<NetworkId, Arc<dyn NetworkReceiverAdapter>>,
    row: InvoiceRow,
) -> Result<(), String> {
    let receiver = receivers
        .get(&row.network_id)
        .ok_or_else(|| format!("no receiver for {}", row.network_id))?;
    let deadline = row.expires_at.min(unix_now().saturating_add(3600));
    let preimage = receiver
        .watch_incoming(row.payment_hash, deadline)
        .await
        .map_err(|e| e.to_string())?;
    receiver
        .claim_incoming(row.payment_hash, preimage)
        .await
        .map_err(|e| e.to_string())?;
    let mut store = Store::open(store_path).map_err(map_store_err)?;
    store
        .mark_status(&row.payment_hash, InvoiceStatus::Claimed)
        .map_err(map_store_err)?;
    info!(
        target: "cassis_cli",
        "claimed {} on {}",
        row.payment_hash, row.network_id
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// invoices list / show
// ---------------------------------------------------------------------------

fn cmd_invoices_list(status_str: Option<String>) -> Result<(), String> {
    let mut store = open_store()?;
    let status = match status_str.as_deref() {
        None => None,
        Some("pending") => Some(InvoiceStatus::Pending),
        Some("claimed") => Some(InvoiceStatus::Claimed),
        Some("failed") => Some(InvoiceStatus::Failed),
        Some(other) => return Err(format!("unknown status filter '{other}'")),
    };
    let rows = store.list(status).map_err(map_store_err)?;
    if rows.is_empty() {
        println!("(no invoices)");
        return Ok(());
    }
    println!(
        "{:<66} {:>12}  {:<10}  {:<8}  {}",
        "payment_hash", "amount_msat", "network", "status", "created_at"
    );
    for r in &rows {
        println!(
            "{:<66} {:>12}  {:<10}  {:<8}  {}",
            r.payment_hash.to_string(),
            r.amount_msat,
            r.network_id.0,
            r.status.as_str(),
            r.created_at,
        );
    }
    Ok(())
}

fn cmd_invoices_show(payment_hash_str: String) -> Result<(), String> {
    let ph = parse_payment_hash(&payment_hash_str)?;
    let mut store = open_store()?;
    let row = store.get(&ph).map_err(map_store_err)?;
    println!("payment_hash: {}", row.payment_hash);
    println!("preimage:     {}", lowercase_hex::encode(row.preimage));
    println!("amount_msat:  {}", row.amount_msat);
    println!("network:      {}", row.network_id);
    println!("payee:        {}", row.payee.as_deref().unwrap_or("-"));
    println!(
        "description:  {}",
        row.description.as_deref().unwrap_or("-")
    );
    println!("expires_at:   {}", row.expires_at);
    println!("status:       {}", row.status.as_str());
    println!("created_at:   {}", row.created_at);
    println!(
        "claimed_at:   {}",
        row.claimed_at
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".to_string())
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// route
// ---------------------------------------------------------------------------

async fn cmd_route(
    destination_pubkey: String,
    amount: u64,
    from: String,
    nostr_relay: Vec<String>,
) -> Result<(), String> {
    let sender_network = NetworkId(from);
    let dest_network = NetworkId(destination_pubkey);
    let relays = if nostr_relay.is_empty() {
        cli::default_nostr_relays()
    } else {
        nostr_relay
    };
    info!(target: "cassis_cli", "fetching route announcements from {} relay(s)...", relays.len());
    let route = cassis_client::find_route(&relays, &dest_network, amount, &sender_network)
        .await
        .map_err(|e| format!("route lookup: {e}"))?;
    if route.is_empty() {
        return Err("empty route".to_string());
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
    Ok(())
}

// ---------------------------------------------------------------------------
// seed init / show
// ---------------------------------------------------------------------------

fn cmd_seed_init(force: bool) -> Result<(), String> {
    let home = paths::ensure_cassis_home().map_err(|e| format!("creating cassis home: {e}"))?;
    let path = seed_store::seed_path(&home);
    let mnemonic = keys::generate_mnemonic().map_err(|e| e.to_string())?;
    seed_store::write_mnemonic(&path, &mnemonic, force)
        .map_err(|e| format!("writing seed to {}: {e}", path.display()))?;
    println!("wrote 12-word mnemonic to {}", path.display());
    println!("backup this phrase — losing it means losing access to all derived keys.");
    Ok(())
}

fn cmd_seed_show() -> Result<(), String> {
    let mnemonic = load_mnemonic()?;
    println!("{mnemonic}");
    Ok(())
}

// ---------------------------------------------------------------------------
// register
// ---------------------------------------------------------------------------

fn cmd_register(specs: Vec<String>) -> Result<(), String> {
    if specs.is_empty() {
        return Err("at least one --network spec is required".to_string());
    }
    let mut store = open_store()?;
    paths::ensure_cassis_home().map_err(|e| e.to_string())?;
    let mut existing = load_registered_networks(&mut store)?;
    for raw in specs {
        let parsed = NetSpec::parse(&raw)?;
        let id = parsed.network_id().0;
        if !existing.iter().any(|e| e == &id) {
            existing.push(id);
        }
    }
    save_registered_networks(&mut store, &existing)?;
    println!("registered networks:");
    for e in &existing {
        println!("  - {e}");
    }
    Ok(())
}

fn load_registered_networks(store: &mut Store) -> Result<Vec<String>, String> {
    use minisqlite::Value;
    store
        .conn()
        .execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);")
        .map_err(map_sql_err)?;
    let result = store
        .conn()
        .query("SELECT value FROM meta WHERE key='networks';")
        .map_err(map_sql_err)?;
    let raw = match result.rows.first().and_then(|r| r.first()) {
        Some(Value::Text(s)) => s.clone(),
        _ => return Ok(Vec::new()),
    };
    Ok(raw
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| l.to_string())
        .collect())
}

fn save_registered_networks(store: &mut Store, networks: &[String]) -> Result<(), String> {
    let joined = networks.join("\n");
    let escaped = joined.replace('\'', "''");
    store
        .conn()
        .execute(&format!(
            "INSERT INTO meta(key, value) VALUES('networks', '{escaped}') \
             ON CONFLICT(key) DO UPDATE SET value=excluded.value;"
        ))
        .map_err(map_sql_err)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// cashu wallet (only with the `cashu` feature)
//
// The `cassis-cli cashu` subcommands drive a local NUT-03
// wallet: `send` picks proofs from the local store, swaps
// them at the mint, and prints a base64-encoded proof set for
// the recipient; `receive` decodes a base64 proof set, swaps
// it into the wallet's active keyset, and persists the
// result. There is no Lightning integration here — funds
// enter and leave the wallet only through the cashu mint.
// ---------------------------------------------------------------------------

#[cfg(feature = "cashu")]
fn load_cashu_wallet(
    network: &str,
) -> Result<(NetSpec, keys::DerivedKeys, Arc<cassis_cashu::CashuAdapter>), String> {
    let spec = NetSpec::parse(network)?;
    if !matches!(spec, NetSpec::Cashu { .. }) {
        return Err(format!(
            "expected a cashu spec like cashu::host, got '{network}'"
        ));
    }
    let specs = vec![spec.clone()];
    let mnemonic = load_mnemonic()?;
    let derived = derive_for(&mnemonic, &specs)?;
    let adapter = futures::executor::block_on(adapters::build_cashu_adapter(&spec, &derived))?;
    Ok((spec, derived, adapter))
}

#[cfg(feature = "cashu")]
fn encode_proofs_base64(proofs: &[cassis_cashu::Proof]) -> Result<String, String> {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine as _;
    let mut encoded = Vec::with_capacity(proofs.len());
    for proof in proofs {
        let json = serde_json::to_vec(proof).map_err(|e| format!("encode proof: {e}"))?;
        encoded.push(BASE64.encode(json));
    }
    // Same wire shape as `HtlcDescriptor::Cashu` so the value
    // round-trips through `cassis-cashu::proofs_from_descriptor`
    // without extra glue.
    let wrapper = serde_json::json!({
        "proofs_b64": encoded,
    });
    let json = serde_json::to_string(&wrapper).map_err(|e| format!("encode proof set: {e}"))?;
    Ok(BASE64.encode(json))
}

#[cfg(feature = "cashu")]
fn decode_proofs_base64(s: &str) -> Result<Vec<cassis_cashu::Proof>, String> {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine as _;
    let trimmed = s.trim();
    // First try the wrapped `{"proofs_b64":[...]}` form that
    // `encode_proofs_base64` produces. Fall back to a bare
    // JSON array of proofs (no base64) and finally a single
    // JSON object as a one-element list, in that order.
    if let Ok(bytes) = BASE64.decode(trimmed) {
        if let Ok(wrapper) = serde_json::from_slice::<serde_json::Value>(&bytes) {
            if let Some(arr) = wrapper.get("proofs_b64").and_then(|v| v.as_array()) {
                let mut out = Vec::with_capacity(arr.len());
                for item in arr {
                    let s = item
                        .as_str()
                        .ok_or_else(|| "proofs_b64 entry is not a string".to_string())?;
                    let raw = BASE64
                        .decode(s)
                        .map_err(|e| format!("base64 decode inner: {e}"))?;
                    let proof: cassis_cashu::Proof = serde_json::from_slice(&raw)
                        .map_err(|e| format!("decode inner proof: {e}"))?;
                    out.push(proof);
                }
                return Ok(out);
            }
        }
    }
    if let Ok(arr) = serde_json::from_str::<Vec<cassis_cashu::Proof>>(trimmed) {
        return Ok(arr);
    }
    if let Ok(single) = serde_json::from_str::<cassis_cashu::Proof>(trimmed) {
        return Ok(vec![single]);
    }
    Err(
        "proof must be a base64-encoded {\"proofs_b64\":[...]} wrapper, \
         a JSON array of cashu proofs, or a single cashu proof JSON object"
            .to_string(),
    )
}

#[cfg(feature = "cashu")]
async fn cmd_cashu_send(network: String, amount: u64) -> Result<(), String> {
    if amount == 0 {
        return Err("amount must be > 0".to_string());
    }
    let (spec, _derived, adapter) = load_cashu_wallet(&network)?;
    let mint_url =
        cassis_core::cashu_mint_url(&spec.network_id()).map_err(|e| format!("mint url: {e}"))?;

    let mut store = open_store()?;
    let rows: Vec<CashuProofRow> = store.list_cashu_proofs(&mint_url).map_err(map_store_err)?;
    if rows.is_empty() {
        return Err(format!(
            "no local cashu proofs for {mint_url}; run `cassis-cli cashu receive` first"
        ));
    }
    let available: Vec<cassis_cashu::Proof> = rows
        .iter()
        .map(|r| -> Result<cassis_cashu::Proof, String> {
            serde_json::from_slice(&r.proof_blob)
                .map_err(|e| format!("decode local proof id={}: {e}", r.id))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let balance: u64 = rows.iter().map(|r| r.amount_sat).sum();
    info!(
        target: "cassis_cli",
        "cashu send: {amount} sat from {mint_url} (local balance {balance} sat, {} proof(s))",
        rows.len()
    );

    let send_result = adapter
        .swap_proofs_for_amount(amount, available)
        .await
        .map_err(|e| format!("cashu send: {e}"))?;

    // Mark the consumed inputs spent and persist any change.
    let consumed_ids: Vec<i64> = rows
        .iter()
        .filter(|r| {
            send_result.inputs_used.iter().any(|p| {
                // Match by `(amount, secret)` — proofs aren't
                // globally unique but the local store never holds
                // two with the same secret at the same time.
                r.amount_sat == u64::from(p.amount)
                    && r.proof_blob == serde_json::to_vec(p).unwrap_or_default().as_slice()
            })
        })
        .map(|r| r.id)
        .collect();
    if consumed_ids.len() != send_result.inputs_used.len() {
        return Err(format!(
            "internal: matched {} local rows for {} inputs; aborting before mutating the store",
            consumed_ids.len(),
            send_result.inputs_used.len()
        ));
    }
    store
        .delete_cashu_proofs(&consumed_ids)
        .map_err(map_store_err)?;
    if !send_result.change.is_empty() {
        store
            .insert_cashu_proofs(&mint_url, &send_result.change)
            .map_err(map_store_err)?;
    }

    let token = encode_proofs_base64(&send_result.output)?;
    let change_sat: u64 = send_result.change.iter().map(|p| u64::from(p.amount)).sum();
    let recipient_sat: u64 = send_result.output.iter().map(|p| u64::from(p.amount)).sum();
    info!(
        target: "cassis_cli",
        "cashu send: produced {recipient_sat} sat for recipient, {change_sat} sat change, \
         spent {} input(s)",
        send_result.inputs_used.len()
    );
    println!("status:       ok");
    println!("mint:         {mint_url}");
    println!("amount_sat:   {recipient_sat}");
    println!("change_sat:   {change_sat}");
    println!("inputs_used:  {}", send_result.inputs_used.len());
    println!("proof_b64:    {token}");
    Ok(())
}

#[cfg(feature = "cashu")]
async fn cmd_cashu_receive(network: String, proof: String) -> Result<(), String> {
    let (spec, _derived, adapter) = load_cashu_wallet(&network)?;
    let mint_url =
        cassis_core::cashu_mint_url(&spec.network_id()).map_err(|e| format!("mint url: {e}"))?;
    let incoming = decode_proofs_base64(&proof)?;
    if incoming.is_empty() {
        return Err("no proofs in input".to_string());
    }
    let total_in: u64 = incoming.iter().map(|p| u64::from(p.amount)).sum();
    let n_in = incoming.len();
    info!(
        target: "cassis_cli",
        "cashu receive: {n_in} proof(s) totaling {total_in} sat at {mint_url}"
    );
    let new_proofs = adapter
        .redeem_proofs(incoming)
        .await
        .map_err(|e| format!("cashu receive: {e}"))?;
    if new_proofs.is_empty() {
        return Err("mint returned no proofs (swap produced empty output)".to_string());
    }
    let total_out: u64 = new_proofs.iter().map(|p| u64::from(p.amount)).sum();
    let mut store = open_store()?;
    store
        .insert_cashu_proofs(&mint_url, &new_proofs)
        .map_err(map_store_err)?;
    info!(
        target: "cassis_cli",
        "cashu receive: stored {} new proof(s) totaling {total_out} sat at {mint_url}",
        new_proofs.len()
    );
    println!("status:       ok");
    println!("mint:         {mint_url}");
    println!("proofs_in:    {n_in} ({total_in} sat)");
    println!("proofs_out:   {} ({total_out} sat)", new_proofs.len());
    Ok(())
}

#[cfg(feature = "cashu")]
async fn cmd_cashu_balance(network: Option<String>) -> Result<(), String> {
    let mut store = open_store()?;
    match network {
        Some(spec_str) => {
            let net_id = NetSpec::parse(&spec_str)?.network_id();
            let mint_url =
                cassis_core::cashu_mint_url(&net_id).map_err(|e| format!("mint url: {e}"))?;
            let total = store.cashu_balance(&mint_url).map_err(map_store_err)?;
            let rows = store.list_cashu_proofs(&mint_url).map_err(map_store_err)?;
            println!("mint:        {mint_url}");
            println!("balance_sat: {total}");
            println!("proofs:      {}", rows.len());
        }
        None => {
            let registered = load_registered_networks(&mut store)?;
            let mut any = false;
            for raw in &registered {
                let spec = match NetSpec::parse(raw) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                // Only cashu mints carry a local proof wallet.
                if !matches!(spec, NetSpec::Cashu { .. }) {
                    continue;
                }
                let net_id = spec.network_id();
                let mint_url = match cassis_core::cashu_mint_url(&net_id) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let total = store.cashu_balance(&mint_url).map_err(map_store_err)?;
                let rows = store.list_cashu_proofs(&mint_url).map_err(map_store_err)?;
                println!("{mint_url}  {total} sat ({} proof(s))", rows.len());
                any = true;
            }
            if !any {
                println!("(no registered cashu mints)");
            }
        }
    }
    Ok(())
}
