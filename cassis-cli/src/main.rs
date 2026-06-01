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
use cassis_keys as keys;
use clap::Parser;
use log::{error, info, warn};
use rand::RngCore;
use sha2::{Digest, Sha256};

use cli::{Cli, Commands, InvoicesCommands, NetSpec, SeedCommands};
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
        Commands::Pay { invoice, from, nostr_relay } => cmd_pay(invoice, from, nostr_relay).await,
        Commands::Invoice { amount, network, payee, description, expires_at, wait, timeout } => {
            cmd_invoice(amount, network, payee, description, expires_at, wait, timeout).await
        }
        Commands::Receive => cmd_receive().await,
        Commands::Invoices { command } => match command {
            InvoicesCommands::List { status } => cmd_invoices_list(status),
            InvoicesCommands::Show { payment_hash } => cmd_invoices_show(payment_hash),
        },
        Commands::Route { destination_pubkey, amount, from, nostr_relay } => {
            cmd_route(destination_pubkey, amount, from, nostr_relay).await
        }
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

async fn cmd_pay(invoice_str: String, from: String, nostr_relays: Vec<String>) -> Result<(), String> {
    let invoice: Invoice = serde_json::from_str(&invoice_str)
        .map_err(|e| format!("invalid invoice JSON: {e}"))?;
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
    let route = cassis_client::find_route(&relays, &dest_network, invoice.amount_msat, &sender_network)
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
        "preparing hops and sending HTLC for payment_hash={}",
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
    info!(target: "cassis_cli", "waiting for upstream to fund (timeout={timeout}s)...");
    let mnemonic = load_mnemonic()?;
    let specs = vec![net_spec];
    let derived = derive_for(&mnemonic, &specs)?;
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
        return Err(format!("payment hash must be 64 hex chars, got {}", s.len()));
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
        .filter(|r| {
            specs
                .iter()
                .any(|s| s.network_id() == r.network_id)
        })
        .collect();
    info!(
        target: "cassis_cli",
        "receive: {} network(s), {} pending invoice(s)",
        receivers.len(),
        pending.len()
    );

    let _client = cassis_client::CassisClient::with_receivers(
        HashMap::new(),
        receivers.clone(),
        cli::default_nostr_relays(),
    )
    .await;

    let receiver_map: Arc<HashMap<NetworkId, Arc<dyn NetworkReceiverAdapter>>> =
        Arc::new(receivers);
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
    println!("receive: all pending invoices processed (use `cassis-cli invoices list` to inspect)");
    Ok(())
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
    println!("description:  {}", row.description.as_deref().unwrap_or("-"));
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
    nostr_relays: Vec<String>,
) -> Result<(), String> {
    let sender_network = NetworkId(from);
    let dest_network = NetworkId(destination_pubkey);
    let relays = if nostr_relays.is_empty() {
        cli::default_nostr_relays()
    } else {
        nostr_relays
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
    let home = paths::ensure_cassis_home()
        .map_err(|e| format!("creating cassis home: {e}"))?;
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
        .execute(
            "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);",
        )
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
