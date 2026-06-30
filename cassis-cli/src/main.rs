//! Thin CLI over `cassis-client`. Each command delegates the heavy
//! lifting (seed init, adapter building, invoice persistence, route
//! lookup, pay dispatch, receive daemon) to `cassis-client` so the GUI
//! and the CLI share exactly the same logic.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use cassis_client::adapters::{build_receivers, build_rootstock_adapter, build_senders};
use cassis_client::netspec::NetSpec;
use cassis_client::ops::{create_invoice_for, node_store_path, start_receive, unix_now};
use cassis_client::paths::{cassis_home, set_home_override, store_path};
use cassis_client::seed_store::{read_mnemonic, seed_path, write_mnemonic};
use cassis_client::store::{InvoiceStatus, Store};
use cassis_client::CassisClient;
use cassis_core::{Bytes32, Invoice, NetworkId, NetworkReceiverAdapter};
use cassis_keys as keys;
use clap::Parser;
use tracing::{error, info};

mod cli;
use cli::{CashuCommands, Cli, Commands, RootstockCommands};

#[tokio::main]
async fn main() {
    cassis_core::logging::init_logging();
    if let Err(e) = rustls::crypto::aws_lc_rs::default_provider().install_default() {
        eprintln!("failed to install rustls provider: {e:?}");
        std::process::exit(2);
    }
    let cli = Cli::parse();
    if let Some(home) = cli.home.as_deref() {
        set_home_override(PathBuf::from(home));
    }
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
            cli::InvoicesCommands::List { status } => cmd_invoices_list(status),
            cli::InvoicesCommands::Show { payment_hash } => cmd_invoices_show(payment_hash),
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
            cli::SeedCommands::Init { force } => cmd_seed_init(force),
            cli::SeedCommands::Show => cmd_seed_show(),
        },
        Commands::Cashu { command } => match command {
            CashuCommands::Send { network, amount } => cmd_cashu_send_stub(network, amount),
            CashuCommands::Receive { proof } => cmd_cashu_receive_stub(proof),
            CashuCommands::Balance { network } => cmd_cashu_balance(network),
        },
        Commands::Register { network } => cmd_register(network),
        Commands::Rootstock { network, command } => match command {
            RootstockCommands::Send {
                to,
                amount_msat,
                data: _,
                args: _,
            } => cmd_rootstock_send(network, to, amount_msat).await,
            RootstockCommands::Info => cmd_rootstock_info(network).await,
            RootstockCommands::Read { to, data, args } => {
                cmd_rootstock_read(network, to, data, args).await
            }
        },
        Commands::Router { .. } => {
            Err("'router' is now integrated into the GUI; run `cargo run -p cassis-gui`".into())
        }
    };
    if let Err(e) = result {
        error!("{e}");
        std::process::exit(1);
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn node_home() -> PathBuf {
    cassis_home()
}

fn open_store() -> Result<Store, String> {
    Store::open(&store_path()).map_err(|e| e.to_string())
}

fn derive_for(mnemonic: &str, specs: &[NetSpec]) -> Result<keys::DerivedKeys, String> {
    let ids: Vec<NetworkId> = specs.iter().map(|s| s.network_id()).collect();
    keys::derive_keys(mnemonic, ids).map_err(|e| e.to_string())
}

// ============================================================================
// seed init / show
// ============================================================================

fn cmd_seed_init(force: bool) -> Result<(), String> {
    let home = cassis_home();
    std::fs::create_dir_all(&home).map_err(|e| e.to_string())?;
    let p = seed_path(&home);
    if p.exists() && !force {
        return Err(format!(
            "seed already exists at {}; use --force to overwrite",
            p.display()
        ));
    }
    let mn = keys::generate_mnemonic().map_err(|e| e.to_string())?;
    write_mnemonic(&p, &mn, true).map_err(|e| e.to_string())?;
    println!("wrote 12-word mnemonic to {}", p.display());
    println!("backup this phrase — losing it means losing access to all derived keys.");
    Ok(())
}

fn cmd_seed_show() -> Result<(), String> {
    let mn = read_mnemonic(&seed_path(&node_home())).map_err(|e| e.to_string())?;
    println!("{mn}");
    Ok(())
}

// ============================================================================
// register
// ============================================================================

fn cmd_register(specs: Vec<String>) -> Result<(), String> {
    if specs.is_empty() {
        return Err("at least one --network spec is required".to_string());
    }
    let mut store = open_store()?;
    std::fs::create_dir_all(node_home()).map_err(|e| e.to_string())?;
    let mut existing: Vec<String> = load_registered_networks(&mut store)?;
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
    use cassis_client::store::SqlValue;
    store
        .conn()
        .execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);")
        .map_err(|e| e.to_string())?;
    let result = store
        .conn()
        .query("SELECT value FROM meta WHERE key='networks';")
        .map_err(|e| e.to_string())?;
    let raw = match result.rows.first().and_then(|r| r.first()) {
        Some(SqlValue::Text(s)) => s.clone(),
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
        .map_err(|e| e.to_string())?;
    Ok(())
}

// ============================================================================
// pay
// ============================================================================

async fn cmd_pay(invoice: String, from: String, nostr_relay: Vec<String>) -> Result<(), String> {
    let invoice_struct: Invoice =
        serde_json::from_str(&invoice).map_err(|e| format!("invalid invoice JSON: {e}"))?;
    let sender_network = NetworkId(from.clone());
    let dest_network = invoice_struct
        .networks
        .first()
        .cloned()
        .ok_or_else(|| "invoice has no network hints".to_string())?;
    let relays = if nostr_relay.is_empty() {
        cli::default_nostr_relays()
    } else {
        nostr_relay
    };
    let net_spec = NetSpec::parse(&dest_network.0)?;
    let mnemonic = read_mnemonic(&seed_path(&node_home())).map_err(|e| e.to_string())?;
    let derived = derive_for(&mnemonic, std::slice::from_ref(&net_spec))?;
    let senders = build_senders(&[net_spec], &derived, &node_store_path(&node_home())).await?;
    let client = CassisClient::new(senders, relays).await;
    info!(
        "paying {} msat via '{}' route",
        invoice_struct.amount_msat, from
    );
    let result = client
        .pay(invoice_struct, sender_network)
        .await
        .map_err(|e| format!("pay: {e}"))?;
    match result.status {
        cassis_core::PaymentStatus::Completed => println!("status: completed"),
        cassis_core::PaymentStatus::Refunded => println!("status: refunded"),
        cassis_core::PaymentStatus::Failed => println!("status: failed"),
    }
    Ok(())
}

// ============================================================================
// invoice
// ============================================================================

async fn cmd_invoice(
    amount: u64,
    network: String,
    payee: Option<String>,
    _description: Option<String>,
    expires_at: Option<u64>,
    wait: bool,
    timeout: u64,
) -> Result<(), String> {
    let spec = NetSpec::parse(&network)?;
    let network_id = spec.network_id();
    let expiry = expires_at.unwrap_or(unix_now() + 600);
    let (invoice, payment_hash, preimage) =
        create_invoice_for(&node_home(), network_id.clone(), spec.clone(), amount).await?;
    println!("payment_hash: {payment_hash}");
    println!("preimage:     {}", lowercase_hex::encode(&preimage));
    println!("network:      {network_id}");
    println!("amount_msat:  {amount}");
    println!("expires_at:   {expiry}");
    println!("status:       pending (persisted)");
    if let Ok(json) = serde_json::to_string(&invoice) {
        println!("invoice_json: {json}");
    }
    if !wait {
        return Ok(());
    }
    info!("waiting for COMMIT or upstream fund (timeout={timeout}s)...");
    let now = unix_now();
    let deadline = now.saturating_add(timeout);
    let mnemonic = read_mnemonic(&seed_path(&node_home())).map_err(|e| e.to_string())?;
    let derived = derive_for(&mnemonic, std::slice::from_ref(&spec))?;
    let receivers = build_receivers(
        std::slice::from_ref(&spec),
        &derived,
        &node_store_path(&node_home()),
    )
    .await?;
    let receiver_map: Arc<HashMap<NetworkId, Arc<dyn NetworkReceiverAdapter>>> =
        Arc::new(receivers);
    if let Some(rv) = receiver_map.get(&network_id) {
        if let Ok(preimage_seen) = rv.watch_incoming(payment_hash, deadline).await {
            let _ = rv.claim_incoming(payment_hash, preimage_seen).await;
            let _ = payee;
            let mut store = open_store()?;
            store
                .mark_status(&payment_hash, InvoiceStatus::Claimed)
                .map_err(|e| e.to_string())?;
            println!("status:       claimed");
        }
    }
    Ok(())
}

// ============================================================================
// receive
// ============================================================================

async fn cmd_receive() -> Result<(), String> {
    let home = node_home();
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
    info!(
        "receive: {} network(s) listening; pending invoices will be claimed",
        specs.len()
    );
    let _jh = start_receive(&home, &specs).await?;
    println!("receive: ready (cassis_client::start_receive spawned the iroh listener)");
    tokio::signal::ctrl_c().await.ok();
    info!("shutting down");
    Ok(())
}

// ============================================================================
// route
// ============================================================================

async fn cmd_route(
    destination_pubkey: String,
    amount: u64,
    from: String,
    nostr_relay: Vec<String>,
) -> Result<(), String> {
    let from = NetworkId(from);
    let to = NetworkId(destination_pubkey);
    let relays = if nostr_relay.is_empty() {
        cli::default_nostr_relays()
    } else {
        nostr_relay
    };
    let hops = cassis_client::find_route(&relays, &to, amount, &from)
        .await
        .map_err(|e| e.to_string())?;
    println!("route found ({} hop(s)):", hops.len());
    for (i, hop) in hops.iter().enumerate() {
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

// ============================================================================
// invoices list / show
// ============================================================================

fn cmd_invoices_list(status_str: Option<String>) -> Result<(), String> {
    let mut store = open_store()?;
    let status = match status_str.as_deref() {
        None => None,
        Some("pending") => Some(InvoiceStatus::Pending),
        Some("claimed") => Some(InvoiceStatus::Claimed),
        Some("failed") => Some(InvoiceStatus::Failed),
        Some(other) => return Err(format!("unknown status filter '{other}'")),
    };
    let rows = store.list(status).map_err(|e| e.to_string())?;
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
    let row = store.get(&ph).map_err(|e| e.to_string())?;
    println!("payment_hash: {}", row.payment_hash);
    println!("preimage:     {}", lowercase_hex::encode(&row.preimage));
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

// ============================================================================
// cashu wallet
//
// `cashu send`/`cashu receive` need NUT-00 token encode/decode (via
// `cdk`), which lives in the GUI. `cashu balance` is a pure store query.
// ============================================================================

fn cmd_cashu_send_stub(_network: String, _amount: u64) -> Result<(), String> {
    Err("'cassis-cli cashu send' is implemented in `cassis-gui`.".to_string())
}

fn cmd_cashu_receive_stub(_proof: String) -> Result<(), String> {
    Err("'cassis-cli cashu receive' is implemented in `cassis-gui`.".to_string())
}

fn cmd_cashu_balance(network: Option<String>) -> Result<(), String> {
    let mut store = open_store()?;
    match network {
        Some(spec_str) => {
            let net_id = NetSpec::parse(&spec_str)?.network_id();
            let mint_url = cassis_core::cashu_mint_url(&net_id).map_err(|e| e.to_string())?;
            let total = store.cashu_balance(&mint_url).map_err(|e| e.to_string())?;
            let rows = store
                .list_cashu_proofs(&mint_url)
                .map_err(|e| e.to_string())?;
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
                if let NetSpec::Cashu { mint_url, .. } = &spec {
                    let total = store.cashu_balance(mint_url).map_err(|e| e.to_string())?;
                    let rows = store
                        .list_cashu_proofs(mint_url)
                        .map_err(|e| e.to_string())?;
                    println!("{mint_url}  {total} sat ({} proof(s))", rows.len());
                    any = true;
                }
            }
            if !any {
                println!("(no registered cashu mints)");
            }
        }
    }
    Ok(())
}

// ============================================================================
// rootstock
// ============================================================================

async fn cmd_rootstock_send(network: String, to: String, amount_msat: u64) -> Result<(), String> {
    let testnet = network == "rootstock::testnet";
    let spec = NetSpec::Rootstock { testnet };
    let mnemonic = read_mnemonic(&seed_path(&node_home())).map_err(|e| e.to_string())?;
    let derived = derive_for(&mnemonic, std::slice::from_ref(&spec))?;
    let adapter = build_rootstock_adapter(&spec, &derived).await?;
    let tx_hash = adapter
        .transfer(&to, amount_msat)
        .await
        .map_err(|e| format!("rootstock send: {e}"))?;
    println!("status:      ok");
    println!("network:     {network}");
    println!("tx_hash:     {tx_hash}");
    Ok(())
}

async fn cmd_rootstock_info(_network: String) -> Result<(), String> {
    Err("'cassis-cli rootstock info' is implemented in `cassis-gui`.".to_string())
}

async fn cmd_rootstock_read(
    _network: String,
    _to: String,
    _data: String,
    _args: String,
) -> Result<(), String> {
    Err("'cassis-cli rootstock read' is implemented in `cassis-gui`.".to_string())
}
