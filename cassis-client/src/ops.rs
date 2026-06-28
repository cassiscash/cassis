//! High-level node operations that used to live in `cassis-cli`'s
//! commands. The GUI and the CLI both call these so there is no
//! duplicated orchestration logic.

use cassis_core::{Bytes32, Invoice, NetworkId, NetworkReceiverAdapter};
use cassis_iroh::{Frame, IrohServer};
use rand::RngCore;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

pub use crate::netspec::NetSpec;
pub use crate::seed_store::{read_mnemonic, seed_path, write_mnemonic};

use crate::adapters::build_receivers;
use crate::store::{InvoiceRow, InvoiceStatus, Store};
use cassis_keys as keys;

pub const DEFAULT_NOSTR_RELAYS: &[&str] =
    &["wss://relay.damus.io", "wss://nos.lol", "wss://nostr.mom"];
pub const DEFAULT_IROH_RELAY: &str = "https://n0.relay.iroh";

pub fn default_nostr_relays() -> Vec<String> {
    DEFAULT_NOSTR_RELAYS.iter().map(|s| s.to_string()).collect()
}

/// Force-create a fresh 12-word BIP39 mnemonic under `<home>/seed` if
/// one isn't there. Matches `cassis-cli seed init --force`.
pub fn init_node_home(home: &Path) -> Result<(), String> {
    std::fs::create_dir_all(home).map_err(|e| e.to_string())?;
    let p = seed_path(home);
    if !p.exists() {
        let mn = keys::generate_mnemonic().map_err(|e| e.to_string())?;
        write_mnemonic(&p, &mn, true).map_err(|e| e.to_string())?;
    }
    Ok(())
}

pub fn node_store_path(home: &Path) -> PathBuf {
    home.join("store.db")
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn generate_preimage() -> [u8; 32] {
    let mut p = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut p);
    p
}

/// Hash a 32-byte preimage with SHA-256 to produce a payment hash.
pub fn payment_hash_of(preimage: [u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(&preimage);
    let out = h.finalize();
    let mut out32 = [0u8; 32];
    out32.copy_from_slice(&out);
    out32
}

/// Load mnemonic, derive keys for the given networks, return both.
pub fn load_and_derive(home: &Path, ids: Vec<NetworkId>) -> Result<keys::DerivedKeys, String> {
    let mn = read_mnemonic(&seed_path(home)).map_err(|e| e.to_string())?;
    keys::derive_keys(&mn, ids).map_err(|e| e.to_string())
}

/// Build a serialized `Invoice` for `network_id` worth `amount_msat` sat.
/// Generates the preimage locally and persists the row in the node's
/// store. Returns the Invoice (with the local iroh peer id baked in)
/// ready for the payer to consume.
#[allow(unused_variables)]
pub async fn create_invoice_for(
    home: &Path,
    network_id: NetworkId,
    spec: NetSpec,
    amount_msat: u64,
) -> Result<(Invoice, Bytes32, [u8; 32]), String> {
    let mnemonic = read_mnemonic(&seed_path(home)).map_err(|e| e.to_string())?;
    let ids = vec![network_id.clone()];
    let derived = keys::derive_keys(&mnemonic, ids).map_err(|e| e.to_string())?;

    let store_path = node_store_path(home);
    let now = unix_now();
    let ttl = 600u64;
    let preimage = generate_preimage();
    let payment_hash = payment_hash_of(preimage);
    let invoice_expiry = now + ttl;
    // The minisqlite Store is not `Send`; scope it so it drops before
    // any `.await` below (the iroh endpoint bind), so the surrounding
    // async fn stays `Send`.
    {
        let mut store = Store::open(&store_path).map_err(|e| e.to_string())?;
        let row = InvoiceRow {
            payment_hash: Bytes32(payment_hash),
            preimage,
            amount_msat,
            network_id: network_id.clone(),
            payee: None,
            description: None,
            expires_at: invoice_expiry,
            status: InvoiceStatus::Pending,
            created_at: now,
            claimed_at: None,
        };
        store.insert_invoice(&row).map_err(|e| e.to_string())?;
    }

    // Bind a transient iroh endpoint so the payer can dial COMMIT.
    let (iroh_peer_id, iroh_relay) = iroh_endpoint_info(&derived.iroh).await?;

    let invoice = Invoice {
        payment_hash: Bytes32(payment_hash),
        amount_msat,
        payee: derived.invoice.pubkey(),
        expires_at: invoice_expiry,
        networks: vec![network_id],
        description: None,
        iroh_peer_id: Some(iroh_peer_id),
        iroh_relay: Some(iroh_relay),
    };
    Ok((invoice, Bytes32(payment_hash), preimage))
}

async fn iroh_endpoint_info(secret: &iroh::SecretKey) -> Result<(String, String), String> {
    let (server, _secret) = IrohServer::new(secret.clone())
        .await
        .map_err(|e| format!("bind iroh endpoint: {e}"))?;
    let peer = server.peer_id().to_string();
    let relay = server
        .home_relay()
        .map(|s| s.to_string())
        .unwrap_or_else(|| DEFAULT_IROH_RELAY.to_string());
    Ok((peer, relay))
}

/// Handle an iroh Commit frame by matching it to a persisted invoice
/// and claiming the incoming HTLC on its receiver adapter.
pub async fn handle_commit_frame(
    frame: Frame,
    receivers: Arc<HashMap<NetworkId, Arc<dyn NetworkReceiverAdapter>>>,
    store_path: PathBuf,
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
    // Look up the persisted preimage.
    let preimage = {
        let mut store = Store::open(&store_path)
            .map_err(|e| cassis_iroh::IrohError::Protocol(format!("store: {e}")))?;
        let row = store
            .get(&commit.payment_hash)
            .map_err(|e| cassis_iroh::IrohError::Protocol(format!("lookup: {e}")))?;
        row.preimage
    };
    let receiver = receivers.get(&commit.network).ok_or_else(|| {
        cassis_iroh::IrohError::Protocol(format!("no receiver for {}", commit.network))
    })?;
    receiver
        .accept_incoming_via_descriptor(
            commit.payment_hash,
            &commit.incoming_descriptor,
            commit.incoming_deadline,
        )
        .await
        .map_err(|e| cassis_iroh::IrohError::Protocol(format!("accept_incoming: {e}")))?;
    receiver
        .claim_incoming(commit.payment_hash, Bytes32(preimage))
        .await
        .map_err(|e| cassis_iroh::IrohError::Protocol(format!("claim: {e}")))?;
    let mut store = Store::open(&store_path)
        .map_err(|e| cassis_iroh::IrohError::Protocol(format!("store reopen: {e}")))?;
    store
        .mark_status(&commit.payment_hash, InvoiceStatus::Claimed)
        .map_err(|e| cassis_iroh::IrohError::Protocol(format!("mark claimed: {e}")))?;
    Ok(Frame::Committed(cassis_core::HopCommitted {
        payment_hash: commit.payment_hash,
        preimage: Bytes32(preimage),
    }))
}

#[derive(Debug, Serialize)]
pub struct ReceiverHandle {
    pub iroh_peer_id: String,
    pub iroh_relay: String,
}

/// Start the long-running receive daemon for a node: bind an iroh
/// server for COMMIT, claim any pending invoices, and run until the
/// returned `JoinHandle` is dropped (or the process exits).
pub async fn start_receive(
    home: &Path,
    networks: &[NetSpec],
) -> Result<tokio::task::JoinHandle<()>, String> {
    let ids: Vec<NetworkId> = networks.iter().map(|s| s.network_id()).collect();
    let derived = load_and_derive(home, ids)?;
    let receivers = build_receivers(networks, &derived, &node_store_path(home)).await?;
    let receivers: Arc<HashMap<NetworkId, Arc<dyn NetworkReceiverAdapter>>> = Arc::new(receivers);

    let (iroh_server, iroh_secret) = IrohServer::new(derived.iroh.clone())
        .await
        .map_err(|e| format!("bind iroh endpoint: {e}"))?;
    let iroh_peer_id = iroh_secret.public().to_string();
    let iroh_relay = iroh_server
        .home_relay()
        .map(|s| s.to_string())
        .unwrap_or_else(|| DEFAULT_IROH_RELAY.to_string());

    let store_path = node_store_path(home);
    // Spawn the COMMIT-handler server task.
    {
        let receivers = receivers.clone();
        let store_path = store_path.clone();
        let handler = Arc::new(move |frame: Frame| {
            let receivers = receivers.clone();
            let store_path = store_path.clone();
            Box::pin(async move { handle_commit_frame(frame, receivers, store_path).await })
                as std::pin::Pin<
                    Box<
                        dyn std::future::Future<Output = Result<Frame, cassis_iroh::IrohError>>
                            + Send,
                    >,
                >
        });
        tokio::spawn(async move {
            if let Err(e) = iroh_server.run(handler).await {
                log::error!(target: "cassis_client", "iroh server error: {e}");
            }
        });
    }

    // Claim any pending invoices via the legacy watch path (this also
    // wakes the COMMIT flow). Then idle; the iroh server task above
    // keeps the runtime alive. Drop the JoinHandle to stop.
    let pending: Vec<crate::store::InvoiceRow> = {
        let mut store = Store::open(&store_path).map_err(|e| e.to_string())?;
        let rows = store
            .list(Some(InvoiceStatus::Pending))
            .map_err(|e| e.to_string())?;
        rows.into_iter()
            .filter(|r| networks.iter().any(|s| s.network_id() == r.network_id))
            .collect()
    };
    let jh = tokio::spawn(async move {
        for row in pending {
            let r = receivers.get(&row.network_id);
            if let Some(rv) = r {
                let deadline = row.expires_at.min(unix_now().saturating_add(3600));
                // Block until the upstream hop funds the invoice (or the
                // deadline passes), then claim with the revealed preimage.
                let fund = tokio::time::timeout(
                    std::time::Duration::from_secs(30),
                    rv.watch_incoming(row.payment_hash, deadline),
                )
                .await;
                if let Ok(Ok(preimage)) = fund {
                    let _ = rv.claim_incoming(row.payment_hash, preimage).await;
                    if let Ok(mut st) = Store::open(&store_path) {
                        let _ = st.mark_status(&row.payment_hash, InvoiceStatus::Claimed);
                    }
                }
            }
        }
        // Hold the task alive forever; dropping this handle cancels it.
        std::future::pending::<()>().await;
    });
    log::info!(
        target: "cassis_client",
        "receive: listening for COMMIT on iroh peer_id={iroh_peer_id} relay={iroh_relay}"
    );
    Ok(jh)
}
