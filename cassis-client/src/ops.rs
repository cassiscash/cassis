//! High-level node operations that used to live in `cassis-cli`'s
//! commands. The GUI and the CLI both call these so there is no
//! duplicated orchestration logic.

use cassis_core::{Bytes32, Invoice, NetworkAdapter, NetworkId};
use cassis_iroh::{Frame, IrohServer, PublicKey};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::error;
use tracing::{info, warn, Instrument, Span};

pub use crate::netspec::NetSpec;
pub use crate::seed_store::{read_mnemonic, seed_path, write_mnemonic};

use crate::adapters::{build_adapters_with_config, AdapterConfig};
use crate::store::{InvoiceRow, InvoiceStatus, Store};
use cassis_keys as keys;

pub const DEFAULT_NOSTR_RELAYS: &[&str] =
    &["wss://relay.damus.io", "wss://nos.lol", "wss://nostr.mom"];
pub const DEFAULT_IROH_RELAY: &str = "https://n0.relay.iroh";

pub fn default_nostr_relays() -> Vec<String> {
    DEFAULT_NOSTR_RELAYS.iter().map(|s| s.to_string()).collect()
}

/// Force-create a fresh 12-word BIP39 mnemonic under `<home>/seed` if
/// one isn't there. Mirrors the CLI's on-first-use auto-init.
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

/// Hash a 32-byte preimage with SHA-256 to produce a payment hash.
pub fn payment_hash_of(preimage: [u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(preimage);
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

/// Create and persist invoice using an already-open adapter object.
///
/// Adapter state stays in caller-owned instance, so later receive/COMMIT
/// operations address same reservation and native invoice.
pub async fn create_invoice_with_adapter(
    home: &Path,
    adapter: &dyn NetworkAdapter,
    network_id: NetworkId,
    amount_msat: u64,
    expiry: u64,
) -> Result<(Invoice, Bytes32, [u8; 32]), String> {
    if adapter.network_id() != network_id {
        return Err(format!(
            "adapter network {} does not match invoice network {}",
            adapter.network_id(),
            network_id
        ));
    }
    if amount_msat == 0 {
        return Err("invoice amount must be positive".to_string());
    }
    if expiry <= unix_now() {
        return Err("invoice expiry must be in the future".to_string());
    }
    let handle = cassis_core::create_invoice_handle(adapter, amount_msat, expiry, None)
        .await
        .map_err(|error| error.to_string())?;
    let mut invoice = handle.invoice;
    invoice.networks = vec![network_id];
    invoice.expires_at = expiry;

    let derived = load_and_derive(home, vec![invoice.networks[0].clone()])?;
    let (iroh_peer_id, iroh_relay) = iroh_endpoint_info(&derived.iroh).await?;
    invoice.iroh_peer_id = Some(iroh_peer_id);
    invoice.iroh_relay = Some(iroh_relay);

    let payment_hash = invoice.payment_hash;
    let now = unix_now();
    {
        let mut store = Store::open(&node_store_path(home)).map_err(|e| e.to_string())?;
        store
            .insert_invoice(&InvoiceRow {
                payment_hash,
                preimage: handle.preimage.0,
                amount_msat,
                network_id: invoice.networks[0].clone(),
                payee: None,
                description: None,
                expires_at: expiry,
                status: InvoiceStatus::Pending,
                created_at: now,
                claimed_at: None,
            })
            .map_err(|e| e.to_string())?;
        store
            .insert_invoice_handle(&cassis_core::InvoiceHandle {
                invoice: invoice.clone(),
                reservation: handle.reservation,
                preimage: handle.preimage,
            })
            .map_err(|e| e.to_string())?;
    }
    Ok((invoice, payment_hash, handle.preimage.0))
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
    adapters: Arc<HashMap<NetworkId, Arc<dyn NetworkAdapter>>>,
    store_path: PathBuf,
    _remote: PublicKey,
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
    if !commit.operation_id.is_valid() {
        return Err(cassis_iroh::IrohError::Protocol(
            "COMMIT operation_id must be 32 hexadecimal characters".to_string(),
        ));
    }
    if let Some((payment_hash, preimage)) = {
        let mut store = Store::open(&store_path)
            .map_err(|e| cassis_iroh::IrohError::Protocol(format!("store: {e}")))?;
        store
            .get_commit_attempt(&commit.operation_id)
            .map_err(|e| cassis_iroh::IrohError::Protocol(format!("commit replay lookup: {e}")))?
    } {
        if payment_hash != commit.payment_hash {
            return Err(cassis_iroh::IrohError::Protocol(
                "commit replay operation_id hash mismatch".to_string(),
            ));
        }
        return Ok(Frame::Committed(cassis_core::HopCommitted {
            payment_hash,
            operation_id: commit.operation_id.clone(),
            preimage: Bytes32(preimage),
        }));
    }
    // Load persisted invoice state. COMMIT must use invoice's original
    // reservation operation; creating a second reservation for same hash
    // would violate adapter duplicate-hash protection.
    let (preimage, invoice, reservation) = {
        let mut store = Store::open(&store_path)
            .map_err(|e| cassis_iroh::IrohError::Protocol(format!("store: {e}")))?;
        let row = store
            .get(&commit.payment_hash)
            .map_err(|e| cassis_iroh::IrohError::Protocol(format!("lookup: {e}")))?;
        let handle = store
            .list_invoice_handles()
            .map_err(|e| cassis_iroh::IrohError::Protocol(format!("invoice handle lookup: {e}")))?
            .into_iter()
            .find(|handle| handle.invoice.payment_hash == commit.payment_hash)
            .ok_or_else(|| {
                cassis_iroh::IrohError::Protocol(format!(
                    "no invoice reservation for payment_hash={}",
                    commit.payment_hash.short()
                ))
            })?;
        (row.preimage, handle.invoice, handle.reservation)
    };
    if invoice.amount_msat != commit.amount_msat {
        return Err(cassis_iroh::IrohError::Protocol(format!(
            "COMMIT amount {} does not match invoice amount {}",
            commit.amount_msat, invoice.amount_msat
        )));
    }
    if !invoice
        .networks
        .iter()
        .any(|network| network == &commit.network)
    {
        return Err(cassis_iroh::IrohError::Protocol(
            "COMMIT network does not match invoice network".to_string(),
        ));
    }
    if commit.incoming_deadline > invoice.expires_at {
        return Err(cassis_iroh::IrohError::Protocol(
            "COMMIT deadline exceeds invoice expiry".to_string(),
        ));
    }
    let receiver = adapters.get(&commit.network).ok_or_else(|| {
        cassis_iroh::IrohError::Protocol(format!("no receiver for {}", commit.network))
    })?;
    info!(
        target: "cassis_client",
        "received COMMIT for payment_hash={} amount_msat={} network={}",
        commit.payment_hash.short(),
        commit.amount_msat,
        commit.network,
    );
    // The payee is the origin of the preimage: claiming publishes it,
    // which is what lets every upstream hop claim in turn. Logged
    // immediately before it leaves this process, so the reveal has a
    // definite point in the timeline to compare the hops against.
    let preimage = Bytes32(preimage);
    info!(
        target: "cassis_client",
        "revealing preimage and claiming incoming HTLC for payment_hash={} on {}",
        commit.payment_hash.short(),
        commit.network,
    );
    receiver
        .restore_incoming_reservation(&reservation)
        .await
        .map_err(|e| cassis_iroh::IrohError::Protocol(format!("restore reservation: {e}")))?;
    let accepted = receiver
        .accept_incoming(&reservation, &commit.incoming_descriptor)
        .await
        .map_err(|e| cassis_iroh::IrohError::Protocol(format!("accept_incoming: {e}")))?;
    if let Err(e) = receiver.claim_incoming(&accepted, preimage).await {
        error!(
            target: "cassis_client",
            "incoming HTLC claim failed for payment_hash={} on {}: {e}",
            commit.payment_hash.short(),
            commit.network,
        );
        return Err(cassis_iroh::IrohError::Protocol(format!("claim: {e}")));
    }
    info!(
        target: "cassis_client",
        "incoming HTLC claimed for payment_hash={} on {}",
        commit.payment_hash.short(),
        commit.network,
    );
    let mut store = Store::open(&store_path)
        .map_err(|e| cassis_iroh::IrohError::Protocol(format!("store reopen: {e}")))?;
    store
        .mark_status(&commit.payment_hash, InvoiceStatus::Claimed)
        .map_err(|e| cassis_iroh::IrohError::Protocol(format!("mark claimed: {e}")))?;
    store
        .insert_commit_attempt(&commit.operation_id, commit.payment_hash, preimage.0)
        .map_err(|e| cassis_iroh::IrohError::Protocol(format!("record commit attempt: {e}")))?;
    Ok(Frame::Committed(cassis_core::HopCommitted {
        payment_hash: commit.payment_hash,
        operation_id: commit.operation_id,
        preimage,
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
    span: Span,
) -> Result<tokio::task::JoinHandle<()>, String> {
    start_receive_with_config(home, networks, span, &AdapterConfig::default()).await
}

pub async fn start_receive_with_config(
    home: &Path,
    networks: &[NetSpec],
    span: Span,
    config: &AdapterConfig,
) -> Result<tokio::task::JoinHandle<()>, String> {
    let ids: Vec<NetworkId> = networks.iter().map(|s| s.network_id()).collect();
    let derived = load_and_derive(home, ids)?;
    let adapters = build_adapters_with_config(
        networks,
        &derived,
        &node_store_path(home),
        span.clone(),
        config,
    )
    .await?;
    start_receive_with(home, Arc::new(adapters), networks, span).await
}

/// [`start_receive`] with caller-supplied receiver adapters, so an
/// already-open wallet set can be reused instead of reopened (some
/// networks hold exclusive locks on their wallet state).
pub async fn start_receive_with(
    home: &Path,
    adapters: Arc<HashMap<NetworkId, Arc<dyn NetworkAdapter>>>,
    networks: &[NetSpec],
    span: Span,
) -> Result<tokio::task::JoinHandle<()>, String> {
    let ids: Vec<NetworkId> = networks.iter().map(|s| s.network_id()).collect();
    let derived = load_and_derive(home, ids)?;

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
        let adapters = adapters.clone();
        let store_path = store_path.clone();
        let handler_span = span.clone();
        let handler = Arc::new(move |frame: Frame, remote: PublicKey| {
            let adapters = adapters.clone();
            let store_path = store_path.clone();
            Box::pin(
                async move { handle_commit_frame(frame, adapters, store_path, remote).await }
                    .instrument(handler_span.clone()),
            )
                as std::pin::Pin<
                    Box<
                        dyn std::future::Future<Output = Result<Frame, cassis_iroh::IrohError>>
                            + Send,
                    >,
                >
        });
        tokio::spawn(async move {
            if let Err(e) = iroh_server.run(handler).await {
                tracing::error!(target: "cassis_client", "iroh server error: {e}");
            }
        });
    }

    // Watch pending invoice reservations and claim them when funded.
    // Then idle; iroh server task keeps runtime alive. Drop JoinHandle to stop.
    let pending: Vec<crate::store::InvoiceRow> = {
        let mut store = Store::open(&store_path).map_err(|e| e.to_string())?;
        let rows = store
            .list(Some(InvoiceStatus::Pending))
            .map_err(|e| e.to_string())?;
        rows.into_iter()
            .filter(|r| networks.iter().any(|s| s.network_id() == r.network_id))
            .collect()
    };
    let handles = {
        let mut store = Store::open(&store_path).map_err(|e| e.to_string())?;
        store.list_invoice_handles().map_err(|e| e.to_string())?
    };
    let jh = tokio::spawn(
        async move {
            for row in pending {
                let Some(rv) = adapters.get(&row.network_id) else {
                    continue;
                };
                let Some(handle) = handles
                    .iter()
                    .find(|handle| handle.invoice.payment_hash == row.payment_hash)
                else {
                    warn!(
                        target: "cassis_client",
                        "no invoice handle for pending payment_hash={}; COMMIT path only",
                        row.payment_hash.short(),
                    );
                    continue;
                };
                if let Err(error) = rv.restore_incoming_reservation(&handle.reservation).await {
                    warn!(
                        target: "cassis_client",
                        "cannot restore invoice reservation {}: {error}; COMMIT remains authoritative",
                        row.payment_hash.short(),
                    );
                    continue;
                }
                let deadline = row.expires_at.min(unix_now().saturating_add(3600));
                let fund = tokio::time::timeout(
                    std::time::Duration::from_secs(30),
                    rv.watch_incoming(&handle.reservation, deadline),
                )
                .await;
                match fund {
                    Ok(Ok(())) => match rv
                        .claim_reserved_incoming(&handle.reservation, handle.preimage)
                        .await
                    {
                        Ok(()) => {
                            if let Ok(mut st) = Store::open(&store_path) {
                                let _ = st.mark_status(&row.payment_hash, InvoiceStatus::Claimed);
                            }
                        }
                        Err(error) => {
                            warn!(
                                target: "cassis_client",
                                "reservation claim unavailable for {}: {error}; COMMIT remains authoritative",
                                row.payment_hash.short(),
                            );
                        }
                    },
                    Ok(Err(error)) => {
                        warn!(
                            target: "cassis_client",
                            "invoice watcher unavailable for {}: {error}; COMMIT remains authoritative",
                            row.payment_hash.short(),
                        );
                    }
                    Err(_) => {
                        warn!(
                            target: "cassis_client",
                            "invoice watcher timed out for {}",
                            row.payment_hash.short(),
                        );
                    }
                }
            }
            // Hold the task alive forever; dropping this handle cancels it.
            std::future::pending::<()>().await;
        }
        .instrument(span),
    );
    tracing::info!(
        target: "cassis_client",
        "receive: listening for COMMIT on iroh peer_id={iroh_peer_id} relay={iroh_relay}"
    );
    Ok(jh)
}
