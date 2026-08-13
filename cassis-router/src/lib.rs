//! Cassis multi-network routing daemon, as a library.
//!
//! Hosts the [`CassisRouter`] state machine, the per-network
//! adapter construction, the iroh server loop, and the
//! 30-second preimage poll loop. The CLI's `router run`
//! subcommand builds a [`RouterConfig`] and hands it to
//! [`run_router`]; no other entry point is supported.
//!
//! Replaces the old standalone `cassis-router` binary. The
//! router reads its seed from the same config directory the
//! wallet uses (`$CASSIS_HOME` / `$HOME/.cassis` / `--home`)
//! and announces routes for the same networks the wallet is
//! registered against.

#[cfg(feature = "cashu")]
use cassis_core::{cashu_mint_url, cashu_network_id};
use cassis_core::{
    network_id_for_spec, normalize_network_id, AcceptedIncoming, AdapterError, Bytes32, HopCommit,
    HopCommitted, HopDiscard, HopDiscarded, HopExecute, HopExecuted, HopPrepare, HopPrepared,
    HtlcDescriptor, HtlcTarget, IncomingRequest, IncomingReservation, NetworkAdapter, NetworkId,
    OperationId, OutgoingPayment, OutgoingRequest,
};
use cassis_iroh::{Frame, IrohError, IrohServer, PublicKey};
use cassis_keys as keys;
use ritualistic::{EventTemplate, Kind, Network, Tags, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
#[cfg(feature = "liquid")]
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn, Instrument, Span};

const NOSTR_KIND_ROUTE_ANNOUNCEMENT: u16 = 35515;

/// Optional PREPARE veto hook: returns a rejection reason, or `None`
/// to let the normal checks proceed.
pub type PrepareVeto = Arc<dyn Fn(&HopPrepare) -> Option<String> + Send + Sync>;

const DEFAULT_NOSTR_RELAYS: &[&str] = &["wss://relay.damus.io", "wss://nos.lol", "wss://nostr.mom"];

/// How often the per-execution poll task wakes up to check
/// whether the receiver of an outgoing HTLC has revealed the
/// preimage.
const POLL_INTERVAL_SECS: u64 = 30;

/// Current on-disk router journal format. Bump whenever pending or
/// executed state shape changes; old journals are intentionally not
/// migrated.
const ROUTER_JOURNAL_VERSION: u8 = 4;

/// Top-level configuration for [`run_router`].
#[derive(Clone)]
pub struct RouterConfig {
    /// Network specs in the same `--network` format the old
    /// `cassis-router` binary accepted (`cashu::host`,
    /// `fedimint::invite`, `liquid`, `rootstock`).
    pub network_specs: Vec<String>,
    /// Nostr relays to publish route announcements to. When
    /// empty, [`DEFAULT_NOSTR_RELAYS`] is used.
    pub nostr_relays: Vec<String>,
    /// Keys derived from the same BIP39 seed the wallet uses.
    /// The router consumes `derived.iroh` for its iroh
    /// endpoint and `derived.networks` for per-network
    /// adapter signing.
    pub derived_keys: keys::DerivedKeys,
    /// Span identifying node that owns router and its adapter calls.
    pub span: Span,
    /// Optional durable router journal. Funded outgoing HTLC state is
    /// written here before the router acknowledges EXECUTE.
    pub state_path: Option<PathBuf>,
    /// Parent directory for persistent Liquid wallet state.
    /// Each Liquid network gets its own child directory.
    #[cfg(feature = "liquid")]
    pub liquid_store_dir: Option<std::path::PathBuf>,
    /// Persistence backend for cashu wallet proofs. The cashu
    /// adapter reads and writes every held proof through this,
    /// so balances survive router restarts. Required only when
    /// the router is built with the `cashu` feature.
    #[cfg(feature = "cashu")]
    pub cashu_store: Arc<dyn cassis_cashu::CashuProofStore>,
    /// Connection to the external LND REST API. LND is deliberately
    /// configured outside the Cassis node rather than embedded in it.
    #[cfg(feature = "lightning")]
    pub lnd_config: Option<cassis_lnd::LndConfig>,
    /// Data directory under which Fedimint federation client
    /// databases are stored (`<dir>/fedimint/<slug>`). Required only
    /// when routing the `fedimint` network.
    pub fedimint_data_dir: Option<std::path::PathBuf>,
    /// Adapter instances the caller already opened (e.g. a
    /// long-running wallet process holding exclusive Liquid
    /// wallet state). When an entry's [`NetworkId`] matches a
    /// spec below it is used instead of building a fresh
    /// adapter for that network.
    pub prebuilt_adapters: Vec<Arc<dyn NetworkAdapter>>,
    /// Optional hook run before a PREPARE is accepted, so a caller
    /// (e.g. a test) can veto a payment for arbitrary reasons. When it
    /// returns `Some(reason)`, the PREPARE is rejected with that reason;
    /// `None` lets the normal checks proceed. Runs *after* the built-in
    /// validation but *before* any reservation is recorded, so a vetoed
    /// PREPARE reserves nothing.
    pub prepare_veto: Option<PrepareVeto>,
}

/// Run the router daemon. Blocks until Ctrl-C. The caller
/// must have already initialized logging
/// ([`cassis_core::logging::init_logging`]).
pub async fn run_router(config: RouterConfig) -> Result<(), String> {
    if config.network_specs.len() < 2 {
        return Err(format!(
            "at least two --network flags are required for routing, got {}",
            config.network_specs.len()
        ));
    }

    let network_ids: Vec<NetworkId> = config
        .network_specs
        .iter()
        .map(|spec| network_id_for_spec(spec))
        .collect::<Result<Vec<_>, _>>()?;
    let _ = network_ids; // Used by build_adapter below; held for the diagnostic.

    info!(
        target: "cassis_router",
        "derived node pubkey: {}",
        config.derived_keys.node.pubkey().to_hex()
    );
    for (network_id, sk) in &config.derived_keys.networks {
        info!(
            target: "cassis_router",
            "  derived key for {network_id}: pubkey={}",
            sk.pubkey().to_hex()
        );
    }

    let mut adapters: HashMap<NetworkId, NetworkEntry> = HashMap::new();
    for spec in &config.network_specs {
        let network_id = network_id_for_spec(spec).map_err(|e| e.to_string())?;
        let entry = match config
            .prebuilt_adapters
            .iter()
            .find(|adapter| adapter.network_id() == network_id)
        {
            Some(adapter) => {
                let incoming_delta_secs = adapter.incoming_delta_secs();
                NetworkEntry {
                    network_id,
                    adapter: adapter.clone(),
                    incoming_delta_secs,
                }
            }
            None => match build_adapter(
                spec,
                &config.derived_keys,
                config.span.clone(),
                #[cfg(feature = "cashu")]
                &config.cashu_store,
                #[cfg(feature = "liquid")]
                config.liquid_store_dir.as_deref(),
                #[cfg(feature = "lightning")]
                config.lnd_config.as_ref(),
                #[cfg(feature = "fedimint")]
                config.fedimint_data_dir.as_deref(),
            )
            .await
            {
                Ok(entry) => entry,
                Err(err) => {
                    return Err(err);
                }
            },
        };
        adapters.insert(entry.network_id.clone(), entry);
    }

    if adapters.len() < 2 {
        return Err("at least two distinct networks are required for routing".to_string());
    }

    info!(
        target: "cassis_router",
        "routing between {} networks:", adapters.len()
    );
    for id in adapters.keys() {
        info!(target: "cassis_router", "  - {id}");
    }

    let relay_urls = if config.nostr_relays.is_empty() {
        DEFAULT_NOSTR_RELAYS.iter().map(|s| s.to_string()).collect()
    } else {
        config.nostr_relays.clone()
    };

    let router = Arc::new(CassisRouter::new_with_state(
        adapters,
        config.span,
        config.prepare_veto.clone(),
        config.state_path.clone(),
    ));
    router
        .restore_state_from_disk()
        .await
        .map_err(|error| format!("restore router state: {error}"))?;
    let handler_router = router.clone();
    let poll_router = router.clone();
    let server_span = router.span.clone();

    let (iroh_server, iroh_secret) = IrohServer::new(config.derived_keys.iroh.clone())
        .await
        .map_err(|e| format!("failed to bind iroh endpoint: {e}"))?;
    let iroh_peer_id = iroh_secret.public();
    let iroh_relay = iroh_server
        .home_relay()
        .map(|s| s.to_string())
        .unwrap_or_else(|| cassis_iroh::DEFAULT_IROH_RELAY.to_string());
    info!(
        target: "cassis_router",
        "iroh endpoint: {iroh_peer_id} relay: {iroh_relay}"
    );

    tokio::spawn(
        async move {
            let handler = Arc::new(
                move |frame: Frame,
                      remote: PublicKey|
                      -> std::pin::Pin<
                    Box<dyn std::future::Future<Output = Result<Frame, IrohError>> + Send>,
                > {
                    let router = handler_router.clone();
                    Box::pin(async move { router.handle_frame(frame, remote).await })
                },
            );
            if let Err(e) = iroh_server.run(handler).await {
                error!(target: "cassis_router", "iroh server error: {e}");
            }
        }
        .instrument(server_span),
    );

    // Instrumented with the node span: the poll loop is where every
    // preimage-reveal and incoming-claim log comes from, and without
    // this they are emitted with no span in scope and so render with no
    // node name at all.
    let poll_span = router.span.clone();
    tokio::spawn(
        async move {
            poll_router.run_poll_loop().await;
        }
        .instrument(poll_span),
    );

    publish_route_announcements(
        &router.adapters,
        relay_urls,
        &config.derived_keys.node,
        &iroh_peer_id.to_string(),
        &iroh_relay,
    )
    .await;

    tokio::signal::ctrl_c().await.ok();
    info!(target: "cassis_router", "shutting down");
    Ok(())
}

/// Per-network entry the router tracks. Router and client use the same
/// direct [`NetworkAdapter`] object; no wrapper or separate user-facing
/// trait exists.
#[derive(Clone)]
pub struct NetworkEntry {
    pub network_id: NetworkId,
    pub adapter: Arc<dyn NetworkAdapter>,
    pub incoming_delta_secs: u64,
}

/// Per-network signing key for `network_id`, or a descriptive error.
/// An all-zero fallback is not a valid secp256k1 scalar, so it only
/// deferred the failure to the first signature.
///
/// Gated to exactly the features whose arms call it, so it disappears
/// rather than needing a blanket dead-code allow.
#[cfg(any(
    feature = "cashu",
    feature = "fedimint",
    feature = "rootstock",
    feature = "arkade",
    feature = "bitcoin",
    feature = "liquid",
    feature = "spark"
))]
fn network_sk(derived: &keys::DerivedKeys, network_id: &NetworkId) -> Result<[u8; 32], String> {
    derived
        .networks
        .get(network_id)
        .map(|k| *k.as_bytes())
        .ok_or_else(|| {
            format!("no signing key derived for network '{network_id}'; derive keys for it first")
        })
}

#[allow(unused_variables)]
async fn build_adapter(
    spec: &str,
    derived: &keys::DerivedKeys,
    span: Span,
    #[cfg(feature = "cashu")] cashu_store: &Arc<dyn cassis_cashu::CashuProofStore>,
    #[cfg(feature = "liquid")] liquid_store_dir: Option<&Path>,
    #[cfg(feature = "lightning")] lnd_config: Option<&cassis_lnd::LndConfig>,
    #[cfg(feature = "fedimint")] fedimint_data_dir: Option<&std::path::Path>,
) -> Result<NetworkEntry, String> {
    let (kind, param) = cassis_core::split_spec(spec);

    match kind {
        #[cfg(feature = "cashu")]
        "cashu" => {
            let host = param.ok_or_else(|| {
                "network 'cashu' requires a host, \
                 e.g. cashu::mint.example.com (https) or cashu::localhost:3338 (http)"
                    .to_string()
            })?;
            let network_id = cashu_network_id(host);
            let mint_url =
                cashu_mint_url(&network_id).map_err(|e| format!("cashu mint url: {e}"))?;
            // The cashu adapter signs NUT-14 witnesses with this key and
            // advertises the matching identity via `claim_pubkey()`, so
            // upstream hops lock proofs to a key we can actually spend.
            let sk = network_sk(derived, &network_id)?;
            let adapter: Arc<dyn NetworkAdapter> = Arc::new(
                cassis_cashu::CashuAdapter::new(
                    network_id.clone(),
                    mint_url,
                    sk,
                    cashu_store.clone(),
                    span.clone(),
                )
                .map_err(|e| format!("cashu adapter init failed: {e}"))?,
            );
            let incoming_delta_secs = adapter.incoming_delta_secs();
            Ok(NetworkEntry {
                network_id,
                adapter,
                incoming_delta_secs,
            })
        }

        #[cfg(not(feature = "cashu"))]
        "cashu" => Err(
            "network 'cashu' requested but cassis-router was not compiled with the 'cashu' feature"
                .into(),
        ),

        #[cfg(feature = "fedimint")]
        "fedimint" => {
            let invite = param.ok_or_else(|| {
                "network 'fedimint' requires an invite code, e.g. fedimint::fed1q...".to_string()
            })?;
            let network_id = NetworkId(format!("fedimint::{invite}"));
            // The fedimint adapter derives its static even-parity
            // claim keypair from this per-network key and advertises
            // the matching x-only identity via `claim_pubkey()`, so
            // upstream hops lock contracts to a key we can actually
            // claim with.
            let sk = network_sk(derived, &network_id)?;
            let data_dir = fedimint_data_dir.ok_or_else(|| {
                "network 'fedimint' requires a fedimint_data_dir in the router config"
                    .to_string()
            })?;
            let adapter: Arc<dyn NetworkAdapter> = Arc::new(
                cassis_fedimint::FedimintAdapter::new(
                    network_id.clone(),
                    invite.to_string(),
                    sk,
                    data_dir.to_path_buf(),
                )
                .await
                .map_err(|e| format!("fedimint adapter init failed: {e}"))?,
            );
            let incoming_delta_secs = adapter.incoming_delta_secs();
            Ok(NetworkEntry {
                network_id,
                adapter,
                incoming_delta_secs,
            })
        }

        #[cfg(not(feature = "fedimint"))]
        "fedimint" => Err(
            "network 'fedimint' requested but cassis-router was not compiled with the 'fedimint' feature"
                .into(),
        ),

        #[cfg(feature = "liquid")]
        "liquid" => {
            let network_id = match param {
                None => NetworkId("liquid".to_string()),
                Some("testnet") => NetworkId("liquid::testnet".to_string()),
                Some(other) => {
                    return Err(format!(
                        "network 'liquid' only accepts no parameter or 'testnet', got '{other}'"
                    ));
                }
            };
            // Liquid claims happen with the dedicated even-Y claim key
            // derived from the per-network key; the adapter
            // self-reports its x-only half via `claim_pubkey()` so
            // upstream hops lock to it.
            let sk = network_sk(derived, &network_id)?;
            let cfg = cassis_liquid::default_config(
                network_id.clone(),
                sk,
                span.clone(),
            );
            let mut cfg = cfg;
            cfg.persist_dir = liquid_store_dir.map(|dir| {
                dir.join(network_id.0.replace("::", "_"))
            });
            let adapter: Arc<dyn NetworkAdapter> = cassis_liquid::LiquidAdapter::new(cfg)
                .await
                .map_err(|e| format!("liquid adapter init failed: {e}"))?;
            let incoming_delta_secs = adapter.incoming_delta_secs();
            Ok(NetworkEntry {
                network_id,
                adapter,
                incoming_delta_secs,
            })
        }

        #[cfg(not(feature = "liquid"))]
        "liquid" => Err(
            "network 'liquid' requested but cassis-router was not compiled with the 'liquid' feature"
                .into(),
        ),

        #[cfg(feature = "arkade")]
        "arkade" => {
            let network_id = match param {
                None => NetworkId("arkade".to_string()),
                Some("testnet") => NetworkId("arkade::mutinynet".to_string()),
                Some(other) => {
                    return Err(format!(
                        "network 'arkade' only accepts no parameter or 'testnet', got '{other}'"
                    ));
                }
            };
            // Arkade claims happen with the dedicated per-network
            // key's x-only identity; the adapter self-reports it via
            // `claim_pubkey()` so upstream hops lock to it.
            let sk = network_sk(derived, &network_id)?;
            let cfg = cassis_arkade::default_config(
                network_id.clone(),
                sk,
                span.clone(),
            );
            let adapter: Arc<dyn NetworkAdapter> = cassis_arkade::ArkadeAdapter::new(cfg)
                .await
                .map_err(|e| format!("arkade adapter init failed: {e}"))?;
            let incoming_delta_secs = adapter.incoming_delta_secs();
            Ok(NetworkEntry {
                network_id,
                adapter,
                incoming_delta_secs,
            })
        }

        #[cfg(not(feature = "arkade"))]
        "arkade" => Err(
            "network 'arkade' requested but cassis-router was not compiled with the 'arkade' feature"
                .into(),
        ),

        #[cfg(feature = "bitcoin")]
        "bitcoin" => {
            let network_id = match param {
                None => NetworkId("bitcoin".to_string()),
                Some("mutinynet") => NetworkId("bitcoin::mutinynet".to_string()),
                Some(other) => {
                    return Err(format!(
                        "network 'bitcoin' only accepts no parameter or 'mutinynet', got '{other}'"
                    ));
                }
            };
            // The on-chain adapter claims with the even-parity key
            // derived from the per-network key; it self-reports the
            // x-only half via `claim_pubkey()` so upstream hops lock
            // to it.
            let sk = network_sk(derived, &network_id)?;
            let cfg = cassis_bitcoin::default_config(
                network_id.clone(),
                sk,
                span.clone(),
            )
            .map_err(|e| format!("bitcoin adapter config: {e}"))?;
            let adapter: Arc<dyn NetworkAdapter> = Arc::new(
                cassis_bitcoin::BitcoinAdapter::new(cfg)
                    .await
                    .map_err(|e| format!("bitcoin adapter init failed: {e}"))?,
            );
            let incoming_delta_secs = adapter.incoming_delta_secs();
            Ok(NetworkEntry {
                network_id,
                adapter,
                incoming_delta_secs,
            })
        }

        #[cfg(not(feature = "bitcoin"))]
        "bitcoin" => Err(
            "network 'bitcoin' requested but cassis-router was not compiled with the 'bitcoin' feature"
                .into(),
        ),

        #[cfg(feature = "rootstock")]
        "rootstock" => {
            let network_id = match param {
                None => NetworkId("rootstock".to_string()),
                Some("testnet") => NetworkId("rootstock::testnet".to_string()),
                Some(other) => {
                    return Err(format!(
                        "network 'rootstock' only accepts no parameter or 'testnet', got '{other}'"
                    ));
                }
            };
            let sk = network_sk(derived, &network_id)?;
            // Rootstock claims are signed by a dedicated per-network
            // EVM account. The adapter
            // advertises the matching identity via `claim_pubkey()` so
            // upstream hops lock to an address we can actually claim
            // from.
            let cfg = cassis_rootstock::default_config(
                network_id.clone(),
                sk,
                span.clone(),
            );
            let adapter: Arc<dyn NetworkAdapter> = cassis_rootstock::RootstockAdapter::new(cfg)
                .await
                .map_err(|e| format!("rootstock adapter init failed: {e}"))?;
            let incoming_delta_secs = adapter.incoming_delta_secs();
            Ok(NetworkEntry {
                network_id,
                adapter,
                incoming_delta_secs,
            })
        }

        #[cfg(not(feature = "rootstock"))]
        "rootstock" => Err(
            "network 'rootstock' requested but cassis-router was not compiled with the 'rootstock' feature"
                .into(),
        ),

        #[cfg(feature = "spark")]
        "spark" => {
            if param.is_some() {
                return Err("network 'spark' does not accept parameters".to_string());
            }
            let network_id = NetworkId("spark".to_string());
            let sk = network_sk(derived, &network_id)?;
            let adapter = cassis_spark::SparkAdapter::new(
                network_id.clone(),
                cassis_spark::SparkConfig::default(),
                sk,
                derived.node.pubkey(),
                span.clone(),
            )
            .await
            .map_err(|error| format!("spark adapter init failed: {error}"))?;
            let adapter: Arc<dyn NetworkAdapter> = adapter;
            let incoming_delta_secs = adapter.incoming_delta_secs();
            Ok(NetworkEntry {
                network_id,
                adapter,
                incoming_delta_secs,
            })
        }
        #[cfg(not(feature = "spark"))]
        "spark" => Err(
            "network 'spark' requested but cassis-router was not compiled with the 'spark' feature"
                .into(),
        ),

        #[cfg(feature = "lightning")]
        "lightning" => {
            let config = lnd_config.ok_or_else(|| {
                "network 'lightning' requires an LND REST configuration".to_string()
            })?;
            let network_id = NetworkId("lightning".to_string());
            let adapter = cassis_lnd::LndAdapter::new(
                network_id.clone(),
                config.clone(),
                span.clone(),
            )
            .await
            .map_err(|error| format!("LND adapter init failed: {error}"))?;
            let adapter: Arc<dyn NetworkAdapter> = adapter;
            let incoming_delta_secs = adapter.incoming_delta_secs();
            Ok(NetworkEntry {
                network_id,
                adapter,
                incoming_delta_secs,
            })
        }
        #[cfg(not(feature = "lightning"))]
        "lightning" => Err(
            "network 'lightning' requested but cassis-router was not compiled with the 'lightning' feature"
                .into(),
        ),

        _ => Err(format!("unsupported network kind '{kind}'")),
    }
}

/// Per-execution state the router retains between EXECUTE
/// and the eventual claim. `outgoing_deadline` is the
/// unix-second cutoff the router passes to the adapter's
/// `watch_outgoing`; once exceeded, the execution is refunded
/// (outgoing side) and the incoming side is left to expire
/// on its own.
#[derive(Clone, Serialize, Deserialize)]
struct ExecutedHop {
    operation_id: OperationId,
    owner: String,
    prepare: HopPrepare,
    reservation: IncomingReservation,
    accepted: AcceptedIncoming,
    outgoing: OutgoingPayment,
    /// Unix seconds; the router stops polling after this and
    /// runs the refund path on the outgoing side.
    outgoing_deadline: u64,
}

/// Write-ahead state for an EXECUTE whose external side effects have not
/// all completed yet. The record exists before `accept_incoming` and
/// `create_outgoing` run, so a crash cannot make a funded outgoing HTLC
/// unreachable to recovery.
#[derive(Clone, Serialize, Deserialize)]
struct PendingExecute {
    operation_id: OperationId,
    owner: String,
    prepare: HopPrepare,
    reservation: IncomingReservation,
    incoming_descriptor: HtlcDescriptor,
    outgoing_target: HtlcTarget,
    outgoing_operation_id: OperationId,
    accepted: Option<AcceptedIncoming>,
    outgoing: Option<OutgoingPayment>,
    /// In-process guard. Reset on journal restore after a crash.
    processing: bool,
}

#[derive(Serialize, Deserialize)]
struct RouterJournal {
    version: u8,
    pending: Vec<PendingExecute>,
    executed: Vec<ExecutedHop>,
}

pub struct CassisRouter {
    pub adapters: HashMap<NetworkId, NetworkEntry>,
    /// Identifies the owning node in logs. Every task the router spawns
    /// must be instrumented with this, or its logs lose the node name.
    span: Span,
    prepared: Arc<Mutex<Vec<PreparedEntry>>>,
    pending: Arc<Mutex<HashMap<OperationId, PendingExecute>>>,
    executed: Arc<Mutex<HashMap<OperationId, ExecutedHop>>>,
    state_path: Option<PathBuf>,
    state_write_lock: Arc<Mutex<()>>,
    settled: Arc<Mutex<HashMap<OperationId, String>>>,
    /// See [`RouterConfig::prepare_veto`].
    prepare_veto: Option<PrepareVeto>,
}

impl CassisRouter {
    pub fn new(
        adapters: HashMap<NetworkId, NetworkEntry>,
        span: Span,
        prepare_veto: Option<PrepareVeto>,
    ) -> Self {
        Self::new_with_state(adapters, span, prepare_veto, None)
    }

    pub fn new_with_state(
        adapters: HashMap<NetworkId, NetworkEntry>,
        span: Span,
        prepare_veto: Option<PrepareVeto>,
        state_path: Option<PathBuf>,
    ) -> Self {
        Self {
            adapters,
            span,
            prepared: Arc::new(Mutex::new(Vec::new())),
            pending: Arc::new(Mutex::new(HashMap::new())),
            executed: Arc::new(Mutex::new(HashMap::new())),
            state_path,
            state_write_lock: Arc::new(Mutex::new(())),
            settled: Arc::new(Mutex::new(HashMap::new())),
            prepare_veto,
        }
    }

    async fn restore_state_from_disk(&self) -> Result<(), String> {
        let Some(path) = &self.state_path else {
            return Ok(());
        };
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.to_string()),
        };
        let journal: RouterJournal = serde_json::from_slice(&bytes)
            .map_err(|error| format!("decode {}: {error}", path.display()))?;
        if journal.version != ROUTER_JOURNAL_VERSION {
            return Err(format!(
                "unsupported router state version {} in {}",
                journal.version,
                path.display()
            ));
        }

        for mut pending in journal.pending {
            pending.processing = false;
            if let Some(incoming) = self.adapters.get(&pending.prepare.incoming_network) {
                if let Err(error) = incoming
                    .adapter
                    .restore_incoming_reservation(&pending.reservation)
                    .await
                {
                    warn!(
                        target: "cassis_router",
                        "restore pending reservation for operation_id={} failed: {error}; will retry from journal",
                        pending.operation_id,
                    );
                }
                if let Some(accepted) = pending.accepted.as_ref() {
                    if let Err(error) = incoming.adapter.restore_incoming(accepted).await {
                        warn!(
                            target: "cassis_router",
                            "restore pending accepted state for operation_id={} failed: {error}; will retry from journal",
                            pending.operation_id,
                        );
                    }
                }
            }
            if let (Some(outgoing), Some(payment)) = (
                self.adapters.get(&pending.prepare.outgoing_network),
                pending.outgoing.as_ref(),
            ) {
                if let Err(error) = outgoing.adapter.restore_outgoing(payment).await {
                    warn!(
                        target: "cassis_router",
                        "restore pending outgoing state for operation_id={} failed: {error}; will retry from journal",
                        pending.operation_id,
                    );
                }
            }
            self.pending
                .lock()
                .await
                .insert(pending.operation_id.clone(), pending);
        }

        let restored_count = journal.executed.len();
        for hop in journal.executed {
            if let Some(incoming) = self.adapters.get(&hop.prepare.incoming_network) {
                if let Err(error) = incoming.adapter.restore_incoming(&hop.accepted).await {
                    warn!(
                        target: "cassis_router",
                        "restore incoming state for operation_id={} failed: {error}; will retry from journal",
                        hop.operation_id,
                    );
                }
            }
            if let Some(outgoing) = self.adapters.get(&hop.prepare.outgoing_network) {
                let payment = hop.outgoing.clone();
                if let Err(error) = outgoing.adapter.restore_outgoing(&payment).await {
                    warn!(
                        target: "cassis_router",
                        "restore outgoing state for operation_id={} failed: {error}; will retry from journal",
                        hop.operation_id,
                    );
                }
            }
            self.executed
                .lock()
                .await
                .insert(hop.operation_id.clone(), hop);
        }
        self.recover_pending_executees().await;
        info!(
            target: "cassis_router",
            "restored {} funded execute(es) from {}",
            restored_count,
            path.display(),
        );
        Ok(())
    }

    async fn persist_state_to_disk(&self) -> Result<(), String> {
        let Some(path) = &self.state_path else {
            return Ok(());
        };
        let _guard = self.state_write_lock.lock().await;
        let pending = self.pending.lock().await;
        let executed = self.executed.lock().await;
        let journal = RouterJournal {
            version: ROUTER_JOURNAL_VERSION,
            pending: pending.values().cloned().collect(),
            executed: executed.values().cloned().collect(),
        };
        drop(executed);
        drop(pending);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("create state directory: {error}"))?;
        }
        let encoded = serde_json::to_vec(&journal)
            .map_err(|error| format!("encode router state: {error}"))?;
        let temporary = path.with_extension(format!(
            "{}.tmp",
            path.extension().and_then(|e| e.to_str()).unwrap_or("state")
        ));
        {
            use std::io::Write;
            let mut file = std::fs::File::create(&temporary)
                .map_err(|error| format!("create router state: {error}"))?;
            file.write_all(&encoded)
                .map_err(|error| format!("write router state: {error}"))?;
            file.sync_all()
                .map_err(|error| format!("sync router state: {error}"))?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = std::fs::metadata(&temporary)
                .map_err(|error| format!("read router state permissions: {error}"))?
                .permissions();
            permissions.set_mode(0o600);
            std::fs::set_permissions(&temporary, permissions)
                .map_err(|error| format!("set router state permissions: {error}"))?;
        }
        std::fs::rename(&temporary, path)
            .map_err(|error| format!("replace router state: {error}"))?;
        #[cfg(unix)]
        if let Some(parent) = path.parent() {
            std::fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| format!("sync router state directory: {error}"))?;
        }
        Ok(())
    }

    async fn store_pending(&self, pending: PendingExecute) -> Result<(), String> {
        self.pending
            .lock()
            .await
            .insert(pending.operation_id.clone(), pending);
        self.persist_state_to_disk().await
    }

    async fn claim_pending_operation(
        &self,
        operation_id: &OperationId,
    ) -> Result<PendingExecute, String> {
        let mut pending = self.pending.lock().await;
        let entry = pending
            .get_mut(operation_id)
            .ok_or_else(|| format!("no pending execute for operation_id={operation_id}"))?;
        if entry.processing {
            return Err(format!(
                "EXECUTE already processing operation_id={operation_id}"
            ));
        }
        entry.processing = true;
        Ok(entry.clone())
    }

    async fn clear_pending_processing(&self, operation_id: &OperationId) {
        if let Some(entry) = self.pending.lock().await.get_mut(operation_id) {
            entry.processing = false;
        }
    }

    async fn recover_pending_executees(&self) {
        let candidates: Vec<PendingExecute> = {
            let pending = self.pending.lock().await;
            pending
                .values()
                .filter(|entry| !entry.processing)
                .cloned()
                .collect()
        };
        for candidate in candidates {
            if candidate.prepare.outgoing_expiry <= unix_now() {
                self.abandon_pending_execute(candidate).await;
                continue;
            }
            let mut pending = match self.claim_pending_operation(&candidate.operation_id).await {
                Ok(pending) => pending,
                Err(error) => {
                    warn!(
                        target: "cassis_router",
                        "claim pending execute {} failed: {error}",
                        candidate.operation_id,
                    );
                    continue;
                }
            };
            if let Err(error) = self.resume_pending_execute(&mut pending).await {
                warn!(
                    target: "cassis_router",
                    "recover pending execute {} failed: {error}",
                    candidate.operation_id,
                );
            }
        }
    }

    async fn abandon_pending_execute(&self, pending: PendingExecute) {
        if let Some(payment) = pending.outgoing.clone() {
            if let Some(outgoing) = self.adapters.get(&pending.prepare.outgoing_network) {
                if let Err(error) = outgoing.adapter.refund_outgoing(&payment).await {
                    warn!(
                        target: "cassis_router",
                        "refund abandoned pending execute {} failed: {error}; keeping journal record",
                        pending.operation_id,
                    );
                    return;
                }
            }
        }
        if let Some(incoming) = self.adapters.get(&pending.prepare.incoming_network) {
            if let Err(error) = incoming.adapter.cancel_incoming(&pending.reservation).await {
                warn!(
                    target: "cassis_router",
                    "cancel abandoned incoming reservation {} failed: {error}; keeping journal record",
                    pending.operation_id,
                );
                return;
            }
        }
        self.prepared
            .lock()
            .await
            .retain(|entry| entry.reservation.operation_id != pending.operation_id);
        self.pending.lock().await.remove(&pending.operation_id);
        if let Err(error) = self.persist_state_to_disk().await {
            warn!(
                target: "cassis_router",
                "persist abandonment of pending execute {} failed: {error}",
                pending.operation_id,
            );
        }
    }

    async fn resume_pending_execute(
        &self,
        pending: &mut PendingExecute,
    ) -> Result<HopExecuted, String> {
        let result = self.resume_pending_execute_inner(pending).await;
        if result.is_err() {
            self.clear_pending_processing(&pending.operation_id).await;
        }
        result
    }

    async fn resume_pending_execute_inner(
        &self,
        pending: &mut PendingExecute,
    ) -> Result<HopExecuted, String> {
        if pending.accepted.is_none() {
            let incoming = self
                .adapters
                .get(&pending.prepare.incoming_network)
                .ok_or_else(|| "incoming network unsupported".to_string())?;
            let accepted = incoming
                .adapter
                .accept_incoming(&pending.reservation, &pending.incoming_descriptor)
                .await
                .map_err(|error| format!("incoming HTLC not claimable: {error}"))?;
            pending.accepted = Some(accepted);
            self.store_pending(pending.clone()).await?;
        }

        let outgoing = match pending.outgoing.clone() {
            Some(outgoing) => outgoing,
            None => {
                let outgoing_entry = self
                    .adapters
                    .get(&pending.prepare.outgoing_network)
                    .ok_or_else(|| "outgoing network unsupported".to_string())?;
                let outgoing = outgoing_entry
                    .adapter
                    .create_outgoing(OutgoingRequest {
                        operation_id: pending.outgoing_operation_id.clone(),
                        payment_hash: pending.prepare.payment_hash,
                        amount_msat: pending.prepare.outgoing_amount_msat,
                        expiry: pending.prepare.outgoing_expiry,
                        target: pending.outgoing_target.clone(),
                        network: pending.prepare.outgoing_network.clone(),
                    })
                    .await
                    .map_err(|error| {
                        format!(
                            "create_outgoing failed on {}: {error}",
                            pending.prepare.outgoing_network
                        )
                    })?;
                pending.outgoing = Some(outgoing.clone());
                self.store_pending(pending.clone()).await?;
                outgoing
            }
        };

        {
            let mut prepared = self.prepared.lock().await;
            prepared.retain(|entry| entry.reservation.operation_id != pending.operation_id);
        }
        self.executed.lock().await.insert(
            pending.operation_id.clone(),
            ExecutedHop {
                operation_id: pending.operation_id.clone(),
                owner: pending.owner.clone(),
                prepare: pending.prepare.clone(),
                reservation: pending.reservation.clone(),
                accepted: pending
                    .accepted
                    .clone()
                    .ok_or_else(|| "pending execute has no accepted state".to_string())?,
                outgoing: outgoing.clone(),
                outgoing_deadline: pending.prepare.outgoing_expiry,
            },
        );
        self.pending.lock().await.remove(&pending.operation_id);
        self.persist_state_to_disk().await?;
        Ok(HopExecuted {
            payment_hash: pending.prepare.payment_hash,
            operation_id: pending.operation_id.clone(),
            outgoing_descriptor: outgoing.descriptor,
        })
    }

    /// Top-level executor: turn a [`Frame`] into the
    /// matching reply [`Frame`]. The router only handles
    /// Prepare / Prepared / Execute / Executed / Discard /
    /// Discarded; Commit / Committed flow directly from sender to
    /// receiver (payee's `cassis-cli`) without crossing a router hop.
    ///
    /// `remote` is the authenticated iroh identity of the requesting
    /// peer. It scopes state the router keeps on a caller's behalf:
    /// PREPARE reservations belong to whoever created them, and only
    /// that peer may release one via DISCARD.
    pub async fn handle_frame(&self, frame: Frame, remote: PublicKey) -> Result<Frame, IrohError> {
        self.handle_frame_inner(frame, remote)
            .instrument(self.span.clone())
            .await
    }

    async fn handle_frame_inner(
        &self,
        frame: Frame,
        remote: PublicKey,
    ) -> Result<Frame, IrohError> {
        match &frame {
            Frame::Prepare(p) => {
                info!(
                    target: "cassis_router",
                    "received PREPARE from peer={remote}: payment_hash={} amount_msat={} {} -> {} \
                     incoming_deadline={} outgoing_expiry={}",
                    p.payment_hash.short(),
                    p.amount_msat,
                    p.incoming_network,
                    p.outgoing_network,
                    p.incoming_deadline,
                    p.outgoing_expiry,
                );
            }
            Frame::Execute(d) => {
                info!(
                    target: "cassis_router",
                    "received EXECUTE: payment_hash={} addressing=<redacted> incoming_descriptor=<redacted>",
                    d.payment_hash.short(),
                );
            }
            Frame::Discard(d) => {
                info!(
                    target: "cassis_router",
                    "received DISCARD from peer={remote}: payment_hash={}",
                    d.payment_hash.short(),
                );
            }
            Frame::Commit(c) => {
                info!(
                    target: "cassis_router",
                    "received COMMIT (unusual for a router): payment_hash={} amount_msat={} network={}",
                    c.payment_hash.short(), c.amount_msat, c.network,
                );
            }
            Frame::Committed(c) => {
                info!(
                    target: "cassis_router",
                    "received COMMITTED preimage fanout from peer={remote}: payment_hash={}",
                    c.payment_hash.short(),
                );
            }
            other => {
                warn!(
                    target: "cassis_router",
                    "received unexpected frame: payment_hash={} {:?}",
                    other.payment_hash(),
                    other,
                );
            }
        }
        match frame {
            Frame::Prepare(p) => self
                .handle_prepare(p, remote)
                .await
                .map(Frame::Prepared)
                .map_err(internal),
            Frame::Execute(d) => self
                .handle_execute(d, remote)
                .await
                .map(Frame::Executed)
                .map_err(internal),
            Frame::Discard(d) => self
                .handle_discard(d, remote)
                .await
                .map(Frame::Discarded)
                .map_err(internal),
            Frame::Commit(c) => self
                .handle_commit(c)
                .await
                .map(Frame::Committed)
                .map_err(internal),
            Frame::Committed(c) => self
                .handle_committed(c, remote)
                .await
                .map(Frame::Committed)
                .map_err(internal),
            other => Err(IrohError::Protocol(format!(
                "router received unexpected frame {:?}",
                other
            ))),
        }
    }

    /// PREPARE handler: validate the request, check funds on
    /// the outgoing side, store the spec. Do NOT create any
    /// HTLCs.
    ///
    /// The reservation is bound to `remote`: the iroh peer that sent
    /// the PREPARE is the only peer allowed to release it later with
    /// a DISCARD. This closes the cheap DoS where anyone who learns a
    /// payment_hash could otherwise free someone else's reservation
    /// and strand their EXECUTE with "no matching PREPARE". No funds
    /// are ever at risk — a reservation is bookkeeping, not money.
    async fn handle_prepare(
        &self,
        mut prepare: HopPrepare,
        remote: PublicKey,
    ) -> Result<HopPrepared, String> {
        let incoming_raw = prepare.incoming_network.clone();
        let outgoing_raw = prepare.outgoing_network.clone();
        prepare.incoming_network = normalize_network_id(&prepare.incoming_network);
        prepare.outgoing_network = normalize_network_id(&prepare.outgoing_network);
        if prepare.incoming_network != incoming_raw || prepare.outgoing_network != outgoing_raw {
            debug!(
                target: "cassis_router",
                "canonicalized network ids: incoming {} -> {}, outgoing {} -> {}",
                incoming_raw,
                prepare.incoming_network,
                outgoing_raw,
                prepare.outgoing_network,
            );
        }
        self.validate_prepare(&prepare)?;
        self.cleanup_expired_prepared().await;

        if let Some(veto) = &self.prepare_veto {
            if let Some(reason) = veto(&prepare) {
                warn!(
                    target: "cassis_router",
                    "PREPARE vetoed: payment_hash={} amount_msat={} {} -> {} reason={reason}",
                    prepare.payment_hash.short(),
                    prepare.amount_msat,
                    prepare.incoming_network,
                    prepare.outgoing_network,
                );
                return Ok(HopPrepared {
                    payment_hash: prepare.payment_hash,
                    operation_id: prepare.operation_id.clone(),
                    accepted: false,
                    reason: Some(reason),
                    htlc_target: None,
                });
            }
        }

        let incoming_entry = self
            .adapters
            .get(&prepare.incoming_network)
            .ok_or_else(|| "incoming network unsupported".to_string())?;
        let outgoing_entry = self
            .adapters
            .get(&prepare.outgoing_network)
            .ok_or_else(|| "outgoing network unsupported".to_string())?;

        // Reject same-hash attempts while any local reservation or
        // funded execution exists. Adapters enforce same invariant in their
        // operation-keyed state; router check preserves owner/replay
        // semantics before adapter call.
        {
            let prepared = self.prepared.lock().await;
            if let Some(entry) = prepared.iter().find(|entry| {
                entry.prepare.payment_hash == prepare.payment_hash
                    && entry.reservation.operation_id == prepare.operation_id
                    && entry.owner == remote
            }) {
                return Ok(HopPrepared {
                    payment_hash: prepare.payment_hash,
                    operation_id: entry.reservation.operation_id.clone(),
                    accepted: true,
                    reason: None,
                    htlc_target: Some(entry.reservation.target.clone()),
                });
            }
            if prepared
                .iter()
                .any(|entry| entry.prepare.payment_hash == prepare.payment_hash)
            {
                return Ok(HopPrepared {
                    payment_hash: prepare.payment_hash,
                    operation_id: prepare.operation_id.clone(),
                    accepted: false,
                    reason: Some("payment hash already has an active attempt".into()),
                    htlc_target: None,
                });
            }
        }
        {
            let executed = self.executed.lock().await;
            if let Some(hop) = executed.get(&prepare.operation_id) {
                if hop.owner != remote.to_string() {
                    return Err("operation_id belongs to another peer".to_string());
                }
                return Ok(HopPrepared {
                    payment_hash: prepare.payment_hash,
                    operation_id: prepare.operation_id.clone(),
                    accepted: true,
                    reason: None,
                    htlc_target: Some(hop.reservation.target.clone()),
                });
            }
            if executed
                .values()
                .any(|hop| hop.prepare.payment_hash == prepare.payment_hash)
            {
                return Ok(HopPrepared {
                    payment_hash: prepare.payment_hash,
                    operation_id: prepare.operation_id.clone(),
                    accepted: false,
                    reason: Some("payment hash already has a funded execute".into()),
                    htlc_target: None,
                });
            }
        }

        // Check capacity before creating remote resources or adapter state.
        {
            let prepared = self.prepared.lock().await;
            if prepared.len() >= 100 {
                return Ok(HopPrepared {
                    payment_hash: prepare.payment_hash,
                    operation_id: prepare.operation_id.clone(),
                    accepted: false,
                    reason: Some("PREPARE capacity exhausted".into()),
                    htlc_target: None,
                });
            }
        }

        if let Err(error) = outgoing_entry
            .adapter
            .can_route(prepare.outgoing_amount_msat)
            .await
        {
            warn!(
                target: "cassis_router",
                "PREPARE rejected: payment_hash={} reason=can_route failed on {}: {error}",
                prepare.payment_hash.short(),
                prepare.outgoing_network,
            );
            return Ok(HopPrepared {
                payment_hash: prepare.payment_hash,
                operation_id: prepare.operation_id.clone(),
                accepted: false,
                reason: Some(format!("can_route failed: {error}")),
                htlc_target: None,
            });
        }

        if let Err(error) = incoming_entry.adapter.can_claim(prepare.amount_msat).await {
            warn!(
                target: "cassis_router",
                "PREPARE rejected: payment_hash={} reason=can_claim failed on {}: {error}",
                prepare.payment_hash.short(),
                prepare.incoming_network,
            );
            return Ok(HopPrepared {
                payment_hash: prepare.payment_hash,
                operation_id: prepare.operation_id.clone(),
                accepted: false,
                reason: Some(format!("can_claim failed: {error}")),
                htlc_target: None,
            });
        }

        let operation_id = prepare.operation_id.clone();
        let reservation = match incoming_entry
            .adapter
            .reserve_incoming(IncomingRequest {
                operation_id: operation_id.clone(),
                payment_hash: prepare.payment_hash,
                amount_msat: prepare.amount_msat,
                deadline: prepare.incoming_deadline,
                preimage: None,
            })
            .await
        {
            Ok(reservation) => reservation,
            Err(error) => {
                warn!(
                    target: "cassis_router",
                    "PREPARE rejected: payment_hash={} reason=reserve_incoming failed on {}: {error}",
                    prepare.payment_hash.short(),
                    prepare.incoming_network,
                );
                return Ok(HopPrepared {
                    payment_hash: prepare.payment_hash,
                    operation_id: prepare.operation_id.clone(),
                    accepted: false,
                    reason: Some(format!("reserve_incoming failed: {error}")),
                    htlc_target: None,
                });
            }
        };

        let expires_at = unix_now().saturating_add(600);
        self.prepared.lock().await.push(PreparedEntry {
            prepare: prepare.clone(),
            reservation: reservation.clone(),
            outgoing_operation_id: OperationId::random(),
            expires_at,
            processing: false,
            owner: remote,
        });

        info!(
            target: "cassis_router",
            "PREPARE accepted: payment_hash={} operation_id={} amount_msat={} {} -> {}",
            prepare.payment_hash.short(),
            reservation.operation_id,
            prepare.amount_msat,
            prepare.incoming_network,
            prepare.outgoing_network,
        );
        Ok(HopPrepared {
            payment_hash: prepare.payment_hash,
            operation_id: reservation.operation_id,
            accepted: true,
            reason: None,
            htlc_target: Some(reservation.target),
        })
    }

    /// EXECUTE handler: verify the incoming HTLC is
    /// claimable on the hop's incoming adapter, then create
    /// the outgoing HTLC on the outgoing adapter and stash
    /// state for the poll loop.
    async fn handle_execute(
        &self,
        execute: HopExecute,
        remote: PublicKey,
    ) -> Result<HopExecuted, String> {
        self.cleanup_expired_prepared().await;
        if let Some(existing) = self
            .executed
            .lock()
            .await
            .get(&execute.operation_id)
            .cloned()
        {
            if existing.owner != remote.to_string() {
                return Err("operation_id belongs to another peer".to_string());
            }
            if existing.prepare.payment_hash != execute.payment_hash {
                return Err("EXECUTE payment hash does not match operation".to_string());
            }
            return Ok(HopExecuted {
                payment_hash: execute.payment_hash,
                operation_id: execute.operation_id,
                outgoing_descriptor: existing.outgoing.descriptor,
            });
        }
        if let Some(existing) = self
            .pending
            .lock()
            .await
            .get(&execute.operation_id)
            .cloned()
        {
            if existing.owner != remote.to_string() {
                return Err("operation_id belongs to another peer".to_string());
            }
            if existing.prepare.payment_hash != execute.payment_hash
                || existing.incoming_descriptor != execute.incoming_descriptor
                || existing.outgoing_target != execute.htlc_target
            {
                return Err("EXECUTE does not match pending operation state".to_string());
            }
            let mut pending = self.claim_pending_operation(&execute.operation_id).await?;
            return self.resume_pending_execute(&mut pending).await;
        }

        let entry = {
            let mut prepared = self.prepared.lock().await;
            let index = prepared
                .iter()
                .position(|entry| entry.reservation.operation_id == execute.operation_id)
                .ok_or_else(|| {
                    format!(
                        "no matching PREPARE for operation_id={}",
                        execute.operation_id
                    )
                })?;
            if prepared[index].owner != remote {
                return Err(format!(
                    "EXECUTE denied: operation_id={} reserved by {} but request came from {remote}",
                    execute.operation_id, prepared[index].owner
                ));
            }
            if prepared[index].processing {
                return Err(format!(
                    "EXECUTE already processing operation_id={}",
                    execute.operation_id
                ));
            }
            if prepared[index].prepare.payment_hash != execute.payment_hash {
                return Err("EXECUTE payment hash does not match reservation".to_string());
            }
            prepared[index].processing = true;
            prepared[index].clone()
        };

        let prepare = entry.prepare.clone();
        if !self.adapters.contains_key(&prepare.incoming_network) {
            self.clear_processing(&execute.operation_id).await;
            return Err("incoming network unsupported".to_string());
        }
        if !self.adapters.contains_key(&prepare.outgoing_network) {
            self.clear_processing(&execute.operation_id).await;
            return Err("outgoing network unsupported".to_string());
        }

        let mut pending = PendingExecute {
            operation_id: execute.operation_id.clone(),
            owner: remote.to_string(),
            prepare: prepare.clone(),
            reservation: entry.reservation,
            incoming_descriptor: execute.incoming_descriptor.clone(),
            outgoing_target: execute.htlc_target.clone(),
            outgoing_operation_id: entry.outgoing_operation_id,
            accepted: None,
            outgoing: None,
            processing: true,
        };
        self.pending
            .lock()
            .await
            .insert(pending.operation_id.clone(), pending.clone());
        if let Err(error) = self.persist_state_to_disk().await {
            self.pending.lock().await.remove(&pending.operation_id);
            self.clear_processing(&execute.operation_id).await;
            return Err(format!("persist pending execute: {error}"));
        }
        let outgoing_operation_id = pending.outgoing_operation_id.clone();
        let result = self.resume_pending_execute(&mut pending).await;
        if result.is_ok() {
            info!(
                target: "cassis_router",
                "EXECUTE done: payment_hash={} operation_id={} outgoing_operation_id={} amount_msat={} {} -> {}",
                prepare.payment_hash.short(),
                pending.operation_id,
                outgoing_operation_id,
                prepare.amount_msat,
                prepare.incoming_network,
                prepare.outgoing_network,
            );
        }
        result
    }

    async fn clear_processing(&self, operation_id: &OperationId) {
        let mut prepared = self.prepared.lock().await;
        if let Some(entry) = prepared
            .iter_mut()
            .find(|entry| &entry.reservation.operation_id == operation_id)
        {
            entry.processing = false;
        }
    }

    async fn cleanup_expired_prepared(&self) {
        let now = unix_now();
        let expired: Vec<PreparedEntry> = {
            let mut prepared = self.prepared.lock().await;
            let mut expired = Vec::new();
            let mut retained = Vec::with_capacity(prepared.len());
            for entry in prepared.drain(..) {
                if entry.expires_at <= now && !entry.processing {
                    expired.push(entry);
                } else {
                    retained.push(entry);
                }
            }
            *prepared = retained;
            expired
        };
        for mut entry in expired {
            let Some(adapter) = self.adapters.get(&entry.prepare.incoming_network) else {
                continue;
            };
            match adapter.adapter.cancel_incoming(&entry.reservation).await {
                Ok(()) => {}
                Err(error) if error.is_retryable() => {
                    entry.expires_at = unix_now().saturating_add(30);
                    self.prepared.lock().await.push(entry);
                }
                Err(error) => {
                    warn!(
                        target: "cassis_router",
                        "dropping expired reservation operation_id={} after cancel error: {error}",
                        entry.reservation.operation_id,
                    );
                }
            }
        }
    }

    /// DISCARD handler: release a PREPARE reservation that will never
    /// be followed by an EXECUTE.
    ///
    /// Only the peer that created the reservation may release it, and
    /// only while it still exists: `handle_execute` removes the entry
    /// before creating any HTLC, so a DISCARD can never unwind funded
    /// money — it either frees pure bookkeeping or finds nothing. Both
    /// "already consumed" and "never existed" report `released: false`
    /// as normal outcomes; the payer treats this whole exchange as
    /// best-effort cleanup.
    async fn handle_discard(
        &self,
        discard: HopDiscard,
        remote: PublicKey,
    ) -> Result<HopDiscarded, String> {
        if !discard.operation_id.is_valid() {
            return Err("DISCARD operation_id must be 32 hexadecimal characters".to_string());
        }
        self.cleanup_expired_prepared().await;
        let entry = {
            let mut prepared = self.prepared.lock().await;
            let Some(index) = prepared
                .iter()
                .position(|entry| entry.reservation.operation_id == discard.operation_id)
            else {
                return Ok(HopDiscarded {
                    payment_hash: discard.payment_hash,
                    operation_id: discard.operation_id,
                    released: false,
                });
            };
            if prepared[index].processing {
                return Ok(HopDiscarded {
                    payment_hash: discard.payment_hash,
                    operation_id: discard.operation_id,
                    released: false,
                });
            }
            if prepared[index].owner != remote {
                warn!(
                    target: "cassis_router",
                    "DISCARD denied: operation_id={} reserved by {} but request came from {remote}",
                    discard.operation_id, prepared[index].owner,
                );
                return Ok(HopDiscarded {
                    payment_hash: discard.payment_hash,
                    operation_id: discard.operation_id,
                    released: false,
                });
            }
            prepared[index].processing = true;
            prepared[index].clone()
        };

        let cancel_result =
            if let Some(adapter) = self.adapters.get(&entry.prepare.incoming_network) {
                adapter.adapter.cancel_incoming(&entry.reservation).await
            } else {
                Ok(())
            };
        match cancel_result {
            Ok(()) => {
                self.prepared.lock().await.retain(|candidate| {
                    candidate.reservation.operation_id != entry.reservation.operation_id
                });
                info!(
                    target: "cassis_router",
                    "DISCARD processed: payment_hash={} operation_id={} peer={remote} released=true",
                    discard.payment_hash.short(),
                    entry.reservation.operation_id,
                );
                Ok(HopDiscarded {
                    payment_hash: discard.payment_hash,
                    operation_id: entry.reservation.operation_id,
                    released: true,
                })
            }
            Err(error) if error.is_retryable() => {
                self.clear_processing(&entry.reservation.operation_id).await;
                warn!(
                    target: "cassis_router",
                    "DISCARD deferred for operation_id={}: {error}",
                    entry.reservation.operation_id,
                );
                Ok(HopDiscarded {
                    payment_hash: discard.payment_hash,
                    operation_id: entry.reservation.operation_id,
                    released: false,
                })
            }
            Err(error) => {
                self.prepared.lock().await.retain(|candidate| {
                    candidate.reservation.operation_id != entry.reservation.operation_id
                });
                warn!(
                    target: "cassis_router",
                    "DISCARD cleanup permanently failed for operation_id={}: {error}",
                    entry.reservation.operation_id,
                );
                Ok(HopDiscarded {
                    payment_hash: discard.payment_hash,
                    operation_id: entry.reservation.operation_id,
                    released: false,
                })
            }
        }
    }

    /// COMMIT handler. Routers don't normally receive COMMIT
    /// (the sender sends COMMIT directly to the final
    /// receiver), but we accept it defensively in case the
    /// route has zero hops (sender == receiver) and the call
    /// loops back through us. In that case we just
    /// acknowledge the payment hash.
    async fn handle_commit(&self, commit: HopCommit) -> Result<HopCommitted, String> {
        if !commit.operation_id.is_valid() {
            return Err("COMMIT operation_id must be 32 hexadecimal characters".to_string());
        }
        info!(
            target: "cassis_router",
            "COMMIT (received by router, unusual): payment_hash={} amount_msat={} network={}",
            commit.payment_hash.short(),
            commit.amount_msat,
            commit.network,
        );
        // Routers don't hold preimages; the final receiver
        // does. The COMMIT handler on a router is a no-op
        // that returns a zero preimage so the sender can
        // detect the misroute if it ever happens. The normal
        // path skips routers entirely for COMMIT.
        Ok(HopCommitted {
            payment_hash: commit.payment_hash,
            operation_id: commit.operation_id,
            preimage: Bytes32([0u8; 32]),
        })
    }

    /// COMMITTED preimage fanout. After the payee reveals the preimage
    /// to the payer, the payer pushes it to every hop so each can claim
    /// its incoming HTLC immediately instead of waiting for the poll
    /// loop to observe the preimage on the downstream network. The
    /// preimage is validated against the route hash before any claim is
    /// attempted, so a bogus fanout cannot burn the hop's executed
    /// state; the poll loop remains the fallback when the fanout never
    /// arrives.
    async fn handle_committed(
        &self,
        committed: HopCommitted,
        remote: PublicKey,
    ) -> Result<HopCommitted, String> {
        if !committed.operation_id.is_valid() {
            return Err("COMMITTED operation_id must be 32 hexadecimal characters".to_string());
        }
        let operation_id = committed.operation_id.clone();
        if !committed.payment_hash.matches_preimage(&committed.preimage) {
            return Err(format!(
                "preimage does not hash to payment_hash={}",
                committed.payment_hash
            ));
        }
        if let Some(owner) = self.settled.lock().await.get(&operation_id) {
            if owner != &remote.to_string() {
                return Err("COMMITTED operation_id belongs to another peer".to_string());
            }
            return Ok(committed);
        }
        let hop = {
            let executed = self.executed.lock().await;
            executed.get(&operation_id).cloned()
        }
        .ok_or_else(|| {
            format!(
                "no executed hop for operation_id={} payment_hash={}",
                operation_id, committed.payment_hash
            )
        })?;
        if hop.owner != remote.to_string() {
            return Err(format!(
                "COMMITTED denied: operation_id={} belongs to another peer",
                operation_id
            ));
        }
        if hop.prepare.payment_hash != committed.payment_hash {
            return Err("COMMITTED payment hash does not match operation".to_string());
        }
        if let Err(error) = self.claim_incoming(&hop, committed.preimage).await {
            warn!(
                target: "cassis_router",
                "preimage fanout claim deferred for operation_id={}: {error}",
                operation_id,
            );
        }
        Ok(committed)
    }

    /// Background task: every [`POLL_INTERVAL_SECS`] seconds,
    /// walk the executed table and poll each outgoing HTLC
    /// for the preimage. When the preimage is known, claim
    /// the incoming HTLC on the incoming adapter with the
    /// same preimage. On deadline, refund the outgoing side
    /// and drop the execute row from it.
    async fn run_poll_loop(self: Arc<Self>) {
        let interval = Duration::from_secs(POLL_INTERVAL_SECS);
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            if let Err(e) = self.poll_once().await {
                warn!(target: "cassis_router", "poll_once error: {e}");
            }
        }
    }

    async fn poll_once(&self) -> Result<(), String> {
        self.cleanup_expired_prepared().await;
        self.recover_pending_executees().await;

        let snapshot: Vec<ExecutedHop> = {
            let executed = self.executed.lock().await;
            executed.values().cloned().collect()
        };
        let now = unix_now();
        for hop in snapshot {
            if now >= hop.outgoing_deadline {
                warn!(
                    target: "cassis_router",
                    "outgoing deadline exceeded for operation_id={}, refunding",
                    hop.operation_id,
                );
                self.refund_executeed(&hop).await;
                continue;
            }
            let Some(outgoing_entry) = self.adapters.get(&hop.prepare.outgoing_network) else {
                warn!(
                    target: "cassis_router",
                    "outgoing adapter missing for operation_id={}",
                    hop.operation_id,
                );
                continue;
            };
            let payment = hop.outgoing.clone();
            let poll_deadline = hop
                .outgoing_deadline
                .min(now.saturating_add(POLL_INTERVAL_SECS));
            match outgoing_entry
                .adapter
                .watch_outgoing(&payment, poll_deadline)
                .await
            {
                Ok(preimage) => {
                    if !hop.prepare.payment_hash.matches_preimage(&preimage) {
                        warn!(
                            target: "cassis_router",
                            "preimage hash mismatch for operation_id={}",
                            hop.operation_id,
                        );
                        continue;
                    }
                    info!(
                        target: "cassis_router",
                        "preimage revealed by downstream on {} for operation_id={}",
                        hop.prepare.outgoing_network,
                        hop.operation_id,
                    );
                    if let Err(error) = self.claim_incoming(&hop, preimage).await {
                        warn!(
                            target: "cassis_router",
                            "claim deferred for operation_id={}: {error}",
                            hop.operation_id,
                        );
                    }
                }
                Err(AdapterError::DeadlineExceeded) => {
                    debug!(
                        target: "cassis_router",
                        "poll for operation_id={}: no preimage yet",
                        hop.operation_id,
                    );
                }
                Err(AdapterError::Network(err)) | Err(AdapterError::Retryable(err)) => {
                    warn!(
                        target: "cassis_router",
                        "poll for operation_id={} retryable error: {err}",
                        hop.operation_id,
                    );
                }
                Err(AdapterError::Unimplemented) => {
                    warn!(
                        target: "cassis_router",
                        "poll for operation_id={} unsupported by adapter",
                        hop.operation_id,
                    );
                }
                Err(AdapterError::InvalidParams(error)) | Err(AdapterError::NotFound(error)) => {
                    warn!(
                        target: "cassis_router",
                        "poll for operation_id={} state error: {error}",
                        hop.operation_id,
                    );
                }
            }
        }
        Ok(())
    }

    async fn claim_incoming(&self, hop: &ExecutedHop, preimage: Bytes32) -> Result<(), String> {
        let incoming_entry = self
            .adapters
            .get(&hop.prepare.incoming_network)
            .ok_or_else(|| "incoming network unsupported".to_string())?;
        incoming_entry
            .adapter
            .claim_incoming(&hop.accepted, preimage)
            .await
            .map_err(|error| error.to_string())?;
        info!(
            target: "cassis_router",
            "incoming HTLC claimed on {} for operation_id={}",
            hop.prepare.incoming_network,
            hop.operation_id,
        );
        self.settled
            .lock()
            .await
            .insert(hop.operation_id.clone(), hop.owner.clone());
        self.drop_executeed(&hop.operation_id).await;
        Ok(())
    }

    async fn refund_executeed(&self, hop: &ExecutedHop) {
        let Some(entry) = self.adapters.get(&hop.prepare.outgoing_network) else {
            return;
        };
        let payment = hop.outgoing.clone();
        if let Err(error) = entry.adapter.refund_outgoing(&payment).await {
            warn!(
                target: "cassis_router",
                "refund failed for operation_id={}: {error}",
                hop.operation_id,
            );
            if error.is_retryable() {
                return;
            }
        }
        self.drop_executeed(&hop.operation_id).await;
    }

    async fn drop_executeed(&self, operation_id: &OperationId) {
        let removed = {
            let mut executed = self.executed.lock().await;
            executed.remove(operation_id).is_some()
        };
        if removed {
            if let Err(error) = self.persist_state_to_disk().await {
                warn!(
                    target: "cassis_router",
                    "persist router state after dropping operation_id={} failed: {error}",
                    operation_id,
                );
            }
        }
    }

    fn validate_prepare(&self, prepare: &HopPrepare) -> Result<(), String> {
        if prepare.payment_hash.0.iter().all(|byte| *byte == 0) {
            return Err("zero payment hash".to_string());
        }
        if !prepare.operation_id.is_valid() {
            return Err("operation_id must be 32 hexadecimal characters".to_string());
        }
        if prepare.amount_msat == 0 {
            return Err(format!(
                "incoming amount must be positive, got {}",
                prepare.amount_msat
            ));
        }
        if prepare.outgoing_amount_msat == 0 {
            return Err("outgoing amount must be positive".to_string());
        }
        if prepare.outgoing_amount_msat > prepare.amount_msat {
            return Err(format!(
                "outgoing amount {} exceeds incoming amount {}",
                prepare.outgoing_amount_msat, prepare.amount_msat
            ));
        }
        let incoming = self
            .adapters
            .get(&prepare.incoming_network)
            .ok_or_else(|| {
                format!(
                    "incoming network unsupported, accepted: {:?}, actual: {}",
                    self.adapters.keys().collect::<Vec<_>>(),
                    prepare.incoming_network
                )
            })?;
        if !self.adapters.contains_key(&prepare.outgoing_network) {
            return Err(format!(
                "outgoing network unsupported, accepted: {:?}, actual: {}",
                self.adapters.keys().collect::<Vec<_>>(),
                prepare.outgoing_network
            ));
        }
        let now = unix_now();
        if prepare.outgoing_expiry <= now {
            return Err(format!(
                "outgoing expiry must be in the future, got {} (now {now})",
                prepare.outgoing_expiry
            ));
        }
        if prepare.outgoing_expiry >= prepare.incoming_deadline {
            return Err(format!(
                "outgoing expiry {} must precede incoming deadline {}",
                prepare.outgoing_expiry, prepare.incoming_deadline
            ));
        }
        let required_delta = incoming.incoming_delta_secs;
        let min_deadline = now.saturating_add(required_delta);
        if prepare.incoming_deadline < min_deadline {
            return Err(format!(
                "incoming deadline too soon, accepted: >= {}, actual: {}",
                min_deadline, prepare.incoming_deadline
            ));
        }
        Ok(())
    }
}

#[derive(Clone)]
struct PreparedEntry {
    prepare: HopPrepare,
    reservation: IncomingReservation,
    /// Stable outgoing attempt identity. Replayed EXECUTE reuses it
    /// instead of funding same payment under new operation id.
    outgoing_operation_id: OperationId,
    expires_at: u64,
    processing: bool,
    /// Authenticated iroh identity of the peer that sent the PREPARE.
    /// Only this peer may free the reservation via DISCARD; a DISCARD
    /// from anyone else is refused (logged, reported as
    /// `released: false`).
    owner: PublicKey,
}

/// Tiny shim: lift a string rejection into an iroh-level
/// [`IrohError`]. The frame's `payment_hash` is lost here;
/// the peer's handler will see the error in the protocol
/// layer and the local log carries the hash.
fn internal<E: std::fmt::Display>(e: E) -> IrohError {
    IrohError::Protocol(e.to_string())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// Spark adapter has asymmetric HTLC addressing: LND can pay its
/// Lightning invoice, but Spark cannot originate a generic pubkey HTLC.
/// Publish only bridge edge where role combination is executable.
fn route_pair_supported(from: &NetworkId, to: &NetworkId) -> bool {
    if from.0 == "spark" {
        return false;
    }
    if to.0 == "spark" {
        return from.0 == "lightning";
    }
    true
}

async fn publish_route_announcements(
    adapters: &HashMap<NetworkId, NetworkEntry>,
    relay_urls: Vec<String>,
    node_key: &ritualistic::SecretKey,
    iroh_peer_id: &str,
    iroh_relay: &str,
) {
    if relay_urls.is_empty() {
        warn!(target: "cassis_router", "no nostr relays configured, skipping route announcement publication");
        return;
    }

    let mut network_ids: Vec<NetworkId> = adapters.keys().cloned().collect();
    network_ids.sort_by(|a, b| a.0.cmp(&b.0));

    let pairs: Vec<(NetworkId, NetworkId)> = network_ids
        .iter()
        .flat_map(|from| network_ids.iter().map(move |to| (from.clone(), to.clone())))
        .filter(|(from, to)| from != to && route_pair_supported(from, to))
        .collect();

    let fee_base_msat: u64 = 1000;
    let fee_ppm: u64 = 500;
    let transit_slack_secs: u64 = 60;

    let events: Vec<(String, ritualistic::Event)> = pairs
        .iter()
        .map(|(from, to)| {
            let incoming_delta_secs = adapters
                .get(from)
                .map(|entry| entry.incoming_delta_secs)
                .unwrap_or_else(|| from.default_incoming_delta());
            let d_tag = format!("{from}->{to}");
            let template = EventTemplate {
                created_at: Timestamp::now(),
                kind: Kind(NOSTR_KIND_ROUTE_ANNOUNCEMENT),
                tags: Tags(vec![
                    vec!["d".to_string(), d_tag.clone()],
                    vec![
                        "iroh".to_string(),
                        iroh_peer_id.to_string(),
                        iroh_relay.to_string(),
                    ],
                    vec!["fee_base_msat".to_string(), fee_base_msat.to_string()],
                    vec!["fee_ppm".to_string(), fee_ppm.to_string()],
                    vec![
                        "incoming_delta_secs".to_string(),
                        incoming_delta_secs.to_string(),
                    ],
                    vec![
                        "transit_slack_secs".to_string(),
                        transit_slack_secs.to_string(),
                    ],
                ]),
                content: String::new(),
            };
            (d_tag, template.finalize(node_key))
        })
        .collect();

    info!(
        target: "cassis_router",
        "publishing {} route announcement event(s) (kind {}, transit_slack_secs={}) to {} relay(s) for pubkey {}",
        events.len(),
        NOSTR_KIND_ROUTE_ANNOUNCEMENT,
        transit_slack_secs,
        relay_urls.len(),
        node_key.pubkey().to_hex()
    );

    let mut pool = Network::new();
    for (d_tag, event) in events {
        let mut results = pool.publish_many(relay_urls.clone(), event).await;
        let mut ok = 0usize;
        let mut failed = Vec::new();
        while let Some(result) = results.recv().await {
            match result.error {
                None => ok += 1,
                Some(err) => failed.push(format!("{}: {err}", result.relay_url)),
            }
        }
        info!(target: "cassis_router", "  route {d_tag}: published to {ok} relay(s)");
        for failure in &failed {
            warn!(target: "cassis_router", "    rejected by {failure}");
        }
    }
}
