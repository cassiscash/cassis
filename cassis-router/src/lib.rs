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
    network_id_for_spec, normalize_network_id, Bytes32, HopCommit, HopCommitted, HopDispatch,
    HopDispatched, HopPrepare, HopPrepared, HtlcDescriptor, NetworkId, NetworkRouterAdapter,
    WatchError,
};
use cassis_iroh::{Frame, IrohError, IrohServer};
use cassis_keys as keys;
use log::{debug, error, info, warn};
use ritualistic::{EventTemplate, Kind, Network, Tags, Timestamp};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

const NOSTR_KIND_ROUTE_ANNOUNCEMENT: u16 = 35515;

const DEFAULT_NOSTR_RELAYS: &[&str] = &["wss://relay.damus.io", "wss://nos.lol", "wss://nostr.mom"];

/// How often the per-dispatch poll task wakes up to check
/// whether the receiver of an outgoing HTLC has revealed the
/// preimage.
const POLL_INTERVAL_SECS: u64 = 30;

/// Top-level configuration for [`run_router`].
#[derive(Clone)]
pub struct RouterConfig {
    /// Network specs in the same `--network` format the old
    /// `cassis-router` binary accepted (`cashu::host`,
    /// `fedimint::invite`, `liquid`, `ark`, `rootstock`).
    pub network_specs: Vec<String>,
    /// Nostr relays to publish route announcements to. When
    /// empty, [`DEFAULT_NOSTR_RELAYS`] is used.
    pub nostr_relays: Vec<String>,
    /// Keys derived from the same BIP39 seed the wallet uses.
    /// The router consumes `derived.iroh` for its iroh
    /// endpoint and `derived.networks` for per-network
    /// adapter signing.
    pub derived_keys: keys::DerivedKeys,
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
        "derived nostr signing key: {} ({})",
        config.derived_keys.nostr.to_nsec(),
        config.derived_keys.nostr.pubkey().to_hex()
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
        match build_adapter(spec, &config.derived_keys).await {
            Ok(entry) => {
                adapters.insert(entry.network_id.clone(), entry);
            }
            Err(err) => {
                return Err(err);
            }
        }
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

    let router = Arc::new(CassisRouter::new(adapters));
    let handler_router = router.clone();
    let poll_router = router.clone();

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

    tokio::spawn(async move {
        let handler = Arc::new(
            move |frame: Frame| -> std::pin::Pin<
                Box<dyn std::future::Future<Output = Result<Frame, IrohError>> + Send>,
            > {
                let router = handler_router.clone();
                Box::pin(async move { router.handle_frame(frame).await })
            },
        );
        if let Err(e) = iroh_server.run(handler).await {
            error!(target: "cassis_router", "iroh server error: {e}");
        }
    });

    tokio::spawn(async move {
        poll_router.run_poll_loop().await;
    });

    publish_route_announcements(
        &router.adapters,
        relay_urls,
        &config.derived_keys.nostr,
        &iroh_peer_id.to_string(),
        &iroh_relay,
    )
    .await;

    tokio::signal::ctrl_c().await.ok();
    info!(target: "cassis_router", "shutting down");
    Ok(())
}

/// Per-network entry the router tracks. The router holds a
/// [`NetworkRouterAdapter`] (the low-level HTLC-instrument
/// trait) and *never* a `NetworkReceiverAdapter` or
/// `NetworkSenderAdapter` (those are user-facing wrappers
/// used by `cassis-cli`). `incoming_delta_secs` is read off
/// the same adapter at construction and cached, so the
/// router can validate timelocks without ever calling into
/// any user-facing trait.
#[derive(Clone)]
pub struct NetworkEntry {
    pub network_id: NetworkId,
    pub adapter: Arc<dyn NetworkRouterAdapter>,
    pub incoming_delta_secs: u64,
}

#[allow(unused_variables)]
async fn build_adapter(spec: &str, derived: &keys::DerivedKeys) -> Result<NetworkEntry, String> {
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
            let sk = derived
                .networks
                .get(&network_id)
                .map(|k| *k.as_bytes())
                .unwrap_or([0u8; 32]);
            let adapter: Arc<dyn NetworkRouterAdapter> = Arc::new(
                cassis_cashu::CashuAdapter::new(network_id.clone(), mint_url, sk)
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

        "fedimint" => Err(
            "network 'fedimint' is not supported by cassis-router; \
             use cassis-cli to receive on a fedimint federation"
                .into(),
        ),

        #[cfg(feature = "liquid")]
        "liquid" => {
            if param.is_some() {
                return Err("network 'liquid' does not take a parameter".into());
            }
            let network_id = NetworkId("liquid".to_string());
            let adapter: Arc<dyn NetworkRouterAdapter> =
                Arc::new(cassis_liquid::LiquidAdapter::new(network_id.clone()));
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

        #[cfg(feature = "ark")]
        "ark" => {
            if param.is_some() {
                return Err("network 'ark' does not take a parameter".into());
            }
            let network_id = NetworkId("ark".to_string());
            let adapter: Arc<dyn NetworkRouterAdapter> =
                Arc::new(cassis_arkade::ArkAdapter::new(network_id.clone()));
            let incoming_delta_secs = adapter.incoming_delta_secs();
            Ok(NetworkEntry {
                network_id,
                adapter,
                incoming_delta_secs,
            })
        }

        #[cfg(not(feature = "ark"))]
        "ark" => Err(
            "network 'ark' requested but cassis-router was not compiled with the 'ark' feature"
                .into(),
        ),

        #[cfg(feature = "rootstock")]
        "rootstock" => {
            if param.is_some() {
                return Err("network 'rootstock' does not take a parameter".into());
            }
            let network_id = NetworkId("rootstock".to_string());
            let adapter: Arc<dyn NetworkRouterAdapter> = Arc::new(
                cassis_rootstock::RootstockAdapter::new(network_id.clone()),
            );
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

        _ => Err(format!("unsupported network kind '{kind}'")),
    }
}

/// Per-dispatch state the router retains between DISPATCH
/// and the eventual claim. `outgoing_deadline` is the
/// unix-second cutoff the router passes to the adapter's
/// `watch_preimage`; once exceeded, the dispatch is refunded
/// (outgoing side) and the incoming side is left to expire
/// on its own.
struct DispatchedHop {
    prepare: HopPrepare,
    /// Unix seconds; the router stops polling after this and
    /// runs the refund path on the outgoing side.
    outgoing_deadline: u64,
}

pub struct CassisRouter {
    pub adapters: HashMap<NetworkId, NetworkEntry>,
    prepared: PreparedMap,
    dispatched: Arc<Mutex<HashMap<Bytes32, DispatchedHop>>>,
}

impl CassisRouter {
    pub fn new(adapters: HashMap<NetworkId, NetworkEntry>) -> Self {
        Self {
            adapters,
            prepared: Arc::new(Mutex::new(HashMap::new())),
            dispatched: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Top-level dispatcher: turn a [`Frame`] into the
    /// matching reply [`Frame`]. The router only handles
    /// Prepare / Prepared / Dispatch / Dispatched; Commit /
    /// Committed flow directly from sender to receiver
    /// (payee's `cassis-cli`) without crossing a router hop.
    pub async fn handle_frame(&self, frame: Frame) -> Result<Frame, IrohError> {
        match frame {
            Frame::Prepare(p) => self
                .handle_prepare(p)
                .await
                .map(Frame::Prepared)
                .map_err(internal),
            Frame::Dispatch(d) => self
                .handle_dispatch(d)
                .await
                .map(Frame::Dispatched)
                .map_err(internal),
            Frame::Commit(c) => self
                .handle_commit(c)
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
    async fn handle_prepare(&self, mut prepare: HopPrepare) -> Result<HopPrepared, String> {
        let incoming_raw = prepare.incoming_network.clone();
        let outgoing_raw = prepare.outgoing_network.clone();
        prepare.incoming_network = normalize_network_id(&prepare.incoming_network);
        prepare.outgoing_network = normalize_network_id(&prepare.outgoing_network);
        if prepare.incoming_network != incoming_raw || prepare.outgoing_network != outgoing_raw {
            debug!(
                target: "cassis_router",
                "canonicalized network ids: incoming {} -> {}, outgoing {} -> {}",
                incoming_raw, prepare.incoming_network,
                outgoing_raw, prepare.outgoing_network,
            );
        }
        info!(
            target: "cassis_router",
            "iroh PREPARE: {} msat {} -> {} via {}",
            prepare.amount_msat,
            prepare.incoming_network,
            prepare.outgoing_network,
            prepare.recipient,
        );
        self.validate_prepare(&prepare)?;

        // Funds check on the outgoing side: the adapter must
        // be able to back the HTLC right now. The default
        // (cashu) sums the local balance; stub adapters
        // return Unimplemented and we surface that as a
        // rejection.
        let outgoing_entry = self
            .adapters
            .get(&prepare.outgoing_network)
            .ok_or_else(|| "outgoing network unsupported".to_string())?;
        if let Err(e) = outgoing_entry.adapter.can_route(prepare.amount_msat).await {
            return Ok(HopPrepared {
                payment_hash: prepare.payment_hash,
                accepted: false,
                reason: Some(format!("can_route failed: {e}")),
            });
        }

        let mut prepared = self.prepared.lock().await;
        prepared.insert(prepare.payment_hash, prepare.clone());
        Ok(HopPrepared {
            payment_hash: prepare.payment_hash,
            accepted: true,
            reason: None,
        })
    }

    /// DISPATCH handler: verify the incoming HTLC is
    /// claimable on the hop's incoming adapter, then create
    /// the outgoing HTLC on the outgoing adapter and stash
    /// state for the poll loop.
    async fn handle_dispatch(&self, dispatch: HopDispatch) -> Result<HopDispatched, String> {
        info!(
            target: "cassis_router",
            "iroh DISPATCH: {} msat {} -> {} via {}",
            dispatch.amount_msat,
            dispatch.incoming_network,
            dispatch.outgoing_network,
            dispatch.recipient,
        );

        // Look up the matching PREPARE; the sender must have
        // PREPAREd us first.
        let prepare = {
            let prepared = self.prepared.lock().await;
            prepared.get(&dispatch.payment_hash).cloned()
        };
        let prepare = match prepare {
            Some(p) => p,
            None => {
                return Err(format!(
                    "no matching PREPARE for payment_hash={:?}",
                    dispatch.payment_hash
                ));
            }
        };
        if prepare.incoming_network != dispatch.incoming_network
            || prepare.outgoing_network != dispatch.outgoing_network
            || prepare.amount_msat != dispatch.amount_msat
            || prepare.recipient != dispatch.recipient
        {
            return Err(format!(
                "DISPATCH specs do not match PREPARE: \
                 prepare(in={}, out={}, amt={}, to={}) vs \
                 dispatch(in={}, out={}, amt={}, to={})",
                prepare.incoming_network,
                prepare.outgoing_network,
                prepare.amount_msat,
                prepare.recipient,
                dispatch.incoming_network,
                dispatch.outgoing_network,
                dispatch.amount_msat,
                dispatch.recipient,
            ));
        }

        let incoming_entry = self
            .adapters
            .get(&dispatch.incoming_network)
            .ok_or_else(|| "incoming network unsupported".to_string())?;
        let outgoing_entry = self
            .adapters
            .get(&dispatch.outgoing_network)
            .ok_or_else(|| "outgoing network unsupported".to_string())?;

        // Verify the incoming HTLC is really claimable on
        // this adapter (e.g. cashu: NUT-14 proofs decode and
        // reference the right payment hash).
        if let Err(e) = incoming_entry
            .adapter
            .verify_incoming_htlc(&dispatch.incoming_descriptor, dispatch.payment_hash)
            .await
        {
            return Err(format!("incoming HTLC not claimable: {e}"));
        }

        // Stash the incoming descriptor so a later
        // claim_incoming can find it after the preimage is
        // known.
        if let Err(e) = incoming_entry
            .adapter
            .accept_incoming_htlc(
                dispatch.payment_hash,
                &dispatch.incoming_descriptor,
                dispatch.incoming_deadline,
            )
            .await
        {
            return Err(format!("accept_incoming_htlc failed: {e}"));
        }

        // Now create the outgoing HTLC on the next network.
        match outgoing_entry
            .adapter
            .create_outgoing_htlc(
                dispatch.payment_hash,
                dispatch.amount_msat,
                dispatch.outgoing_expiry,
                &dispatch.recipient,
            )
            .await
        {
            Ok(htlc) => {
                info!(
                    target: "cassis_router",
                    "  outgoing HTLC on {} for {} ({} msat)",
                    htlc.network, htlc.recipient, htlc.amount_msat,
                );
            }
            Err(err) => {
                return Err(format!(
                    "create_outgoing_htlc failed on {}: {err}",
                    dispatch.outgoing_network
                ));
            }
        };

        let outgoing_descriptor: HtlcDescriptor = match outgoing_entry
            .adapter
            .outgoing_htlc_descriptor(dispatch.payment_hash)
            .await
        {
            Ok(d) => d,
            Err(e) => {
                return Err(format!("outgoing_htlc_descriptor failed: {e}"));
            }
        };

        // Record dispatched state for the poll loop.
        {
            let mut dispatched = self.dispatched.lock().await;
            dispatched.insert(
                dispatch.payment_hash,
                DispatchedHop {
                    prepare: dispatch.clone().into_prepare(),
                    outgoing_deadline: dispatch.outgoing_expiry,
                },
            );
        }
        // Drop the prepared entry; the spec has been used.
        {
            let mut prepared = self.prepared.lock().await;
            prepared.remove(&dispatch.payment_hash);
        }

        Ok(HopDispatched {
            payment_hash: dispatch.payment_hash,
            outgoing_descriptor,
        })
    }

    /// COMMIT handler. Routers don't normally receive COMMIT
    /// (the sender sends COMMIT directly to the final
    /// receiver), but we accept it defensively in case the
    /// route has zero hops (sender == receiver) and the call
    /// loops back through us. In that case we just
    /// acknowledge the payment hash.
    async fn handle_commit(&self, commit: HopCommit) -> Result<HopCommitted, String> {
        info!(
            target: "cassis_router",
            "iroh COMMIT (received by router, unusual): {} msat on {}",
            commit.amount_msat, commit.network,
        );
        // Routers don't hold preimages; the final receiver
        // does. The COMMIT handler on a router is a no-op
        // that returns a zero preimage so the sender can
        // detect the misroute if it ever happens. The normal
        // path skips routers entirely for COMMIT.
        Ok(HopCommitted {
            payment_hash: commit.payment_hash,
            preimage: Bytes32([0u8; 32]),
        })
    }

    /// Background task: every [`POLL_INTERVAL_SECS`] seconds,
    /// walk the dispatched table and poll each outgoing HTLC
    /// for the preimage. When the preimage is known, claim
    /// the incoming HTLC on the incoming adapter with the
    /// same preimage. On deadline, refund the outgoing side
    /// and drop the dispatch row.
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
        // Snapshot the payment hashes under the lock, then
        // drop it before doing network work.
        let snapshot: Vec<(Bytes32, HopPrepare, u64)> = {
            let dispatched = self.dispatched.lock().await;
            dispatched
                .iter()
                .map(|(ph, d)| (*ph, d.prepare.clone(), d.outgoing_deadline))
                .collect()
        };
        let now = unix_now();
        for (payment_hash, prepare, outgoing_deadline) in snapshot {
            if now >= outgoing_deadline {
                warn!(
                    target: "cassis_router",
                    "  outgoing deadline exceeded for {payment_hash}, refunding"
                );
                self.refund_dispatched(payment_hash, &prepare).await;
                continue;
            }
            let outgoing_entry = match self.adapters.get(&prepare.outgoing_network) {
                Some(e) => e,
                None => {
                    self.drop_dispatched(payment_hash).await;
                    continue;
                }
            };
            // Use a short poll deadline so the loop keeps
            // making progress even when nothing has settled.
            let poll_deadline = now.saturating_add(POLL_INTERVAL_SECS);
            match outgoing_entry
                .adapter
                .watch_preimage(payment_hash, poll_deadline)
                .await
            {
                Ok(preimage) => {
                    info!(
                        target: "cassis_router",
                        "  preimage revealed for {payment_hash} on {}, claiming incoming",
                        prepare.outgoing_network,
                    );
                    self.claim_incoming(payment_hash, &prepare, preimage).await;
                }
                Err(WatchError::DeadlineExceeded) => {
                    debug!(
                        target: "cassis_router",
                        "  poll for {payment_hash}: no preimage yet"
                    );
                }
                Err(WatchError::Network(err)) => {
                    warn!(
                        target: "cassis_router",
                        "  poll for {payment_hash} network error: {err}"
                    );
                }
                Err(WatchError::Unimplemented) => {
                    debug!(
                        target: "cassis_router",
                        "  poll for {payment_hash}: adapter watch_preimage unimplemented"
                    );
                }
            }
        }
        Ok(())
    }

    async fn claim_incoming(&self, payment_hash: Bytes32, prepare: &HopPrepare, preimage: Bytes32) {
        let incoming_entry = match self.adapters.get(&prepare.incoming_network) {
            Some(e) => e,
            None => {
                self.drop_dispatched(payment_hash).await;
                return;
            }
        };
        match incoming_entry
            .adapter
            .claim_incoming(payment_hash, preimage)
            .await
        {
            Ok(()) => {
                info!(
                    target: "cassis_router",
                    "  incoming HTLC claimed on {} for {payment_hash}",
                    prepare.incoming_network,
                );
            }
            Err(err) => {
                error!(
                    target: "cassis_router",
                    "  claim_incoming failed for {payment_hash} on {}: {err}",
                    prepare.incoming_network,
                );
            }
        }
        self.drop_dispatched(payment_hash).await;
    }

    async fn refund_dispatched(&self, payment_hash: Bytes32, prepare: &HopPrepare) {
        if let Some(entry) = self.adapters.get(&prepare.outgoing_network) {
            if let Err(e) = entry.adapter.refund_outgoing(payment_hash).await {
                warn!(
                    target: "cassis_router",
                    "  refund_outgoing failed for {payment_hash}: {e}"
                );
            }
        }
        self.drop_dispatched(payment_hash).await;
    }

    async fn drop_dispatched(&self, payment_hash: Bytes32) {
        let mut dispatched = self.dispatched.lock().await;
        dispatched.remove(&payment_hash);
    }

    fn validate_prepare(&self, prepare: &HopPrepare) -> Result<(), String> {
        if prepare.payment_hash.0.iter().all(|byte| *byte == 0) {
            return Err("zero payment hash".to_string());
        }
        if prepare.amount_msat == 0 {
            return Err(format!(
                "amount must be positive, got {}",
                prepare.amount_msat
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

type PreparedMap = Arc<Mutex<HashMap<Bytes32, HopPrepare>>>;

/// Tiny shim: lift a string rejection into an iroh-level
/// [`IrohError`]. The frame's `payment_hash` is lost here;
/// the peer's handler will see the error in the protocol
/// layer and the local log carries the hash.
fn internal<E: std::fmt::Display>(e: E) -> IrohError {
    IrohError::Protocol(e.to_string())
}

trait HopDispatchExt {
    fn into_prepare(self) -> HopPrepare;
}

impl HopDispatchExt for HopDispatch {
    fn into_prepare(self) -> HopPrepare {
        HopPrepare {
            payment_hash: self.payment_hash,
            amount_msat: self.amount_msat,
            incoming_network: self.incoming_network,
            outgoing_network: self.outgoing_network,
            incoming_deadline: self.incoming_deadline,
            outgoing_expiry: self.outgoing_expiry,
            recipient: self.recipient,
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

async fn publish_route_announcements(
    adapters: &HashMap<NetworkId, NetworkEntry>,
    relay_urls: Vec<String>,
    secret_key: &ritualistic::SecretKey,
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
        .filter(|(from, to)| from != to)
        .collect();

    let fee_base_msat: u64 = 1000;
    let fee_ppm: u64 = 500;
    let transit_slack_secs: u64 = 60;

    let events: Vec<(String, ritualistic::Event)> = pairs
        .iter()
        .map(|(from, to)| {
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
                        "transit_slack_secs".to_string(),
                        transit_slack_secs.to_string(),
                    ],
                ]),
                content: String::new(),
            };
            (d_tag, template.finalize(secret_key))
        })
        .collect();

    info!(
        target: "cassis_router",
        "publishing {} route announcement event(s) (kind {}, transit_slack_secs={}) to {} relay(s) for pubkey {}",
        events.len(),
        NOSTR_KIND_ROUTE_ANNOUNCEMENT,
        transit_slack_secs,
        relay_urls.len(),
        secret_key.pubkey().to_hex()
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
