use cassis_core::{
    network_id_for_spec, normalize_network_id, split_spec, Bytes32, HopAck, HopInstruction,
    HopReject, NetworkId, NetworkRouterAdapter, OutgoingHtlc, WatchError,
};
#[cfg(feature = "cashu")]
use cassis_core::{cashu_mint_url, cashu_network_id};
use cassis_iroh::IrohServer;
use cassis_keys as keys;
use clap::Parser;
use log::{debug, error, info, warn};
use ritualistic::{EventTemplate, Kind, Network, Tags, Timestamp};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

const NOSTR_KIND_ROUTE_ANNOUNCEMENT: u16 = 35515;

const DEFAULT_NOSTR_RELAYS: &[&str] = &[
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://nostr.mom",
];

type PendingMap = Arc<Mutex<HashMap<Bytes32, HopInstruction>>>;

#[derive(Parser)]
#[command(name = "cassis-router")]
#[command(about = "Cassis multi-network routing daemon (router only; receivers live in cassis-cli)")]
struct Cli {
    /// Networks to route between. The format depends on the network kind:
    ///     cashu::<host[:port]>     e.g. cashu::mint.example.com (https) or
    ///                              cashu::localhost:3338 (http, since loopback)
    ///     fedimint::<invite_code>  e.g. fedimint::fed1qgqrg5c3plq3tts70rt7q3l4yy2v9m9te5t...
    ///     liquid               (no parameter)
    ///     ark                  (no parameter)
    ///     rootstock            (no parameter)
    ///
    /// The `cashu::` and `fedimint::` forms are the canonical on-the-wire
    /// syntax used in Nostr route announcements and iroh `HopInstruction`s.
    /// For `cashu` the scheme is never part of the id: `localhost`/
    /// `127.0.0.1`/`::1` are always `http`, everything else is `https`.
    ///
    /// At least two are required so the daemon can route between them.
    /// The same kind may be repeated with different parameters.
    #[arg(long, action = clap::ArgAction::Append, value_name = "SPEC")]
    network: Vec<String>,

    /// Nostr relays to publish route announcements to.
    /// Defaults to a built-in list when none are provided.
    #[arg(long, action = clap::ArgAction::Append, value_name = "URL")]
    nostr_relay: Vec<String>,

    /// BIP39 mnemonic seed (12 words, space-separated) from which every key the
    /// daemon uses is derived deterministically: the nostr signing key and one
    /// key per network adapter.
    #[arg(long, value_name = "MNEMONIC")]
    seed: String,
}

#[tokio::main]
async fn main() {
    cassis_core::logging::init_logging();

    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install default rustls crypto provider");

    let cli = Cli::parse();

    if cli.network.len() < 2 {
        error!(
            target: "cassis_router",
            "at least two --network flags are required for routing, got {}",
            cli.network.len()
        );
        std::process::exit(2);
    }

    let network_ids: Vec<NetworkId> = cli
        .network
        .iter()
        .map(|spec| network_id_for_spec(spec))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|err| {
            error!(target: "cassis_router", "{err}");
            std::process::exit(2);
        });

    let derived = match keys::derive_keys(&cli.seed, network_ids.clone()) {
        Ok(keys) => keys,
        Err(err) => {
            error!(target: "cassis_router", "invalid --seed: {err}");
            std::process::exit(2);
        }
    };

    info!(
        target: "cassis_router",
        "derived nostr signing key: {} ({})",
        derived.nostr.to_nsec(),
        derived.nostr.pubkey().to_hex()
    );
    for (network_id, sk) in &derived.networks {
        info!(
            target: "cassis_router",
            "  derived key for {network_id}: pubkey={}",
            sk.pubkey().to_hex()
        );
    }

    let mut adapters: HashMap<NetworkId, NetworkEntry> = HashMap::new();
    for spec in &cli.network {
        match build_adapter(spec, &derived).await {
            Ok(entry) => {
                adapters.insert(entry.network_id.clone(), entry);
            }
            Err(err) => {
                error!(target: "cassis_router", "{err}");
                std::process::exit(2);
            }
        }
    }

    if adapters.len() < 2 {
        error!(target: "cassis_router", "at least two distinct networks are required for routing");
        std::process::exit(2);
    }

    info!(target: "cassis_router", "routing between {} networks:", adapters.len());
    for id in adapters.keys() {
        info!(target: "cassis_router", "  - {id}");
    }

    let relay_urls = if cli.nostr_relay.is_empty() {
        DEFAULT_NOSTR_RELAYS.iter().map(|s| s.to_string()).collect()
    } else {
        cli.nostr_relay.clone()
    };

    let router = Arc::new(CassisRouter::new(adapters));
    let handler_router = router.clone();

    let (iroh_server, iroh_secret) =
        IrohServer::new(derived.iroh.clone()).await.expect("failed to bind iroh endpoint");
    let iroh_peer_id = iroh_secret.public();
    let iroh_relay = iroh_server
        .home_relay()
        .map(|s| s.to_string())
        .unwrap_or_else(|| cassis_iroh::DEFAULT_IROH_RELAY.to_string());
    info!(target: "cassis_router", "iroh endpoint: {iroh_peer_id} relay: {iroh_relay}");

    tokio::spawn(async move {
        let handler = Arc::new(
            move |inst: HopInstruction| -> std::pin::Pin<
                Box<dyn std::future::Future<Output = Result<HopAck, HopReject>> + Send>,
            > {
                let router = handler_router.clone();
                Box::pin(async move {
                    match router.handle_instruction(inst).await {
                        Ok(ack) => Ok(ack),
                        Err(reject) => Err(reject),
                    }
                })
            },
        );
        if let Err(e) = iroh_server.run(handler).await {
            error!(target: "cassis_router", "iroh server error: {e}");
        }
    });

    publish_route_announcements(
        &router.adapters,
        relay_urls,
        &derived.nostr,
        &iroh_peer_id.to_string(),
        &iroh_relay,
    )
    .await;

    tokio::signal::ctrl_c().await.ok();
    info!(target: "cassis_router", "shutting down");
}

/// Per-network entry the router tracks. The router holds a
/// [`NetworkRouterAdapter`] (the low-level HTLC-instrument trait) and
/// *never* a [`NetworkReceiverAdapter`] or [`NetworkSenderAdapter`]
/// (those are user-facing wrappers used by `cassis-cli`).
/// `incoming_delta_secs` is read off the same adapter at construction
/// and cached, so the router can validate timelocks without ever
/// calling into any user-facing trait.
#[derive(Clone)]
pub struct NetworkEntry {
    pub network_id: NetworkId,
    pub adapter: Arc<dyn NetworkRouterAdapter>,
    pub incoming_delta_secs: u64,
}

#[allow(unused_variables)]
async fn build_adapter(
    spec: &str,
    derived: &keys::DerivedKeys,
) -> Result<NetworkEntry, String> {
    let (kind, param) = split_spec(spec);

    match kind {
        #[cfg(feature = "cashu")]
        "cashu" => {
            let host = param.ok_or_else(|| {
                "network 'cashu' requires a host, \
                 e.g. cashu::mint.example.com (https) or cashu::localhost:3338 (http)"
                    .to_string()
            })?;
            let network_id = cashu_network_id(host);
            let mint_url = cashu_mint_url(&network_id)
                .map_err(|e| format!("cashu mint url: {e}"))?;
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
            "network 'ark' requested but cassis-router was not compiled with the 'ark' feature".into(),
        ),

        #[cfg(feature = "rootstock")]
        "rootstock" => {
            if param.is_some() {
                return Err("network 'rootstock' does not take a parameter".into());
            }
            let network_id = NetworkId("rootstock".to_string());
            let adapter: Arc<dyn NetworkRouterAdapter> =
                Arc::new(cassis_rootstock::RootstockAdapter::new(network_id.clone()));
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

pub struct CassisRouter {
    pub adapters: HashMap<NetworkId, NetworkEntry>,
    pending: PendingMap,
}

impl CassisRouter {
    pub fn new(adapters: HashMap<NetworkId, NetworkEntry>) -> Self {
        Self {
            adapters,
            pending: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn handle_instruction(
        &self,
        mut instruction: HopInstruction,
    ) -> Result<HopAck, HopReject> {
        let incoming_raw = instruction.incoming_network.clone();
        let outgoing_raw = instruction.outgoing_network.clone();
        instruction.incoming_network = normalize_network_id(&instruction.incoming_network);
        instruction.outgoing_network = normalize_network_id(&instruction.outgoing_network);
        if instruction.incoming_network != incoming_raw
            || instruction.outgoing_network != outgoing_raw
        {
            debug!(
                target: "cassis_router",
                "canonicalized network ids: incoming {} -> {}, outgoing {} -> {}",
                incoming_raw, instruction.incoming_network,
                outgoing_raw, instruction.outgoing_network,
            );
        }
        info!(
            target: "cassis_router",
            "iroh instruction: {} msat {} -> {} via {}",
            instruction.amount_msat,
            instruction.incoming_network,
            instruction.outgoing_network,
            instruction.recipient,
        );
        self.validate_instruction(&instruction)?;
        {
            let mut pending = self.pending.lock().await;
            pending.insert(instruction.payment_hash, instruction.clone());
        }

        let adapters = self.adapters.clone();
        let pending = Arc::clone(&self.pending);
        tokio::spawn(async move {
    let outgoing_entry = match adapters.get(&instruction.outgoing_network) {
        Some(entry) => entry,
        None => {
            remove_pending(&pending, instruction.payment_hash).await;
            return;
        }
    };

    let htlc: OutgoingHtlc = match outgoing_entry
        .adapter
        .create_outgoing_htlc(
            instruction.payment_hash,
            instruction.amount_msat,
            instruction.outgoing_expiry,
            &instruction.recipient,
        )
        .await
    {
        Ok(htlc) => {
            info!(
                target: "cassis_router",
                "  outgoing HTLC on {} for {} ({} msat)",
                htlc.network, htlc.recipient, htlc.amount_msat,
            );
            htlc
        }
        Err(err) => {
            warn!(
                target: "cassis_router",
                "  create_outgoing_htlc failed on {}: {:?}",
                instruction.outgoing_network, err
            );
            remove_pending(&pending, instruction.payment_hash).await;
            return;
        }
    };

    match outgoing_entry
        .adapter
        .watch_preimage(htlc.payment_hash, instruction.outgoing_expiry)
        .await
    {
        Ok(_preimage) => {
            info!(
                target: "cassis_router",
                "  outgoing settled on {} (preimage revealed upstream)",
                instruction.outgoing_network
            );
        }
        Err(WatchError::DeadlineExceeded) => {
            warn!(target: "cassis_router", "  deadline exceeded, refunding outgoing");
            let _ = outgoing_entry.adapter.refund_outgoing(htlc.payment_hash).await;
        }
        Err(err) => {
            error!(
                target: "cassis_router",
                "  error watching payment on {}: {:?}",
                instruction.outgoing_network, err
            );
            let _ = outgoing_entry.adapter.refund_outgoing(htlc.payment_hash).await;
        }
    }

    remove_pending(&pending, instruction.payment_hash).await;
        });

        Ok(HopAck {
            payment_hash: instruction.payment_hash,
            accepted: true,
            reason: None,
        })
    }

    fn validate_instruction(&self, instruction: &HopInstruction) -> Result<(), HopReject> {
        debug!(
            target: "cassis_router",
            "validate_instruction: payment_hash={}, amount_msat={}, incoming={}, outgoing={}, \
             incoming_deadline={}, outgoing_expiry={}",
            lowercase_hex::encode(instruction.payment_hash),
            instruction.amount_msat,
            instruction.incoming_network,
            instruction.outgoing_network,
            instruction.incoming_deadline,
            instruction.outgoing_expiry,
        );
        if instruction.payment_hash.0.iter().all(|byte| *byte == 0) {
            return Err(HopReject {
                payment_hash: instruction.payment_hash,
                reason: "zero payment hash, accepted: non-zero hash".to_string(),
            });
        }

        if instruction.amount_msat == 0 {
            return Err(HopReject {
                payment_hash: instruction.payment_hash,
                reason: format!(
                    "amount must be positive, accepted: > 0, actual: {}",
                    instruction.amount_msat
                ),
            });
        }

        let incoming = self
            .adapters
            .get(&instruction.incoming_network)
            .ok_or_else(|| HopReject {
                payment_hash: instruction.payment_hash,
                reason: format!(
                    "incoming network unsupported, accepted: {:?}, actual: {}",
                    self.adapters.keys().collect::<Vec<_>>(),
                    instruction.incoming_network
                ),
            })?;
        if !self.adapters.contains_key(&instruction.outgoing_network) {
            return Err(HopReject {
                payment_hash: instruction.payment_hash,
                reason: format!(
                    "outgoing network unsupported, accepted: {:?}, actual: {}",
                    self.adapters.keys().collect::<Vec<_>>(),
                    instruction.outgoing_network
                ),
            });
        }

        let now = unix_now();
        let required_delta = incoming.incoming_delta_secs;
        let min_deadline = now.saturating_add(required_delta);
        debug!(
            target: "cassis_router",
            "validate_instruction: incoming_network={}, incoming_delta={required_delta}, \
             now={now}, min_deadline={min_deadline}, actual={}",
            instruction.incoming_network, instruction.incoming_deadline
        );
        if instruction.incoming_deadline < min_deadline {
            return Err(HopReject {
                payment_hash: instruction.payment_hash,
                reason: format!(
                    "incoming deadline too soon, accepted: >= {}, actual: {}",
                    min_deadline, instruction.incoming_deadline
                ),
            });
        }

        Ok(())
    }
}

async fn remove_pending(pending: &PendingMap, payment_hash: Bytes32) {
    let mut pending = pending.lock().await;
    pending.remove(&payment_hash);
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
        .flat_map(|from| {
            network_ids
                .iter()
                .map(move |to| (from.clone(), to.clone()))
        })
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
                    vec!["iroh".to_string(), iroh_peer_id.to_string(), iroh_relay.to_string()],
                    vec!["fee_base_msat".to_string(), fee_base_msat.to_string()],
                    vec!["fee_ppm".to_string(), fee_ppm.to_string()],
                    vec!["transit_slack_secs".to_string(), transit_slack_secs.to_string()],
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
