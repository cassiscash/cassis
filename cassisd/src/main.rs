use cassis_core::{Bytes32, HopAck, HopInstruction, HopReject, NetworkAdapter, NetworkId, WatchError};
use cassis_iroh::IrohServer;
use cassis_onchain::validate_timelock_delta;
use clap::Parser;
use log::{error, info, warn};
use ritualistic::{EventTemplate, Kind, Network, Tags, Timestamp};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

mod seed;

const NOSTR_KIND_ROUTE_ANNOUNCEMENT: u16 = 35515;

const DEFAULT_NOSTR_RELAYS: &[&str] = &[
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://nostr.mom",
];

type PendingMap = Arc<Mutex<HashMap<Bytes32, HopInstruction>>>;

#[derive(Parser)]
#[command(name = "cassisd")]
#[command(about = "Cassis multi-network routing daemon")]
struct Cli {
    /// Networks to route between. The format depends on the network kind:
    ///     cashu:<mint_url>     e.g. cashu:https://mint.example.com
    ///     fedimint:<invite_or_db>   e.g. fedimint:fed1qgqrg5c3plq3tts70rt7q3l4yy2v9m9te5t...
    ///     liquid               (no parameter)
    ///     ark                  (no parameter)
    ///     rootstock            (no parameter)
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
            target: "cassisd",
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
            error!(target: "cassisd", "{err}");
            std::process::exit(2);
        });

    let keys = match seed::derive_keys(&cli.seed, network_ids) {
        Ok(keys) => keys,
        Err(err) => {
            error!(target: "cassisd", "invalid --seed: {err}");
            std::process::exit(2);
        }
    };

    info!(
        target: "cassisd",
        "derived nostr signing key: {} ({})",
        keys.nostr.to_nsec(),
        keys.nostr.pubkey().to_hex()
    );
    for (network_id, sk) in &keys.networks {
        info!(
            target: "cassisd",
            "  derived key for {network_id}: pubkey={}",
            sk.pubkey().to_hex()
        );
    }

    let mut adapters: HashMap<NetworkId, Arc<dyn NetworkAdapter>> = HashMap::new();
    for spec in &cli.network {
        match build_adapter(spec, &keys).await {
            Ok(adapter) => {
                adapters.insert(adapter.network_id(), adapter);
            }
            Err(err) => {
                error!(target: "cassisd", "{err}");
                std::process::exit(2);
            }
        }
    }

    if adapters.len() < 2 {
        error!(target: "cassisd", "at least two distinct networks are required for routing");
        std::process::exit(2);
    }

    info!(target: "cassisd", "routing between {} networks:", adapters.len());
    for id in adapters.keys() {
        info!(target: "cassisd", "  - {id}");
    }

    let relay_urls = if cli.nostr_relay.is_empty() {
        DEFAULT_NOSTR_RELAYS.iter().map(|s| s.to_string()).collect()
    } else {
        cli.nostr_relay.clone()
    };

    let daemon = Arc::new(CassisDaemon::new(adapters));
    let handler_daemon = daemon.clone();

    let (iroh_server, iroh_secret) =
        IrohServer::new(keys.iroh.clone()).await.expect("failed to bind iroh endpoint");
    let iroh_peer_id = iroh_secret.public();
    let iroh_relay = iroh_server
        .home_relay()
        .map(|s| s.to_string())
        .unwrap_or_else(|| cassis_iroh::DEFAULT_IROH_RELAY.to_string());
    info!(target: "cassisd", "iroh endpoint: {iroh_peer_id} relay: {iroh_relay}");

    tokio::spawn(async move {
        let handler = Arc::new(
            move |inst: HopInstruction| -> std::pin::Pin<
                Box<dyn std::future::Future<Output = Result<HopAck, String>> + Send>,
            > {
                let daemon = handler_daemon.clone();
                Box::pin(async move {
                    match daemon.handle_instruction(inst).await {
                        Ok(ack) => Ok(ack),
                        Err(reject) => Err(format!("{:?}", reject)),
                    }
                })
            },
        );
        if let Err(e) = iroh_server.run(handler).await {
            error!(target: "cassisd", "iroh server error: {e}");
        }
    });

    publish_route_announcements(
        &daemon.adapters,
        relay_urls,
        &keys.nostr,
        &iroh_peer_id.to_string(),
        &iroh_relay,
    )
    .await;

    tokio::signal::ctrl_c().await.ok();
    info!(target: "cassisd", "shutting down");
}

/// Compute the [`NetworkId`] for a network spec without building the adapter.
fn network_id_for_spec(spec: &str) -> Result<NetworkId, String> {
    let (kind, param) = match spec.split_once(':') {
        Some((kind, param)) => (kind, Some(param)),
        None => (spec, None),
    };
    match kind {
        "cashu" => {
            let mint_url = param.ok_or_else(|| {
                "network 'cashu' requires a mint URL, e.g. cashu:https://mint.example.com"
                    .to_string()
            })?;
            Ok(NetworkId(format!("cashu:{mint_url}")))
        }
        "fedimint" => {
            let address = param.ok_or_else(|| {
                "network 'fedimint' requires an invite code, e.g. fedimint:fed1qgqrg5c3plq3tts70rt7q3l4yy2v9m9te5t..."
                    .to_string()
            })?;
            Ok(NetworkId(format!("fedimint:{address}")))
        }
        "liquid" => {
            if param.is_some() {
                return Err("network 'liquid' does not take a parameter".into());
            }
            Ok(NetworkId("liquid".to_string()))
        }
        "ark" => {
            if param.is_some() {
                return Err("network 'ark' does not take a parameter".into());
            }
            Ok(NetworkId("ark".to_string()))
        }
        "rootstock" => {
            if param.is_some() {
                return Err("network 'rootstock' does not take a parameter".into());
            }
            Ok(NetworkId("rootstock".to_string()))
        }
        _ => Err(format!("unsupported network kind '{kind}'")),
    }
}

#[allow(unused_variables)]
async fn build_adapter(spec: &str, seed_keys: &seed::DerivedKeys) -> Result<Arc<dyn NetworkAdapter>, String> {
    let (kind, param) = match spec.split_once(':') {
        Some((kind, param)) => (kind, Some(param)),
        None => (spec, None),
    };

    match kind {
        #[cfg(feature = "cashu")]
        "cashu" => {
            let mint_url = param.ok_or_else(|| {
                "network 'cashu' requires a mint URL, e.g. cashu:https://mint.example.com"
                    .to_string()
            })?;
            let network_id = NetworkId(format!("cashu:{mint_url}"));
            let sk = seed_keys
                .networks
                .get(&network_id)
                .map(|k| *k.as_bytes())
                .unwrap_or([0u8; 32]);
            Ok(Arc::new(cassis_cashu::CashuAdapter::new(
                network_id,
                mint_url.to_string(),
                sk,
            )))
        }

        #[cfg(not(feature = "cashu"))]
        "cashu" => Err(
            "network 'cashu' requested but cassisd was not compiled with the 'cashu' feature"
                .into(),
        ),

        #[cfg(feature = "fedimint")]
        "fedimint" => {
            let address = param.ok_or_else(|| {
                "network 'fedimint' requires an invite code or pre-joined DB identifier, \
                 e.g. fedimint:fed1qgqrg5c3plq3tts70rt7q3l4yy2v9m9te5t..."
                    .to_string()
            })?;
            let network_id = NetworkId(format!("fedimint:{address}"));
            let sk = seed_keys
                .networks
                .get(&network_id)
                .map(|k| *k.as_bytes())
                .unwrap_or([0u8; 32]);
            Ok(Arc::new(
                match cassis_fedimint::FedimintAdapter::new(network_id, address.to_string(), sk).await {
                    Ok(adapter) => adapter,
                    Err(err) => return Err(err),
                },
            ))
        }

        #[cfg(not(feature = "fedimint"))]
        "fedimint" => Err(
            "network 'fedimint' requested but cassisd was not compiled with the 'fedimint' feature"
                .into(),
        ),

        #[cfg(feature = "liquid")]
        "liquid" => {
            if param.is_some() {
                return Err("network 'liquid' does not take a parameter".into());
            }
            Ok(Arc::new(cassis_liquid::LiquidAdapter::new(NetworkId(
                "liquid".to_string(),
            ))))
        }

        #[cfg(not(feature = "liquid"))]
        "liquid" => Err(
            "network 'liquid' requested but cassisd was not compiled with the 'liquid' feature"
                .into(),
        ),

        #[cfg(feature = "ark")]
        "ark" => {
            if param.is_some() {
                return Err("network 'ark' does not take a parameter".into());
            }
            Ok(Arc::new(cassis_ark::ArkAdapter::new(NetworkId("ark".to_string()))))
        }

        #[cfg(not(feature = "ark"))]
        "ark" => Err(
            "network 'ark' requested but cassisd was not compiled with the 'ark' feature".into(),
        ),

        #[cfg(feature = "rootstock")]
        "rootstock" => {
            if param.is_some() {
                return Err("network 'rootstock' does not take a parameter".into());
            }
            Ok(Arc::new(cassis_rootstock::RootstockAdapter::new(NetworkId(
                "rootstock".to_string(),
            ))))
        }

        #[cfg(not(feature = "rootstock"))]
        "rootstock" => Err(
            "network 'rootstock' requested but cassisd was not compiled with the 'rootstock' feature"
                .into(),
        ),

        _ => Err(format!("unsupported network kind '{kind}'")),
    }
}

pub struct CassisDaemon {
    pub adapters: HashMap<NetworkId, Arc<dyn NetworkAdapter>>,
    pending: PendingMap,
}

impl CassisDaemon {
    pub fn new(adapters: HashMap<NetworkId, Arc<dyn NetworkAdapter>>) -> Self {
        Self {
            adapters,
            pending: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn handle_instruction(
        &self,
        instruction: HopInstruction,
    ) -> Result<HopAck, HopReject> {
        info!(
            target: "cassisd",
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
        let inst = instruction.clone();
        tokio::spawn(async move {
            watch_instruction(inst, adapters, pending).await;
        });

        Ok(HopAck {
            payment_hash: instruction.payment_hash,
            accepted: true,
            signature: None,
        })
    }

    fn validate_instruction(&self, instruction: &HopInstruction) -> Result<(), HopReject> {
        if instruction.payment_hash.0.iter().all(|byte| *byte == 0) {
            return Err(HopReject {
                payment_hash: instruction.payment_hash,
                reason: "zero payment hash".to_string(),
            });
        }

        if instruction.amount_msat == 0 {
            return Err(HopReject {
                payment_hash: instruction.payment_hash,
                reason: "amount must be positive".to_string(),
            });
        }

        let incoming = self
            .adapters
            .get(&instruction.incoming_network)
            .ok_or_else(|| HopReject {
                payment_hash: instruction.payment_hash,
                reason: "incoming network unsupported".to_string(),
            })?;
        if !self.adapters.contains_key(&instruction.outgoing_network) {
            return Err(HopReject {
                payment_hash: instruction.payment_hash,
                reason: "outgoing network unsupported".to_string(),
            });
        }

        let now = unix_now();
        if instruction.incoming_deadline < now.saturating_add(incoming.incoming_delta_secs()) {
            return Err(HopReject {
                payment_hash: instruction.payment_hash,
                reason: "incoming deadline too soon".to_string(),
            });
        }

        Ok(())
    }
}

async fn watch_instruction(
    instruction: HopInstruction,
    adapters: HashMap<NetworkId, Arc<dyn NetworkAdapter>>,
    pending: PendingMap,
) {
    let incoming_adapter = match adapters.get(&instruction.incoming_network) {
        Some(adapter) => adapter,
        None => {
            remove_pending(&pending, instruction.payment_hash).await;
            return;
        }
    };
    let outgoing_adapter = match adapters.get(&instruction.outgoing_network) {
        Some(adapter) => adapter,
        None => {
            remove_pending(&pending, instruction.payment_hash).await;
            return;
        }
    };

    let incoming = match incoming_adapter
        .watch_incoming_htlc(
            instruction.payment_hash,
            instruction.amount_msat,
            instruction.incoming_deadline,
        )
        .await
    {
        Ok(htlc) => {
            info!(target: "cassisd", "  incoming HTLC on {}: amount={}", htlc.network, htlc.amount_msat);
            htlc
        }
        Err(_) => {
            warn!(target: "cassisd", "  incoming HTLC failed on {}", instruction.incoming_network);
            remove_pending(&pending, instruction.payment_hash).await;
            return;
        }
    };

    if incoming.amount_msat < instruction.amount_msat {
        remove_pending(&pending, instruction.payment_hash).await;
        return;
    }

    if validate_timelock_delta(
        incoming.expiry,
        instruction.outgoing_expiry,
        incoming_adapter.incoming_delta_secs(),
    )
    .is_err()
    {
        remove_pending(&pending, instruction.payment_hash).await;
        return;
    }

    let outgoing = match outgoing_adapter
        .create_outgoing_htlc(
            instruction.payment_hash,
            instruction.amount_msat,
            instruction.outgoing_expiry,
            &instruction.recipient,
        )
        .await
    {
        Ok(htlc) => {
            info!(target: "cassisd", "  outgoing HTLC on {} for {}", htlc.network, htlc.recipient);
            htlc
        }
        Err(_) => {
            warn!(target: "cassisd", "  outgoing HTLC failed on {}", instruction.outgoing_network);
            remove_pending(&pending, instruction.payment_hash).await;
            return;
        }
    };

    match outgoing_adapter
        .watch_preimage(&outgoing, instruction.outgoing_expiry)
        .await
    {
        Ok(preimage) => {
            info!(target: "cassisd", "  preimage received, claiming incoming");
            let _ = incoming_adapter.claim_incoming(&incoming, preimage).await;
        }
        Err(WatchError::DeadlineExceeded) => {
            warn!(target: "cassisd", "  deadline exceeded, refunding outgoing");
            let _ = outgoing_adapter.refund_outgoing(&outgoing).await;
        }
        Err(_) => {
            error!(target: "cassisd", "  error watching preimage, refunding outgoing");
            let _ = outgoing_adapter.refund_outgoing(&outgoing).await;
        }
    }

    remove_pending(&pending, instruction.payment_hash).await;
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
    adapters: &HashMap<NetworkId, Arc<dyn NetworkAdapter>>,
    relay_urls: Vec<String>,
    secret_key: &ritualistic::SecretKey,
    iroh_peer_id: &str,
    iroh_relay: &str,
) {
    if relay_urls.is_empty() {
        warn!(target: "cassisd", "no nostr relays configured, skipping route announcement publication");
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
                ]),
                content: String::new(),
            };
            (d_tag, template.finalize(secret_key))
        })
        .collect();

    info!(
        target: "cassisd",
        "publishing {} route announcement event(s) (kind {}) to {} relay(s) for pubkey {}",
        events.len(),
        NOSTR_KIND_ROUTE_ANNOUNCEMENT,
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
        info!(target: "cassisd", "  route {d_tag}: published to {ok} relay(s)");
        for failure in &failed {
            warn!(target: "cassisd", "    rejected by {failure}");
        }
    }
}
