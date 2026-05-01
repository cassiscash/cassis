use cassis_core::{HopAck, HopInstruction, HopReject, NetworkAdapter, NetworkId, WatchError};
use cassis_onchain::validate_timelock_delta;
use clap::Parser;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

type PendingMap = Arc<Mutex<HashMap<[u8; 32], HopInstruction>>>;

#[derive(Parser)]
#[command(name = "cassisd")]
#[command(about = "Cassis multi-network routing daemon")]
struct Cli {
    /// Networks to route between. The format depends on the network kind:
    ///     cashu:<mint_url>     e.g. cashu:https://mint.example.com
    ///     fedimint:<address>  e.g. fedimint:fedimint://...
    ///     liquid               (no parameter)
    ///     ark                  (no parameter)
    ///     rootstock            (no parameter)
    ///
    /// At least two are required so the daemon can route between them.
    /// The same kind may be repeated with different parameters.
    #[arg(long, action = clap::ArgAction::Append, value_name = "SPEC")]
    network: Vec<String>,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    if cli.network.len() < 2 {
        eprintln!(
            "error: at least two --network flags are required for routing, got {}",
            cli.network.len()
        );
        std::process::exit(2);
    }

    let mut adapters: HashMap<NetworkId, Arc<dyn NetworkAdapter>> = HashMap::new();
    for spec in &cli.network {
        match build_adapter(spec) {
            Ok(adapter) => {
                adapters.insert(adapter.network_id(), adapter);
            }
            Err(err) => {
                eprintln!("error: {err}");
                std::process::exit(2);
            }
        }
    }

    if adapters.len() < 2 {
        eprintln!("error: at least two distinct networks are required for routing");
        std::process::exit(2);
    }

    eprintln!("cassisd routing between {} networks:", adapters.len());
    for id in adapters.keys() {
        eprintln!("  - {id}");
    }

    let _daemon = CassisDaemon::new(adapters);

    tokio::signal::ctrl_c().await.ok();
    eprintln!("shutting down");
}

#[allow(unused_variables)]
fn build_adapter(spec: &str) -> Result<Arc<dyn NetworkAdapter>, String> {
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
            Ok(Arc::new(cassis_cashu::CashuAdapter::new(NetworkId(
                format!("cashu:{mint_url}"),
            ))))
        }

        #[cfg(not(feature = "cashu"))]
        "cashu" => Err(
            "network 'cashu' requested but cassisd was not compiled with the 'cashu' feature"
                .into(),
        ),

        #[cfg(feature = "fedimint")]
        "fedimint" => {
            let address = param.ok_or_else(|| {
                "network 'fedimint' requires an address, e.g. fedimint:fedimint://..."
                    .to_string()
            })?;
            Ok(Arc::new(cassis_fedimint::FedimintAdapter::new(NetworkId(
                format!("fedimint:{address}"),
            ))))
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
    adapters: HashMap<NetworkId, Arc<dyn NetworkAdapter>>,
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
        if instruction.payment_hash.iter().all(|byte| *byte == 0) {
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
        Ok(htlc) => htlc,
        Err(_) => {
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
        Ok(htlc) => htlc,
        Err(_) => {
            remove_pending(&pending, instruction.payment_hash).await;
            return;
        }
    };

    match outgoing_adapter
        .watch_preimage(&outgoing, instruction.outgoing_expiry)
        .await
    {
        Ok(preimage) => {
            let _ = incoming_adapter.claim_incoming(&incoming, preimage).await;
        }
        Err(WatchError::DeadlineExceeded) => {
            let _ = outgoing_adapter.refund_outgoing(&outgoing).await;
        }
        Err(_) => {
            let _ = outgoing_adapter.refund_outgoing(&outgoing).await;
        }
    }

    remove_pending(&pending, instruction.payment_hash).await;
}

async fn remove_pending(pending: &PendingMap, payment_hash: [u8; 32]) {
    let mut pending = pending.lock().await;
    pending.remove(&payment_hash);
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
