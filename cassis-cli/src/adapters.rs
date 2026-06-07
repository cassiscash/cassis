use std::collections::HashMap;
use std::sync::Arc;

use cassis_core::{NetworkId, NetworkReceiverAdapter, NetworkSenderAdapter};
use cassis_keys::DerivedKeys;

use crate::cli::NetSpec;

/// Construct receiver + sender adapters for a list of network specs
/// (e.g. parsed from `--network cashu::host` flags). Each spec uses
/// the same key-derivation scheme `cassis-router` does, so the
/// node's identity is consistent across the two binaries.
pub async fn build_receivers(
    specs: &[NetSpec],
    derived: &DerivedKeys,
) -> Result<HashMap<NetworkId, Arc<dyn NetworkReceiverAdapter>>, String> {
    let mut out: HashMap<NetworkId, Arc<dyn NetworkReceiverAdapter>> = HashMap::new();
    for spec in specs {
        let entry = build_receiver(spec, derived).await?;
        out.insert(entry.network_id.clone(), entry.receiver);
    }
    Ok(out)
}

/// Construct sender adapters for a list of network specs. Used by
/// the `pay` subcommand.
#[allow(dead_code)]
pub async fn build_senders(
    specs: &[NetSpec],
    derived: &DerivedKeys,
) -> Result<HashMap<NetworkId, Arc<dyn NetworkSenderAdapter>>, String> {
    let mut out: HashMap<NetworkId, Arc<dyn NetworkSenderAdapter>> = HashMap::new();
    for spec in specs {
        let entry = build_receiver(spec, derived).await?;
        out.insert(entry.network_id.clone(), entry.sender);
    }
    Ok(out)
}

/// Build a concrete [`cassis_cashu::CashuAdapter`] for a single
/// cashu spec. Used by the `cassis-cli cashu` wallet
/// subcommands, which need the wallet methods
/// (`redeem_proofs`, `swap_proofs_for_amount`) that aren't
/// visible through the `NetworkReceiverAdapter` /
/// `NetworkSenderAdapter` trait objects.
#[cfg(feature = "cashu")]
#[allow(unreachable_patterns)]
pub async fn build_cashu_adapter(
    spec: &NetSpec,
    derived: &DerivedKeys,
) -> Result<Arc<cassis_cashu::CashuAdapter>, String> {
    match spec {
        NetSpec::Cashu { mint_url, host: _ } => {
            let network_id = spec.network_id();
            let sk = derived
                .networks
                .get(&network_id)
                .map(|k| *k.as_bytes())
                .unwrap_or([0u8; 32]);
            let adapter = cassis_cashu::CashuAdapter::new(network_id, mint_url.clone(), sk)
                .map_err(|e| format!("cashu adapter init failed: {e}"))?;
            Ok(Arc::new(adapter))
        }
        _ => Err(format!("expected a cashu spec, got {}", spec.kind_name())),
    }
}

pub struct AdapterPair {
    pub network_id: NetworkId,
    pub receiver: Arc<dyn NetworkReceiverAdapter>,
    #[allow(dead_code)]
    pub sender: Arc<dyn NetworkSenderAdapter>,
}

#[allow(unused_variables)]
async fn build_receiver(spec: &NetSpec, derived: &DerivedKeys) -> Result<AdapterPair, String> {
    let network_id = spec.network_id();
    let sk = derived
        .networks
        .get(&network_id)
        .map(|k| *k.as_bytes())
        .unwrap_or([0u8; 32]);
    match spec {
        #[cfg(feature = "cashu")]
        NetSpec::Cashu { mint_url, host: _ } => {
            let adapter = Arc::new(
                cassis_cashu::CashuAdapter::new(network_id.clone(), mint_url.clone(), sk)
                    .map_err(|e| format!("cashu adapter init failed: {e}"))?,
            );
            let receiver: Arc<dyn NetworkReceiverAdapter> = adapter.clone();
            let sender: Arc<dyn NetworkSenderAdapter> = adapter;
            Ok(AdapterPair {
                network_id,
                receiver,
                sender,
            })
        }
        #[cfg(feature = "fedimint")]
        NetSpec::Fedimint { address } => {
            let adapter =
                cassis_fedimint::FedimintAdapter::new(network_id.clone(), address.clone(), sk)
                    .await
                    .map_err(|e| format!("fedimint adapter init failed: {e}"))?;
            let adapter = Arc::new(adapter);
            let receiver: Arc<dyn NetworkReceiverAdapter> = adapter.clone();
            let sender: Arc<dyn NetworkSenderAdapter> = adapter;
            Ok(AdapterPair {
                network_id,
                receiver,
                sender,
            })
        }
        #[cfg(feature = "liquid")]
        NetSpec::Liquid => {
            let adapter = Arc::new(cassis_liquid::LiquidAdapter::new(network_id.clone()));
            let receiver: Arc<dyn NetworkReceiverAdapter> = adapter.clone();
            let sender: Arc<dyn NetworkSenderAdapter> = adapter;
            Ok(AdapterPair {
                network_id,
                receiver,
                sender,
            })
        }
        #[cfg(feature = "ark")]
        NetSpec::Ark => {
            let adapter = Arc::new(cassis_arkade::ArkAdapter::new(network_id.clone()));
            let receiver: Arc<dyn NetworkReceiverAdapter> = adapter.clone();
            let sender: Arc<dyn NetworkSenderAdapter> = adapter;
            Ok(AdapterPair {
                network_id,
                receiver,
                sender,
            })
        }
        #[cfg(feature = "rootstock")]
        NetSpec::Rootstock => {
            let adapter = Arc::new(cassis_rootstock::RootstockAdapter::new(network_id.clone()));
            let receiver: Arc<dyn NetworkReceiverAdapter> = adapter.clone();
            let sender: Arc<dyn NetworkSenderAdapter> = adapter;
            Ok(AdapterPair {
                network_id,
                receiver,
                sender,
            })
        }
        #[allow(unreachable_patterns)]
        _ => Err(format!(
            "network kind '{}' requested but cassis-cli was not compiled with that feature",
            spec.kind_name()
        )),
    }
}
