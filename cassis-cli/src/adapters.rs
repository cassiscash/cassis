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
            let store: Arc<dyn cassis_cashu::CashuProofStore> =
                Arc::new(crate::store::CashuProofDb::new(crate::paths::store_path()));
            let adapter = cassis_cashu::CashuAdapter::new(network_id, mint_url.clone(), sk, store)
                .map_err(|e| format!("cashu adapter init failed: {e}"))?;
            Ok(Arc::new(adapter))
        }
        _ => Err(format!("expected a cashu spec, got {}", spec.kind_name())),
    }
}

/// Same as [`build_cashu_adapter`] but takes a raw mint URL
/// instead of a parsed `NetSpec`. The receive flow uses this
/// when the mint URL comes out of the proof string itself
/// rather than from `--network` / the registered networks.
#[cfg(feature = "cashu")]
pub async fn build_cashu_adapter_from_url(
    mint_url: &str,
    derived: &DerivedKeys,
) -> Result<(NetSpec, Arc<cassis_cashu::CashuAdapter>), String> {
    let host = mint_url_to_host(mint_url)?;
    let network_id = cassis_core::cashu_network_id(&host);
    let sk = derived
        .networks
        .get(&network_id)
        .map(|k| *k.as_bytes())
        .unwrap_or([0u8; 32]);
    let store: Arc<dyn cassis_cashu::CashuProofStore> =
        Arc::new(crate::store::CashuProofDb::new(crate::paths::store_path()));
    let adapter =
        cassis_cashu::CashuAdapter::new(network_id.clone(), mint_url.to_string(), sk, store)
            .map_err(|e| format!("cashu adapter init failed: {e}"))?;
    // `cashu_mint_url` rebuilds the canonical form
    // (lowercased scheme/host, trimmed trailing slash) so the
    // adapter stores the same string everywhere else.
    let canonical = cassis_core::cashu_mint_url(&network_id)
        .map_err(|e| format!("canonicalize mint url: {e}"))?;
    let spec = NetSpec::Cashu {
        mint_url: canonical,
        host,
    };
    Ok((spec, Arc::new(adapter)))
}

/// Extract `host[:port]` from a cashu mint URL. The cashu
/// `MintUrl` keeps the canonical `{scheme}://{host}/{path}`
/// form, so we slice on the scheme separator and the first
/// following slash.
#[cfg(feature = "cashu")]
pub fn mint_url_to_host(mint_url: &str) -> Result<String, String> {
    let trimmed = mint_url.trim().trim_end_matches('/');
    let after_scheme = trimmed
        .split_once("://")
        .ok_or_else(|| format!("mint url missing scheme: '{mint_url}'"))?
        .1;
    let host = after_scheme
        .split('/')
        .next()
        .ok_or_else(|| format!("mint url missing host: '{mint_url}'"))?;
    if host.is_empty() {
        return Err(format!("mint url has empty host: '{mint_url}'"));
    }
    Ok(host.to_string())
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
            let store: Arc<dyn cassis_cashu::CashuProofStore> =
                Arc::new(crate::store::CashuProofDb::new(crate::paths::store_path()));
            let adapter = Arc::new(
                cassis_cashu::CashuAdapter::new(network_id.clone(), mint_url.clone(), sk, store)
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
