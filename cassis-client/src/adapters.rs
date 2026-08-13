//! Build one direct network adapter map for a list of [`NetSpec`]s.
//! Router, client, receive daemon, and CLI all consume same adapter
//! boundary. Concrete constructors remain available for wallet commands.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use cassis_core::{NetworkAdapter, NetworkId};
use cassis_keys::DerivedKeys;
use tracing::Span;

use crate::netspec::NetSpec;
use crate::store::CashuProofDb;

#[derive(Clone, Debug, Default)]
pub struct AdapterConfig {
    #[cfg(feature = "lightning")]
    pub lnd: Option<cassis_lnd::LndConfig>,
}

pub async fn build_adapters(
    specs: &[NetSpec],
    derived: &DerivedKeys,
    store_path: &Path,
    span: Span,
) -> Result<HashMap<NetworkId, Arc<dyn NetworkAdapter>>, String> {
    build_adapters_with_config(specs, derived, store_path, span, &AdapterConfig::default()).await
}

pub async fn build_adapters_with_config(
    specs: &[NetSpec],
    derived: &DerivedKeys,
    store_path: &Path,
    span: Span,
    config: &AdapterConfig,
) -> Result<HashMap<NetworkId, Arc<dyn NetworkAdapter>>, String> {
    let mut out = HashMap::new();
    for spec in specs {
        let entry = build_one(spec, derived, store_path, span.clone(), config).await?;
        out.insert(entry.network_id, entry.adapter);
    }
    Ok(out)
}

struct AdapterEntry {
    pub network_id: NetworkId,
    pub adapter: Arc<dyn NetworkAdapter>,
}

/// Per-network signing key for `network_id`, or a descriptive error.
///
/// Previously this fell back to an all-zero key, which is not a valid
/// secp256k1 scalar: the failure was merely deferred to the first
/// signature (or, worse, produced an identity the node could not claim
/// with). Naming the missing key here is far clearer than an "invalid
/// secret key" surfacing from inside an adapter.
fn network_sk(derived: &DerivedKeys, network_id: &NetworkId) -> Result<[u8; 32], String> {
    derived
        .networks
        .get(network_id)
        .map(|k| *k.as_bytes())
        .ok_or_else(|| {
            format!("no signing key derived for network '{network_id}'; derive keys for it first")
        })
}

#[allow(unused_variables)]
async fn build_one(
    spec: &NetSpec,
    derived: &DerivedKeys,
    store_path: &Path,
    span: Span,
    config: &AdapterConfig,
) -> Result<AdapterEntry, String> {
    let network_id = spec.network_id();
    match spec {
        NetSpec::Cashu { mint_url, host: _ } => {
            let store: Arc<dyn cassis_cashu::CashuProofStore> =
                Arc::new(CashuProofDb::new(store_path.to_path_buf()));
            let adapter = Arc::new(
                cassis_cashu::CashuAdapter::new(
                    network_id.clone(),
                    mint_url.clone(),
                    network_sk(derived, &network_id)?,
                    store,
                    span.clone(),
                )
                .map_err(|e| format!("cashu adapter init failed: {e}"))?,
            );
            Ok(AdapterEntry {
                network_id,
                adapter,
            })
        }
        #[cfg(feature = "liquid")]
        NetSpec::Liquid { .. } => {
            let mut cfg = cassis_liquid::default_config(
                network_id.clone(),
                network_sk(derived, &network_id)?,
                span.clone(),
            );
            let persist_dir = store_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join("liquid")
                .join(network_id.0.replace("::", "_"));
            cfg.persist_dir = Some(persist_dir);
            let adapter = cassis_liquid::LiquidAdapter::new(cfg)
                .await
                .map_err(|e| format!("liquid adapter init failed: {e}"))?;
            Ok(AdapterEntry {
                network_id,
                adapter,
            })
        }
        NetSpec::Rootstock { .. } => {
            let cfg = cassis_rootstock::default_config(
                network_id.clone(),
                network_sk(derived, &network_id)?,
                span.clone(),
            );
            let adapter = cassis_rootstock::RootstockAdapter::new(cfg)
                .await
                .map_err(|e| format!("rootstock adapter init failed: {e}"))?;
            Ok(AdapterEntry {
                network_id,
                adapter,
            })
        }
        #[cfg(feature = "lightning")]
        NetSpec::Lightning => {
            let lnd = config
                .lnd
                .as_ref()
                .ok_or_else(|| "network 'lightning' requires LND configuration".to_string())?;
            let adapter = cassis_lnd::LndAdapter::new(network_id.clone(), lnd.clone(), span)
                .await
                .map_err(|error| format!("LND adapter init failed: {error}"))?;
            Ok(AdapterEntry {
                network_id,
                adapter,
            })
        }
        #[cfg(feature = "arkade")]
        NetSpec::Arkade { .. } => {
            let cfg = cassis_arkade::default_config(
                network_id.clone(),
                network_sk(derived, &network_id)?,
                span.clone(),
            );
            let adapter = cassis_arkade::ArkadeAdapter::new(cfg)
                .await
                .map_err(|e| format!("arkade adapter init failed: {e}"))?;
            Ok(AdapterEntry {
                network_id,
                adapter,
            })
        }
        #[cfg(feature = "bitcoin")]
        NetSpec::Bitcoin { .. } => {
            let cfg = cassis_bitcoin::default_config(
                network_id.clone(),
                network_sk(derived, &network_id)?,
                span.clone(),
            )
            .map_err(|e| format!("bitcoin adapter config: {e}"))?;
            let adapter = Arc::new(
                cassis_bitcoin::BitcoinAdapter::new(cfg)
                    .await
                    .map_err(|e| format!("bitcoin adapter init failed: {e}"))?,
            );
            Ok(AdapterEntry {
                network_id,
                adapter,
            })
        }
        #[cfg(feature = "fedimint")]
        NetSpec::Fedimint { address } => {
            let adapter = Arc::new(
                cassis_fedimint::FedimintAdapter::new(
                    network_id.clone(),
                    address.clone(),
                    network_sk(derived, &network_id)?,
                    fedimint_data_dir(store_path),
                )
                .await
                .map_err(|e| format!("fedimint adapter init failed: {e}"))?,
            );
            Ok(AdapterEntry {
                network_id,
                adapter,
            })
        }
        #[allow(unreachable_patterns)]
        _ => Err(format!(
            "network kind '{}' requested but cassis-client was not compiled with that feature",
            spec.kind_name()
        )),
    }
}

/// Data directory for a fedimint federation client DB: the parent of
/// the node's store file (the same base the liquid wallet directories
/// hang off), then a `fedimint/<slug>` subdirectory.
#[cfg(feature = "fedimint")]
fn fedimint_data_dir(store_path: &Path) -> std::path::PathBuf {
    store_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("fedimint")
}

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

/// Build a concrete `cassis_cashu::CashuAdapter` for a cashu spec (the
/// wallet methods `redeem_proofs` / `swap_proofs_for_amount` aren't
/// visible through the trait objects).
pub async fn build_cashu_adapter(
    spec: &NetSpec,
    derived: &DerivedKeys,
    store_path: &Path,
    span: Span,
) -> Result<Arc<cassis_cashu::CashuAdapter>, String> {
    let NetSpec::Cashu { mint_url, host: _ } = spec else {
        return Err(format!("expected a cashu spec, got {}", spec.kind_name()));
    };
    let network_id = spec.network_id();
    let sk = network_sk(derived, &network_id)?;
    let store: Arc<dyn cassis_cashu::CashuProofStore> =
        Arc::new(CashuProofDb::new(store_path.to_path_buf()));
    cassis_cashu::CashuAdapter::new(network_id, mint_url.clone(), sk, store, span)
        .map(Arc::new)
        .map_err(|e| format!("cashu adapter init failed: {e}"))
}

/// Build a concrete `cassis_liquid::LiquidAdapter` for a liquid
/// spec (for the wallet/CLI `balance` / `deposit` / `send`
/// subcommands).
#[cfg(feature = "liquid")]
pub async fn build_liquid_adapter(
    spec: &NetSpec,
    derived: &DerivedKeys,
    store_path: &Path,
    span: Span,
) -> Result<Arc<cassis_liquid::LiquidAdapter>, String> {
    let NetSpec::Liquid { .. } = spec else {
        return Err(format!("expected a liquid spec, got {}", spec.kind_name()));
    };
    let network_id = spec.network_id();
    let sk = network_sk(derived, &network_id)?;
    let mut cfg = cassis_liquid::default_config(network_id, sk, span);
    let persist_dir = store_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("liquid")
        .join(cfg.network_id.0.replace("::", "_"));
    cfg.persist_dir = Some(persist_dir);
    cassis_liquid::LiquidAdapter::new(cfg)
        .await
        .map_err(|e| format!("liquid adapter init failed: {e}"))
}

/// Build a concrete `cassis_fedimint::FedimintAdapter` for a fedimint
/// spec (for the wallet `balance` subcommand).
#[cfg(feature = "fedimint")]
pub async fn build_fedimint_adapter(
    spec: &NetSpec,
    derived: &DerivedKeys,
    store_path: &Path,
) -> Result<Arc<cassis_fedimint::FedimintAdapter>, String> {
    let NetSpec::Fedimint { address } = spec else {
        return Err(format!(
            "expected a fedimint spec, got {}",
            spec.kind_name()
        ));
    };
    let network_id = spec.network_id();
    let sk = network_sk(derived, &network_id)?;
    cassis_fedimint::FedimintAdapter::new(
        network_id,
        address.clone(),
        sk,
        fedimint_data_dir(store_path),
    )
    .await
    .map(Arc::new)
    .map_err(|e| format!("fedimint adapter init failed: {e}"))
}

/// Build a concrete `cassis_rootstock::RootstockAdapter` for a
/// rootstock spec (for `send` / `info` / `balance` subcommands).
pub async fn build_rootstock_adapter(
    spec: &NetSpec,
    derived: &DerivedKeys,
    span: Span,
) -> Result<Arc<cassis_rootstock::RootstockAdapter>, String> {
    let NetSpec::Rootstock { .. } = spec else {
        return Err(format!(
            "expected a rootstock spec, got {}",
            spec.kind_name()
        ));
    };
    let network_id = spec.network_id();
    let sk = network_sk(derived, &network_id)?;
    let cfg = cassis_rootstock::default_config(network_id, sk, span);
    cassis_rootstock::RootstockAdapter::new(cfg)
        .await
        .map_err(|e| format!("rootstock adapter init failed: {e}"))
}

/// Build a concrete `cassis_arkade::ArkadeAdapter` for an arkade
/// spec (for the wallet/CLI `balance` / `deposit` / `send`
/// subcommands).
#[cfg(feature = "arkade")]
pub async fn build_arkade_adapter(
    spec: &NetSpec,
    derived: &DerivedKeys,
    span: Span,
) -> Result<Arc<cassis_arkade::ArkadeAdapter>, String> {
    let NetSpec::Arkade { .. } = spec else {
        return Err(format!("expected an arkade spec, got {}", spec.kind_name()));
    };
    let network_id = spec.network_id();
    let sk = network_sk(derived, &network_id)?;
    let cfg = cassis_arkade::default_config(network_id, sk, span);
    cassis_arkade::ArkadeAdapter::new(cfg)
        .await
        .map_err(|e| format!("arkade adapter init failed: {e}"))
}

/// Build a concrete `cassis_bitcoin::BitcoinAdapter` for a bitcoin
/// spec (for the wallet `transfer` / prefund flows).
#[cfg(feature = "bitcoin")]
pub async fn build_bitcoin_adapter(
    spec: &NetSpec,
    derived: &DerivedKeys,
    span: Span,
) -> Result<Arc<cassis_bitcoin::BitcoinAdapter>, String> {
    let NetSpec::Bitcoin { .. } = spec else {
        return Err(format!("expected a bitcoin spec, got {}", spec.kind_name()));
    };
    let network_id = spec.network_id();
    let sk = network_sk(derived, &network_id)?;
    let cfg = cassis_bitcoin::default_config(network_id, sk, span).map_err(|e| e.to_string())?;
    cassis_bitcoin::BitcoinAdapter::new(cfg)
        .await
        .map(Arc::new)
        .map_err(|e| format!("bitcoin adapter init failed: {e}"))
}

/// Build a concrete cashu adapter from a raw mint URL (used by the
/// `cashu receive` flow where the URL comes from the token, not from
/// `--network`).
pub async fn build_cashu_adapter_from_url(
    mint_url: &str,
    derived: &DerivedKeys,
    store_path: &Path,
    span: Span,
) -> Result<(NetSpec, Arc<cassis_cashu::CashuAdapter>), String> {
    let host = mint_url_to_host(mint_url)?;
    let network_id = cassis_core::cashu_network_id(&host);
    // The mint here comes from the *token*, which may well be a mint
    // the caller never derived a key for, so fall back to the node key
    // rather than to an all-zero key. Redeeming a token only swaps
    // unrestricted proofs and needs no HTLC signing key, but the
    // adapter still requires a usable one to derive its claim identity.
    let sk = derived
        .networks
        .get(&network_id)
        .map(|k| *k.as_bytes())
        .unwrap_or(*derived.node.as_bytes());
    let store: Arc<dyn cassis_cashu::CashuProofStore> =
        Arc::new(CashuProofDb::new(store_path.to_path_buf()));
    let adapter =
        cassis_cashu::CashuAdapter::new(network_id.clone(), mint_url.to_string(), sk, store, span)
            .map_err(|e| format!("cashu adapter init failed: {e}"))?;
    let canonical = cassis_core::cashu_mint_url(&network_id)
        .map_err(|e| format!("canonicalize mint url: {e}"))?;
    let spec = NetSpec::Cashu {
        mint_url: canonical,
        host,
    };
    Ok((spec, Arc::new(adapter)))
}
