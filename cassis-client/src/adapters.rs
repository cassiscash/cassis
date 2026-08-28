//! Build network senders/receivers for a list of [`NetSpec`]s. Used by
//! the GUI and the CLI to materialise the per-network adapters from a
//! node's derived keys, and to construct concrete
//! (`cassis_cashu::CashuAdapter`, `cassis_rootstock::RootstockAdapter`)
//! instances for the wallet/CLI subcommands.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use cassis_core::{NetworkId, NetworkReceiverAdapter, NetworkSenderAdapter};
use cassis_keys::DerivedKeys;
use tracing::Span;

use crate::netspec::NetSpec;
use crate::store::CashuProofDb;

pub async fn build_receivers(
    specs: &[NetSpec],
    derived: &DerivedKeys,
    store_path: &Path,
    span: Span,
) -> Result<HashMap<NetworkId, Arc<dyn NetworkReceiverAdapter>>, String> {
    let mut out: HashMap<NetworkId, Arc<dyn NetworkReceiverAdapter>> = HashMap::new();
    for spec in specs {
        let entry = build_pair(spec, derived, store_path, span.clone()).await?;
        out.insert(entry.network_id.clone(), entry.receiver);
    }
    Ok(out)
}

pub async fn build_senders(
    specs: &[NetSpec],
    derived: &DerivedKeys,
    store_path: &Path,
    span: Span,
) -> Result<HashMap<NetworkId, Arc<dyn NetworkSenderAdapter>>, String> {
    let mut out: HashMap<NetworkId, Arc<dyn NetworkSenderAdapter>> = HashMap::new();
    for spec in specs {
        let entry = build_pair(spec, derived, store_path, span.clone()).await?;
        out.insert(entry.network_id.clone(), entry.sender);
    }
    Ok(out)
}

pub struct AdapterPair {
    pub network_id: NetworkId,
    pub receiver: Arc<dyn NetworkReceiverAdapter>,
    #[allow(dead_code)]
    pub sender: Arc<dyn NetworkSenderAdapter>,
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
async fn build_pair(
    spec: &NetSpec,
    derived: &DerivedKeys,
    store_path: &Path,
    span: Span,
) -> Result<AdapterPair, String> {
    let network_id = spec.network_id();
    match spec {
        NetSpec::Cashu { mint_url, host: _ } => {
            let store: Arc<dyn cassis_cashu::CashuProofStore> =
                Arc::new(CashuProofDb::new(store_path.to_path_buf()));
            let adapter = Arc::new(
                cassis_cashu::CashuAdapter::new(
                    network_id.clone(),
                    mint_url.clone(),
                    *derived.invoice.as_bytes(),
                    derived.invoice.pubkey(),
                    store,
                    span.clone(),
                )
                .map_err(|e| format!("cashu adapter init failed: {e}"))?,
            );
            Ok(AdapterPair {
                network_id,
                receiver: adapter.clone(),
                sender: adapter,
            })
        }
        NetSpec::Rootstock { .. } => {
            let cfg = cassis_rootstock::default_config(
                network_id.clone(),
                network_sk(derived, &network_id)?,
                derived.invoice.pubkey(),
                span.clone(),
            );
            let adapter = cassis_rootstock::RootstockAdapter::new(cfg)
                .await
                .map_err(|e| format!("rootstock adapter init failed: {e}"))?;
            Ok(AdapterPair {
                network_id,
                receiver: adapter.clone(),
                sender: adapter,
            })
        }
        #[cfg(feature = "arkade")]
        NetSpec::Arkade { .. } => {
            let cfg = cassis_arkade::default_config(
                network_id.clone(),
                network_sk(derived, &network_id)?,
                derived.invoice.pubkey(),
                span.clone(),
            );
            let adapter = cassis_arkade::ArkadeAdapter::new(cfg)
                .await
                .map_err(|e| format!("arkade adapter init failed: {e}"))?;
            Ok(AdapterPair {
                network_id,
                receiver: adapter.clone(),
                sender: adapter,
            })
        }
        #[allow(unreachable_patterns)]
        _ => Err(format!(
            "network kind '{}' requested but cassis-client was not compiled with that feature",
            spec.kind_name()
        )),
    }
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
    cassis_cashu::CashuAdapter::new(
        network_id,
        mint_url.clone(),
        sk,
        derived.invoice.pubkey(),
        store,
        span,
    )
    .map(|a| Arc::new(a))
    .map_err(|e| format!("cashu adapter init failed: {e}"))
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
    let cfg = cassis_rootstock::default_config(network_id, sk, derived.invoice.pubkey(), span);
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
    let cfg = cassis_arkade::default_config(network_id, sk, derived.invoice.pubkey(), span);
    cassis_arkade::ArkadeAdapter::new(cfg)
        .await
        .map_err(|e| format!("arkade adapter init failed: {e}"))
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
    // the caller never derived a key for, so fall back to the invoice
    // key rather than to an all-zero key. Redeeming a token only swaps
    // unrestricted proofs and needs no HTLC signing key, but the
    // adapter still requires a usable one to derive its claim identity.
    let sk = derived
        .networks
        .get(&network_id)
        .map(|k| *k.as_bytes())
        .unwrap_or(*derived.invoice.as_bytes());
    let store: Arc<dyn cassis_cashu::CashuProofStore> =
        Arc::new(CashuProofDb::new(store_path.to_path_buf()));
    let adapter = cassis_cashu::CashuAdapter::new(
        network_id.clone(),
        mint_url.to_string(),
        sk,
        derived.invoice.pubkey(),
        store,
        span,
    )
    .map_err(|e| format!("cashu adapter init failed: {e}"))?;
    let canonical = cassis_core::cashu_mint_url(&network_id)
        .map_err(|e| format!("canonicalize mint url: {e}"))?;
    let spec = NetSpec::Cashu {
        mint_url: canonical,
        host,
    };
    Ok((spec, Arc::new(adapter)))
}
