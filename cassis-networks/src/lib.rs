//! Opening the [`Network`] adapters this build was compiled with, one
//! cargo feature per network, the same way in every Cassis binary.

use cassis_core::{Network, NetworkId};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::Span;

#[cfg(feature = "arkade")]
pub use cassis_arkade as arkade;
#[cfg(feature = "bark-lightning")]
pub use cassis_bark_lightning as bark_lightning;
#[cfg(feature = "bitcoin")]
pub use cassis_bitcoin as bitcoin;
#[cfg(feature = "cashu")]
pub use cassis_cashu as cashu;
#[cfg(feature = "fedimint")]
pub use cassis_fedimint as fedimint;
#[cfg(feature = "liquid")]
pub use cassis_liquid as liquid;
#[cfg(feature = "lightning")]
pub use cassis_lnd as lnd;
#[cfg(feature = "rootstock")]
pub use cassis_rootstock as rootstock;

/// Everything needed to open one network besides its id.
#[derive(Clone, Default)]
pub struct NetworkSettings {
    /// Signing key of the node on the network.
    pub secret: [u8; 32],
    /// Private directory of the network's wallet (see [`network_dir`]).
    pub dir: PathBuf,
    /// Longest an HTLC received on the network may run, instead of what
    /// the network derives.
    pub max_incoming_lifetime_secs: Option<u64>,
    /// Chain API instead of the public one, for `arkade` and `bitcoin`
    /// (regtest has none).
    pub esplora_url: Option<String>,
    /// The LND node a `lightning` network goes through, unless `bark`.
    #[cfg(feature = "lightning")]
    pub lnd: Option<cassis_lnd::LndConfig>,
    /// The Ark server a `lightning` network goes through instead of LND.
    #[cfg(feature = "bark-lightning")]
    pub bark: Option<cassis_bark_lightning::BarkConfig>,
}

/// Private directory of `network` under `root`: `<root>/<kind>/<variant>`.
pub fn network_dir(root: &Path, network: &NetworkId) -> PathBuf {
    let variant: String = network
        .param()
        .unwrap_or("mainnet")
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    root.join(network.kind()).join(variant)
}

/// Open the adapter of `network`, if this build has it.
#[allow(unused_variables)]
pub async fn open(
    network: &NetworkId,
    settings: &NetworkSettings,
    span: &Span,
) -> Result<Arc<dyn Network>, String> {
    let secret = settings.secret;
    let dir = &settings.dir;
    let opened: Arc<dyn Network> = match network.kind() {
        #[cfg(feature = "cashu")]
        "cashu" => Arc::new(cassis_cashu::CashuAdapter::open(
            network.clone(),
            secret,
            dir,
            span,
        )?),
        #[cfg(feature = "liquid")]
        "liquid" => {
            Arc::new(cassis_liquid::LiquidAdapter::open(network.clone(), secret, dir, span).await?)
        }
        #[cfg(feature = "bitcoin")]
        "bitcoin" => Arc::new(cassis_bitcoin::BitcoinAdapter::open_with_esplora(
            network.clone(),
            secret,
            settings.esplora_url.as_deref(),
            span,
        )?),
        #[cfg(feature = "arkade")]
        "arkade" => Arc::new(
            cassis_arkade::ArkadeAdapter::open_with_esplora(
                network.clone(),
                secret,
                settings.esplora_url.as_deref(),
                span,
            )
            .await?,
        ),
        #[cfg(feature = "rootstock")]
        "rootstock" => Arc::new(cassis_rootstock::RootstockAdapter::open(
            network.clone(),
            secret,
            span,
        )?),
        #[cfg(feature = "fedimint")]
        "fedimint" => Arc::new(
            cassis_fedimint::FedimintAdapter::open(network.clone(), secret, dir, span).await?,
        ),
        #[cfg(any(feature = "lightning", feature = "bark-lightning"))]
        "lightning" => open_lightning(network, settings, span).await?,
        kind => return Err(format!("this build has no '{kind}' support")),
    };
    Ok(match settings.max_incoming_lifetime_secs {
        Some(secs) => cassis_core::with_max_incoming_lifetime(opened, secs),
        None => opened,
    })
}

/// A `lightning` network goes through bark when it has an Ark server,
/// else through LND.
#[cfg(any(feature = "lightning", feature = "bark-lightning"))]
#[allow(unused_variables, unreachable_code)]
async fn open_lightning(
    network: &NetworkId,
    settings: &NetworkSettings,
    span: &Span,
) -> Result<Arc<dyn Network>, String> {
    #[cfg(feature = "bark-lightning")]
    if let Some(bark) = &settings.bark {
        return Ok(Arc::new(
            cassis_bark_lightning::BarkLightningAdapter::open(
                network.clone(),
                settings.secret,
                &settings.dir,
                bark,
                span,
            )
            .await?,
        ));
    }
    #[cfg(feature = "lightning")]
    {
        let lnd = settings
            .lnd
            .clone()
            .ok_or("lightning needs an LND node or an Ark server (bark)")?;
        return Ok(Arc::new(
            cassis_lnd::LndAdapter::open(network.clone(), lnd, span).await?,
        ));
    }
    Err(format!(
        "{network} needs an Ark server: this build has no LND support"
    ))
}
