//! Opening the [`Network`] adapters this build was compiled with, one
//! cargo feature per network, the same way in every Cassis binary.

mod wallet;

use cassis_core::{Network, NetworkId};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::Span;
pub use wallet::{Address, Balance, Can, Done, Op, Then, Wallet};

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

/// Whether this build has the kind of network named `kind`: a network
/// kind, or `lnd` or `bark` for the two ways of being on `lightning`.
#[allow(clippy::match_like_matches_macro)]
pub fn built(kind: &str) -> bool {
    match kind {
        "arkade" => cfg!(feature = "arkade"),
        "bark" => cfg!(feature = "bark-lightning"),
        "bitcoin" => cfg!(feature = "bitcoin"),
        "cashu" => cfg!(feature = "cashu"),
        "fedimint" => cfg!(feature = "fedimint"),
        "liquid" => cfg!(feature = "liquid"),
        "lnd" => cfg!(feature = "lightning"),
        "rootstock" => cfg!(feature = "rootstock"),
        _ => false,
    }
}

/// Open the adapter of `network`, if this build has it.
pub async fn open(
    network: &NetworkId,
    settings: &NetworkSettings,
    span: &Span,
) -> Result<Arc<dyn Network>, String> {
    open_wallet(network, settings, span)
        .await
        .map(|(opened, _)| opened)
}

/// The adapter and its wallet, sharing one handle.
#[allow(dead_code)]
fn with_wallet<A: Network + 'static>(
    adapter: A,
    wallet: fn(Arc<A>) -> Wallet,
) -> (Arc<dyn Network>, Wallet) {
    let adapter = Arc::new(adapter);
    (adapter.clone(), wallet(adapter))
}

/// Open the adapter of `network`, if this build has it, and its wallet.
#[allow(unused_variables, unreachable_code)]
pub async fn open_wallet(
    network: &NetworkId,
    settings: &NetworkSettings,
    span: &Span,
) -> Result<(Arc<dyn Network>, Wallet), String> {
    let secret = settings.secret;
    let dir = &settings.dir;
    let (opened, wallet) = match network.kind() {
        #[cfg(feature = "cashu")]
        "cashu" => with_wallet(
            cassis_cashu::CashuAdapter::open(network.clone(), secret, dir, span)?,
            Wallet::Cashu,
        ),
        #[cfg(feature = "liquid")]
        "liquid" => with_wallet(
            cassis_liquid::LiquidAdapter::open(network.clone(), secret, dir, span).await?,
            Wallet::Liquid,
        ),
        #[cfg(feature = "bitcoin")]
        "bitcoin" => with_wallet(
            cassis_bitcoin::BitcoinAdapter::open_with_esplora(
                network.clone(),
                secret,
                settings.esplora_url.as_deref(),
                span,
            )?,
            Wallet::Bitcoin,
        ),
        #[cfg(feature = "arkade")]
        "arkade" => with_wallet(
            cassis_arkade::ArkadeAdapter::open_with_esplora(
                network.clone(),
                secret,
                dir,
                settings.esplora_url.as_deref(),
                span,
            )
            .await?,
            Wallet::Arkade,
        ),
        #[cfg(feature = "rootstock")]
        "rootstock" => with_wallet(
            cassis_rootstock::RootstockAdapter::open(network.clone(), secret, span)?,
            Wallet::Rootstock,
        ),
        #[cfg(feature = "fedimint")]
        "fedimint" => with_wallet(
            cassis_fedimint::FedimintAdapter::open(network.clone(), secret, dir, span).await?,
            Wallet::Fedimint,
        ),
        #[cfg(any(feature = "lightning", feature = "bark-lightning"))]
        "lightning" => open_lightning(network, settings, span).await?,
        kind => return Err(format!("this build has no '{kind}' support")),
    };
    Ok((opened, wallet))
}

/// A `lightning` network goes through bark when it has an Ark server,
/// else through LND.
#[cfg(any(feature = "lightning", feature = "bark-lightning"))]
#[allow(unused_variables, unreachable_code)]
async fn open_lightning(
    network: &NetworkId,
    settings: &NetworkSettings,
    span: &Span,
) -> Result<(Arc<dyn Network>, Wallet), String> {
    #[cfg(feature = "bark-lightning")]
    if let Some(bark) = &settings.bark {
        return Ok(with_wallet(
            cassis_bark_lightning::BarkLightningAdapter::open(
                network.clone(),
                settings.secret,
                &settings.dir,
                bark,
                span,
            )
            .await?,
            Wallet::Bark,
        ));
    }
    #[cfg(feature = "lightning")]
    {
        let lnd = settings
            .lnd
            .clone()
            .ok_or("lightning needs an LND node or an Ark server (bark)")?;
        return Ok(with_wallet(
            cassis_lnd::LndAdapter::open(network.clone(), lnd, span).await?,
            Wallet::Lnd,
        ));
    }
    Err(format!(
        "{network} needs an Ark server: this build has no LND support"
    ))
}
