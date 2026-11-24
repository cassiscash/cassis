//! Opening the [`Network`] adapters this build was compiled with, one
//! cargo feature per network, the same way in every Cassis binary.

mod wallet;

use cassis_core::keys::Mnemonic;
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
#[cfg(feature = "citrea")]
pub use cassis_citrea as citrea;
#[cfg(feature = "fedimint")]
pub use cassis_fedimint as fedimint;
#[cfg(feature = "liquid")]
pub use cassis_liquid as liquid;
#[cfg(feature = "lightning")]
pub use cassis_lnd as lnd;
#[cfg(feature = "rootstock")]
pub use cassis_rootstock as rootstock;
#[cfg(feature = "solana-wbtc")]
pub use cassis_solana_wbtc as solana_wbtc;
#[cfg(feature = "spark-lightning")]
pub use cassis_spark_lightning as spark_lightning;
#[cfg(feature = "starknet-wbtc")]
pub use cassis_starknet_wbtc as starknet_wbtc;

/// Everything needed to open one network besides its id.
#[derive(Clone)]
pub struct NetworkSettings {
    /// The BIP39 mnemonic the wallet on the network is restored from.
    /// Every network derives its keys from it the way that network's
    /// wallets do (see each adapter).
    pub mnemonic: Mnemonic,
    /// Private directory of the network's wallet (see [`network_dir`]).
    pub dir: PathBuf,
    /// Chain API instead of the public one, for `arkade` and `bitcoin`
    /// (regtest has none).
    pub esplora_url: Option<String>,
    /// The LND node a `lightning` network goes through, unless `bark` or
    /// `spark`.
    #[cfg(feature = "lightning")]
    pub lnd: Option<cassis_lnd::LndConfig>,
    /// The Ark server a `lightning` network goes through instead of LND.
    #[cfg(feature = "bark-lightning")]
    pub bark: Option<cassis_bark_lightning::BarkConfig>,
    /// The Spark wallet a `lightning` network goes through instead of LND.
    #[cfg(feature = "spark-lightning")]
    pub spark: Option<cassis_spark_lightning::SparkConfig>,
}

impl NetworkSettings {
    /// Settings with nothing but a wallet: no chain API of its own, and
    /// no LND, Ark server or Spark wallet.
    pub fn new(mnemonic: Mnemonic, dir: PathBuf) -> Self {
        Self {
            mnemonic,
            dir,
            esplora_url: None,
            #[cfg(feature = "lightning")]
            lnd: None,
            #[cfg(feature = "bark-lightning")]
            bark: None,
            #[cfg(feature = "spark-lightning")]
            spark: None,
        }
    }
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
/// kind, or `lnd`, `bark` or `spark` for the ways of being on `lightning`.
#[allow(clippy::match_like_matches_macro)]
pub fn built(kind: &str) -> bool {
    match kind {
        "arkade" => cfg!(feature = "arkade"),
        "bark" => cfg!(feature = "bark-lightning"),
        "bitcoin" => cfg!(feature = "bitcoin"),
        "cashu" => cfg!(feature = "cashu"),
        "citrea" => cfg!(feature = "citrea"),
        "fedimint" => cfg!(feature = "fedimint"),
        "liquid" => cfg!(feature = "liquid"),
        "lnd" => cfg!(feature = "lightning"),
        "rootstock" => cfg!(feature = "rootstock"),
        "solana-wbtc" => cfg!(feature = "solana-wbtc"),
        "spark" => cfg!(feature = "spark-lightning"),
        "starknet-wbtc" => cfg!(feature = "starknet-wbtc"),
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
    let mnemonic = &settings.mnemonic;
    let dir = &settings.dir;
    let (opened, wallet) = match network.kind() {
        #[cfg(feature = "cashu")]
        "cashu" => with_wallet(
            cassis_cashu::CashuAdapter::open(network.clone(), mnemonic, dir, span)?,
            Wallet::Cashu,
        ),
        #[cfg(feature = "liquid")]
        "liquid" => with_wallet(
            cassis_liquid::LiquidAdapter::open(network.clone(), mnemonic, dir, span).await?,
            Wallet::Liquid,
        ),
        #[cfg(feature = "bitcoin")]
        "bitcoin" => with_wallet(
            cassis_bitcoin::BitcoinAdapter::open_with_esplora(
                network.clone(),
                mnemonic,
                settings.esplora_url.as_deref(),
                span,
            )?,
            Wallet::Bitcoin,
        ),
        #[cfg(feature = "arkade")]
        "arkade" => with_wallet(
            cassis_arkade::ArkadeAdapter::open_with_esplora(
                network.clone(),
                mnemonic,
                dir,
                settings.esplora_url.as_deref(),
                span,
            )
            .await?,
            Wallet::Arkade,
        ),
        #[cfg(feature = "rootstock")]
        "rootstock" => with_wallet(
            cassis_rootstock::RootstockAdapter::open(network.clone(), mnemonic, span)?,
            Wallet::Rootstock,
        ),
        #[cfg(feature = "citrea")]
        "citrea" => with_wallet(
            cassis_citrea::CitreaAdapter::open(network.clone(), mnemonic, span)?,
            Wallet::Citrea,
        ),
        #[cfg(feature = "starknet-wbtc")]
        "starknet-wbtc" => with_wallet(
            cassis_starknet_wbtc::StarknetWbtcAdapter::open(network.clone(), mnemonic, span)?,
            Wallet::StarknetWbtc,
        ),
        #[cfg(feature = "solana-wbtc")]
        "solana-wbtc" => with_wallet(
            cassis_solana_wbtc::SolanaWbtcAdapter::open(network.clone(), mnemonic, span)?,
            Wallet::SolanaWbtc,
        ),
        #[cfg(feature = "fedimint")]
        "fedimint" => with_wallet(
            cassis_fedimint::FedimintAdapter::open(network.clone(), mnemonic, dir, span).await?,
            Wallet::Fedimint,
        ),
        #[cfg(any(
            feature = "lightning",
            feature = "bark-lightning",
            feature = "spark-lightning"
        ))]
        "lightning" => open_lightning(network, settings, span).await?,
        kind => return Err(format!("this build has no '{kind}' support")),
    };
    Ok((opened, wallet))
}

/// A `lightning` network goes through bark when it has an Ark server,
/// through Spark when it has a Spark wallet, else through LND.
#[cfg(any(
    feature = "lightning",
    feature = "bark-lightning",
    feature = "spark-lightning"
))]
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
                &settings.mnemonic,
                &settings.dir,
                bark,
                span,
            )
            .await?,
            Wallet::Bark,
        ));
    }
    #[cfg(feature = "spark-lightning")]
    if let Some(spark) = &settings.spark {
        return Ok(with_wallet(
            cassis_spark_lightning::SparkLightningAdapter::open(
                network.clone(),
                &settings.mnemonic,
                &settings.dir,
                spark,
                span,
            )
            .await?,
            Wallet::Spark,
        ));
    }
    #[cfg(feature = "lightning")]
    {
        let lnd = settings
            .lnd
            .clone()
            .ok_or("lightning needs an LND node, an Ark server (bark) or spark")?;
        return Ok(with_wallet(
            cassis_lnd::LndAdapter::open(network.clone(), lnd, span).await?,
            Wallet::Lnd,
        ));
    }
    Err(format!(
        "{network} needs an Ark server or spark: this build has no LND support"
    ))
}
