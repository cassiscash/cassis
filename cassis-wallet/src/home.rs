//! The wallet's home directory:
//!
//! ```text
//! <home>/config.toml        mnemonic, and every network with its key (see [`crate::config`])
//! <home>/wallet.redb        invoices, transactions, pending payments (see [`crate::db`])
//! <home>/<kind>/<variant>/  private data of one network (wallets, ...)
//! ```
//!
//! A router (`cassis-routerd`) and a gateway (`cassis-gateway`) keep
//! their wallet the same way, next to their own files.

use crate::config::{self, NetworkConfig, WalletConfig};
use crate::db::Db;
use cassis_core::keys::NodeKeys;
use cassis_core::{Network, NetworkId};
#[cfg(feature = "arkade")]
use cassis_networks::arkade;
#[cfg(feature = "bark-lightning")]
use cassis_networks::bark_lightning;
#[cfg(feature = "cashu")]
use cassis_networks::cashu;
use cassis_networks::NetworkSettings;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{warn, Span};

/// The wallet database of the node living in `dir`, readable by its
/// owner only.
pub fn open_db(dir: &Path) -> Result<Arc<Db>, String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let path = dir.join("wallet.redb");
    let db = Db::open(&path).map_err(|e| format!("open {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("restrict {}: {e}", path.display()))?;
    }
    Ok(Arc::new(db))
}

pub struct Home {
    pub dir: PathBuf,
    pub keys: NodeKeys,
    pub config: WalletConfig,
    pub db: Arc<Db>,
}

impl Home {
    /// Open `dir`, or `$CASSIS_HOME`, or `~/.cassis`, creating it and a
    /// fresh config on first use.
    pub fn open(dir: Option<PathBuf>) -> Result<Self, String> {
        let dir = dir
            .or_else(|| std::env::var_os("CASSIS_HOME").map(PathBuf::from))
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cassis")))
            .ok_or("cannot locate a home directory; pass --home")?;
        std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        let config = WalletConfig::load_or_create(&dir)?;
        let keys = config.keys()?;
        let db = open_db(&dir)?;
        Ok(Self {
            dir,
            keys,
            config,
            db,
        })
    }

    pub fn mnemonic(&self) -> &str {
        &self.config.mnemonic
    }

    /// The networks in the config.
    pub fn networks(&self) -> Result<Vec<NetworkId>, String> {
        self.config.network_ids()
    }

    /// Add `network` to the config with a fresh key, if it is not there
    /// yet, and apply `change` to its table.
    pub fn enable(
        &mut self,
        network: &NetworkId,
        change: impl FnOnce(&mut toml_edit::Table) -> Result<(), String>,
    ) -> Result<(), String> {
        self.config = config::edit(&self.dir, |doc| {
            change(config::network_table(doc, network)?)
        })?;
        Ok(())
    }

    /// Remove `networks` from the config. Their keys go with them.
    pub fn disable(&mut self, networks: &[NetworkId]) -> Result<(), String> {
        self.config = config::edit(&self.dir, |doc| {
            if let Some(table) = doc.get_mut("networks").and_then(|n| n.as_table_mut()) {
                for network in networks {
                    table.remove(&network.0);
                }
            }
            Ok(())
        })?;
        Ok(())
    }

    fn network_config(&self, network: &NetworkId) -> Result<&NetworkConfig, String> {
        self.config.network(network)
    }

    /// Private directory of `network`: `<home>/<kind>/<variant>`.
    pub fn network_dir(&self, network: &NetworkId) -> PathBuf {
        cassis_networks::network_dir(&self.dir, network)
    }

    /// The wallet key on `network`, from the config.
    pub fn secret(&self, network: &NetworkId) -> Result<[u8; 32], String> {
        self.network_config(network)?.secret(network)
    }

    /// What opening `network` takes, as configured. `$CASSIS_ESPLORA_URL`
    /// stands in for an `esplora_url` the config does not set, as
    /// operators on chains without a public one (regtest) need.
    pub fn settings(&self, network: &NetworkId) -> Result<NetworkSettings, String> {
        let mut settings = self.network_config(network)?.settings(network, &self.dir)?;
        if settings.esplora_url.is_none() && matches!(network.kind(), "arkade" | "bitcoin") {
            settings.esplora_url = std::env::var("CASSIS_ESPLORA_URL").ok();
        }
        Ok(settings)
    }

    /// The bark wallet of `network`, which must go through an Ark server
    /// (`bark` in its config).
    #[cfg(feature = "bark-lightning")]
    pub async fn open_bark(
        &self,
        network: &NetworkId,
        span: &Span,
    ) -> Result<bark_lightning::BarkLightningAdapter, String> {
        let settings = self.settings(network)?;
        let config = settings.bark.ok_or_else(|| {
            format!("{network} goes through LND here: enable it with --bark to use bark")
        })?;
        let adapter = bark_lightning::BarkLightningAdapter::open(
            network.clone(),
            settings.secret,
            &settings.dir,
            &config,
            span,
        )
        .await?;
        routine_checks(&adapter).await;
        Ok(adapter)
    }

    /// The arkade wallet of `network`.
    #[cfg(feature = "arkade")]
    pub async fn open_arkade(
        &self,
        network: &NetworkId,
        span: &Span,
    ) -> Result<arkade::ArkadeAdapter, String> {
        let settings = self.settings(network)?;
        let adapter = arkade::ArkadeAdapter::open_with_esplora(
            network.clone(),
            settings.secret,
            &settings.dir,
            settings.esplora_url.as_deref(),
            span,
        )
        .await?;
        routine_checks(&adapter).await;
        Ok(adapter)
    }

    /// The cashu wallet of `network`.
    #[cfg(feature = "cashu")]
    pub fn open_cashu(
        &self,
        network: &NetworkId,
        span: &Span,
    ) -> Result<cashu::CashuAdapter, String> {
        let settings = self.settings(network)?;
        cashu::CashuAdapter::open(network.clone(), settings.secret, &settings.dir, span)
    }

    /// Open the adapter of `network`, if this binary was built with it,
    /// and run its [`routine_checks`].
    pub async fn open_network(
        &self,
        network: &NetworkId,
        span: &Span,
    ) -> Result<Arc<dyn Network>, String> {
        let opened = cassis_networks::open(network, &self.settings(network)?, span).await?;
        routine_checks(opened.as_ref()).await;
        Ok(opened)
    }

    pub async fn open_networks(
        &self,
        networks: &[NetworkId],
        span: &Span,
    ) -> Result<Vec<Arc<dyn Network>>, String> {
        let mut opened = Vec::with_capacity(networks.len());
        for network in networks {
            opened.push(
                self.open_network(network, span)
                    .await
                    .map_err(|e| format!("{network}: {e}"))?,
            );
        }
        Ok(opened)
    }
}

/// The upkeep a long-running node would do now and then (see
/// [`Network::maintain`]: settling arkade boarding deposits, refreshing
/// VTXOs before the operator may sweep them, syncing bark), done once
/// whenever the wallet opens `network`, before any command uses it. A
/// failure only warns: the command may still work.
pub async fn routine_checks(network: &dyn Network) {
    if let Err(error) = network.maintain().await {
        warn!("routine checks of {}: {error}", network.id());
    }
}
