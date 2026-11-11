//! The node's home directory:
//!
//! ```text
//! <home>/seed               12-word mnemonic every key derives from
//! <home>/store.db           invoices, payments, routed hops, settings
//! <home>/<kind>/<variant>/  private data of one network (wallets, ...)
//! ```

use cassis_core::keys::{generate_mnemonic, NodeKeys};
use cassis_core::store::Store;
use cassis_core::{Network, NetworkId};
#[cfg(feature = "arkade")]
use cassis_networks::arkade;
#[cfg(feature = "bark-lightning")]
use cassis_networks::bark_lightning;
#[cfg(feature = "cashu")]
use cassis_networks::cashu;
#[cfg(feature = "lightning")]
use cassis_networks::lnd;
use cassis_networks::NetworkSettings;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{warn, Span};

const SETTINGS: &str = "settings";
const NETWORKS: &str = "networks";
#[cfg(feature = "lightning")]
const LND: &str = "lnd";
#[cfg(feature = "bark-lightning")]
const BARK: &str = "bark";

pub struct Home {
    pub dir: PathBuf,
    pub keys: NodeKeys,
    pub store: Arc<Store>,
}

impl Home {
    /// Open `dir`, or `$CASSIS_HOME`, or `~/.cassis`, creating it and a
    /// fresh seed on first use.
    pub fn open(dir: Option<PathBuf>) -> Result<Self, String> {
        let dir = dir
            .or_else(|| std::env::var_os("CASSIS_HOME").map(PathBuf::from))
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cassis")))
            .ok_or("cannot locate a home directory; pass --home")?;
        std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        let keys =
            NodeKeys::from_mnemonic(&read_or_create_seed(&dir)?).map_err(|e| e.to_string())?;
        let store = Arc::new(Store::open(&dir.join("store.db"))?);
        Ok(Self { dir, keys, store })
    }

    pub fn mnemonic(&self) -> Result<String, String> {
        read_or_create_seed(&self.dir)
    }

    /// Networks this node participates in.
    pub fn networks(&self) -> Result<Vec<NetworkId>, String> {
        if let Some(networks) = self.store.get(SETTINGS, NETWORKS)? {
            return Ok(networks);
        }
        // Homes from before the store redesign kept them in a `meta`
        // table, one spec per line.
        let legacy = legacy_query(&self.dir, "SELECT value FROM meta WHERE key = 'networks';")
            .into_iter()
            .filter_map(|value| match value {
                minisqlite::Value::Text(text) => Some(text),
                _ => None,
            })
            .flat_map(|text| {
                text.lines()
                    .filter_map(|line| NetworkId::parse(line).ok())
                    .collect::<Vec<_>>()
            })
            .collect();
        Ok(legacy)
    }

    pub fn set_networks(&self, networks: &[NetworkId]) -> Result<(), String> {
        self.store.put(SETTINGS, NETWORKS, &networks)
    }

    /// Longest an HTLC received on `network` may run, when set by hand
    /// (see [`Network::max_incoming_lifetime_secs`]).
    pub fn max_incoming_lifetime(&self, network: &NetworkId) -> Result<Option<u64>, String> {
        self.store
            .get(SETTINGS, &format!("max_incoming_lifetime:{network}"))
    }

    pub fn set_max_incoming_lifetime(&self, network: &NetworkId, secs: u64) -> Result<(), String> {
        self.store
            .put(SETTINGS, &format!("max_incoming_lifetime:{network}"), &secs)
    }

    #[cfg(feature = "lightning")]
    pub fn lnd_config(&self) -> Result<Option<lnd::LndConfig>, String> {
        self.store.get(SETTINGS, LND)
    }

    #[cfg(feature = "lightning")]
    pub fn set_lnd_config(&self, config: &lnd::LndConfig) -> Result<(), String> {
        self.store.put(SETTINGS, LND, config)
    }

    /// The Ark server a `lightning` network goes through instead of LND,
    /// if any.
    #[cfg(feature = "bark-lightning")]
    pub fn bark_config(
        &self,
        network: &NetworkId,
    ) -> Result<Option<bark_lightning::BarkConfig>, String> {
        self.store.get(SETTINGS, &format!("{BARK}:{network}"))
    }

    #[cfg(feature = "bark-lightning")]
    pub fn set_bark_config(
        &self,
        network: &NetworkId,
        config: &bark_lightning::BarkConfig,
    ) -> Result<(), String> {
        self.store
            .put(SETTINGS, &format!("{BARK}:{network}"), config)
    }

    /// The bark wallet of `network`, which must have been enabled with
    /// `--bark`.
    #[cfg(feature = "bark-lightning")]
    pub async fn open_bark(
        &self,
        network: &NetworkId,
        span: &Span,
    ) -> Result<bark_lightning::BarkLightningAdapter, String> {
        let config = self.bark_config(network)?.ok_or_else(|| {
            format!("{network} goes through LND here: enable it with --bark to use bark")
        })?;
        let adapter = bark_lightning::BarkLightningAdapter::open(
            network.clone(),
            self.secret(network),
            &self.network_dir(network),
            &config,
            span,
        )
        .await?;
        routine_checks(&adapter).await;
        Ok(adapter)
    }

    /// Private directory of `network`: `<home>/<kind>/<variant>`.
    pub fn network_dir(&self, network: &NetworkId) -> PathBuf {
        cassis_networks::network_dir(&self.dir, network)
    }

    #[allow(dead_code)] // unused in lightning-only builds
    pub fn secret(&self, network: &NetworkId) -> [u8; 32] {
        self.keys.network_secret(network)
    }

    /// The arkade wallet of `network`. `$CASSIS_ESPLORA_URL` overrides
    /// the chain API, as operators on chains without a public one
    /// (regtest) need.
    #[cfg(feature = "arkade")]
    pub async fn open_arkade(
        &self,
        network: &NetworkId,
        span: &Span,
    ) -> Result<arkade::ArkadeAdapter, String> {
        let esplora = std::env::var("CASSIS_ESPLORA_URL").ok();
        let adapter = arkade::ArkadeAdapter::open_with_esplora(
            network.clone(),
            self.secret(network),
            &self.network_dir(network),
            esplora.as_deref(),
            span,
        )
        .await?;
        routine_checks(&adapter).await;
        Ok(adapter)
    }

    /// What opening `network` takes, as configured with `enable`.
    fn settings(&self, network: &NetworkId) -> Result<NetworkSettings, String> {
        Ok(NetworkSettings {
            secret: self.secret(network),
            dir: self.network_dir(network),
            max_incoming_lifetime_secs: self.max_incoming_lifetime(network)?,
            esplora_url: match network.kind() {
                "arkade" => std::env::var("CASSIS_ESPLORA_URL").ok(),
                _ => None,
            },
            #[cfg(feature = "lightning")]
            lnd: self.lnd_config()?,
            #[cfg(feature = "bark-lightning")]
            bark: self.bark_config(network)?,
        })
    }

    /// Open the adapter of `network`, if this binary was built with it,
    /// and run its [`routine_checks`].
    pub async fn open_network(
        &self,
        network: &NetworkId,
        span: &Span,
    ) -> Result<Arc<dyn Network>, String> {
        #[cfg(feature = "cashu")]
        if network.kind() == "cashu" && !self.network_dir(network).exists() {
            // Import the proofs an older home kept in its database.
            drop(self.open_cashu(network, span)?);
        }
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

    /// The cashu wallet of `network`, importing proofs an older home
    /// kept in its database.
    #[cfg(feature = "cashu")]
    pub fn open_cashu(
        &self,
        network: &NetworkId,
        span: &Span,
    ) -> Result<cashu::CashuAdapter, String> {
        let dir = self.network_dir(network);
        let fresh = !dir.exists();
        let adapter = cashu::CashuAdapter::open(network.clone(), self.secret(network), &dir, span)?;
        if fresh {
            let proofs: Vec<cashu::Proof> = legacy_query(
                &self.dir,
                &format!(
                    "SELECT proof_blob FROM cashu_proofs WHERE mint_url = '{}';",
                    adapter.mint_url().replace('\'', "''")
                ),
            )
            .into_iter()
            .filter_map(|value| match value {
                minisqlite::Value::Blob(blob) => serde_json::from_slice(&blob).ok(),
                _ => None,
            })
            .collect();
            if !proofs.is_empty() {
                adapter.import_proofs(&proofs)?;
                eprintln!("imported {} proof(s) from the old store", proofs.len());
            }
        }
        Ok(adapter)
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

fn read_or_create_seed(home: &Path) -> Result<String, String> {
    let path = home.join("seed");
    if !path.exists() {
        use std::io::Write;
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options
            .open(&path)
            .map_err(|e| format!("create {}: {e}", path.display()))?;
        writeln!(file, "{}", generate_mnemonic()).map_err(|e| e.to_string())?;
        eprintln!(
            "generated a new seed at {}; back it up, it controls every key of this node",
            path.display()
        );
    }
    std::fs::read_to_string(&path)
        .map(|seed| seed.trim().to_string())
        .map_err(|e| format!("read {}: {e}", path.display()))
}

/// First column of `sql` against the store as older versions laid it
/// out; empty when there is no such table.
fn legacy_query(home: &Path, sql: &str) -> Vec<minisqlite::Value> {
    let Ok(mut connection) = minisqlite::Connection::open(&home.join("store.db")) else {
        return Vec::new();
    };
    connection
        .query(sql)
        .map(|result| {
            result
                .rows
                .into_iter()
                .filter_map(|row| row.into_iter().next())
                .collect()
        })
        .unwrap_or_default()
}
