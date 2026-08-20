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
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::Span;

const SETTINGS: &str = "settings";
const NETWORKS: &str = "networks";
#[cfg(feature = "lightning")]
const LND: &str = "lnd";

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

    #[cfg(feature = "lightning")]
    pub fn lnd_config(&self) -> Result<Option<cassis_lnd::LndConfig>, String> {
        self.store.get(SETTINGS, LND)
    }

    #[cfg(feature = "lightning")]
    pub fn set_lnd_config(&self, config: &cassis_lnd::LndConfig) -> Result<(), String> {
        self.store.put(SETTINGS, LND, config)
    }

    #[allow(dead_code)] // unused when no compiled-in network keeps files
    /// Private directory of `network`: `<home>/<kind>/<variant>`.
    pub fn network_dir(&self, network: &NetworkId) -> PathBuf {
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
        self.dir.join(network.kind()).join(variant)
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
    ) -> Result<cassis_arkade::ArkadeAdapter, String> {
        let esplora = std::env::var("CASSIS_ESPLORA_URL").ok();
        cassis_arkade::ArkadeAdapter::open_with_esplora(
            network.clone(),
            self.secret(network),
            esplora.as_deref(),
            span,
        )
        .await
    }

    /// Open the adapter of `network`, if this binary was built with it.
    pub async fn open_network(
        &self,
        network: &NetworkId,
        span: &Span,
    ) -> Result<Arc<dyn Network>, String> {
        let opened: Arc<dyn Network> = match network.kind() {
            #[cfg(feature = "cashu")]
            "cashu" => Arc::new(self.open_cashu(network, span)?),
            #[cfg(feature = "liquid")]
            "liquid" => Arc::new(
                cassis_liquid::LiquidAdapter::open(
                    network.clone(),
                    self.secret(network),
                    &self.network_dir(network),
                    span,
                )
                .await?,
            ),
            #[cfg(feature = "bitcoin")]
            "bitcoin" => Arc::new(cassis_bitcoin::BitcoinAdapter::open(
                network.clone(),
                self.secret(network),
                span,
            )?),
            #[cfg(feature = "arkade")]
            "arkade" => Arc::new(self.open_arkade(network, span).await?),
            #[cfg(feature = "rootstock")]
            "rootstock" => Arc::new(cassis_rootstock::RootstockAdapter::open(
                network.clone(),
                self.secret(network),
                span,
            )?),
            #[cfg(feature = "fedimint")]
            "fedimint" => Arc::new(
                cassis_fedimint::FedimintAdapter::open(
                    network.clone(),
                    self.secret(network),
                    &self.network_dir(network),
                    span,
                )
                .await?,
            ),
            #[cfg(feature = "lightning")]
            "lightning" => {
                let config = self.lnd_config()?.ok_or(
                    "lightning needs an LND node: cassis-cli enable lightning --lnd-rest-url ...",
                )?;
                Arc::new(cassis_lnd::LndAdapter::open(network.clone(), config, span).await?)
            }
            kind => {
                return Err(format!(
                    "this cassis-cli was built without the '{kind}' feature"
                ))
            }
        };
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
    ) -> Result<cassis_cashu::CashuAdapter, String> {
        let dir = self.network_dir(network);
        let fresh = !dir.exists();
        let adapter =
            cassis_cashu::CashuAdapter::open(network.clone(), self.secret(network), &dir, span)?;
        if fresh {
            let proofs: Vec<cassis_cashu::Proof> = legacy_query(
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
