//! The networks the daemon has open, kept in step with the config while
//! it runs: [`Networks::sync`] opens what the config adds, closes what
//! it removes, and reopens what it changes. A network with hops in
//! flight is left as it is until they settle, since they need it to
//! claim or refund, and their tasks hold on to its wallet.

use crate::config::{Config, NetworkConfig};
use cassis_core::keys::NodeKeys;
use cassis_core::node::{HopState, Node};
use cassis_core::{Network, NetworkId};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use tokio::task::AbortHandle;
use tracing::{info, warn, Instrument, Span};

/// Attempts at reopening a network, whose previous wallet may take a
/// moment to let go of its files.
const REOPEN_ATTEMPTS: u32 = 3;
const REOPEN_WAIT: Duration = Duration::from_secs(1);

#[derive(Clone, Debug, PartialEq)]
pub enum Status {
    Opening,
    Open,
    Failed(String),
    /// Changes wait for this many hops in flight to settle.
    Waiting(usize),
}

/// One network as the daemon has it.
pub struct Slot {
    /// The config it was opened, or last tried, with.
    pub config: NetworkConfig,
    pub status: Status,
    upkeep: Option<AbortHandle>,
}

pub struct Networks {
    node: Node,
    keys: NodeKeys,
    dir: PathBuf,
    span: Span,
    slots: Mutex<BTreeMap<String, Slot>>,
    /// Held by the one [`Networks::sync`] running.
    syncing: tokio::sync::Mutex<()>,
}

/// Open `id` as `config` says, its wallet under `dir`.
pub async fn open(
    config: &Config,
    id: &NetworkId,
    keys: &NodeKeys,
    dir: &std::path::Path,
    span: &Span,
) -> Result<Arc<dyn Network>, String> {
    let settings = config.network_settings(id, keys, dir)?;
    cassis_networks::open(id, &settings, span)
        .await
        .map_err(|e| e.to_string())
}

impl Networks {
    /// Take over the networks opened on start, `node`'s, and the ones
    /// that failed to.
    pub fn new(
        node: Node,
        keys: NodeKeys,
        dir: PathBuf,
        span: Span,
        config: &Config,
        failed: BTreeMap<String, String>,
    ) -> Arc<Self> {
        let networks = Arc::new(Self {
            node,
            keys,
            dir,
            span,
            slots: Default::default(),
            syncing: Default::default(),
        });
        for (id, network_config) in &config.networks {
            let (status, upkeep) = match failed.get(id) {
                Some(error) => (Status::Failed(error.clone()), None),
                None => match NetworkId::parse(id).and_then(|id| networks.node.network(&id)) {
                    Ok(network) => (Status::Open, networks.upkeep(network)),
                    Err(error) => (Status::Failed(error), None),
                },
            };
            networks.slots().insert(
                id.clone(),
                Slot {
                    config: network_config.clone(),
                    status,
                    upkeep,
                },
            );
        }
        networks
    }

    pub fn slots(&self) -> MutexGuard<'_, BTreeMap<String, Slot>> {
        self.slots.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Whether a [`Networks::sync`] is running.
    pub fn syncing(&self) -> bool {
        self.syncing.try_lock().is_err()
    }

    /// The hops in flight through `id`, which need it to settle.
    pub fn in_flight(&self, id: &str) -> usize {
        self.node
            .hops()
            .unwrap_or_default()
            .iter()
            .filter(|hop| {
                matches!(
                    hop.state,
                    HopState::Verifying | HopState::Funding | HopState::Forwarded
                ) && (hop.prepare.incoming_network.0 == id || hop.prepare.outgoing_network.0 == id)
            })
            .count()
    }

    /// Open, close and reopen networks until they are as `config` says,
    /// reopening `retry` even if unchanged, and calling `progress` after
    /// each step. Networks that failed are tried again only when their
    /// config changes, or as `retry`. Whether any network opened or
    /// closed.
    pub async fn sync(
        &self,
        config: &Config,
        retry: Option<&str>,
        progress: &(dyn Fn() + Sync),
    ) -> bool {
        let _syncing = self.syncing.lock().await;
        let mut changed = false;
        let gone: Vec<String> = self
            .slots()
            .keys()
            .filter(|id| !config.networks.contains_key(*id))
            .cloned()
            .collect();
        for id in gone {
            match self.in_flight(&id) {
                0 => {
                    self.close(&id);
                    self.slots().remove(&id);
                    info!("closed {id}");
                    changed = true;
                }
                hops => self.wait(&id, hops),
            }
        }
        for (id, wanted) in &config.networks {
            let reopen = {
                let mut slots = self.slots();
                match slots.get_mut(id) {
                    None => false,
                    Some(slot) if slot.config != *wanted || retry == Some(id.as_str()) => {
                        matches!(slot.status, Status::Open | Status::Waiting(_))
                    }
                    Some(slot) => {
                        // Changed back while waiting: nothing to wait for.
                        if matches!(slot.status, Status::Waiting(_)) {
                            slot.status = Status::Open;
                        }
                        continue;
                    }
                }
            };
            if reopen {
                match self.in_flight(id) {
                    0 => self.close(id),
                    hops => {
                        self.wait(id, hops);
                        continue;
                    }
                }
            }
            self.slots().insert(
                id.clone(),
                Slot {
                    config: wanted.clone(),
                    status: Status::Opening,
                    upkeep: None,
                },
            );
            progress();
            let (status, upkeep) = match self.open(config, id, reopen).await {
                Ok(network) => {
                    info!("opened {id}");
                    self.node.add_network(network.clone());
                    (Status::Open, self.upkeep(network))
                }
                Err(error) => {
                    warn!("not opening {id}: {error}");
                    (Status::Failed(error), None)
                }
            };
            if let Some(slot) = self.slots().get_mut(id) {
                slot.status = status;
                slot.upkeep = upkeep;
            }
            changed = true;
            progress();
        }
        changed
    }

    async fn open(
        &self,
        config: &Config,
        id: &str,
        reopen: bool,
    ) -> Result<Arc<dyn Network>, String> {
        let id = NetworkId::parse(id)?;
        let mut attempt = 1;
        loop {
            match open(config, &id, &self.keys, &self.dir, &self.span).await {
                Err(_) if reopen && attempt < REOPEN_ATTEMPTS => {
                    attempt += 1;
                    tokio::time::sleep(REOPEN_WAIT).await;
                }
                opened => return opened,
            }
        }
    }

    /// Stop using `id`: its upkeep, and the node's handle to it.
    fn close(&self, id: &str) {
        if let Some(upkeep) = self.slots().get_mut(id).and_then(|slot| slot.upkeep.take()) {
            upkeep.abort();
        }
        if let Ok(id) = NetworkId::parse(id) {
            self.node.remove_network(&id);
        }
    }

    fn wait(&self, id: &str, hops: usize) {
        if let Some(slot) = self.slots().get_mut(id) {
            if slot.status != Status::Waiting(hops) {
                info!("{id}: changes wait for {hops} hop(s) in flight");
                slot.status = Status::Waiting(hops);
            }
        }
    }

    /// Run the upkeep of `network`, if it has any.
    fn upkeep(&self, network: Arc<dyn Network>) -> Option<AbortHandle> {
        let interval = network.maintenance_interval()?;
        info!("maintaining {} every {}s", network.id(), interval.as_secs());
        Some(tokio::spawn(maintain(network).instrument(self.span.clone())).abort_handle())
    }
}

/// Run the upkeep of `network` now and then every
/// [`Network::maintenance_interval`], which may change as the wallet
/// learns about its network.
async fn maintain(network: Arc<dyn Network>) {
    loop {
        if let Err(error) = network.maintain().await {
            warn!("maintaining {}: {error}", network.id());
        }
        let Some(interval) = network.maintenance_interval() else {
            return;
        };
        tokio::time::sleep(interval.max(Duration::from_secs(1))).await;
    }
}
