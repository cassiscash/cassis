//! The networks a daemon has open, kept in step with its config while it
//! runs: [`Networks::sync`] opens what the config adds, closes what it
//! removes, and reopens what it changes. A network with payments in
//! flight is left as it is until they settle, since they need it to
//! claim or refund, and their tasks hold on to its wallet.
//!
//! For a daemon that only verifies payments on its networks; one that
//! keeps wallets on them has them kept by `hyperb-cassis-wallet` instead.

use crate::Refresh;
use cassis_core::keys::parse_wallet_mnemonic;
use cassis_core::{Network, NetworkId};
use cassis_networks::NetworkSettings;
use futures::future::BoxFuture;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
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
    /// Changes wait for this many payments in flight to settle.
    Waiting(usize),
}

/// What opening a network gives.
pub struct Opened {
    pub network: Arc<dyn Network>,
}

/// How a daemon opens a network from its config `C`.
pub trait Opener<C>: Send + Sync + 'static {
    fn open<'a>(
        &'a self,
        id: &'a NetworkId,
        config: &'a C,
    ) -> BoxFuture<'a, Result<Opened, String>>;
}

/// The daemon that uses the networks.
pub trait Daemon: Send + Sync + 'static {
    /// The payments in flight through `id`, which need it to settle.
    fn in_flight(&self, id: &NetworkId) -> usize;

    fn add_network(&self, network: Arc<dyn Network>);

    fn remove_network(&self, id: &NetworkId);
}

/// One network as the daemon has it.
pub struct Slot<C> {
    /// The config it was opened, or last tried, with.
    pub config: C,
    pub status: Status,
    network: Option<Arc<dyn Network>>,
    upkeep: Option<AbortHandle>,
}

pub struct Networks<C> {
    opener: Box<dyn Opener<C>>,
    span: Span,
    /// Whether to run the upkeep of the networks open.
    upkeep: bool,
    daemon: OnceLock<Arc<dyn Daemon>>,
    slots: Mutex<BTreeMap<String, Slot<C>>>,
    /// Held by the one [`Networks::sync`] running.
    syncing: tokio::sync::Mutex<()>,
}

impl<C: Clone + PartialEq + Send + Sync + 'static> Networks<C> {
    pub fn new(opener: impl Opener<C>, span: Span, upkeep: bool) -> Arc<Self> {
        Arc::new(Self {
            opener: Box::new(opener),
            span,
            upkeep,
            daemon: OnceLock::new(),
            slots: Default::default(),
            syncing: Default::default(),
        })
    }

    /// Open what `wanted` names before the daemon starts, returning the
    /// networks for it to resume its payments on. A network that does
    /// not open is left out, for the admin interface to fix and open
    /// later.
    pub async fn open_all(&self, wanted: &BTreeMap<String, C>) -> Vec<Arc<dyn Network>> {
        let mut networks = Vec::new();
        for (id, config) in wanted {
            let opened = match NetworkId::parse(id) {
                Ok(parsed) => self.opener.open(&parsed, config).await,
                Err(error) => Err(error),
            };
            let (status, network) = match opened {
                Ok(opened) => {
                    networks.push(opened.network.clone());
                    (Status::Open, Some(opened.network))
                }
                Err(error) => {
                    warn!("not opening {id}: {error}");
                    (Status::Failed(error), None)
                }
            };
            self.slots().insert(
                id.clone(),
                Slot {
                    config: config.clone(),
                    status,
                    network,
                    upkeep: None,
                },
            );
        }
        networks
    }

    /// Hand the networks to the daemon started with them.
    pub fn attach(&self, daemon: Arc<dyn Daemon>) {
        let _ = self.daemon.set(daemon);
        for slot in self.slots().values_mut() {
            if let Some(network) = slot.network.clone() {
                slot.upkeep = self.start_upkeep(network);
            }
        }
    }

    pub fn slots(&self) -> MutexGuard<'_, BTreeMap<String, Slot<C>>> {
        self.slots.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Whether a [`Networks::sync`] is running.
    pub fn syncing(&self) -> bool {
        self.syncing.try_lock().is_err()
    }

    /// The payments in flight through `id`.
    pub fn in_flight(&self, id: &str) -> usize {
        match (self.daemon.get(), NetworkId::parse(id)) {
            (Some(daemon), Ok(id)) => daemon.in_flight(&id),
            _ => 0,
        }
    }

    /// Open, close and reopen networks until they are as `wanted` says,
    /// reopening `retry` even if unchanged, and calling `progress` after
    /// each step. Networks that failed are tried again only when their
    /// config changes, or as `retry`. Whether any network opened or
    /// closed.
    pub async fn sync(
        &self,
        wanted: &BTreeMap<String, C>,
        retry: Option<&str>,
        progress: &(dyn Fn() + Sync),
    ) -> bool {
        let _syncing = self.syncing.lock().await;
        let mut changed = false;
        let gone: Vec<String> = self
            .slots()
            .keys()
            .filter(|id| !wanted.contains_key(*id))
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
                payments => self.wait(&id, payments),
            }
        }
        for (id, config) in wanted {
            let reopen = {
                let mut slots = self.slots();
                match slots.get_mut(id) {
                    None => false,
                    Some(slot) if slot.config != *config || retry == Some(id.as_str()) => {
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
                    payments => {
                        self.wait(id, payments);
                        continue;
                    }
                }
            }
            self.slots().insert(
                id.clone(),
                Slot {
                    config: config.clone(),
                    status: Status::Opening,
                    network: None,
                    upkeep: None,
                },
            );
            progress();
            let (status, network, upkeep) = match self.open(id, config, reopen).await {
                Ok(opened) => {
                    info!("opened {id}");
                    if let Some(daemon) = self.daemon.get() {
                        daemon.add_network(opened.network.clone());
                    }
                    let upkeep = self.start_upkeep(opened.network.clone());
                    (Status::Open, Some(opened.network), upkeep)
                }
                Err(error) => {
                    warn!("not opening {id}: {error}");
                    (Status::Failed(error), None, None)
                }
            };
            if let Some(slot) = self.slots().get_mut(id) {
                slot.status = status;
                slot.network = network;
                slot.upkeep = upkeep;
            }
            changed = true;
            progress();
        }
        changed
    }

    async fn open(&self, id: &str, config: &C, reopen: bool) -> Result<Opened, String> {
        let id = NetworkId::parse(id)?;
        let mut attempt = 1;
        loop {
            match self.opener.open(&id, config).await {
                Err(_) if reopen && attempt < REOPEN_ATTEMPTS => {
                    attempt += 1;
                    tokio::time::sleep(REOPEN_WAIT).await;
                }
                opened => return opened,
            }
        }
    }

    /// Stop using `id`: its upkeep, and the daemon's handle to it.
    fn close(&self, id: &str) {
        if let Some(slot) = self.slots().get_mut(id) {
            if let Some(upkeep) = slot.upkeep.take() {
                upkeep.abort();
            }
            slot.network = None;
        }
        if let (Some(daemon), Ok(id)) = (self.daemon.get(), NetworkId::parse(id)) {
            daemon.remove_network(&id);
        }
    }

    fn wait(&self, id: &str, payments: usize) {
        if let Some(slot) = self.slots().get_mut(id) {
            if slot.status != Status::Waiting(payments) {
                info!("{id}: changes wait for {payments} payment(s) in flight");
                slot.status = Status::Waiting(payments);
            }
        }
    }

    /// Run the upkeep of `network`, if asked to and it has any.
    fn start_upkeep(&self, network: Arc<dyn Network>) -> Option<AbortHandle> {
        if !self.upkeep {
            return None;
        }
        let interval = network.maintenance_interval()?;
        info!("maintaining {} every {}s", network.id(), interval.as_secs());
        Some(tokio::spawn(maintain(network).instrument(self.span.clone())).abort_handle())
    }

    /// [`Networks::sync`] in the background, bringing pages up to date
    /// as it goes, unless one is running and `retry` is none: it, or the
    /// next call, picks up what changed.
    pub fn sync_in_background(
        self: &Arc<Self>,
        wanted: BTreeMap<String, C>,
        retry: Option<String>,
        refresh: &Refresh,
    ) {
        if retry.is_none() && self.syncing() {
            return;
        }
        let networks = self.clone();
        let refresh = refresh.clone();
        tokio::spawn(async move {
            networks
                .sync(&wanted, retry.as_deref(), &|| refresh.now())
                .await;
        });
    }

    /// Check that `network.open` can reopen `id`, which `known` says the
    /// config has.
    pub fn can_reopen(&self, id: &NetworkId, known: bool) -> Result<(), String> {
        if !known {
            return Err(format!("{id} is not under [networks]"));
        }
        match self.in_flight(&id.0) {
            0 => Ok(()),
            payments => Err(format!(
                "{id} has {payments} payment(s) in flight: wait for them to settle"
            )),
        }
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

/// A network of a daemon that needs little to open one.
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    /// BIP39 mnemonic (12 or 24 words) of the wallet on this network,
    /// written when it is added.
    pub mnemonic: Option<String>,
    /// Chain API of `arkade` and `bitcoin`, instead of the public one.
    pub esplora_url: Option<String>,
}

impl NetworkConfig {
    /// What opening `id` takes, its wallet under `dir`.
    pub fn settings(&self, id: &NetworkId, dir: &Path) -> Result<NetworkSettings, String> {
        let words = self
            .mnemonic
            .as_deref()
            .ok_or_else(|| format!("networks.\"{id}\" has no mnemonic"))?;
        let mnemonic = parse_wallet_mnemonic(words).map_err(|e| format!("{id} mnemonic: {e}"))?;
        Ok(NetworkSettings {
            esplora_url: self.esplora_url.clone(),
            ..NetworkSettings::new(mnemonic, cassis_networks::network_dir(dir, id))
        })
    }
}
