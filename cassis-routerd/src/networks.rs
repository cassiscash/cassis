//! The networks the daemon has open, kept in step with the config while
//! it runs: [`Networks::sync`] opens what the config adds, closes what
//! it removes, and reopens what it changes. A network with hops in
//! flight is left as it is until they settle, since they need it to
//! claim or refund, and their tasks hold on to its wallet.
//!
//! Each open network also has its [`Wallet`], whose [`Funds`] are read
//! now and then and moved in and out with [`Networks::run`].

use crate::config::{Config, NetworkConfig};
use cassis_core::keys::NodeKeys;
use cassis_core::node::{HopState, Node};
use cassis_core::{unix_now, Network, NetworkId};
use cassis_networks::{Address, Balance, Op, Wallet};
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
    /// Its wallet, while open.
    pub wallet: Option<Wallet>,
    pub funds: Funds,
}

/// What is known of a network's wallet, for the admin interface.
#[derive(Clone, Default)]
pub struct Funds {
    /// As last read.
    pub balances: Option<Result<Vec<Balance>, String>>,
    /// When the balances were last read, in unix seconds.
    pub read_at: Option<u64>,
    pub reading: bool,
    pub addresses: Option<Result<Vec<Address>, String>>,
    /// The operation running, if any.
    pub busy: Option<&'static str>,
    /// Payments and deposits waited for.
    pub waiting: usize,
    /// What the last operation did.
    pub outcome: Option<Result<String, String>>,
    /// What an operation handed out, until dismissed: a token is money.
    pub output: Option<Address>,
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
) -> Result<(Arc<dyn Network>, Wallet), String> {
    let settings = config.network_settings(id, keys, dir)?;
    cassis_networks::open_wallet(id, &settings, span).await
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
        mut wallets: BTreeMap<String, Wallet>,
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
                    wallet: wallets.remove(id),
                    funds: Funds::default(),
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
                    wallet: None,
                    funds: Funds::default(),
                },
            );
            progress();
            let (status, upkeep, wallet) = match self.open(config, id, reopen).await {
                Ok((network, wallet)) => {
                    info!("opened {id}");
                    self.node.add_network(network.clone());
                    (Status::Open, self.upkeep(network), Some(wallet))
                }
                Err(error) => {
                    warn!("not opening {id}: {error}");
                    (Status::Failed(error), None, None)
                }
            };
            if let Some(slot) = self.slots().get_mut(id) {
                slot.status = status;
                slot.upkeep = upkeep;
                slot.wallet = wallet;
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
    ) -> Result<(Arc<dyn Network>, Wallet), String> {
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
        if let Some(slot) = self.slots().get_mut(id) {
            if let Some(upkeep) = slot.upkeep.take() {
                upkeep.abort();
            }
            slot.wallet = None;
        }
        if let Ok(id) = NetworkId::parse(id) {
            self.node.remove_network(&id);
        }
    }

    /// Whether `id` is open, with its wallet.
    pub fn has_wallet(&self, id: &str) -> bool {
        self.slots()
            .get(id)
            .is_some_and(|slot| slot.wallet.is_some())
    }

    /// The networks whose balances were never read, or not for `max_age`
    /// seconds.
    pub fn stale_funds(&self, max_age: u64) -> Vec<String> {
        let now = unix_now();
        self.slots()
            .iter()
            .filter(|(_, slot)| {
                slot.wallet.is_some()
                    && !slot.funds.reading
                    && slot
                        .funds
                        .read_at
                        .is_none_or(|at| now.saturating_sub(at) >= max_age)
            })
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Read the balances of `id`'s wallet, and its addresses when asked
    /// or not read yet, calling `progress` after.
    pub async fn read_funds(&self, id: &str, addresses: bool, progress: &(dyn Fn() + Sync)) {
        let wallet = {
            let mut slots = self.slots();
            let Some(slot) = slots.get_mut(id) else {
                return;
            };
            let Some(wallet) = slot.wallet.clone() else {
                return;
            };
            if slot.funds.reading {
                return;
            }
            slot.funds.reading = true;
            wallet
        };
        let addresses = addresses
            || !matches!(
                self.slots()
                    .get(id)
                    .and_then(|slot| slot.funds.addresses.as_ref()),
                Some(Ok(_))
            );
        let balances = wallet.balances().await;
        let addresses = match addresses {
            true => Some(wallet.addresses().await),
            false => None,
        };
        if let Some(slot) = self.slots().get_mut(id) {
            if let Err(error) = &balances {
                warn!("reading the wallet of {id}: {error}");
            }
            slot.funds.balances = Some(balances);
            slot.funds.read_at = Some(unix_now());
            slot.funds.reading = false;
            if addresses.is_some() {
                slot.funds.addresses = addresses;
            }
        }
        progress();
    }

    /// Start `op` on `id`'s wallet, saying it is `doing` it, unless it
    /// is busy. The wallet to run it on with [`Networks::run`].
    pub fn start(&self, id: &str, doing: &'static str) -> Result<Wallet, String> {
        let mut slots = self.slots();
        let slot = slots
            .get_mut(id)
            .ok_or_else(|| format!("{id} is not open"))?;
        let wallet = slot
            .wallet
            .clone()
            .ok_or_else(|| format!("{id} is not open"))?;
        if let Some(busy) = slot.funds.busy {
            return Err(format!("{id} is busy: {busy}"));
        }
        slot.funds.busy = Some(doing);
        Ok(wallet)
    }

    /// Run `op` on `wallet`, `id`'s from [`Networks::start`], and on
    /// what it then waits for, keeping what it did and reading the funds
    /// again after, calling `progress` after each step.
    pub async fn run(&self, id: &str, wallet: Wallet, op: Op, progress: &(dyn Fn() + Sync)) {
        let done = wallet.run(op).await;
        let then = {
            let mut slots = self.slots();
            let Some(funds) = slots.get_mut(id).map(|slot| &mut slot.funds) else {
                return;
            };
            funds.busy = None;
            match done {
                Ok(done) => {
                    info!("{id}: {}", done.message);
                    funds.outcome = Some(Ok(done.message));
                    if done.output.is_some() {
                        funds.output = done.output;
                    }
                    if done.then.is_some() {
                        funds.waiting += 1;
                    }
                    done.then
                }
                Err(error) => {
                    warn!("{id}: {error}");
                    funds.outcome = Some(Err(error));
                    None
                }
            }
        };
        self.read_funds(id, false, progress).await;
        let Some(then) = then else {
            return;
        };
        let result = then.await;
        if let Some(funds) = self.slots().get_mut(id).map(|slot| &mut slot.funds) {
            funds.waiting = funds.waiting.saturating_sub(1);
            match &result {
                Ok(message) => info!("{id}: {message}"),
                Err(error) => warn!("{id}: {error}"),
            }
            funds.outcome = Some(result);
        }
        self.read_funds(id, false, progress).await;
    }

    /// Forget what `id`'s wallet handed out.
    pub fn dismiss(&self, id: &str) {
        if let Some(slot) = self.slots().get_mut(id) {
            slot.funds.output = None;
            slot.funds.outcome = None;
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
