//! A [hyperb](https://github.com/hypereffect/hyperb) interface to manage
//! Cassis wallets, to put in the admin page of any server that has them.
//!
//! [`WalletAdmin`] keeps the networks listed in a config file (see
//! [`config`]) open, one wallet each, on any network `cassis-networks`
//! supports (one cargo feature per network, as in `cassis-wallet`). The
//! page it draws ([`WalletAdmin::view`]) adds networks to the file,
//! removes them and edits them; and for each open one shows its balances,
//! its deposit addresses and its internals, and moves funds in and out as
//! far as the wallet can (see [`cassis_networks::Can`]): send, take out
//! as a token, redeem, onboard, create and pay Lightning invoices, make
//! deposit addresses.
//!
//! The host brings the transport and the session: it keeps its own
//! hypereffect page, and
//!
//! 1. opens the wallets before it starts what uses them
//!    ([`WalletAdmin::open`], which gives the networks to use) and then
//!    hands them its [`Host`] ([`WalletAdmin::attach`]), so networks
//!    opened and closed later reach it;
//! 2. per session, sends [`WalletAdmin::signals`] (the forms' drafts),
//!    draws [`WalletAdmin::view`] somewhere in its page, and passes each
//!    action to [`WalletAdmin::act`], sending the patch it returns;
//! 3. draws the page again whenever [`WalletAdmin::updates`] fires, and
//!    holds [`WalletAdmin::watch`] while a session is open, so balances
//!    are kept fresh only then.
//!
//! Actions are named `wallet.*` and `network.*`, and each carries in its
//! payload what it acts on, so they can be sent from anywhere, like API
//! calls:
//!
//! | action                   | payload                                  |
//! | ------------------------ | ---------------------------------------- |
//! | `network.add`            | `draft`: `new_network`                   |
//! | `network.set`            | `id`, `draft`                            |
//! | `network.open`           | `id`                                     |
//! | `network.disable`        | `id` (closes it, keeping its mnemonic)   |
//! | `network.enable`         | `id`                                     |
//! | `network.remove`         | `id` (asks to confirm)                   |
//! | `network.remove.confirm` | `id`                                     |
//! | `network.remove.cancel`  | `id`                                     |
//! | `network.reveal`         | `id` (shows the mnemonic)              |
//! | `network.hide`           | `id`                                     |
//! | `wallet.refresh`         | `id`                                     |
//! | `wallet.address`         | `id`                                     |
//! | `wallet.deposit`         | `id`                                     |
//! | `wallet.invoice`         | `id`, `amount_sat`                       |
//! | `wallet.redeem`          | `id`, `token`                            |
//! | `wallet.onboard`         | `id`                                     |
//! | `wallet.send`            | `id`, `to`, `amount_sat`                 |
//! | `wallet.pay`             | `id`, `invoice`                          |
//! | `wallet.issue`           | `id`, `amount_sat`                       |
//! | `wallet.dismiss`         | `id`                                     |
//!
//! A `draft` names a form's signal, `hw.<draft>`, whose fields are the
//! rest of the payload. What an action did is shown in the page, as a
//! notice.

mod args;
pub mod config;
mod view;

use args::Args;
use cassis_core::{Network, NetworkId, unix_now};
use cassis_networks::{Address, Balance, Can, Op, Wallet};
pub use config::{ConfigFile, Entry};
use hypereffect::vtree::Node;
use hypereffect::{Action, Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::Duration;
use tokio::sync::broadcast;
use tokio::task::AbortHandle;
use tracing::{Instrument, Span, info, warn};

/// How often the balances of the wallets are read while a page is open.
const FUNDS_INTERVAL: u64 = 60;
/// How often the config file is looked at again, and changes applied.
const SYNC_INTERVAL: Duration = Duration::from_secs(5);
/// Attempts at reopening a network, whose previous wallet may take a
/// moment to let go of its files.
const REOPEN_ATTEMPTS: u32 = 3;
const REOPEN_WAIT: Duration = Duration::from_secs(1);

/// What uses the networks of the wallets.
pub trait Host: Send + Sync + 'static {
    /// A network was opened, after [`WalletAdmin::attach`].
    fn opened(&self, network: Arc<dyn Network>);

    /// A network was closed: forget it.
    fn closed(&self, id: &NetworkId);

    /// The payments in flight through `id`, which need it to settle:
    /// until they have, it is not closed or reopened.
    fn in_flight(&self, _id: &NetworkId) -> usize {
        0
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Status {
    Opening,
    Open,
    Failed(String),
    /// Changes wait for this many payments in flight to settle.
    Waiting(usize),
    /// Not opened, as the config file says.
    Disabled,
}

/// What is known of a network's wallet.
#[derive(Clone, Default)]
pub(crate) struct Funds {
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

pub(crate) struct Slot {
    /// The config it was opened, or last tried, with.
    pub entry: Entry,
    pub status: Status,
    network: Option<Arc<dyn Network>>,
    pub wallet: Option<Wallet>,
    upkeep: Option<AbortHandle>,
    pub funds: Funds,
    /// Whether its key is shown.
    pub reveal: bool,
    /// Whether removing it waits for the operator to confirm.
    pub confirm_remove: bool,
}

impl Slot {
    pub(crate) fn new(entry: Entry, status: Status) -> Self {
        Self {
            entry,
            status,
            network: None,
            wallet: None,
            upkeep: None,
            funds: Funds::default(),
            reveal: false,
            confirm_remove: false,
        }
    }
}

#[derive(Default)]
pub(crate) struct State {
    pub slots: BTreeMap<String, Slot>,
    /// The networks the config file has, as last read.
    pub wanted: BTreeMap<String, Entry>,
    /// Why the config file could not be read.
    pub config_error: Option<String>,
    /// What the last action did.
    pub result: Option<Result<String, String>>,
    /// The kinds of network the page adds.
    pub kinds: Vec<config::Kind>,
}

/// What an action leaves for the host to do.
pub struct Handled {
    /// A patch to the signals, to send.
    pub patch: Option<Value>,
}

/// The drafts a session has been sent.
#[derive(Default)]
pub struct Drafts(BTreeSet<String>);

/// Keeps the balances fresh while held.
pub struct Watching(Arc<WalletAdmin>);

impl Drop for Watching {
    fn drop(&mut self) {
        self.0.watchers.fetch_sub(1, Ordering::Relaxed);
    }
}

pub struct WalletAdmin {
    file: ConfigFile,
    /// Where the wallets keep their files.
    dir: PathBuf,
    span: Span,
    host: OnceLock<Arc<dyn Host>>,
    state: Mutex<State>,
    /// Held by the one [`WalletAdmin::reconcile`] running.
    syncing: tokio::sync::Mutex<()>,
    changed: broadcast::Sender<()>,
    watchers: AtomicUsize,
}

impl WalletAdmin {
    /// Open the networks of `file`, their wallets kept under `dir`
    /// (`<dir>/<kind>/<variant>`), returning them for the host to use. A
    /// network that does not open is left out, for the page to fix and
    /// open later. Fails if the file cannot be read.
    pub async fn open(
        file: ConfigFile,
        dir: impl Into<PathBuf>,
        span: Span,
    ) -> Result<(Arc<Self>, Vec<Arc<dyn Network>>), String> {
        let admin = Arc::new(Self {
            file,
            dir: dir.into(),
            span,
            host: OnceLock::new(),
            state: Mutex::new(State {
                kinds: config::KINDS.to_vec(),
                ..State::default()
            }),
            syncing: Default::default(),
            changed: broadcast::channel(16).0,
            watchers: AtomicUsize::new(0),
        });
        let networks = admin.reconcile(None).await?;
        Ok((admin, networks))
    }

    /// Hand the host the networks opened from now on, and start keeping
    /// them as the config file says.
    pub fn attach(self: &Arc<Self>, host: Arc<dyn Host>) {
        let _ = self.host.set(host);
        let admin = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(SYNC_INTERVAL).await;
                let _ = admin.reconcile(None).await;
                if admin.watchers.load(Ordering::Relaxed) > 0 {
                    for id in admin.stale(FUNDS_INTERVAL) {
                        admin.read_in_background(id, false);
                    }
                }
            }
        });
    }

    /// Add only networks of these `kinds` (names of [`config::KINDS`]),
    /// instead of every kind.
    pub fn offer(&self, kinds: &[&str]) {
        self.state().kinds = config::KINDS
            .into_iter()
            .filter(|(kind, _)| kinds.contains(kind))
            .collect();
        self.notify();
    }

    /// Fires when the page is out of date.
    pub fn updates(&self) -> broadcast::Receiver<()> {
        self.changed.subscribe()
    }

    /// Hold this while a session is open.
    pub fn watch(self: &Arc<Self>) -> Watching {
        self.watchers.fetch_add(1, Ordering::Relaxed);
        Watching(self.clone())
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn notify(&self) {
        let _ = self.changed.send(());
    }

    /// The drafts of the forms a session has not been sent yet, as a
    /// patch to its signals, to send before [`WalletAdmin::view`]
    /// is drawn.
    pub fn signals(&self, known: &mut Drafts) -> Option<Value> {
        let mut drafts = hypereffect::Map::new();
        let mut add = |name: String, value: Value| {
            if known.0.insert(name.clone()) {
                drafts.insert(name, value);
            }
        };
        let (name, value) = view::new_network_draft();
        add(name, value);
        for (id, entry) in &self.state().wanted {
            add(view::network_draft(id), view::entry_draft(entry));
            for (name, value) in view::wallet_drafts(id) {
                add(name, value);
            }
        }
        (!drafts.is_empty()).then(|| json!({"hw": drafts}))
    }

    /// The page: what to put in a tab of the host's.
    pub fn view(&self) -> Vec<Node> {
        view::page(
            unix_now(),
            &self.state(),
            self.file.path().display().to_string(),
        )
    }

    /// Do what `action` says, if it is for the wallets: `None` if not.
    pub fn act(self: &Arc<Self>, action: &Action) -> Option<Handled> {
        let name = action.name.as_str();
        if !(name.starts_with("wallet.") || name.starts_with("network.")) {
            return None;
        }
        let result = self.dispatch(name, &Args::of(action));
        let mut patch = None;
        match &result {
            Ok(message) => {
                info!("wallets: {message}");
                // A form that added something is emptied for the next one.
                if name == "network.add" {
                    let (draft, value) = view::new_network_draft();
                    patch = Some(json!({"hw": {draft: value}}));
                }
            }
            Err(error) => warn!("wallets: {name}: {error}"),
        }
        self.state().result = Some(result);
        self.notify();
        Some(Handled { patch })
    }

    fn dispatch(self: &Arc<Self>, name: &str, args: &Args) -> Result<String, String> {
        let id = || NetworkId::parse(&args.required("id")?);
        let amount = || args.sats("amount_sat");
        match name {
            "network.add" => {
                let kind = args.text("kind");
                if !self.state().kinds.iter().any(|(name, _)| *name == kind) {
                    return Err(format!("{kind:?} networks are not added here"));
                }
                let id = config::network_id(
                    &args.text("kind"),
                    &args.text("chain"),
                    &args.text("mint"),
                    &args.text("invite"),
                )?;
                if self.file.read()?.contains_key(&id.0) {
                    return Err(format!("{id} is added already"));
                }
                let fields = view::fields(args);
                let kind = args.text("kind");
                self.file
                    .edit(|networks| config::set(networks, &id, &fields, Some(&kind)))?;
                self.reconcile_in_background(None);
                Ok(format!("{id} added, opening it"))
            }
            "network.set" => {
                let id = id()?;
                let fields = view::fields(args);
                self.file.edit(|networks| {
                    if !networks.contains_key(&id.0) {
                        return Err(format!("{id} is not in the config file"));
                    }
                    config::set(networks, &id, &fields, None)
                })?;
                self.reconcile_in_background(None);
                Ok(format!("{id} saved"))
            }
            "network.open" => {
                let id = id()?;
                match self.state().wanted.get(&id.0) {
                    None => return Err(format!("{id} is not in the config file")),
                    Some(entry) if entry.disabled => return Err(format!("{id} is disabled")),
                    Some(_) => {}
                }
                self.reconcile_in_background(Some(id.0.clone()));
                Ok(format!("Opening {id}"))
            }
            "network.disable" | "network.enable" => {
                let id = id()?;
                let disabled = name == "network.disable";
                self.file
                    .edit(|networks| config::set_disabled(networks, &id, disabled))?;
                self.reconcile_in_background(None);
                Ok(match disabled {
                    true => format!("{id} disabled, closing it"),
                    false => format!("{id} enabled, opening it"),
                })
            }
            "network.remove" => {
                let id = id()?;
                self.slot(&id.0, |slot| slot.confirm_remove = true)?;
                Ok(format!("Confirm to remove {id}"))
            }
            "network.remove.cancel" => {
                let id = id()?;
                self.slot(&id.0, |slot| slot.confirm_remove = false)?;
                Ok(format!("{id} stays"))
            }
            "network.remove.confirm" => {
                let id = id()?;
                self.file.edit(|networks| config::remove(networks, &id))?;
                self.reconcile_in_background(None);
                Ok(format!("{id} removed, with its mnemonic"))
            }
            "network.reveal" | "network.hide" => {
                let id = id()?;
                self.slot(&id.0, |slot| slot.reveal = name == "network.reveal")?;
                Ok(String::new())
            }
            "wallet.refresh" | "wallet.address" => {
                let id = id()?;
                if self.wallet(&id.0).is_none() {
                    return Err(format!("{id} is not open"));
                }
                self.read_in_background(id.0.clone(), name == "wallet.address");
                Ok(match name {
                    "wallet.address" => format!("Asking {id} for new addresses"),
                    _ => format!("Reading the wallet of {id}"),
                })
            }
            "wallet.send" => self.op(
                id()?,
                "Sending",
                Op::Send {
                    to: args.required("to")?,
                    amount_sat: amount()?,
                },
            ),
            "wallet.issue" => self.op(
                id()?,
                "Taking funds out",
                Op::Issue {
                    amount_sat: amount()?,
                },
            ),
            "wallet.redeem" => self.op(
                id()?,
                "Redeeming",
                Op::Redeem {
                    token: args.required("token")?,
                },
            ),
            "wallet.onboard" => self.op(id()?, "Onboarding", Op::Onboard),
            "wallet.invoice" => self.op(
                id()?,
                "Creating an invoice",
                Op::Invoice {
                    amount_sat: amount()?,
                },
            ),
            "wallet.pay" => self.op(
                id()?,
                "Paying",
                Op::Pay {
                    invoice: args.required("invoice")?,
                },
            ),
            "wallet.deposit" => self.op(id()?, "Creating a deposit address", Op::Deposit),
            "wallet.dismiss" => {
                let id = id()?;
                self.slot(&id.0, |slot| {
                    slot.funds.output = None;
                    slot.funds.outcome = None;
                })?;
                Ok(format!("{id}: dismissed"))
            }
            other => Err(format!("unknown action {other}")),
        }
    }

    fn slot(&self, id: &str, change: impl FnOnce(&mut Slot)) -> Result<(), String> {
        let mut state = self.state();
        let slot = state
            .slots
            .get_mut(id)
            .ok_or_else(|| format!("{id} is not open"))?;
        change(slot);
        Ok(())
    }

    fn wallet(&self, id: &str) -> Option<Wallet> {
        self.state().slots.get(id)?.wallet.clone()
    }

    // keeping the networks as the config file says

    fn in_flight(&self, id: &str) -> usize {
        match (self.host.get(), NetworkId::parse(id)) {
            (Some(host), Ok(id)) => host.in_flight(&id),
            _ => 0,
        }
    }

    fn reconcile_in_background(self: &Arc<Self>, retry: Option<String>) {
        let admin = self.clone();
        tokio::spawn(async move {
            let _ = admin.reconcile(retry.as_deref()).await;
        });
    }

    /// Open, close and reopen networks until they are as the config file
    /// says, reopening `retry` even if unchanged. A network that failed
    /// is tried again only when its entry changes, or as `retry`. The
    /// networks opened, which the host has already if it is attached.
    async fn reconcile(
        self: &Arc<Self>,
        retry: Option<&str>,
    ) -> Result<Vec<Arc<dyn Network>>, String> {
        let _syncing = self.syncing.lock().await;
        let wanted = match self.file.read() {
            Ok(wanted) => wanted,
            Err(error) => {
                let changed =
                    self.state().config_error.replace(error.clone()) != Some(error.clone());
                if changed {
                    self.notify();
                }
                return Err(error);
            }
        };
        let before = {
            let mut state = self.state();
            state.config_error = None;
            std::mem::replace(&mut state.wanted, wanted.clone())
        };
        let mut opened = Vec::new();
        let mut changed = before != wanted;

        let gone: Vec<String> = self
            .state()
            .slots
            .keys()
            .filter(|id| !wanted.contains_key(*id))
            .cloned()
            .collect();
        for id in gone {
            match self.in_flight(&id) {
                0 => {
                    self.close(&id);
                    self.state().slots.remove(&id);
                    info!("closed {id}");
                }
                payments => self.wait(&id, payments),
            }
            changed = true;
        }

        for (id, entry) in &wanted {
            if entry.disabled {
                changed |= self.disable(id, entry);
                continue;
            }
            let reopen = {
                let mut state = self.state();
                match state.slots.get_mut(id) {
                    None => false,
                    Some(slot) if slot.entry != *entry || retry == Some(id.as_str()) => {
                        matches!(slot.status, Status::Open | Status::Waiting(_))
                    }
                    Some(slot) => {
                        // Changed back while waiting: nothing to wait for.
                        if matches!(slot.status, Status::Waiting(_)) {
                            slot.status = Status::Open;
                            changed = true;
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
                        changed = true;
                        continue;
                    }
                }
            }
            self.state()
                .slots
                .insert(id.clone(), Slot::new(entry.clone(), Status::Opening));
            self.notify();
            match self.open_one(id, entry, reopen).await {
                Ok((network, wallet)) => {
                    info!("opened {id}");
                    // What a long-running node does now and then, once
                    // before anything uses the wallet.
                    if let Err(error) = network.maintain().await {
                        warn!("routine checks of {id}: {error}");
                    }
                    let upkeep = self.start_upkeep(network.clone());
                    if let Some(slot) = self.state().slots.get_mut(id) {
                        slot.status = Status::Open;
                        slot.network = Some(network.clone());
                        slot.wallet = Some(wallet);
                        slot.upkeep = upkeep;
                    }
                    if let Some(host) = self.host.get() {
                        host.opened(network.clone());
                    }
                    opened.push(network);
                    self.read_in_background(id.clone(), true);
                }
                Err(error) => {
                    warn!("not opening {id}: {error}");
                    if let Some(slot) = self.state().slots.get_mut(id) {
                        slot.status = Status::Failed(error);
                    }
                }
            }
            changed = true;
            self.notify();
        }
        if changed {
            self.notify();
        }
        Ok(opened)
    }

    async fn open_one(
        &self,
        id: &str,
        entry: &Entry,
        reopen: bool,
    ) -> Result<(Arc<dyn Network>, Wallet), String> {
        let id = NetworkId::parse(id)?;
        let settings = entry.settings(&id, &self.dir)?;
        let mut attempt = 1;
        loop {
            match cassis_networks::open_wallet(&id, &settings, &self.span).await {
                Err(_) if reopen && attempt < REOPEN_ATTEMPTS => {
                    attempt += 1;
                    tokio::time::sleep(REOPEN_WAIT).await;
                }
                opened => return opened,
            }
        }
    }

    /// Stop using `id`: its upkeep, its wallet and the host's handle to it.
    fn close(&self, id: &str) {
        if let Some(slot) = self.state().slots.get_mut(id) {
            if let Some(upkeep) = slot.upkeep.take() {
                upkeep.abort();
            }
            slot.network = None;
            slot.wallet = None;
        }
        if let (Some(host), Ok(id)) = (self.host.get(), NetworkId::parse(id)) {
            host.closed(&id);
        }
    }

    /// Keep `id` closed, as disabled with `entry`, closing it once
    /// nothing is in flight through it. Whether anything changed.
    fn disable(&self, id: &str, entry: &Entry) -> bool {
        let open = match self.state().slots.get(id) {
            Some(slot) if slot.status == Status::Disabled && slot.entry == *entry => return false,
            Some(slot) => slot.network.is_some(),
            None => false,
        };
        if open {
            match self.in_flight(id) {
                0 => {
                    self.close(id);
                    info!("closed {id}, disabled");
                }
                payments => {
                    self.wait(id, payments);
                    return true;
                }
            }
        }
        let mut state = self.state();
        match state.slots.get_mut(id) {
            Some(slot) => {
                slot.entry = entry.clone();
                slot.status = Status::Disabled;
                slot.funds = Funds::default();
            }
            None => {
                state
                    .slots
                    .insert(id.to_string(), Slot::new(entry.clone(), Status::Disabled));
            }
        }
        true
    }

    fn wait(&self, id: &str, payments: usize) {
        if let Some(slot) = self.state().slots.get_mut(id)
            && slot.status != Status::Waiting(payments)
        {
            info!("{id}: changes wait for {payments} payment(s) in flight");
            slot.status = Status::Waiting(payments);
        }
    }

    /// Run the upkeep of `network` every [`Network::maintenance_interval`],
    /// if it has any.
    fn start_upkeep(&self, network: Arc<dyn Network>) -> Option<AbortHandle> {
        network.maintenance_interval()?;
        let task = async move {
            // May change as the wallet learns about its network.
            while let Some(interval) = network.maintenance_interval() {
                tokio::time::sleep(interval.max(Duration::from_secs(1))).await;
                if let Err(error) = network.maintain().await {
                    warn!("maintaining {}: {error}", network.id());
                }
            }
        };
        Some(tokio::spawn(task.instrument(self.span.clone())).abort_handle())
    }

    // funds

    /// The wallets whose balances were never read, or not for `max_age`
    /// seconds.
    fn stale(&self, max_age: u64) -> Vec<String> {
        let now = unix_now();
        self.state()
            .slots
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

    fn read_in_background(self: &Arc<Self>, id: String, addresses: bool) {
        let admin = self.clone();
        tokio::spawn(async move { admin.read_funds(&id, addresses).await });
    }

    /// Read the balances of `id`'s wallet, and its addresses when asked
    /// or not read yet.
    async fn read_funds(&self, id: &str, addresses: bool) {
        let (wallet, addresses) = {
            let mut state = self.state();
            let Some(slot) = state.slots.get_mut(id) else {
                return;
            };
            let Some(wallet) = slot.wallet.clone() else {
                return;
            };
            if slot.funds.reading {
                return;
            }
            slot.funds.reading = true;
            let addresses = addresses || !matches!(slot.funds.addresses, Some(Ok(_)));
            (wallet, addresses)
        };
        self.notify();
        let balances = wallet.balances().await;
        let addresses = match addresses {
            true => Some(wallet.addresses().await),
            false => None,
        };
        if let Some(slot) = self.state().slots.get_mut(id) {
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
        self.notify();
    }

    /// Run `op` on the wallet of `id` in the background, saying it is
    /// `doing` it, unless it is busy.
    fn op(self: &Arc<Self>, id: NetworkId, doing: &'static str, op: Op) -> Result<String, String> {
        let wallet = {
            let mut state = self.state();
            let slot = state
                .slots
                .get_mut(&id.0)
                .ok_or_else(|| format!("{id} is not open"))?;
            let wallet = slot
                .wallet
                .clone()
                .ok_or_else(|| format!("{id} is not open"))?;
            if let Some(busy) = slot.funds.busy {
                return Err(format!("{id} is busy: {busy}"));
            }
            slot.funds.busy = Some(doing);
            wallet
        };
        let admin = self.clone();
        let network = id.0.clone();
        tokio::spawn(async move { admin.run(&network, wallet, op).await });
        Ok(format!("{id}: {doing}…"))
    }

    /// Run `op` on `wallet`, and on what it then waits for, keeping what
    /// it did and reading the funds again after.
    async fn run(&self, id: &str, wallet: Wallet, op: Op) {
        let done = wallet.run(op).await;
        let then = {
            let mut state = self.state();
            let Some(funds) = state.slots.get_mut(id).map(|slot| &mut slot.funds) else {
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
        self.notify();
        self.read_funds(id, false).await;
        let Some(then) = then else {
            return;
        };
        let result = then.await;
        if let Some(funds) = self.state().slots.get_mut(id).map(|slot| &mut slot.funds) {
            funds.waiting = funds.waiting.saturating_sub(1);
            match &result {
                Ok(message) => info!("{id}: {message}"),
                Err(error) => warn!("{id}: {error}"),
            }
            funds.outcome = Some(result);
        }
        self.notify();
        self.read_funds(id, false).await;
    }
}

/// What a wallet can do, in words.
pub(crate) fn abilities(can: &Can) -> Vec<String> {
    let mut abilities = Vec::new();
    if let Some(to) = can.send {
        abilities.push(format!("send to: {to}"));
    }
    if let Some(issue) = can.issue {
        abilities.push(format!("take out as: {issue}"));
    }
    if let Some(redeem) = can.redeem {
        abilities.push(format!("redeem: {redeem}"));
    }
    if can.onboard {
        abilities.push("onboard deposits".into());
    }
    if can.lightning {
        abilities.push("Lightning invoices, created and paid".into());
    }
    if let Some(deposit) = can.deposit {
        abilities.push(format!("deposit with: {deposit}"));
    }
    if can.new_addresses {
        abilities.push("new deposit addresses".into());
    }
    abilities
}
