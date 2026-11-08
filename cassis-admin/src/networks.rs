//! The networks a daemon has open, kept in step with its config while it
//! runs: [`Networks::sync`] opens what the config adds, closes what it
//! removes, and reopens what it changes. A network with payments in
//! flight is left as it is until they settle, since they need it to
//! claim or refund, and their tasks hold on to its wallet.
//!
//! Also here is what their pages share: the form adding a network
//! ([`new_network`]) and its card ([`network_card`]), and for daemons
//! whose networks are just a [`NetworkConfig`], its actions
//! ([`Networks::act`]):
//!
//! | action           | payload                                                 |
//! | ---------------- | ------------------------------------------------------- |
//! | `network.add`    | `kind`, `chain`, `mint`, `invite`, `esplora_url`        |
//! | `network.set`    | `id`, `esplora_url`                                     |
//! | `network.remove` | `id`                                                    |
//! | `network.open`   | `id`                                                    |

use crate::config::{child, implicit_table, put_text, ConfigFile, DaemonConfig};
use crate::view::{act, field, options, quote, short_hash, submit};
use crate::wallets::Wallets;
use crate::{Args, Refresh};
use cassis_core::keys::NodeKeys;
use cassis_core::{Network, NetworkId};
use cassis_networks::{NetworkSettings, Wallet};
use futures::future::BoxFuture;
use hypereffect::vtree::{badge, button, card, column, divider, notice, row, select, text, Node};
use hypereffect::{cel, json, Handler, Map, Value};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::Duration;
use tokio::task::AbortHandle;
use toml_edit::{DocumentMut, Item};
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
    /// Its wallet, for a daemon that moves funds on it.
    pub wallet: Option<Wallet>,
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
    /// The wallets of the networks open.
    pub wallets: Arc<Wallets>,
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
            wallets: Default::default(),
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
                    if let Some(wallet) = opened.wallet {
                        self.wallets.insert(id.clone(), wallet);
                    }
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
                    if let Some(wallet) = opened.wallet {
                        self.wallets.insert(id.clone(), wallet);
                    }
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
        self.wallets.remove(id);
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
    /// Chain API of `arkade` and `bitcoin`, instead of the public one.
    pub esplora_url: Option<String>,
}

impl NetworkConfig {
    /// What opening `id` takes, with `keys`, its wallet under `dir`.
    pub fn settings(&self, id: &NetworkId, keys: &NodeKeys, dir: &Path) -> NetworkSettings {
        NetworkSettings {
            secret: keys.network_secret(id),
            dir: cassis_networks::network_dir(dir, id),
            esplora_url: self.esplora_url.clone(),
            ..Default::default()
        }
    }

    /// The fields of its form.
    pub fn values(&self) -> Value {
        json!({"esplora_url": self.esplora_url.clone().unwrap_or_default()})
    }
}

impl Networks<NetworkConfig> {
    /// Do what the `network.*` action `name` says on `file`, whose
    /// networks `wanted` gives, of the `kinds` this daemon takes.
    pub fn act<T: DaemonConfig>(
        self: &Arc<Self>,
        name: &str,
        args: &Args,
        file: &ConfigFile<T>,
        wanted: fn(&T) -> &BTreeMap<String, NetworkConfig>,
        kinds: &[Kind],
        refresh: &Refresh,
    ) -> Result<String, String> {
        let network = || NetworkId::parse(&args.required("id")?);
        let (message, retry) = match name {
            "network.add" => {
                let id = new_network_id(args, kinds)?;
                file.edit(|doc| {
                    if has_network(doc, &id) {
                        return Err(format!("{id} is added already"));
                    }
                    set_network(doc, &id, args)
                })?;
                (format!("{id} added, opening it"), None)
            }
            "network.set" => {
                let id = network()?;
                file.edit(|doc| set_network(doc, &id, args))?;
                (format!("{id} saved"), None)
            }
            "network.remove" => {
                let id = network()?;
                file.edit(|doc| remove_network(doc, &id))?;
                (format!("{id} removed"), None)
            }
            "network.open" => {
                let id = network()?;
                self.can_reopen(&id, wanted(&file.get()).contains_key(&id.0))?;
                (format!("Opening {id}"), Some(id.0))
            }
            other => return Err(format!("unknown action {other}")),
        };
        self.sync_in_background(wanted(&file.get()).clone(), retry, refresh);
        Ok(message)
    }
}

fn has_network(doc: &DocumentMut, id: &NetworkId) -> bool {
    doc.get("networks")
        .and_then(Item::as_table_like)
        .is_some_and(|networks| networks.contains_key(&id.0))
}

/// Adds `id` if missing. Fields: `esplora_url`.
fn set_network(doc: &mut DocumentMut, id: &NetworkId, args: &Args) -> Result<(), String> {
    let networks = child(doc.as_table_mut(), "networks", implicit_table)?;
    let network = child(networks, &id.0, toml_edit::table)?;
    put_text(network, "esplora_url", args.text("esplora_url")?);
    Ok(())
}

fn remove_network(doc: &mut DocumentMut, id: &NetworkId) -> Result<(), String> {
    doc.get_mut("networks")
        .and_then(Item::as_table_like_mut)
        .and_then(|networks| networks.remove(&id.0))
        .map(|_| ())
        .ok_or_else(|| format!("{id} is not under [networks]"))
}

/// A kind of network to add: its name in `network.add`, and its label.
pub type Kind = (&'static str, &'static str);

/// Every kind of network.
pub const ALL_KINDS: [Kind; 8] = [
    ("arkade", "Arkade"),
    ("cashu", "Cashu"),
    ("liquid", "Liquid"),
    ("lnd", "Lightning (LND)"),
    ("bark", "Lightning (bark)"),
    ("fedimint", "Fedimint"),
    ("bitcoin", "Bitcoin"),
    ("rootstock", "Rootstock"),
];

/// The kinds of network a gateway or a preimage server is on: those a
/// payee can be paid on while offline.
pub const OFFLINE_KINDS: [Kind; 6] = [
    ("arkade", "Arkade"),
    ("cashu", "Cashu"),
    ("liquid", "Liquid"),
    ("fedimint", "Fedimint"),
    ("bitcoin", "Bitcoin"),
    ("rootstock", "Rootstock"),
];

/// The chains a kind runs on, the first its default.
pub fn chains(kind: &str) -> &'static [&'static str] {
    match kind {
        "arkade" => &["mainnet", "mutinynet"],
        "bitcoin" => &["mainnet", "mutinynet", "regtest"],
        "liquid" | "rootstock" => &["mainnet", "testnet"],
        "lnd" | "bark" => &["mainnet", "signet", "mutinynet", "regtest"],
        _ => &[],
    }
}

/// The id of the network a `network.add` describes: `kind`, one of
/// `kinds`, then `chain` (one of its [`chains`]), `mint` (a cashu mint's
/// URL) or `invite` (a fedimint invite code).
pub fn new_network_id(args: &Args, kinds: &[Kind]) -> Result<NetworkId, String> {
    let kind = args.required("kind")?;
    let (_, label) = kinds
        .iter()
        .find(|(name, _)| *name == kind)
        .ok_or_else(|| {
            let names: Vec<&str> = kinds.iter().map(|(name, _)| *name).collect();
            format!("kind {kind}: expected one of {}", names.join(", "))
        })?;
    if !cassis_networks::built(&kind) {
        return Err(format!("this build has no {label} support"));
    }
    let spec = match kind.as_str() {
        "cashu" => {
            let mint = args.required("mint")?;
            let host = mint
                .strip_prefix("https://")
                .or_else(|| mint.strip_prefix("http://"))
                .unwrap_or(&mint)
                .trim_end_matches('/');
            format!("cashu::{host}")
        }
        "fedimint" => format!("fedimint::{}", args.required("invite")?),
        kind => {
            let chains = chains(kind);
            let chain = args.text("chain")?.filter(|chain| !chain.is_empty());
            let chain = chain.as_deref().unwrap_or(chains[0]);
            if !chains.contains(&chain) {
                return Err(format!(
                    "{label} runs on {}, not {chain}",
                    chains.join(", ")
                ));
            }
            let kind = if matches!(kind, "lnd" | "bark") {
                "lightning"
            } else {
                kind
            };
            match chain {
                "mainnet" => kind.to_string(),
                chain => format!("{kind}::{chain}"),
            }
        }
    };
    NetworkId::parse(&spec)
}

/// The signal path segment of the draft of a network's form.
pub fn network_draft(id: &str) -> String {
    format!("n_{}", short_hash(id))
}

/// The draft of [`new_network`], empty.
pub fn new_network_draft() -> (String, Value) {
    (
        "new_network".into(),
        json!({
            "kind": "",
            "chain": "",
            "mint": "",
            "invite": "",
            "esplora_url": "",
            "lnd_rest_url": "",
            "lnd_tls_cert_path": "",
            "lnd_macaroon_path": "",
            "bark_server_url": "",
            "bark_esplora_url": "",
        }),
    )
}

/// The picker of a network's kind, among `kinds`, then what that kind
/// needs.
pub fn new_network(kinds: &[Kind]) -> Node {
    let kind_is = |kind: &str| format!("s.d.new_network.kind == {}", quote(kind));
    let picker = kinds.iter().map(|(kind, label)| {
        let chain = chains(kind).first().copied().unwrap_or_default();
        button(format!("network/new/kind/{kind}"))
            .label(*label)
            .variant(cel(format!("{} ? 'primary' : 'secondary'", kind_is(kind))))
            .disabled(!cassis_networks::built(kind))
            .on_press(Handler::patch(
                json!({"d": {"new_network": {"kind": kind, "chain": chain}}}),
            ))
    });
    let missing = kinds
        .iter()
        .any(|(kind, _)| !cassis_networks::built(kind))
        .then(|| {
            text("network/new/missing")
                .variant("caption")
                .text("Greyed out: not compiled into this build.")
        });
    let details = kinds.iter().map(|(kind, _)| {
        let el = |part: &str| format!("network/new/{kind}/{part}");
        let d = |field: &str| format!("d.new_network.{field}");
        let chains = chains(kind);
        let chain = (!chains.is_empty()).then(|| {
            select(el("chain"))
                .label("Chain")
                .variant("segmented")
                .bind(d("chain"))
                .options(options(
                    chains.iter().map(|chain| (*chain, chain_label(chain))),
                ))
        });
        let fields: Vec<Node> = match *kind {
            "cashu" => {
                vec![field(el("mint"), "Mint URL", &d("mint")).placeholder("https://mint.example")]
            }
            "fedimint" => {
                vec![field(el("invite"), "Invite code", &d("invite")).placeholder("fed1…")]
            }
            "arkade" | "bitcoin" => {
                vec![field(el("esplora_url"), "Esplora URL", &d("esplora_url"))
                    .placeholder("the public one")]
            }
            "lnd" => lnd_fields(&el, &d),
            "bark" => bark_fields(&el, &d),
            _ => Vec::new(),
        };
        column(format!("network/new/{kind}"))
            .visible(cel(kind_is(kind)))
            .children(chain)
            .children(fields)
    });
    card("network/new")
        .title("Add a network")
        .child(row("network/new/kinds").wrap(true).children(picker))
        .children(missing)
        .children(details)
        .child(submit(
            "network/new/add",
            "Add",
            "network.add",
            json!({"draft": "new_network"}),
            "s.d.new_network.kind == '' \
             || (s.d.new_network.kind == 'cashu' && s.d.new_network.mint.trim() == '') \
             || (s.d.new_network.kind == 'fedimint' && s.d.new_network.invite.trim() == '')",
        ))
}

fn chain_label(chain: &str) -> &str {
    match chain {
        "mainnet" => "Mainnet",
        "mutinynet" => "Mutinynet",
        "signet" => "Signet",
        "testnet" => "Testnet",
        "regtest" => "Regtest",
        other => other,
    }
}

/// The inputs of an LND node, under element ids from `el` and signal
/// paths from `d`.
pub fn lnd_fields(el: &dyn Fn(&str) -> String, d: &dyn Fn(&str) -> String) -> Vec<Node> {
    vec![
        field(el("lnd_rest_url"), "LND REST URL", &d("lnd_rest_url"))
            .placeholder("https://127.0.0.1:8080"),
        field(
            el("lnd_tls_cert_path"),
            "TLS certificate",
            &d("lnd_tls_cert_path"),
        )
        .placeholder("/path/to/tls.cert"),
        field(el("lnd_macaroon_path"), "Macaroon", &d("lnd_macaroon_path"))
            .placeholder("/path/to/admin.macaroon"),
    ]
}

/// The inputs of an Ark server for bark, like [`lnd_fields`].
pub fn bark_fields(el: &dyn Fn(&str) -> String, d: &dyn Fn(&str) -> String) -> Vec<Node> {
    vec![
        field(el("bark_server_url"), "Ark server", &d("bark_server_url"))
            .placeholder("Second's server"),
        field(
            el("bark_esplora_url"),
            "Esplora URL",
            &d("bark_esplora_url"),
        )
        .placeholder("the default one"),
    ]
}

/// The card of the network `id`.
pub struct NetworkCard<'a> {
    pub id: &'a str,
    /// Its status, if the daemon has it yet.
    pub status: Option<&'a Status>,
    /// Whether it runs with the config asked for.
    pub applied: bool,
    /// What its payments in flight are called: `hop`, `payment`.
    pub unit: &'a str,
    /// The inputs of its form, whose draft is [`network_draft`].
    pub fields: Vec<Node>,
    pub wallet: Vec<Node>,
}

pub fn network_card(network: NetworkCard) -> Node {
    let NetworkCard {
        id,
        status,
        applied,
        unit,
        fields,
        wallet,
    } = network;
    let el = |part: &str| format!("network/{id}/{part}");
    let (variant, status_text) = match status {
        None | Some(Status::Opening) => ("info", "opening…".to_string()),
        Some(Status::Open) if !applied => ("info", "applying changes…".to_string()),
        Some(Status::Open) => ("success", "open".to_string()),
        Some(Status::Failed(error)) => ("failure", format!("failed to open: {error}")),
        Some(Status::Waiting(count)) => (
            "warning",
            format!("open, changes apply once its {count} {unit}(s) in flight settle"),
        ),
    };
    let reopen = match status {
        Some(Status::Failed(_)) => Some("Retry"),
        Some(Status::Open) => Some("Reopen"),
        _ => None,
    }
    .map(|label| act(el("open"), label, "network.open", json!({"id": id})));
    let save = (!fields.is_empty()).then(|| {
        submit(
            el("save"),
            "Save",
            "network.set",
            json!({"draft": network_draft(id), "id": id}),
            "false",
        )
    });
    let settings = (!fields.is_empty()).then(|| divider(el("divider")));
    card(format!("network/{id}"))
        .title(id)
        .child(badge(el("status")).variant(variant).text(status_text))
        .children(wallet)
        .children(settings)
        .children(fields)
        .child(row(el("actions")).children(save).children(reopen).child(
            act(el("remove"), "Remove", "network.remove", json!({"id": id})).variant("failure"),
        ))
}

/// The inputs of a [`NetworkConfig`] of the network `id`.
pub fn config_fields(id: &str) -> Vec<Node> {
    let kind = id.split_once("::").map_or(id, |(kind, _)| kind);
    match kind {
        "arkade" | "bitcoin" => vec![field(
            format!("network/{id}/esplora_url"),
            "Esplora URL",
            &format!("d.{}.esplora_url", network_draft(id)),
        )
        .placeholder("the public one")],
        _ => Vec::new(),
    }
}

/// The cards of a daemon's [`NetworkConfig`]s, as it has them, showing
/// their wallets if they have any at unix time `now`, then the networks
/// removed from them that are still open for the payments through them.
pub fn config_cards(
    networks: &Networks<NetworkConfig>,
    wanted: &BTreeMap<String, NetworkConfig>,
    unit: &str,
    now: u64,
) -> (Vec<Node>, Vec<Node>) {
    let slots = networks.slots();
    let cards = wanted
        .iter()
        .map(|(id, config)| {
            let slot = slots.get(id);
            let wallet = networks
                .wallets
                .get(id)
                .map(|(can, funds)| crate::wallets::view(now, id, &can, &funds))
                .unwrap_or_default();
            network_card(NetworkCard {
                id,
                status: slot.map(|slot| &slot.status),
                applied: slot.is_some_and(|slot| slot.config == *config),
                unit,
                fields: config_fields(id),
                wallet,
            })
        })
        .collect();
    let closing = slots
        .iter()
        .filter_map(|(id, slot)| {
            let Status::Waiting(count) = &slot.status else {
                return None;
            };
            (!wanted.contains_key(id)).then(|| closing_notice(id, *count, unit))
        })
        .collect();
    (closing, cards)
}

/// Says the network `id`, removed from the config, is still open.
pub fn closing_notice(id: &str, count: usize, unit: &str) -> Node {
    notice(format!("network/{id}/closing"))
        .variant("warning")
        .text(format!(
            "{id} closes once its {count} {unit}(s) in flight settle."
        ))
}

/// The drafts of a daemon's [`NetworkConfig`]s, with their wallets' if
/// `wallets`.
pub fn config_drafts(
    wanted: &BTreeMap<String, NetworkConfig>,
    wallets: bool,
) -> Map<String, Value> {
    let mut drafts = Map::new();
    for (id, config) in wanted {
        drafts.insert(network_draft(id), config.values());
        if wallets {
            drafts.extend(crate::wallets::drafts(id));
        }
    }
    drafts
}
