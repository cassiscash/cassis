//! The router's admin interface: a hypereffect app over the config
//! file, for [hyperb](https://github.com/hypereffect/hyperb) renderers.
//! It is served open over HTTP on loopback ([`http`]), and over iroh
//! ([`iroh`]) to the renderers listed in `admin.peers`, or to the first
//! one opening the pairing link printed on the console, which is then
//! replaced by a new one.
//!
//! The page is a [`view`] of the config and of what the daemon runs,
//! sent as a diff after each change. Every element that does something
//! has an id naming what it acts on (`route/<from>/<to>/save`), and its
//! action carries in its payload what it acts on, so actions can be
//! sent from anywhere, like API calls (`hypb action <address> <name>
//! --payload <json>`):
//!
//! | action                | payload                                                   |
//! | --------------------- | --------------------------------------------------------- |
//! | `settings.set`        | `name`, `nostr_relays`, `max_reservations`                |
//! | `admin.set`           | `listen`, `iroh`                                          |
//! | `network.add`         | `kind` (`arkade`, `cashu`, `liquid`, `lnd`, `bark`, `fedimint`, `bitcoin`, `rootstock`), `chain`, `mint`, `invite`, and the fields of `network.set` but `id` and `backend` |
//! | `network.set`         | `id`, `esplora_url`, `backend` (`lnd`, `bark`, `none`), `lnd_rest_url`, `lnd_tls_cert_path`, `lnd_macaroon_path`, `bark_server_url`, `bark_esplora_url` |
//! | `network.remove`      | `id`                                                      |
//! | `network.open`        | `id`                                                      |
//! | `route.set`           | `from`, `to`, `fee_base_msat`, `fee_ppm`, `transit_slack_secs`, `max_incoming_lifetime_secs`, `test_money` |
//! | `route.remove`        | `from`, `to`                                              |
//! | `routes.announce`     |                                                           |
//! | `announcements.check` |                                                           |
//! | `peer.add`            | `key`                                                     |
//! | `peer.remove`         | `key`                                                     |
//! | `pairing.rotate`      |                                                           |
//! | `daemon.restart`      |                                                           |
//!
//! `*.set` actions add what they name if it is missing, and change only
//! the fields given (see [`edit::Args`]); a form's payload names its
//! `draft` instead of the fields it edits. Config changes are written
//! right away and apply at once: routes are announced again, and
//! networks opened, closed or reopened in the background (see
//! [`Networks`]); only the admin section waits for a restart. The outcome of an action is the
//! `result` notice of the page of the session that sent it; announcing
//! and checking the relays run in the background, and show in the
//! announcements card of the Routes tab.

mod edit;
mod http;
mod icon;
mod iroh;
mod view;

use crate::config::{self, AdminConfig, Config};
use crate::networks::Networks;
use cassis_core::node::Node;
use cassis_core::routing::{autohue, autoname, fetch_published, Published};
use cassis_core::store::Store;
use cassis_core::{unix_now, NetworkId};
use edit::Args;
use hypereffect::vtree;
use hypereffect::{json, Action, Map, Metadata, RendererMessage, ServerMessage, Value};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, SystemTime};
use tokio::sync::{mpsc, Notify};
use toml_edit::DocumentMut;
use tracing::{info, warn};

/// How often open pages are brought up to date with the hops and the
/// config file.
const REFRESH_INTERVAL: Duration = Duration::from_secs(5);
/// How long after start the relays are first checked, leaving time for
/// the first announcement.
const FIRST_CHECK_DELAY: Duration = Duration::from_secs(20);
/// How often the relays are checked for this router's announcements.
const CHECK_INTERVAL: Duration = Duration::from_secs(10 * 60);

/// Who a session is.
#[derive(Clone, Debug, PartialEq)]
pub enum Access {
    /// Over HTTP on loopback.
    Local,
    /// Over iroh, with the renderer's key.
    Peer(String),
}

pub struct Admin {
    dir: PathBuf,
    node: Node,
    networks: Arc<Networks>,
    store: Arc<Store>,
    /// The admin section served, which changes apply to on restart.
    serving: AdminConfig,
    state: Mutex<State>,
    nostr: Mutex<Nostr>,
    sessions: Mutex<Vec<Arc<Session>>>,
    restart: Notify,
    http_url: OnceLock<String>,
    iroh_id: OnceLock<String>,
}

struct State {
    config: Config,
    /// When the config file was last read or written.
    modified: Option<SystemTime>,
    /// The drafts of the config as every session has them.
    drafts: Map<String, Value>,
    /// The secret of the pairing link.
    pairing: String,
}

/// What the relays keep of this router's announcements.
#[derive(Default)]
pub struct Nostr {
    /// What the background job is doing, if anything.
    pub busy: Option<&'static str>,
    /// Whether to run the job again when done, and to announce first.
    queued: Option<bool>,
    /// The name last published as the router's profile, if any was
    /// since start.
    published_name: Option<Option<String>>,
    /// When the relays were last checked, in unix seconds.
    pub checked_at: Option<u64>,
    /// The router's announcements by relay, as last checked.
    pub found: BTreeMap<String, Result<Vec<Published>, String>>,
}

pub struct Session {
    access: Access,
    out: mpsc::UnboundedSender<String>,
    shown: Mutex<Shown>,
}

#[derive(Default)]
struct Shown {
    /// The name in the metadata last sent.
    name: String,
    tree: Vec<vtree::Node>,
    /// The outcome of the session's last action.
    flash: Option<Result<String, String>>,
}

impl Session {
    fn send(&self, lines: String) {
        if !lines.is_empty() {
            let _ = self.out.send(lines);
        }
    }

    fn signal(&self, patch: Value) {
        self.send(ServerMessage::signal(patch).to_line());
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

impl Admin {
    pub fn new(
        dir: PathBuf,
        node: Node,
        networks: Arc<Networks>,
        store: Arc<Store>,
        config: Config,
    ) -> Arc<Self> {
        let modified = modified(&dir);
        Arc::new(Self {
            dir,
            node,
            networks,
            store,
            serving: config.admin.clone(),
            state: Mutex::new(State {
                drafts: view::drafts(&config),
                config,
                modified,
                pairing: new_secret(),
            }),
            nostr: Default::default(),
            sessions: Default::default(),
            restart: Notify::new(),
            http_url: OnceLock::new(),
            iroh_id: OnceLock::new(),
        })
    }

    /// Serve the interface as `admin` says, until the process ends.
    pub async fn serve(self: &Arc<Self>, admin: &AdminConfig, iroh_secret: [u8; 32]) {
        match admin.listen_addr() {
            Ok(Some(addr)) => match http::serve(self.clone(), addr).await {
                Ok(addr) => {
                    let url = format!("hyperb://localhost:{}", addr.port());
                    println!("admin interface on this machine: {url}");
                    let _ = self.http_url.set(url);
                }
                Err(error) => warn!("admin over HTTP: {error}"),
            },
            Ok(None) => {}
            Err(error) => warn!("admin over HTTP: {error}"),
        }
        if admin.iroh {
            match iroh::serve(self.clone(), iroh_secret).await {
                Ok(id) => {
                    println!("admin interface over iroh, for peers: hyperb://{id}");
                    let _ = self.iroh_id.set(id);
                    self.print_pairing_link(&lock(&self.state).pairing);
                }
                Err(error) => warn!("admin over iroh: {error}"),
            }
        }
        let admin = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(REFRESH_INTERVAL).await;
                admin.reload_if_modified();
                // Also picks up changes left waiting for hops to settle.
                admin.sync_networks(None);
                admin.refresh();
            }
        });
        let admin = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(FIRST_CHECK_DELAY).await;
            loop {
                admin.nostr_job(false);
                tokio::time::sleep(CHECK_INTERVAL).await;
            }
        });
    }

    /// The name the router goes by: its own, else its autoname.
    fn name(&self, config: &Config) -> String {
        config
            .name
            .clone()
            .unwrap_or_else(|| autoname(&self.node.node_pubkey()))
    }

    /// The metadata of the page, under the router's name.
    fn metadata(&self, name: &str) -> Metadata {
        Metadata::new()
            .name(format!("{name} (cassis router)"))
            .description("Configure and run this Cassis router")
            .icon(icon::square(autohue(&self.node.node_pubkey())))
    }

    /// Run the background job of the relays: publish the router's name
    /// if it changed, announce its routes if `announce`, then check what
    /// the relays keep. Asked while it runs, it runs again after.
    fn nostr_job(self: &Arc<Self>, announce: bool) {
        {
            let mut nostr = lock(&self.nostr);
            nostr.queued = Some(announce || nostr.queued == Some(true));
            if nostr.busy.is_some() {
                return;
            }
            nostr.busy = Some("Starting");
        }
        let admin = self.clone();
        tokio::spawn(async move {
            loop {
                let announce = {
                    let mut nostr = lock(&admin.nostr);
                    let Some(announce) = nostr.queued.take() else {
                        nostr.busy = None;
                        break;
                    };
                    nostr.busy = Some(if announce {
                        "Announcing routes"
                    } else {
                        "Checking the relays"
                    });
                    announce
                };
                admin.refresh();
                let config = lock(&admin.state).config.clone();
                let relays = &config.nostr_relays;
                let published = lock(&admin.nostr).published_name.clone();
                // A router never named keeps its autoname, unpublished.
                if published.as_ref() != Some(&config.name)
                    && (published.is_some() || config.name.is_some())
                {
                    let accepted = admin
                        .node
                        .publish_name(relays, config.name.as_deref())
                        .await;
                    info!(
                        "published the router's name to {accepted}/{} relay(s)",
                        relays.len()
                    );
                    if accepted > 0 {
                        lock(&admin.nostr).published_name = Some(config.name.clone());
                    }
                }
                if announce {
                    admin.node.announce().await;
                }
                let router = admin.node.node_pubkey();
                let found = futures::future::join_all(
                    relays.iter().map(|relay| fetch_published(relay, router)),
                )
                .await;
                let mut nostr = lock(&admin.nostr);
                nostr.found = relays.iter().cloned().zip(found).collect();
                nostr.checked_at = Some(unix_now());
            }
            admin.refresh();
        });
    }

    /// Resolves when `daemon.restart` is asked for.
    pub async fn restart_requested(&self) {
        self.restart.notified().await
    }

    fn pairing_link(&self, secret: &str) -> Option<String> {
        Some(format!("hyperb://{}#pair={secret}", self.iroh_id.get()?))
    }

    fn print_pairing_link(&self, secret: &str) {
        if let Some(link) = self.pairing_link(secret) {
            println!("admin pairing link, lets in the first renderer to open it: {link}");
        }
    }

    fn allowed(&self, state: &State, access: &Access) -> bool {
        match access {
            Access::Local => true,
            Access::Peer(key) => state.config.admin.peers.contains(key),
        }
    }

    /// Start a session from its `hello`, sending `out` the page.
    fn open(
        self: &Arc<Self>,
        access: Access,
        params: &BTreeMap<String, String>,
        out: mpsc::UnboundedSender<String>,
    ) -> Arc<Session> {
        let session = Arc::new(Session {
            access,
            out,
            shown: Default::default(),
        });
        let name = self.name(&lock(&self.state).config);
        let mut metadata = self.metadata(&name);
        lock(&session.shown).name = name;
        if let (Access::Peer(key), Some(secret)) = (&session.access, params.get("pair")) {
            match self.pair(key, secret) {
                Ok(true) => lock(&session.shown).flash = Some(Ok("Paired: you are a peer".into())),
                Ok(false) => {}
                Err(error) => lock(&session.shown).flash = Some(Err(error)),
            }
            // A used link is worth nothing: keep it out of the address.
            metadata = metadata.extra("url", "/");
        }
        let mut lines = ServerMessage::from(metadata).to_line();
        {
            let state = lock(&self.state);
            let mut drafts = state.drafts.clone();
            drafts.extend(view::new_drafts(&state.config));
            lines.push_str(&ServerMessage::signal(json!({"d": drafts, "_busy": false})).to_line());
        }
        session.send(lines);
        lock(&self.sessions).push(session.clone());
        self.refresh();
        session
    }

    fn close(&self, session: &Arc<Session>) {
        lock(&self.sessions).retain(|other| !Arc::ptr_eq(other, session));
    }

    /// Handle a line the renderer sent after its `hello`.
    async fn receive(self: &Arc<Self>, session: &Arc<Session>, line: &str) {
        match RendererMessage::parse(line) {
            Ok(RendererMessage::Action(action)) => self.on_action(session, &action).await,
            Ok(RendererMessage::Hello { .. }) => warn!("admin: ignoring a second hello"),
            Err(error) => warn!("admin: ignoring a message: {error}"),
        }
    }

    async fn on_action(self: &Arc<Self>, session: &Arc<Session>, action: &Action) {
        let allowed = self.allowed(&lock(&self.state), &session.access);
        let result = if allowed {
            self.act(&action.name, &Args::of(action)).await
        } else {
            Err("not let in".to_string())
        };
        match &result {
            Ok(message) => info!("admin {} ({:?}): {message}", action.name, session.access),
            Err(error) => warn!("admin {} ({:?}): {error}", action.name, session.access),
        }
        let mut reset = json!({"_busy": false});
        // A form that added something is emptied for the next one.
        if let Some(draft) = Args::draft(action).filter(|draft| draft.starts_with("new_")) {
            if result.is_ok() {
                let fresh = view::new_drafts(&lock(&self.state).config);
                reset["d"] = json!({draft: fresh.get(draft)});
            }
        }
        session.signal(reset);
        lock(&session.shown).flash = Some(result);
        self.refresh();
    }

    /// Do what the action `name` says, returning what happened.
    async fn act(self: &Arc<Self>, name: &str, args: &Args) -> Result<String, String> {
        let network = || NetworkId::parse(&args.required("id")?);
        let ends = || {
            Ok::<_, String>((
                NetworkId::parse(&args.required("from")?)?,
                NetworkId::parse(&args.required("to")?)?,
            ))
        };
        match name {
            "settings.set" => {
                self.edit(|doc| edit::settings(doc, args))?;
                Ok("Settings saved".into())
            }
            "network.add" => {
                let id = edit::new_network_id(args)?;
                self.edit(|doc| edit::add_network(doc, &id, args))?;
                Ok(format!("{id} added, opening it"))
            }
            "admin.set" => {
                self.edit(|doc| edit::admin(doc, args))?;
                Ok("Admin interface settings saved".into())
            }
            "network.set" => {
                let id = network()?;
                self.edit(|doc| edit::network(doc, &id, args))?;
                Ok(format!("{id} saved"))
            }
            "network.open" => {
                let id = network()?;
                if !lock(&self.state).config.networks.contains_key(&id.0) {
                    return Err(format!("{id} is not under [networks]"));
                }
                match self.networks.in_flight(&id.0) {
                    0 => {}
                    hops => {
                        return Err(format!(
                            "{id} has {hops} hop(s) in flight: wait for them to settle"
                        ))
                    }
                }
                self.sync_networks(Some(id.0.clone()));
                Ok(format!("Opening {id}"))
            }
            "network.remove" => {
                let id = network()?;
                self.edit(|doc| edit::remove_network(doc, &id))?;
                Ok(format!("{id} removed"))
            }
            "route.set" => {
                let (from, to) = ends()?;
                self.edit(|doc| edit::route(doc, &from, &to, args))?;
                Ok(format!("Route {from} → {to} saved"))
            }
            "route.remove" => {
                let (from, to) = ends()?;
                self.edit(|doc| edit::remove_route(doc, &from, &to))?;
                Ok(format!("Route {from} → {to} removed"))
            }
            "routes.announce" => {
                self.nostr_job(true);
                Ok("Announcing routes".into())
            }
            "announcements.check" => {
                self.nostr_job(false);
                Ok("Checking the relays".into())
            }
            "peer.add" => {
                let key = edit::peer_key(&args.required("key")?)?;
                self.edit(|doc| edit::add_peer(doc, &key))?;
                Ok(format!("{key} is a peer"))
            }
            "peer.remove" => {
                let key = edit::peer_key(&args.required("key")?)?;
                self.edit(|doc| edit::remove_peer(doc, &key))?;
                Ok(format!("{key} is no longer a peer"))
            }
            "pairing.rotate" => {
                let mut state = lock(&self.state);
                state.pairing = new_secret();
                self.print_pairing_link(&state.pairing);
                Ok("The old pairing link no longer works".into())
            }
            "daemon.restart" => {
                self.restart.notify_one();
                Ok("Restarting…".into())
            }
            other => Err(format!("unknown action {other}")),
        }
    }

    /// Let `key` in if `secret` is the pairing link's, replacing it.
    /// Whether `key` was let in.
    fn pair(self: &Arc<Self>, key: &str, secret: &str) -> Result<bool, String> {
        let mut state = lock(&self.state);
        if self.allowed(&state, &Access::Peer(key.to_string())) {
            return Ok(false);
        }
        if secret != state.pairing {
            return Err("This pairing link was used already: ask for a new one".into());
        }
        self.edit_locked(&mut state, |doc| edit::add_peer(doc, key))?;
        state.pairing = new_secret();
        info!("admin: paired {key}");
        self.print_pairing_link(&state.pairing);
        Ok(true)
    }

    fn edit(
        self: &Arc<Self>,
        change: impl FnOnce(&mut DocumentMut) -> Result<(), String>,
    ) -> Result<(), String> {
        self.edit_locked(&mut lock(&self.state), change)
    }

    /// Change the config file, and apply what applies right away.
    fn edit_locked(
        self: &Arc<Self>,
        state: &mut State,
        change: impl FnOnce(&mut DocumentMut) -> Result<(), String>,
    ) -> Result<(), String> {
        let config = config::edit(&self.dir, change)?;
        state.modified = modified(&self.dir);
        self.adopt(state, config);
        Ok(())
    }

    /// Make `config` the current one, routing under it and announcing
    /// it if that changed.
    fn adopt(self: &Arc<Self>, state: &mut State, config: Config) {
        let routing = |config: &Config| {
            config.routing_policy().ok().map(|policy| {
                (
                    policy.routes,
                    policy.cleanup_relays,
                    policy.max_reservations,
                )
            })
        };
        let changed = routing(&state.config) != routing(&config);
        let renamed = state.config.name != config.name;
        state.config = config;
        if changed {
            match crate::routing_policy(&state.config, &self.store) {
                Ok(policy) => self.node.set_routing(policy),
                Err(error) => warn!("admin: not routing under the new config: {error}"),
            }
        }
        if changed || renamed {
            self.nostr_job(changed);
        }
        self.sync_networks(None);
    }

    /// Bring the open networks in step with the config, in the
    /// background, reopening `retry` even if unchanged; announce the
    /// routes again if a network opened or closed.
    fn sync_networks(self: &Arc<Self>, retry: Option<String>) {
        // The running one, or the next refresh, picks up what changed.
        if retry.is_none() && self.networks.syncing() {
            return;
        }
        let admin = self.clone();
        tokio::spawn(async move {
            let config = lock(&admin.state).config.clone();
            let changed = admin
                .networks
                .sync(&config, retry.as_deref(), &|| admin.refresh())
                .await;
            if changed && !config.routes.is_empty() {
                admin.nostr_job(true);
            }
        });
    }

    /// Pick up edits made to the config file by hand.
    fn reload_if_modified(self: &Arc<Self>) {
        let mut state = lock(&self.state);
        let modified = modified(&self.dir);
        if modified == state.modified {
            return;
        }
        state.modified = modified;
        match Config::load(&self.dir) {
            Ok(config) => {
                info!("admin: {} changed, reloaded it", config::FILE);
                self.adopt(&mut state, config);
            }
            Err(error) => warn!("admin: keeping the config as it was: {error}"),
        }
    }

    /// Bring every session's page and drafts up to date.
    fn refresh(&self) {
        let mut state = lock(&self.state);
        let drafts = view::drafts(&state.config);
        let mut patch = Map::new();
        for (key, value) in &drafts {
            if state.drafts.get(key) != Some(value) {
                patch.insert(key.clone(), value.clone());
            }
        }
        for key in state.drafts.keys() {
            if !drafts.contains_key(key) {
                patch.insert(key.clone(), Value::Null);
            }
        }
        state.drafts = drafts;
        let nostr = lock(&self.nostr);
        let name = self.name(&state.config);
        let ctx = view::Context {
            config: &state.config,
            serving: &self.serving,
            networks: self
                .networks
                .slots()
                .iter()
                .map(|(id, slot)| (id.clone(), (slot.config.clone(), slot.status.clone())))
                .collect(),
            name: name.clone(),
            autoname: autoname(&self.node.node_pubkey()),
            open: self
                .node
                .network_ids()
                .into_iter()
                .filter_map(|id| {
                    let lifetime = self.node.network(&id).ok()?.max_incoming_lifetime_secs();
                    Some((id.0, lifetime))
                })
                .collect(),
            hops: self.node.hops().unwrap_or_default(),
            node_pubkey: self.node.node_pubkey().to_hex(),
            iroh_peer_id: self.node.iroh_peer_id(),
            http_url: self.http_url.get().cloned(),
            iroh_url: self.iroh_id.get().map(|id| format!("hyperb://{id}")),
            pairing_link: self.pairing_link(&state.pairing),
            nostr: &nostr,
            now: unix_now(),
        };
        let patch = (!patch.is_empty()).then(|| ServerMessage::signal(json!({"d": patch})));
        for session in lock(&self.sessions).iter() {
            let mut lines = patch
                .as_ref()
                .map(ServerMessage::to_line)
                .unwrap_or_default();
            let mut shown = lock(&session.shown);
            if shown.name != name {
                lines.push_str(&ServerMessage::from(self.metadata(&name)).to_line());
                shown.name = name.clone();
            }
            let allowed = self.allowed(&state, &session.access);
            let tree = view::page(&ctx, &session.access, allowed, shown.flash.as_ref());
            for message in vtree::diff_into(None, &shown.tree, &tree) {
                lines.push_str(&message.to_line());
            }
            shown.tree = tree;
            session.send(lines);
        }
    }
}

fn modified(dir: &std::path::Path) -> Option<SystemTime> {
    std::fs::metadata(dir.join(config::FILE))
        .and_then(|metadata| metadata.modified())
        .ok()
}

fn new_secret() -> String {
    lowercase_hex::encode(rand::random::<[u8; 16]>())
}
