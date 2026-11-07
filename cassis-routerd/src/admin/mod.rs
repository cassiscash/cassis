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
//! | action             | payload                                                   |
//! | ------------------ | --------------------------------------------------------- |
//! | `settings.set`     | `nostr_relays`, `test_money`, `max_reservations`          |
//! | `admin.set`        | `listen`, `iroh`                                          |
//! | `network.set`      | `id`, `max_incoming_lifetime_secs`, `esplora_url`, `maintenance`, `backend` (`lnd`, `bark`, `none`), `lnd_rest_url`, `lnd_tls_cert_path`, `lnd_macaroon_path`, `bark_server_url`, `bark_esplora_url` |
//! | `network.remove`   | `id`                                                      |
//! | `network.maintain` | `id`                                                      |
//! | `route.set`        | `from`, `to`, `fee_base_msat`, `fee_ppm`, `transit_slack_secs`, `nostr_relays`, `test_money` |
//! | `route.remove`     | `from`, `to`                                              |
//! | `routes.announce`  |                                                           |
//! | `peer.add`         | `key`                                                     |
//! | `peer.remove`      | `key`                                                     |
//! | `pairing.rotate`   |                                                           |
//! | `daemon.restart`   |                                                           |
//!
//! `*.set` actions add what they name if it is missing, and change only
//! the fields given (see [`edit::Args`]); a form's payload names its
//! `draft` instead of the fields it edits. Config changes are written
//! right away: routing changes apply at once, networks and the admin
//! section on restart. The outcome of an action is the `result` notice
//! of the page of the session that sent it.

mod edit;
mod http;
mod iroh;
mod view;

use crate::config::{self, AdminConfig, Config, NetworkConfig};
use cassis_core::node::Node;
use cassis_core::store::Store;
use cassis_core::NetworkId;
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

/// What the daemon opened on start, which config changes apply to on
/// restart only.
pub struct Running {
    pub networks: BTreeMap<String, NetworkConfig>,
    /// Networks that failed to open, with the error.
    pub failed: BTreeMap<String, String>,
    pub admin: AdminConfig,
}

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
    store: Arc<Store>,
    running: Running,
    state: Mutex<State>,
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

pub struct Session {
    access: Access,
    out: mpsc::UnboundedSender<String>,
    shown: Mutex<Shown>,
}

#[derive(Default)]
struct Shown {
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
        store: Arc<Store>,
        config: Config,
        running: Running,
    ) -> Arc<Self> {
        let modified = modified(&dir);
        Arc::new(Self {
            dir,
            node,
            store,
            running,
            state: Mutex::new(State {
                drafts: view::drafts(&config),
                config,
                modified,
                pairing: new_secret(),
            }),
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
                admin.refresh();
            }
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
        let mut metadata = Metadata::new()
            .name("Cassis router")
            .description("Configure and run this Cassis router");
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
            "admin.set" => {
                self.edit(|doc| edit::admin(doc, args))?;
                Ok("Admin interface settings saved".into())
            }
            "network.set" => {
                let id = network()?;
                self.edit(|doc| edit::network(doc, &id, args))?;
                Ok(format!("{id} saved"))
            }
            "network.remove" => {
                let id = network()?;
                self.edit(|doc| edit::remove_network(doc, &id))?;
                Ok(format!("{id} removed"))
            }
            "network.maintain" => {
                let id = network()?;
                self.node
                    .network(&id)?
                    .maintain()
                    .await
                    .map_err(|e| format!("{id}: {e}"))?;
                Ok(format!("{id} kept up"))
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
                let config = lock(&self.state).config.clone();
                self.node
                    .set_routing(crate::routing_policy(&config, &self.store)?);
                Ok("Announcing routes".into())
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
    fn pair(&self, key: &str, secret: &str) -> Result<bool, String> {
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
        &self,
        change: impl FnOnce(&mut DocumentMut) -> Result<(), String>,
    ) -> Result<(), String> {
        self.edit_locked(&mut lock(&self.state), change)
    }

    /// Change the config file, and apply what applies right away.
    fn edit_locked(
        &self,
        state: &mut State,
        change: impl FnOnce(&mut DocumentMut) -> Result<(), String>,
    ) -> Result<(), String> {
        let config = config::edit(&self.dir, change)?;
        state.modified = modified(&self.dir);
        self.adopt(state, config);
        Ok(())
    }

    /// Make `config` the current one, routing under it if that changed.
    fn adopt(&self, state: &mut State, config: Config) {
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
        state.config = config;
        if changed {
            match crate::routing_policy(&state.config, &self.store) {
                Ok(policy) => self.node.set_routing(policy),
                Err(error) => warn!("admin: not routing under the new config: {error}"),
            }
        }
    }

    /// Pick up edits made to the config file by hand.
    fn reload_if_modified(&self) {
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
        let ctx = view::Context {
            config: &state.config,
            running: &self.running,
            open: self.node.network_ids(),
            hops: self.node.hops().unwrap_or_default(),
            node_pubkey: self.node.node_pubkey().to_hex(),
            iroh_peer_id: self.node.iroh_peer_id(),
            http_url: self.http_url.get().cloned(),
            iroh_url: self.iroh_id.get().map(|id| format!("hyperb://{id}")),
            pairing_link: self.pairing_link(&state.pairing),
        };
        let patch = (!patch.is_empty()).then(|| ServerMessage::signal(json!({"d": patch})));
        for session in lock(&self.sessions).iter() {
            let mut lines = patch
                .as_ref()
                .map(ServerMessage::to_line)
                .unwrap_or_default();
            let mut shown = lock(&session.shown);
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
