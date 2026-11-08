//! The admin interface of a Cassis daemon: a hypereffect app for
//! [hyperb](https://github.com/hypereffect/hyperb) renderers, which a
//! daemon fills in by implementing [`App`]. It is served open over HTTP
//! on loopback ([`http`]), and over iroh ([`iroh`]) to the renderers
//! listed in the daemon's [`AdminConfig`], or to the first one opening
//! the pairing link printed on the console, which is then replaced by a
//! new one.
//!
//! The page is a view of what the daemon has, sent as a diff after each
//! change. Every element that does something has an id naming what it
//! acts on, and its action carries in its payload what it acts on, so
//! actions can be sent from anywhere, like API calls (`hypb action
//! <address> <name> --payload <json>`). Every daemon has these, besides
//! its own:
//!
//! | action           | payload          |
//! | ---------------- | ---------------- |
//! | `admin.set`      | `listen`, `iroh` |
//! | `peer.add`       | `key`            |
//! | `peer.remove`    | `key`            |
//! | `pairing.rotate` |                  |
//! | `daemon.restart` |                  |
//!
//! A form's payload names its `draft` instead of the fields it edits
//! (see [`Args`]). The outcome of an action is the `result` notice of
//! the page of the session that sent it.

mod args;
pub mod config;
mod http;
mod icon;
mod iroh;
pub mod networks;
pub mod view;
pub mod wallets;

pub use args::Args;
pub use config::{AdminConfig, AdminEdit, AdminSection, ConfigFile, DaemonConfig};

use hypereffect::vtree::{self, Node};
use hypereffect::{json, Action, Map, Metadata, RendererMessage, ServerMessage, Value};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::Duration;
use tokio::sync::{mpsc, Notify};
use tracing::{info, warn};

/// How often open pages are brought up to date.
const REFRESH_INTERVAL: Duration = Duration::from_secs(5);

/// Who a session is.
#[derive(Clone, Debug, PartialEq)]
pub enum Access {
    /// Over HTTP on loopback.
    Local,
    /// Over iroh, with the renderer's key.
    Peer(String),
}

/// Who the daemon is, on top of its page.
pub struct Identity {
    /// The name it goes by.
    pub name: String,
    /// What it is: `router`, `gateway`.
    pub what: &'static str,
    pub description: &'static str,
    /// The color of its icon, in degrees.
    pub hue: u16,
}

/// A handle that brings open pages up to date, for what changes in the
/// background. Cheap to clone.
#[derive(Clone, Default)]
pub struct Refresh(Arc<Notify>);

impl Refresh {
    pub fn now(&self) {
        self.0.notify_one();
    }
}

/// What a daemon puts in its admin interface.
pub trait App: Send + Sync + 'static {
    fn identity(&self) -> Identity;

    /// The admin section as it is now.
    fn admin(&self) -> AdminConfig;

    fn edit_admin(self: Arc<Self>, edit: &AdminEdit) -> Result<(), String>;

    /// The drafts of the forms that edit what is there, as it is. A
    /// draft is sent to pages again when it changes.
    fn drafts(&self) -> Map<String, Value> {
        Map::new()
    }

    /// The drafts of the forms that add something, empty: named `new_*`,
    /// they are emptied when their action succeeds, as are the `w_*`
    /// ones of [`wallets`].
    fn new_drafts(&self) -> Map<String, Value> {
        Map::new()
    }

    /// The tabs of the page, placing the `access` one among them.
    fn tabs(&self, access: Node) -> Vec<Node>;

    /// Do what the action `name` says, returning what happened.
    fn act(self: Arc<Self>, name: &str, args: &Args) -> Result<String, String>;

    /// Called every few seconds, before the pages are brought up to
    /// date, with whether any is open.
    fn tick(self: Arc<Self>, _pages_open: bool) {}
}

pub struct Server {
    app: Arc<dyn App>,
    refresh: Refresh,
    /// The admin section served, which changes apply to on restart.
    serving: OnceLock<AdminConfig>,
    /// The drafts of the config as every session has them.
    drafts: Mutex<Map<String, Value>>,
    /// The secret of the pairing link.
    pairing: Mutex<String>,
    sessions: Mutex<Vec<Arc<Session>>>,
    restart: Notify,
    http_url: OnceLock<String>,
    iroh_id: OnceLock<String>,
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
    tree: Vec<Node>,
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

impl Server {
    /// An interface over `app`, whose pages `refresh` brings up to date.
    pub fn new(app: Arc<dyn App>, refresh: Refresh) -> Arc<Self> {
        Arc::new(Self {
            drafts: Mutex::new(all_drafts(&*app)),
            app,
            refresh,
            serving: OnceLock::new(),
            pairing: Mutex::new(new_secret()),
            sessions: Default::default(),
            restart: Notify::new(),
            http_url: OnceLock::new(),
            iroh_id: OnceLock::new(),
        })
    }

    /// Serve the interface as the app's admin section says, until the
    /// process ends. Addresses go to stderr, leaving stdout to the
    /// daemon.
    pub async fn serve(self: &Arc<Self>, iroh_secret: [u8; 32]) {
        let admin = self.app.admin();
        let _ = self.serving.set(admin.clone());
        match admin.listen_addr() {
            Ok(Some(addr)) => match http::serve(self.clone(), addr).await {
                Ok(addr) => {
                    let url = format!("hyperb://localhost:{}", addr.port());
                    eprintln!("admin interface on this machine: {url}");
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
                    eprintln!("admin interface over iroh, for peers: hyperb://{id}");
                    let _ = self.iroh_id.set(id);
                    self.print_pairing_link(&lock(&self.pairing));
                }
                Err(error) => warn!("admin over iroh: {error}"),
            }
        }
        let server = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(REFRESH_INTERVAL).await;
                let pages_open = !lock(&server.sessions).is_empty();
                server.app.clone().tick(pages_open);
                server.bring_up_to_date();
            }
        });
        let server = self.clone();
        tokio::spawn(async move {
            loop {
                server.refresh.0.notified().await;
                server.bring_up_to_date();
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
            eprintln!("admin pairing link, lets in the first renderer to open it: {link}");
        }
    }

    fn allowed(&self, access: &Access) -> bool {
        match access {
            Access::Local => true,
            Access::Peer(key) => self.app.admin().peers.contains(key),
        }
    }

    /// The metadata of the page, under the daemon's name.
    fn metadata(&self, identity: &Identity) -> Metadata {
        Metadata::new()
            .name(format!("{} (cassis {})", identity.name, identity.what))
            .description(identity.description)
            .icon(icon::square(identity.hue))
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
        let identity = self.app.identity();
        let mut metadata = self.metadata(&identity);
        lock(&session.shown).name = identity.name;
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
            let mut drafts = lock(&self.drafts).clone();
            drafts.extend(all_new_drafts(&*self.app));
            lines.push_str(&ServerMessage::signal(json!({"d": drafts, "_busy": false})).to_line());
        }
        session.send(lines);
        lock(&self.sessions).push(session.clone());
        self.bring_up_to_date();
        session
    }

    fn close(&self, session: &Arc<Session>) {
        lock(&self.sessions).retain(|other| !Arc::ptr_eq(other, session));
    }

    /// Handle a line the renderer sent after its `hello`.
    fn receive(self: &Arc<Self>, session: &Arc<Session>, line: &str) {
        match RendererMessage::parse(line) {
            Ok(RendererMessage::Action(action)) => self.on_action(session, &action),
            Ok(RendererMessage::Hello { .. }) => warn!("admin: ignoring a second hello"),
            Err(error) => warn!("admin: ignoring a message: {error}"),
        }
    }

    fn on_action(self: &Arc<Self>, session: &Arc<Session>, action: &Action) {
        let result = if self.allowed(&session.access) {
            self.act(&action.name, &Args::of(action))
        } else {
            Err("not let in".to_string())
        };
        match &result {
            Ok(message) => info!("admin {} ({:?}): {message}", action.name, session.access),
            Err(error) => warn!("admin {} ({:?}): {error}", action.name, session.access),
        }
        let mut reset = json!({"_busy": false});
        // A form that added or moved something is emptied for the next one.
        if let Some(draft) = Args::draft(action).filter(|draft| draft.starts_with("new_")) {
            if result.is_ok() {
                let fresh = all_new_drafts(&*self.app);
                reset["d"] = json!({draft: fresh.get(draft)});
            }
        }
        if let Some(draft) = Args::draft(action).filter(|draft| draft.starts_with("w_")) {
            if result.is_ok() {
                let fresh = all_drafts(&*self.app);
                reset["d"] = json!({draft: fresh.get(draft)});
            }
        }
        session.signal(reset);
        lock(&session.shown).flash = Some(result);
        self.bring_up_to_date();
    }

    /// Do what the action `name` says, returning what happened.
    fn act(self: &Arc<Self>, name: &str, args: &Args) -> Result<String, String> {
        match name {
            "admin.set" => {
                self.app.clone().edit_admin(&AdminEdit::Set {
                    listen: args.text("listen")?,
                    iroh: args.flag("iroh")?,
                })?;
                Ok("Admin interface settings saved".into())
            }
            "peer.add" => {
                let key = config::peer_key(&args.required("key")?)?;
                self.app
                    .clone()
                    .edit_admin(&AdminEdit::AddPeer(key.clone()))?;
                Ok(format!("{key} is a peer"))
            }
            "peer.remove" => {
                let key = config::peer_key(&args.required("key")?)?;
                self.app
                    .clone()
                    .edit_admin(&AdminEdit::RemovePeer(key.clone()))?;
                Ok(format!("{key} is no longer a peer"))
            }
            "pairing.rotate" => {
                let mut pairing = lock(&self.pairing);
                *pairing = new_secret();
                self.print_pairing_link(&pairing);
                Ok("The old pairing link no longer works".into())
            }
            "daemon.restart" => {
                self.restart.notify_one();
                Ok("Restarting…".into())
            }
            name => self.app.clone().act(name, args),
        }
    }

    /// Let `key` in if `secret` is the pairing link's, replacing it.
    /// Whether `key` was let in.
    fn pair(self: &Arc<Self>, key: &str, secret: &str) -> Result<bool, String> {
        let mut pairing = lock(&self.pairing);
        if self.allowed(&Access::Peer(key.to_string())) {
            return Ok(false);
        }
        if secret != *pairing {
            return Err("This pairing link was used already: ask for a new one".into());
        }
        self.app
            .clone()
            .edit_admin(&AdminEdit::AddPeer(key.to_string()))?;
        *pairing = new_secret();
        info!("admin: paired {key}");
        self.print_pairing_link(&pairing);
        Ok(true)
    }

    /// The page `session` gets now.
    fn page(
        &self,
        identity: &Identity,
        admin: &AdminConfig,
        session: &Session,
        shown: &Shown,
    ) -> Vec<Node> {
        let flash = shown.flash.as_ref();
        if !self.allowed(&session.access) {
            return view::locked(identity, &session.access, flash);
        }
        let pairing = lock(&self.pairing);
        let access = view::access_tab(&view::AccessInfo {
            access: &session.access,
            config: admin,
            http_url: self.http_url.get().map(String::as_str),
            iroh_url: self.iroh_id.get().map(|id| format!("hyperb://{id}")),
            pairing_link: self.pairing_link(&pairing),
        });
        drop(pairing);
        let pending = self
            .serving
            .get()
            .is_some_and(|serving| serving.moved_from(admin));
        view::page(identity, pending, flash, self.app.tabs(access))
    }

    /// Bring every session's page and drafts up to date.
    fn bring_up_to_date(&self) {
        let sessions = lock(&self.sessions);
        let drafts = all_drafts(&*self.app);
        let mut patch = Map::new();
        {
            let mut known = lock(&self.drafts);
            for (key, value) in &drafts {
                if known.get(key) != Some(value) {
                    patch.insert(key.clone(), value.clone());
                }
            }
            for key in known.keys() {
                if !drafts.contains_key(key) {
                    patch.insert(key.clone(), Value::Null);
                }
            }
            *known = drafts;
        }
        let identity = self.app.identity();
        let admin = self.app.admin();
        let patch = (!patch.is_empty()).then(|| ServerMessage::signal(json!({"d": patch})));
        for session in sessions.iter() {
            let mut lines = patch
                .as_ref()
                .map(ServerMessage::to_line)
                .unwrap_or_default();
            let mut shown = lock(&session.shown);
            if shown.name != identity.name {
                lines.push_str(&ServerMessage::from(self.metadata(&identity)).to_line());
                shown.name = identity.name.clone();
            }
            let tree = self.page(&identity, &admin, session, &shown);
            for message in vtree::diff_into(None, &shown.tree, &tree) {
                lines.push_str(&message.to_line());
            }
            shown.tree = tree;
            session.send(lines);
        }
    }
}

fn all_drafts(app: &dyn App) -> Map<String, Value> {
    let admin = app.admin();
    let mut drafts = app.drafts();
    drafts.insert(
        "admin".into(),
        json!({"listen": admin.listen, "iroh": admin.iroh}),
    );
    drafts
}

fn all_new_drafts(app: &dyn App) -> Map<String, Value> {
    let mut drafts = app.new_drafts();
    drafts.insert("new_peer".into(), json!({"key": ""}));
    drafts
}

fn new_secret() -> String {
    lowercase_hex::encode(rand::random::<[u8; 16]>())
}

/// Ctrl-C, or SIGTERM from a service manager.
pub async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut term) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
            return;
        }
    }
    tokio::signal::ctrl_c().await.ok();
}

/// Replace this process with a fresh run of the same command, from the
/// binary now at its path, which returns only if that fails.
pub fn reexec() -> String {
    info!("restarting");
    let exe = match std::env::current_exe() {
        // Linux names a binary replaced since it started `<path> (deleted)`.
        Ok(exe) => match exe.to_str().and_then(|exe| exe.strip_suffix(" (deleted)")) {
            Some(path) => PathBuf::from(path),
            None => exe,
        },
        Err(error) => return format!("restart: {error}"),
    };
    let mut command = std::process::Command::new(exe);
    command.args(std::env::args_os().skip(1));
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        format!("restart: {}", command.exec())
    }
    #[cfg(not(unix))]
    match command.spawn() {
        Ok(_) => std::process::exit(0),
        Err(error) => format!("restart: {error}"),
    }
}

/// How long pages get to hear about a restart before it happens.
pub const RESTART_GRACE: Duration = Duration::from_millis(300);

#[cfg(test)]
mod tests {
    use super::*;
    use hypereffect::vtree::{tab, text};

    struct Fake(Mutex<AdminConfig>);

    impl App for Fake {
        fn identity(&self) -> Identity {
            Identity {
                name: "fake".into(),
                what: "gateway",
                description: "",
                hue: 10,
            }
        }

        fn admin(&self) -> AdminConfig {
            lock(&self.0).clone()
        }

        fn edit_admin(self: Arc<Self>, edit: &AdminEdit) -> Result<(), String> {
            match edit {
                AdminEdit::AddPeer(key) => lock(&self.0).peers.push(key.clone()),
                _ => return Err("not here".into()),
            }
            Ok(())
        }

        fn tabs(&self, access: Node) -> Vec<Node> {
            vec![
                tab("tab/own").child(text("own").text("secret stuff")),
                access,
            ]
        }

        fn act(self: Arc<Self>, name: &str, _args: &Args) -> Result<String, String> {
            Ok(format!("did {name}"))
        }
    }

    fn server() -> (Arc<Server>, Arc<Fake>) {
        let fake = Arc::new(Fake(Mutex::new(AdminConfig::default())));
        (Server::new(fake.clone(), Refresh::default()), fake)
    }

    fn received(lines: &mut mpsc::UnboundedReceiver<String>) -> String {
        let mut all = String::new();
        while let Ok(batch) = lines.try_recv() {
            all.push_str(&batch);
        }
        all
    }

    fn action(name: &str) -> String {
        format!("action {}\n", json!({"name": name, "signals": {}}))
    }

    #[test]
    fn strangers_see_nothing_and_do_nothing() {
        let (server, _) = server();
        let (out, mut lines) = mpsc::unbounded_channel();
        let session = server.open(Access::Peer("stranger".into()), &BTreeMap::new(), out);
        let page = received(&mut lines);
        assert!(page.contains("Not let in") && !page.contains("secret stuff"));
        server.receive(&session, action("anything").trim_end());
        let after = received(&mut lines);
        assert!(after.contains("not let in"), "{after}");
    }

    #[test]
    fn locals_are_let_in_and_actions_reach_the_app() {
        let (server, _) = server();
        let (out, mut lines) = mpsc::unbounded_channel();
        let session = server.open(Access::Local, &BTreeMap::new(), out);
        assert!(received(&mut lines).contains("secret stuff"));
        server.receive(&session, action("own.thing").trim_end());
        assert!(received(&mut lines).contains("did own.thing"));
    }

    #[test]
    fn a_pairing_link_lets_in_one_renderer() {
        let (server, fake) = server();
        let secret = lock(&server.pairing).clone();
        let params = BTreeMap::from([("pair".to_string(), secret)]);
        let (out, mut lines) = mpsc::unbounded_channel();
        server.open(Access::Peer("first".into()), &params, out);
        let page = received(&mut lines);
        assert!(page.contains("Paired") && page.contains("secret stuff"));
        assert_eq!(fake.admin().peers, ["first"]);

        let (out, mut lines) = mpsc::unbounded_channel();
        server.open(Access::Peer("second".into()), &params, out);
        let page = received(&mut lines);
        assert!(page.contains("used already") && !page.contains("secret stuff"));
        assert_eq!(fake.admin().peers, ["first"]);
    }
}
