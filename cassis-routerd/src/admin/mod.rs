//! The router's admin interface (see [`cassis_admin`]): a hypereffect
//! app over the config file. The page is a [`view`] of the config and of
//! what the daemon runs. Every element that does something has an id
//! naming what it acts on (`route/<from>/<to>/save`), and its action
//! carries in its payload what it acts on, so actions can be sent from
//! anywhere, like API calls (`hypb action <address> <name> --payload
//! <json>`):
//!
//! | action                | payload                                                   |
//! | --------------------- | --------------------------------------------------------- |
//! | `settings.set`        | `name`, `nostr_relays`, `max_reservations`                |
//! | `admin.set`           | `listen`, `iroh` (see [`cassis_admin`], as `peer.*`, `pairing.rotate` and `daemon.restart`) |
//! | `network.add`         | `kind` (`arkade`, `cashu`, `liquid`, `lnd`, `bark`, `fedimint`, `bitcoin`, `rootstock`), `chain`, `mint`, `invite`, and the fields of `network.set` but `id` and `backend` |
//! | `network.set`         | `id`, `esplora_url`, `backend` (`lnd`, `bark`, `none`), `lnd_rest_url`, `lnd_tls_cert_path`, `lnd_macaroon_path`, `bark_server_url`, `bark_esplora_url` |
//! | `network.remove`      | `id`                                                      |
//! | `network.open`        | `id`                                                      |
//! | `wallet.*`            | see [`cassis_admin::wallets`]                             |
//! | `route.set`           | `from`, `to`, `fee_base_msat`, `fee_ppm`, `transit_slack_secs`, `test_money` |
//! | `route.remove`        | `from`, `to`                                              |
//! | `routes.announce`     |                                                           |
//! | `announcements.check` |                                                           |
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
mod view;

use crate::config::{self, Config};
use crate::networks::Networks;
use cassis_admin::config::child;
use cassis_admin::networks::{new_network_id, ALL_KINDS};
use cassis_admin::{AdminConfig, AdminEdit, App, Args, Identity, Refresh};
use cassis_core::routing::{autohue, autoname, fetch_published, Published};
use cassis_core::{unix_now, NetworkId};
use cassis_routerd::router::Router;
use hypereffect::vtree;
use hypereffect::{Map, Value};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime};
use toml_edit::DocumentMut;
use tracing::{info, warn};

/// How long after start the relays are first checked, leaving time for
/// the first announcement.
const FIRST_CHECK_DELAY: Duration = Duration::from_secs(20);
/// How often the relays are checked for this router's announcements.
const CHECK_INTERVAL: Duration = Duration::from_secs(10 * 60);

pub struct Admin {
    dir: PathBuf,
    router: Router,
    networks: Arc<Networks>,
    refresh: Refresh,
    state: Mutex<State>,
    nostr: Mutex<Nostr>,
}

struct State {
    config: Config,
    /// When the config file was last read or written.
    modified: Option<SystemTime>,
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

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

impl Admin {
    pub fn new(
        dir: PathBuf,
        router: Router,
        networks: Arc<Networks>,
        config: Config,
        refresh: Refresh,
    ) -> Arc<Self> {
        let modified = modified(&dir);
        Arc::new(Self {
            dir,
            router,
            networks,
            refresh,
            state: Mutex::new(State { config, modified }),
            nostr: Default::default(),
        })
    }

    /// Check the relays for this router's announcements now and then,
    /// until the process ends.
    pub fn keep_checking_relays(self: &Arc<Self>) {
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
            .unwrap_or_else(|| autoname(&self.router.node().node_pubkey()))
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
                admin.refresh.now();
                let config = lock(&admin.state).config.clone();
                let relays = &config.nostr_relays;
                let published = lock(&admin.nostr).published_name.clone();
                // A router never named keeps its autoname, unpublished.
                if published.as_ref() != Some(&config.name)
                    && (published.is_some() || config.name.is_some())
                {
                    let accepted = admin
                        .router
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
                    admin.router.announce().await;
                }
                let router = admin.router.node().node_pubkey();
                let found = futures::future::join_all(
                    relays.iter().map(|relay| fetch_published(relay, router)),
                )
                .await;
                let mut nostr = lock(&admin.nostr);
                nostr.found = relays.iter().cloned().zip(found).collect();
                nostr.checked_at = Some(unix_now());
            }
            admin.refresh.now();
        });
    }

    /// Do what the action `name` says, returning what happened.
    fn perform(self: &Arc<Self>, name: &str, args: &Args) -> Result<String, String> {
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
                let id = new_network_id(args, &ALL_KINDS)?;
                self.edit(|doc| edit::add_network(doc, &id, args))?;
                Ok(format!("{id} added, opening it"))
            }
            "network.set" => {
                let id = network()?;
                self.edit(|doc| edit::network(doc, &id, args))?;
                Ok(format!("{id} saved"))
            }
            "network.open" => {
                let id = network()?;
                let known = lock(&self.state).config.networks.contains_key(&id.0);
                self.networks.can_reopen(&id, known)?;
                self.sync_networks(Some(id.0.clone()));
                Ok(format!("Opening {id}"))
            }
            name if name.starts_with("wallet.") => {
                self.networks.wallets.act(name, args, &self.refresh)
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
            other => Err(format!("unknown action {other}")),
        }
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
            match state.config.routing_policy() {
                Ok(policy) => self.router.set_routing(policy),
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
                .sync(&config.networks, retry.as_deref(), &|| admin.refresh.now())
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
}

impl Admin {
    /// What the router's database holds of its hops.
    fn hops(&self) -> view::Hops {
        let db = self.router.db();
        let read = || -> orangedb::Result<view::Hops> {
            let mut failed = BTreeMap::new();
            for fail in db.fails().all()? {
                *failed
                    .entry(view::fail_kind(fail.reason).to_string())
                    .or_default() += 1;
            }
            Ok(view::Hops {
                in_flight: db.incomings().all()?,
                settled: db.forwards().len()? as usize,
                failed,
            })
        };
        read().unwrap_or_else(|error| {
            warn!("admin: reading hops: {error}");
            view::Hops::default()
        })
    }
}

impl App for Admin {
    fn identity(&self) -> Identity {
        let key = self.router.node().node_pubkey();
        Identity {
            name: self.name(&lock(&self.state).config),
            what: "router",
            description: "Configure and run this Cassis router",
            hue: autohue(&key),
        }
    }

    fn admin(&self) -> AdminConfig {
        lock(&self.state).config.admin.clone()
    }

    fn edit_admin(self: Arc<Self>, edit: &AdminEdit) -> Result<(), String> {
        self.edit(|doc| edit.apply(child(doc.as_table_mut(), "admin", toml_edit::table)?))
    }

    fn drafts(&self) -> Map<String, Value> {
        view::drafts(&lock(&self.state).config)
    }

    fn new_drafts(&self) -> Map<String, Value> {
        view::new_drafts(&lock(&self.state).config)
    }

    fn tabs(&self, access: vtree::Node) -> Vec<vtree::Node> {
        let state = lock(&self.state);
        let nostr = lock(&self.nostr);
        let wallets = &self.networks.wallets;
        let node = self.router.node();
        let ctx = view::Context {
            config: &state.config,
            networks: self
                .networks
                .slots()
                .iter()
                .map(|(id, slot)| {
                    let (can, funds) = wallets.get(id).unzip();
                    let network = view::Network {
                        config: slot.config.clone(),
                        status: slot.status.clone(),
                        can,
                        funds: funds.unwrap_or_default(),
                    };
                    (id.clone(), network)
                })
                .collect(),
            name: self.name(&state.config),
            autoname: autoname(&node.node_pubkey()),
            open: node.network_ids().into_iter().map(|id| id.0).collect(),
            hops: self.hops(),
            node_pubkey: node.node_pubkey().to_hex(),
            iroh_peer_id: node.iroh_peer_id(),
            nostr: &nostr,
            now: unix_now(),
        };
        view::tabs(&ctx, access)
    }

    fn act(self: Arc<Self>, name: &str, args: &Args) -> Result<String, String> {
        self.perform(name, args)
    }

    fn tick(self: Arc<Self>, pages_open: bool) {
        self.reload_if_modified();
        // Also picks up changes left waiting for hops to settle.
        self.sync_networks(None);
        if pages_open {
            self.networks.wallets.keep_fresh(&self.refresh);
        }
    }
}

fn modified(dir: &std::path::Path) -> Option<SystemTime> {
    std::fs::metadata(dir.join(config::FILE))
        .and_then(|metadata| metadata.modified())
        .ok()
}
