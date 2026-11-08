//! `cassis-routerd`: a Cassis router daemon. It does what
//! `<data dir>/config.toml` says (see [`config`]), following it as it
//! changes: opens the networks listed there (see [`networks`]), routes and announces the hops listed there, deletes its
//! announcements of anything else, and keeps its wallets in shape
//! (refreshing coins before they expire, and the like). Each
//! network is compiled in by the cargo feature of the same name.
//!
//! It also serves an [`admin`] interface for hyperb renderers, which
//! edits the config and runs the daemon's actions.
//!
//! ```text
//! <data dir>/config.toml        keys, networks, routes
//! <data dir>/store.db           routed hops, announced relays
//! <data dir>/<kind>/<variant>/  wallet of one network
//! ```

#[cfg(not(any(
    feature = "arkade",
    feature = "bark-lightning",
    feature = "bitcoin",
    feature = "cashu",
    feature = "fedimint",
    feature = "lightning",
    feature = "liquid",
    feature = "rootstock"
)))]
compile_error!("cassis-routerd needs at least one network feature, e.g. `--features cashu`");

mod admin;
mod config;
mod networks;

use admin::Admin;
use cassis_admin::{reexec, shutdown_signal, Refresh, Server, RESTART_GRACE};
use cassis_core::node::{Node, NodeConfig, RoutingPolicy};
use cassis_core::store::Store;
use clap::Parser;
use config::Config;
use networks::{Networks, RouterDaemon, RouterOpener};
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{info, info_span, warn};

const SETTINGS: &str = "settings";
/// Every relay the router ever announced on, so it can still delete
/// its announcements from relays the config no longer names.
const ANNOUNCED_RELAYS: &str = "announced_relays";

#[derive(Parser)]
#[command(name = "cassis-routerd", about = "Cassis router daemon")]
struct Cli {
    /// Data directory. Defaults to `$CASSIS_ROUTERD_DIR`, else
    /// `~/.cassis-routerd`.
    #[arg(long, value_name = "DIR", env = "CASSIS_ROUTERD_DIR")]
    data_dir: Option<PathBuf>,
}

#[tokio::main]
async fn main() {
    cassis_core::logging::init_logging();
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    if let Err(error) = run(Cli::parse()).await {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<(), String> {
    let dir = cli
        .data_dir
        .or_else(|| {
            std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cassis-routerd"))
        })
        .ok_or("cannot locate a data directory; pass --data-dir")?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let config = Config::load_or_create(&dir)?;
    let keys = config.keys()?;
    let store = Arc::new(Store::open(&dir.join("store.db"))?);
    let span = info_span!("node", node = "routerd");

    // Networks are opened before the node starts, so that it can resume
    // its hops on them.
    let networks = Networks::new(
        RouterOpener {
            keys: keys.clone(),
            dir: dir.clone(),
            span: span.clone(),
        },
        span.clone(),
        true,
    );
    let opened = networks.open_all(&config.networks).await;
    if config.networks.is_empty() {
        warn!(
            "no networks in {}: add some under [networks], or from the admin interface",
            dir.join(config::FILE).display()
        );
    }

    let admin_secret = keys.admin_endpoint_secret();
    let node = Node::start(
        NodeConfig {
            keys: keys.clone(),
            store: store.clone(),
            span: span.clone(),
            serve: true,
        },
        opened,
    )
    .await?;
    networks.attach(Arc::new(RouterDaemon(node.clone())));

    let policy = routing_policy(&config, &store)?;
    if policy.routes.is_empty() {
        warn!("no [[routes]] configured: not routing, only deleting old announcements");
    }
    node.start_routing(policy);

    info!(
        "routing as {} (node key {})",
        node.iroh_peer_id(),
        node.node_pubkey().to_hex()
    );
    let refresh = Refresh::default();
    let admin = Admin::new(dir, node.clone(), networks, store, config, refresh.clone());
    let server = Server::new(admin.clone(), refresh);
    server.serve(admin_secret).await;
    admin.keep_checking_relays();

    let restart = tokio::select! {
        _ = shutdown_signal() => false,
        _ = server.restart_requested() => true,
    };
    if restart {
        tokio::time::sleep(RESTART_GRACE).await;
    }
    info!("shutting down");
    node.shutdown().await;
    if restart {
        return Err(reexec());
    }
    Ok(())
}

/// What `config` routes under, deleting this node's announcements from
/// every relay it ever announced on, which the store keeps.
pub fn routing_policy(config: &Config, store: &Store) -> Result<RoutingPolicy, String> {
    let mut policy = config.routing_policy()?;
    let mut announced: Vec<String> = store.get(SETTINGS, ANNOUNCED_RELAYS)?.unwrap_or_default();
    let known = announced.len();
    for relay in policy.routes.iter().flat_map(|route| &route.nostr_relays) {
        if !announced.contains(relay) {
            announced.push(relay.clone());
        }
    }
    if announced.len() != known {
        store.put(SETTINGS, ANNOUNCED_RELAYS, &announced)?;
    }
    for relay in announced {
        if !policy.cleanup_relays.contains(&relay) {
            policy.cleanup_relays.push(relay);
        }
    }
    Ok(policy)
}
