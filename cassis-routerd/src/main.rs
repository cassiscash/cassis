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
use cassis_core::node::{Node, NodeConfig, RoutingPolicy};
use cassis_core::store::Store;
use clap::Parser;
use config::Config;
use networks::Networks;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
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
    // its hops on them. A network that does not open is left out, for
    // the admin interface to fix and open later.
    let mut networks = Vec::new();
    let mut failed = BTreeMap::new();
    for network in config.network_ids()? {
        match networks::open(&config, &network, &keys, &dir, &span).await {
            Ok(opened) => networks.push(opened),
            Err(error) => {
                warn!("not opening {network}: {error}");
                failed.insert(network.to_string(), error);
            }
        }
    }
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
        networks,
    )
    .await?;
    let networks = Networks::new(node.clone(), keys, dir.clone(), span, &config, failed);

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
    let admin_config = config.admin.clone();
    let admin = Admin::new(dir, node.clone(), networks, store, config);
    admin.serve(&admin_config, admin_secret).await;

    let restart = tokio::select! {
        _ = shutdown_signal() => false,
        _ = admin.restart_requested() => true,
    };
    if restart {
        // Let the pages hear about it first.
        tokio::time::sleep(Duration::from_millis(300)).await;
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

/// Replace this process with a fresh run of the same command, from the
/// binary now at its path, which returns only if that fails.
fn reexec() -> String {
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

/// Ctrl-C, or SIGTERM from a service manager.
async fn shutdown_signal() {
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
