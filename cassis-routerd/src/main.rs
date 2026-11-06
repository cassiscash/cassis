//! `cassis-routerd`: a Cassis router daemon. It does what
//! `<data dir>/config.toml` says (see [`config`]): opens the networks
//! listed there, routes and announces the hops listed there, deletes its
//! announcements of anything else, and keeps its wallets in shape. Each
//! network is compiled in by the cargo feature of the same name.
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

mod config;

use cassis_core::node::{Node, NodeConfig};
use cassis_core::store::Store;
use cassis_core::Network;
use clap::Parser;
use config::Config;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, info_span, warn, Instrument};

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

    let mut networks = Vec::new();
    for network in config.network_ids()? {
        let settings = config.network_settings(&network, &keys, &dir)?;
        let opened = cassis_networks::open(&network, &settings, &span)
            .await
            .map_err(|e| format!("{network}: {e}"))?;
        networks.push(opened);
    }
    if networks.is_empty() {
        return Err(format!(
            "no networks in {}: add some under [networks]",
            dir.join(config::FILE).display()
        ));
    }

    let node = Node::start(
        NodeConfig {
            keys,
            store: store.clone(),
            span: span.clone(),
            serve: true,
        },
        networks.clone(),
    )
    .await?;

    for network in &networks {
        if config.networks[&network.id().to_string()].maintenance {
            if let Some(interval) = network.maintenance_interval() {
                info!("maintaining {} every {}s", network.id(), interval.as_secs());
                tokio::spawn(maintain(network.clone()).instrument(span.clone()));
            }
        }
    }

    let mut policy = config.routing_policy()?;
    if policy.routes.is_empty() {
        warn!("no [[routes]] configured: not routing, only deleting old announcements");
    }
    let mut announced: Vec<String> = store.get(SETTINGS, ANNOUNCED_RELAYS)?.unwrap_or_default();
    for relay in policy.routes.iter().flat_map(|route| &route.nostr_relays) {
        if !announced.contains(relay) {
            announced.push(relay.clone());
        }
    }
    store.put(SETTINGS, ANNOUNCED_RELAYS, &announced)?;
    for relay in announced {
        if !policy.cleanup_relays.contains(&relay) {
            policy.cleanup_relays.push(relay);
        }
    }
    node.start_routing(policy);

    info!(
        "routing as {} (node key {})",
        node.iroh_peer_id(),
        node.node_pubkey().to_hex()
    );
    shutdown_signal().await;
    info!("shutting down");
    node.shutdown().await;
    Ok(())
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
