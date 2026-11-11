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
//! <data dir>/config.toml        keys, networks with their wallet keys, routes
//! <data dir>/wallet.redb        the router's own payments (see `cassis_wallet::db`)
//! <data dir>/router.redb        routed hops (see `cassis_routerd::db`)
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
use cassis_routerd::db::Db;
use cassis_routerd::router::Router;
use cassis_wallet::{Node, NodeConfig};
use clap::Parser;
use config::Config;
use networks::{Networks, RouterDaemon, RouterOpener};
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{info, info_span, warn};

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
    let wallet = cassis_wallet::open_db(&dir)?;
    let path = dir.join("router.redb");
    let db = Arc::new(Db::open(&path).map_err(|e| format!("open {}: {e}", path.display()))?);
    let span = info_span!("node", node = "routerd");

    // Networks are opened before the node starts, so that it can resume
    // its hops on them.
    let networks = Networks::new(
        RouterOpener {
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
            db: wallet,
            span: span.clone(),
            serve: true,
        },
        opened,
    )
    .await?;
    let router = Router::start(node.clone(), db)?;
    networks.attach(Arc::new(RouterDaemon(router.clone())));

    let policy = config.routing_policy()?;
    if policy.routes.is_empty() {
        warn!("no [[routes]] configured: not routing, only deleting old announcements");
    }
    router.start_routing(policy);

    info!(
        "routing as {} (node key {})",
        node.iroh_peer_id(),
        node.node_pubkey().to_hex()
    );
    let refresh = Refresh::default();
    let admin = Admin::new(dir, router, networks, config, refresh.clone());
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
