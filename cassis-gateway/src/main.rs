//! `cassis-gateway`: serve a gateway (see the library) from a directory
//! of its own, laid out like a `cassis-wallet` home so its funds can be
//! managed with `cassis-wallet --home <dir>` while it is stopped:
//!
//! ```text
//! <dir>/config.toml         mnemonic, networks with their keys, terms, admin (see `cassis_gateway::config`)
//! <dir>/wallet.redb         what it was paid (see `cassis_wallet::db`)
//! <dir>/gateway.redb        standing authorizations and HTLCs to payees (see `cassis_gateway::db`)
//! <dir>/<kind>/<variant>/   private data of one network's wallet
//! ```
//!
//! Each network is compiled in by the cargo feature of the same name.
//!
//! It also serves an admin interface for hyperb renderers (see
//! [`cassis_gateway::admin`]).

use cassis_admin::networks::Networks;
use cassis_admin::{reexec, shutdown_signal, ConfigFile, Refresh, Server, RESTART_GRACE};
use cassis_core::keys::generate_mnemonic;
use cassis_gateway::admin::{GatewayAdmin, GatewayOpener};
use cassis_gateway::config::{template, Config};
use cassis_gateway::db::Db;
use cassis_gateway::{Gateway, GatewayConfig};
use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{info, info_span, warn};

#[derive(Parser)]
#[command(
    name = "cassis-gateway",
    about = "Get paid in place of offline payees and pay them on through HTLCs"
)]
struct Cli {
    /// Gateway directory. Defaults to `$CASSIS_GATEWAY_HOME`, else
    /// `~/.cassis-gateway`.
    #[arg(long, value_name = "DIR")]
    home: Option<PathBuf>,
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
    let dir = match cli.home {
        Some(dir) => dir,
        None => match std::env::var_os("CASSIS_GATEWAY_HOME") {
            Some(dir) => PathBuf::from(dir),
            None => PathBuf::from(std::env::var_os("HOME").ok_or("HOME is not set")?)
                .join(".cassis-gateway"),
        },
    };
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let file: ConfigFile<Config> =
        ConfigFile::load_or_create(&dir, &template(&generate_mnemonic()))?;
    let config = file.get();
    let keys = config.keys()?;
    let wallet = cassis_wallet::open_db(&dir)?;
    let path = dir.join("gateway.redb");
    let db = Arc::new(Db::open(&path).map_err(|e| format!("open {}: {e}", path.display()))?);
    let span = info_span!("node", node = "gateway");
    // Networks are opened before the gateway starts, so that it can
    // resume its forwards on them. Forwards through one that does not
    // open wait for it.
    let networks = Networks::new(
        GatewayOpener {
            dir: dir.clone(),
            span: span.clone(),
        },
        span.clone(),
        // It holds funds like a router: keep its wallets in shape.
        true,
    );
    let opened = networks.open_all(&config.networks).await;
    if config.networks.is_empty() {
        warn!(
            "no networks in {}: add some under [networks], or from the admin interface",
            dir.join(cassis_admin::config::FILE).display()
        );
    }
    let gateway = Gateway::start(GatewayConfig {
        endpoint_secret: keys.iroh,
        db,
        wallet,
        networks: opened,
        policy: config.terms,
        span,
    })
    .await?;
    networks.attach(Arc::new(gateway.clone()));
    let relay = gateway.home_relay().await;
    info!(
        "serving as {} (relay {}); Ctrl-C to stop",
        gateway.peer_id(),
        relay.as_deref().unwrap_or("unknown")
    );
    println!("{}", gateway.peer_id());

    let refresh = Refresh::default();
    let app = GatewayAdmin::new(gateway.clone(), file, networks, relay, refresh.clone());
    let server = Server::new(app, refresh);
    server.serve(keys.admin_endpoint_secret()).await;

    let restart = tokio::select! {
        _ = shutdown_signal() => false,
        _ = server.restart_requested() => true,
    };
    if restart {
        tokio::time::sleep(RESTART_GRACE).await;
    }
    gateway.shutdown().await;
    if restart {
        return Err(reexec());
    }
    Ok(())
}
