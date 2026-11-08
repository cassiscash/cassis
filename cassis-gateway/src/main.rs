//! `cassis-gateway`: serve a gateway (see the library) from a directory
//! of its own, laid out like a `cassis-wallet` home so its funds can be
//! managed with `cassis-wallet --home <dir>` while it is stopped:
//!
//! ```text
//! <dir>/seed                12-word mnemonic every key derives from
//! <dir>/config.toml         networks, terms, admin (see `cassis_gateway::config`)
//! <dir>/store.db            authorizations, invoices and forwards
//! <dir>/<kind>/<variant>/   private data of one network's wallet
//! ```
//!
//! Each network is compiled in by the cargo feature of the same name.
//!
//! It also serves an admin interface for hyperb renderers (see
//! [`cassis_gateway::admin`]).

use cassis_admin::networks::Networks;
use cassis_admin::{reexec, shutdown_signal, ConfigFile, Refresh, Server, RESTART_GRACE};
use cassis_core::keys::{generate_mnemonic, NodeKeys};
use cassis_core::store::Store;
use cassis_gateway::admin::{GatewayAdmin, GatewayOpener};
use cassis_gateway::config::{Config, TEMPLATE};
use cassis_gateway::{Gateway, GatewayConfig};
use clap::Parser;
use std::path::{Path, PathBuf};
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
    let keys = NodeKeys::from_mnemonic(&read_or_create_seed(&dir)?).map_err(|e| e.to_string())?;
    let file: ConfigFile<Config> = ConfigFile::load_or_create(&dir, TEMPLATE)?;
    let config = file.get();
    let store = Arc::new(Store::open(&dir.join("store.db"))?);
    let span = info_span!("node", node = "gateway");
    // Networks are opened before the gateway starts, so that it can
    // resume its forwards on them. Forwards through one that does not
    // open wait for it.
    let networks = Networks::new(
        GatewayOpener {
            keys: keys.clone(),
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
        store,
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

fn read_or_create_seed(dir: &Path) -> Result<String, String> {
    let path = dir.join("seed");
    if !path.exists() {
        use std::io::Write;
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options
            .open(&path)
            .map_err(|e| format!("create {}: {e}", path.display()))?;
        writeln!(file, "{}", generate_mnemonic()).map_err(|e| e.to_string())?;
        eprintln!(
            "generated a new seed at {}; back it up: it holds the gateway's funds",
            path.display()
        );
    }
    std::fs::read_to_string(&path)
        .map(|seed| seed.trim().to_string())
        .map_err(|e| format!("read {}: {e}", path.display()))
}
