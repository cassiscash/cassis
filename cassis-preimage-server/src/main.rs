//! `cassis-preimage-server`: serve a preimage server (see the library)
//! from a directory of its own:
//!
//! ```text
//! <dir>/seed                12-word mnemonic every key derives from
//! <dir>/config.toml         networks, admin (see `cassis_preimage_server::config`)
//! <dir>/releases.redb       HTLCs whose preimage was released, for their payees
//! <dir>/<kind>/<variant>/   private data of one network's adapter
//! ```
//!
//! Each network is compiled in by the cargo feature of the same name.
//!
//! It also serves an admin interface for hyperb renderers (see
//! [`cassis_preimage_server::admin`]).

use cassis_admin::networks::Networks;
use cassis_admin::{reexec, shutdown_signal, ConfigFile, Refresh, Server, RESTART_GRACE};
use cassis_core::keys::{generate_mnemonic, NodeKeys};
use cassis_preimage_server::admin::{PreimageAdmin, PreimageOpener};
use cassis_preimage_server::config::{Config, TEMPLATE};
use cassis_preimage_server::{Db, PreimageServer, ServerConfig};
use clap::Parser;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{info, info_span, warn};

#[derive(Parser)]
#[command(
    name = "cassis-preimage-server",
    about = "Issue payment hashes for offline payees and release preimages to their gateways"
)]
struct Cli {
    /// Server directory. Defaults to `$CASSIS_PREIMAGE_SERVER_HOME`,
    /// else `~/.cassis-preimage-server`.
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
        None => match std::env::var_os("CASSIS_PREIMAGE_SERVER_HOME") {
            Some(dir) => PathBuf::from(dir),
            None => PathBuf::from(std::env::var_os("HOME").ok_or("HOME is not set")?)
                .join(".cassis-preimage-server"),
        },
    };
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let keys = NodeKeys::from_mnemonic(&read_or_create_seed(&dir)?).map_err(|e| e.to_string())?;
    let file: ConfigFile<Config> = ConfigFile::load_or_create(&dir, TEMPLATE)?;
    let config = file.get();
    let db = Db::open(dir.join("releases.redb")).map_err(|e| format!("open database: {e}"))?;
    let span = info_span!("preimage-server");
    let networks = Networks::new(
        PreimageOpener {
            dir: dir.clone(),
            span: span.clone(),
        },
        span.clone(),
        false,
    );
    let opened = networks.open_all(&config.networks).await;
    if config.networks.is_empty() {
        warn!(
            "no networks in {}: add some under [networks], or from the admin interface",
            dir.join(cassis_admin::config::FILE).display()
        );
    }
    let server = PreimageServer::start(ServerConfig {
        endpoint_secret: keys.iroh,
        preimage_secret: keys.preimage_server_secret(),
        db: Arc::new(db),
        networks: opened,
        span,
    })
    .await?;
    networks.attach(Arc::new(server.clone()));
    let relay = server.home_relay().await;
    info!(
        "serving as {} (relay {}); Ctrl-C to stop",
        server.peer_id(),
        relay.as_deref().unwrap_or("unknown")
    );
    println!("{}", server.peer_id());

    let refresh = Refresh::default();
    let admin = Server::new(
        PreimageAdmin::new(server.clone(), file, networks, relay, refresh.clone()),
        refresh,
    );
    admin.serve(keys.admin_endpoint_secret()).await;

    let restart = tokio::select! {
        _ = shutdown_signal() => false,
        _ = admin.restart_requested() => true,
    };
    if restart {
        tokio::time::sleep(RESTART_GRACE).await;
    }
    server.shutdown().await;
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
            "generated a new seed at {}; back it up: it derives every preimage this server \
             issues",
            path.display()
        );
    }
    std::fs::read_to_string(&path)
        .map(|seed| seed.trim().to_string())
        .map_err(|e| format!("read {}: {e}", path.display()))
}
