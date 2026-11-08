//! `cassis-gateway`: serve a gateway (see the library) from a directory
//! of its own, laid out like a `cassis-wallet` home so its funds can be
//! managed with `cassis-wallet --home <dir>` while it is stopped:
//!
//! ```text
//! <dir>/seed                12-word mnemonic every key derives from
//! <dir>/store.db            authorizations, invoices and forwards
//! <dir>/<kind>/<variant>/   private data of one network's wallet
//! ```
//!
//! Each network is compiled in by the cargo feature of the same name.

use cassis_core::keys::{generate_mnemonic, NodeKeys};
use cassis_core::store::Store;
use cassis_core::NetworkId;
use cassis_gateway::{Gateway, GatewayConfig, GatewayPolicy};
use cassis_networks::NetworkSettings;
use clap::Parser;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{info, info_span};

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
    /// Networks to be paid on and to pay payees on, e.g.
    /// `cashu::mint.host`, `liquid`, `arkade::mutinynet`.
    #[arg(long = "network", required = true)]
    networks: Vec<String>,
    /// Longest final timeout a payee may ask for: funds stay locked that
    /// long when a payee never claims.
    #[arg(long, value_name = "SECS", default_value_t = GatewayPolicy::default().max_final_timeout_secs)]
    max_final_timeout: u64,
    /// Longest a standing authorization may run.
    #[arg(long, value_name = "SECS", default_value_t = GatewayPolicy::default().max_authorization_secs)]
    max_authorization: u64,
    /// Expiry of invoices issued under a standing authorization, when
    /// the asker names none.
    #[arg(long, value_name = "SECS", default_value_t = GatewayPolicy::default().default_invoice_expiry_secs)]
    invoice_expiry: u64,
    /// Margin asked of payers on top of each network's: time to pay the
    /// payee and have the preimage released.
    #[arg(long, value_name = "SECS", default_value_t = GatewayPolicy::default().forward_slack_secs)]
    forward_slack: u64,
    /// Margin added to the payee's final timeout.
    #[arg(long, value_name = "SECS", default_value_t = GatewayPolicy::default().final_slack_secs)]
    final_slack: u64,
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
    let store = Arc::new(Store::open(&dir.join("store.db"))?);
    let span = info_span!("node", node = "gateway");
    let mut networks = Vec::new();
    for spec in &cli.networks {
        let id = NetworkId::parse(spec)?;
        let settings = NetworkSettings {
            secret: keys.network_secret(&id),
            dir: cassis_networks::network_dir(&dir, &id),
            // `$CASSIS_ESPLORA_URL` overrides the chain API, as in
            // cassis-wallet.
            esplora_url: match id.kind() {
                "arkade" => std::env::var("CASSIS_ESPLORA_URL").ok(),
                _ => None,
            },
            ..Default::default()
        };
        networks.push(
            cassis_networks::open(&id, &settings, &span)
                .await
                .map_err(|e| format!("{id}: {e}"))?,
        );
    }
    let gateway = Gateway::start(GatewayConfig {
        endpoint_secret: keys.iroh,
        store,
        networks,
        policy: GatewayPolicy {
            max_final_timeout_secs: cli.max_final_timeout,
            max_authorization_secs: cli.max_authorization,
            default_invoice_expiry_secs: cli.invoice_expiry,
            forward_slack_secs: cli.forward_slack,
            final_slack_secs: cli.final_slack,
        },
        span,
    })
    .await?;
    let relay = gateway.home_relay().await;
    info!(
        "serving as {} (relay {}); Ctrl-C to stop",
        gateway.peer_id(),
        relay.as_deref().unwrap_or("unknown")
    );
    println!("{}", gateway.peer_id());
    tokio::signal::ctrl_c().await.ok();
    gateway.shutdown().await;
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
