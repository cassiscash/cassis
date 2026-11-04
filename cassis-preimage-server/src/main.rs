//! `cassis-preimage-server`: serve a preimage server (see the library)
//! from a directory of its own:
//!
//! ```text
//! <dir>/seed                12-word mnemonic every key derives from
//! <dir>/payments.redb       payments let through, for their payees
//! <dir>/<kind>/<variant>/   private data of one network's adapter
//! ```
//!
//! Each network is compiled in by the cargo feature of the same name.

use cassis_core::keys::{generate_mnemonic, NodeKeys};
use cassis_core::{Network, NetworkId};
use cassis_preimage_server::{Db, PreimageServer, ServerConfig};
use clap::Parser;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{info, info_span, Span};

#[derive(Parser)]
#[command(
    name = "cassis-preimage-server",
    about = "Answer PREPARE and COMMIT for offline payees and keep their payments"
)]
struct Cli {
    /// Server directory. Defaults to `$CASSIS_PREIMAGE_SERVER_HOME`,
    /// else `~/.cassis-preimage-server`.
    #[arg(long, value_name = "DIR")]
    home: Option<PathBuf>,
    /// Networks to verify HTLCs on, e.g. `cashu::mint.host`, `liquid`,
    /// `arkade::mutinynet`. Invoices on others are refused.
    #[arg(long = "network", required = true)]
    networks: Vec<String>,
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
    let db = Db::open(dir.join("payments.redb")).map_err(|e| format!("open database: {e}"))?;
    let span = info_span!("preimage-server");
    let mut networks = Vec::new();
    for spec in &cli.networks {
        let id = NetworkId::parse(spec)?;
        networks.push(open_network(&dir, &keys, &id, &span).await?);
    }
    let server = PreimageServer::start(ServerConfig {
        endpoint_secret: keys.iroh,
        preimage_secret: keys.preimage_server_secret(),
        db: Arc::new(db),
        networks,
        span,
    })
    .await?;
    let relay = server.home_relay().await;
    info!(
        "serving as {} (relay {}); Ctrl-C to stop",
        server.peer_id(),
        relay.as_deref().unwrap_or("unknown")
    );
    println!("{}", server.peer_id());
    tokio::signal::ctrl_c().await.ok();
    server.shutdown().await;
    Ok(())
}

/// Open the adapter of `network`, if this binary was built with it.
/// Its keys are the server's own: it only verifies HTLCs paying others.
#[allow(unused_variables)]
async fn open_network(
    dir: &Path,
    keys: &NodeKeys,
    network: &NetworkId,
    span: &Span,
) -> Result<Arc<dyn Network>, String> {
    let secret = keys.network_secret(network);
    let data_dir = network_dir(dir, network);
    Ok(match network.kind() {
        #[cfg(feature = "cashu")]
        "cashu" => Arc::new(cassis_cashu::CashuAdapter::open(
            network.clone(),
            secret,
            &data_dir,
            span,
        )?),
        #[cfg(feature = "liquid")]
        "liquid" => Arc::new(
            cassis_liquid::LiquidAdapter::open(network.clone(), secret, &data_dir, span).await?,
        ),
        #[cfg(feature = "bitcoin")]
        "bitcoin" => Arc::new(cassis_bitcoin::BitcoinAdapter::open(
            network.clone(),
            secret,
            span,
        )?),
        // `$CASSIS_ESPLORA_URL` overrides the chain API, as in cassis-cli.
        #[cfg(feature = "arkade")]
        "arkade" => Arc::new(
            cassis_arkade::ArkadeAdapter::open_with_esplora(
                network.clone(),
                secret,
                std::env::var("CASSIS_ESPLORA_URL").ok().as_deref(),
                span,
            )
            .await?,
        ),
        #[cfg(feature = "rootstock")]
        "rootstock" => Arc::new(cassis_rootstock::RootstockAdapter::open(
            network.clone(),
            secret,
            span,
        )?),
        #[cfg(feature = "fedimint")]
        "fedimint" => Arc::new(
            cassis_fedimint::FedimintAdapter::open(network.clone(), secret, &data_dir, span)
                .await?,
        ),
        "lightning" => {
            return Err(
                "lightning cannot go through a preimage server: its hold invoices need the \
                 payee online"
                    .into(),
            )
        }
        kind => {
            return Err(format!(
                "this cassis-preimage-server was built without the '{kind}' feature"
            ))
        }
    })
}

/// `<dir>/<kind>/<variant>`, as cassis-cli lays out network data.
fn network_dir(dir: &Path, network: &NetworkId) -> PathBuf {
    let variant: String = network
        .param()
        .unwrap_or("mainnet")
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    dir.join(network.kind()).join(variant)
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
