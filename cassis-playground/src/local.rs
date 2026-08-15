//! A self-contained network of ledgers for end-to-end tests: an
//! in-process Nostr relay, `cdk-mintd` cashu mints with fake Lightning
//! backends, and single-guardian `fedimintd` federations on a regtest
//! `bitcoind`, all on free local ports under one directory. Nodes are
//! real [`Node`]s funded with the ledgers' fake money.
//!
//! Needs `cdk-mintd`, `cdk-cli` and `bitcoind` on `PATH`, and
//! `fedimintd` at `$CASSIS_FEDIMINTD` or `<workspace>/tmp/fedimintd-v0.12.1`.

use cassis_cashu::CashuAdapter;
use cassis_core::keys::{generate_mnemonic, NodeKeys};
use cassis_core::node::{Node, NodeConfig, PrepareVeto, RoutingPolicy};
use cassis_core::store::Store;
use cassis_core::{unix_now, Bytes32, Invoice, Network, NetworkId};
use cassis_fedimint::FedimintAdapter;
use fedimint_api_client::api::DynGlobalApi;
use fedimint_connectors::ConnectorRegistry;
use fedimint_core::module::ApiAuth;
use fedimint_core::util::SafeUrl;
use ritualistic::server::RelayInternals;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, OnceCell};
use tracing::{info, info_span};

const BITCOIND_AUTH: (&str, &str) = ("bitcoin", "bitcoin");
const FEDIMINT_PASSWORD: &str = "pass";

pub struct LocalEnv {
    root: PathBuf,
    relay: String,
    children: Mutex<Vec<Child>>,
    bitcoind: OnceCell<Bitcoind>,
    counter: std::sync::atomic::AtomicUsize,
}

impl LocalEnv {
    /// Fresh environment under `target/e2e/<name>`, with its Nostr relay
    /// running.
    pub async fn start(name: &str) -> Result<Self, String> {
        let root = workspace_dir().join("target/e2e").join(name);
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).map_err(|e| e.to_string())?;
        let port = free_port()?;
        let relay = RelayInternals {
            info: Default::default(),
            custom_relay: Box::new(Mutex::new(crate::MemoryRelay::default())),
        };
        tokio::spawn(ritualistic::server::start(
            Arc::new(relay),
            format!("127.0.0.1:{port}").parse().expect("valid address"),
        ));
        wait_for("nostr relay", || async {
            tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .is_ok()
        })
        .await?;
        Ok(Self {
            root,
            relay: format!("ws://127.0.0.1:{port}"),
            children: Mutex::new(Vec::new()),
            bitcoind: OnceCell::new(),
            counter: Default::default(),
        })
    }

    pub fn relays(&self) -> Vec<String> {
        vec![self.relay.clone()]
    }

    fn next_dir(&self, kind: &str) -> PathBuf {
        let n = self
            .counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.root.join(format!("{kind}-{n}"))
    }

    async fn spawn(&self, mut command: Command, log: &Path) -> Result<(), String> {
        let log = std::fs::File::create(log).map_err(|e| e.to_string())?;
        command
            .stdout(log.try_clone().map_err(|e| e.to_string())?)
            .stderr(log)
            .stdin(Stdio::null())
            .kill_on_drop(true);
        let child = command
            .spawn()
            .map_err(|e| format!("spawn {:?}: {e}", command.as_std().get_program()))?;
        self.children.lock().await.push(child);
        Ok(())
    }

    /// Start a cashu mint with a fake Lightning backend.
    pub async fn cashu_mint(&self) -> Result<NetworkId, String> {
        let dir = self.next_dir("mint");
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let seed = dir.join("seed");
        std::fs::write(&seed, generate_mnemonic()).map_err(|e| e.to_string())?;
        let port = free_port()?;
        let mut command = Command::new("cdk-mintd");
        command
            .arg("-w")
            .arg(&dir)
            .arg("--seed-file")
            .arg(&seed)
            .env("CDK_MINTD_LISTEN_HOST", "127.0.0.1")
            .env("CDK_MINTD_LISTEN_PORT", port.to_string())
            .env("CDK_MINTD_URL", format!("http://127.0.0.1:{port}"))
            .env("CDK_MINTD_LN_BACKEND", "fakewallet")
            .env("CDK_MINTD_FAKE_WALLET_SUPPORTED_UNITS", "sat")
            .env("CDK_MINTD_FAKE_WALLET_FEE_PERCENT", "0")
            .env("CDK_MINTD_FAKE_WALLET_RESERVE_FEE_MIN", "0");
        self.spawn(command, &dir.join("mintd.log")).await?;
        let url = format!("http://127.0.0.1:{port}/v1/info");
        wait_for("cashu mint", || async {
            reqwest::get(&url)
                .await
                .is_ok_and(|response| response.status().is_success())
        })
        .await?;
        info!("cashu mint up on port {port}");
        NetworkId::parse(&format!("cashu::127.0.0.1:{port}"))
    }

    async fn bitcoind(&self) -> Result<&Bitcoind, String> {
        self.bitcoind
            .get_or_try_init(|| async {
                let dir = self.root.join("bitcoind");
                std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
                let rpc_port = free_port()?;
                let mut command = Command::new("bitcoind");
                command.args([
                    "-regtest",
                    &format!("-datadir={}", dir.display()),
                    &format!("-rpcuser={}", BITCOIND_AUTH.0),
                    &format!("-rpcpassword={}", BITCOIND_AUTH.1),
                    &format!("-rpcport={rpc_port}"),
                    "-rpcbind=127.0.0.1",
                    "-rpcallowip=127.0.0.1",
                    "-listen=0",
                    "-dnsseed=0",
                    "-txindex=1",
                    "-fallbackfee=0.0002",
                ]);
                self.spawn(command, &dir.join("bitcoind.log")).await?;
                let bitcoind = Bitcoind {
                    url: format!("http://127.0.0.1:{rpc_port}"),
                    http: reqwest::Client::new(),
                };
                wait_for("bitcoind", || async {
                    bitcoind.rpc("getblockchaininfo", json!([])).await.is_ok()
                })
                .await?;
                bitcoind.rpc("createwallet", json!(["cassis"])).await?;
                bitcoind.mine(101).await?;
                Ok(bitcoind)
            })
            .await
    }

    /// Start a one-guardian federation with fedimintd's default modules
    /// (mintv2, walletv2, lnv2), backed by the regtest bitcoind.
    pub async fn federation(&self) -> Result<NetworkId, String> {
        let bitcoind = self.bitcoind().await?;
        let dir = self.next_dir("federation");
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let [p2p, api, ui, metrics] = [free_port()?, free_port()?, free_port()?, free_port()?];
        let mut command = Command::new(fedimintd_path());
        command
            .env("FM_DATA_DIR", &dir)
            .env("FM_BITCOIN_NETWORK", "regtest")
            .env("FM_BITCOIND_URL", &bitcoind.url)
            .env("FM_BITCOIND_USERNAME", BITCOIND_AUTH.0)
            .env("FM_BITCOIND_PASSWORD", BITCOIND_AUTH.1)
            .env("FM_BIND_P2P", format!("127.0.0.1:{p2p}"))
            .env("FM_BIND_API", format!("127.0.0.1:{api}"))
            .env("FM_BIND_UI", format!("127.0.0.1:{ui}"))
            .env("FM_BIND_METRICS", format!("127.0.0.1:{metrics}"))
            .env("FM_P2P_URL", format!("fedimint://127.0.0.1:{p2p}"))
            .env("FM_API_URL", format!("ws://127.0.0.1:{api}"))
            .env("FM_ENABLE_IROH", "false")
            .env("FM_PASSWORD_API", FEDIMINT_PASSWORD)
            .env("FM_TEST_FAST_WEAK_CRYPTO", "1");
        self.spawn(command, &dir.join("fedimintd.log")).await?;

        let connectors = ConnectorRegistry::build_from_client_defaults()
            .bind()
            .await
            .map_err(|e| e.to_string())?;
        let url = SafeUrl::parse(&format!("ws://127.0.0.1:{api}")).map_err(|e| e.to_string())?;
        let admin = DynGlobalApi::new_admin_setup(connectors, url).map_err(|e| e.to_string())?;
        let auth = ApiAuth::new(FEDIMINT_PASSWORD.to_string());
        wait_for("fedimintd setup api", || async {
            admin.setup_status(auth.clone()).await.is_ok()
        })
        .await?;
        let name = dir.file_name().unwrap().to_string_lossy().to_string();
        admin
            .set_local_params(name.clone(), Some(name), None, None, Some(1), auth.clone())
            .await
            .map_err(|e| format!("set local params: {e}"))?;
        admin
            .start_dkg(auth)
            .await
            .map_err(|e| format!("start dkg: {e}"))?;
        let invite_path = dir.join("invite-code");
        wait_for("federation invite code", || async { invite_path.exists() }).await?;
        let invite = std::fs::read_to_string(&invite_path).map_err(|e| e.to_string())?;
        info!("federation up on port {api}");
        NetworkId::parse(&format!("fedimint::{}", invite.trim()))
    }

    /// A serving node on `networks`, named `name` in logs.
    pub async fn node(&self, name: &str, networks: &[NetworkId]) -> Result<TestNode, String> {
        let home = self.root.join("nodes").join(name);
        let keys = NodeKeys::from_mnemonic(&generate_mnemonic()).map_err(|e| e.to_string())?;
        let span = info_span!("node", node = name);
        let mut wallets = HashMap::new();
        for network in networks {
            let dir = home
                .join(network.kind())
                .join(format!("{:x}", hash(&network.0)));
            let secret = keys.network_secret(network);
            let wallet = match network.kind() {
                "cashu" => Wallet::Cashu(Arc::new(CashuAdapter::open(
                    network.clone(),
                    secret,
                    &dir,
                    &span,
                )?)),
                "fedimint" => {
                    // The federation may still be finishing its first
                    // session right after DKG.
                    let mut attempt = 0;
                    let adapter = loop {
                        match FedimintAdapter::open(network.clone(), secret, &dir, &span).await {
                            Ok(adapter) => break adapter,
                            Err(error) if attempt < 30 => {
                                attempt += 1;
                                tracing::debug!("joining federation: {error}");
                                tokio::time::sleep(Duration::from_secs(1)).await;
                            }
                            Err(error) => return Err(error),
                        }
                    };
                    Wallet::Fedimint(Arc::new(adapter))
                }
                other => return Err(format!("the local environment has no '{other}' ledgers")),
            };
            wallets.insert(network.clone(), wallet);
        }
        let node = Node::start(
            NodeConfig {
                keys,
                store: Arc::new(Store::open(&home.join("store.db"))?),
                span,
                serve: true,
            },
            wallets.values().map(Wallet::network).collect(),
        )
        .await?;
        Ok(TestNode {
            name: name.to_string(),
            node,
            wallets,
            relays: self.relays(),
        })
    }

    /// Give `node` `amount_msat` of fake money on `network`.
    pub async fn fund(
        &self,
        node: &TestNode,
        network: &NetworkId,
        amount_msat: u64,
    ) -> Result<(), String> {
        match node.wallet(network)? {
            Wallet::Cashu(wallet) => {
                let sats = amount_msat.div_ceil(1000).to_string();
                let url = wallet.mint_url();
                let cdk = self.root.join("cdk-cli");
                let cli = |args: &[&str]| {
                    let mut command = Command::new("cdk-cli");
                    command.arg("-w").arg(&cdk).arg("-n").args(args);
                    command
                };
                let minted = cli(&["mint", &url, &sats])
                    .output()
                    .await
                    .map_err(|e| format!("cdk-cli: {e}"))?;
                if !minted.status.success() {
                    return Err(String::from_utf8_lossy(&minted.stderr).to_string());
                }
                let sent = cli(&["send", "-a", &sats, "--mint-url", &url])
                    .output()
                    .await
                    .map_err(|e| format!("cdk-cli: {e}"))?;
                let stdout = String::from_utf8_lossy(&sent.stdout);
                let token = stdout
                    .lines()
                    .find(|line| line.starts_with("cashuA") || line.starts_with("cashuB"))
                    .ok_or_else(|| format!("cdk-cli printed no token: {stdout}"))?;
                wallet.receive_token(token).await?;
            }
            Wallet::Fedimint(wallet) => {
                let bitcoind = self.bitcoind().await?;
                let (address, position) = wallet.deposit_address().await?;
                let btc = format!("{:.8}", amount_msat.div_ceil(1000) as f64 / 1e8);
                bitcoind
                    .rpc(
                        "sendtoaddress",
                        json!([address, btc.parse::<f64>().unwrap()]),
                    )
                    .await?;
                // Mine while waiting: peg-ins need six confirmations and
                // the federation only sees blocks it is shown.
                let waiting = {
                    let wallet = wallet.clone();
                    tokio::spawn(async move { wallet.await_deposit(position, 300).await })
                };
                while !waiting.is_finished() {
                    bitcoind.mine(1).await?;
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                waiting.await.map_err(|e| e.to_string())??;
            }
        }
        info!("funded {} on {network}", node.name);
        Ok(())
    }
}

/// A [`Node`] with its wallets.
pub struct TestNode {
    pub name: String,
    pub node: Node,
    wallets: HashMap<NetworkId, Wallet>,
    relays: Vec<String>,
}

#[derive(Clone)]
enum Wallet {
    Cashu(Arc<CashuAdapter>),
    Fedimint(Arc<FedimintAdapter>),
}

impl Wallet {
    fn network(&self) -> Arc<dyn Network> {
        match self {
            Wallet::Cashu(wallet) => wallet.clone(),
            Wallet::Fedimint(wallet) => wallet.clone(),
        }
    }
}

impl TestNode {
    fn wallet(&self, network: &NetworkId) -> Result<&Wallet, String> {
        self.wallets
            .get(network)
            .ok_or_else(|| format!("{} is not on {network}", self.name))
    }

    pub async fn balance_msat(&self, network: &NetworkId) -> Result<u64, String> {
        match self.wallet(network)? {
            Wallet::Cashu(wallet) => wallet.balance_msat(),
            Wallet::Fedimint(wallet) => wallet.balance_msat().await,
        }
    }

    /// Route between all of this node's networks, announcing on the
    /// environment's relay.
    pub fn route(&self, prepare_veto: Option<PrepareVeto>) {
        self.node.start_routing(RoutingPolicy {
            nostr_relays: self.relays.clone(),
            prepare_veto,
            ..RoutingPolicy::default()
        });
    }

    pub async fn invoice(&self, network: &NetworkId, amount_msat: u64) -> Result<Invoice, String> {
        self.node
            .create_invoice(
                std::slice::from_ref(network),
                amount_msat,
                unix_now() + 600,
                None,
            )
            .await
    }

    pub async fn pay(&self, invoice: &Invoice, from: &NetworkId) -> Result<Bytes32, String> {
        self.node.pay(invoice, from, &self.relays).await
    }
}

/// Wait until `routers` route announcements are visible on `env`'s relay.
pub async fn wait_for_announcements(env: &LocalEnv, count: usize) -> Result<(), String> {
    let relays = env.relays();
    wait_for("route announcements", || async {
        cassis_core::routing::fetch_announcements(&relays)
            .await
            .is_ok_and(|announcements| announcements.len() >= count)
    })
    .await
}

struct Bitcoind {
    url: String,
    http: reqwest::Client,
}

impl Bitcoind {
    async fn rpc(&self, method: &str, params: Value) -> Result<Value, String> {
        let response: Value = self
            .http
            .post(&self.url)
            .basic_auth(BITCOIND_AUTH.0, Some(BITCOIND_AUTH.1))
            .json(&json!({"jsonrpc": "1.0", "id": "cassis", "method": method, "params": params}))
            .send()
            .await
            .map_err(|e| format!("bitcoind {method}: {e}"))?
            .json()
            .await
            .map_err(|e| format!("bitcoind {method}: {e}"))?;
        match response.get("error") {
            Some(error) if !error.is_null() => Err(format!("bitcoind {method}: {error}")),
            _ => Ok(response["result"].clone()),
        }
    }

    async fn mine(&self, blocks: u64) -> Result<(), String> {
        let address = self.rpc("getnewaddress", json!([])).await?;
        self.rpc("generatetoaddress", json!([blocks, address]))
            .await
            .map(|_| ())
    }
}

/// Poll `ready` for up to two minutes.
async fn wait_for<F, Fut>(what: &str, ready: F) -> Result<(), String>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    for _ in 0..240 {
        if ready().await {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Err(format!("timed out waiting for {what}"))
}

fn free_port() -> Result<u16, String> {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .map(|address| address.port())
        .map_err(|e| e.to_string())
}

fn workspace_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate lives in the workspace")
        .to_path_buf()
}

fn fedimintd_path() -> PathBuf {
    std::env::var_os("CASSIS_FEDIMINTD")
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace_dir().join("tmp/fedimintd-v0.12.1"))
}

fn hash(text: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    text.hash(&mut hasher);
    hasher.finish()
}
