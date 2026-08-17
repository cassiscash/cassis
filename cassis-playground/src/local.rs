//! A self-contained network of ledgers for end-to-end tests: an
//! in-process Nostr relay, `cdk-mintd` cashu mints with fake Lightning
//! backends, and single-guardian `fedimintd` federations on a regtest
//! `bitcoind`, all on free local ports under one directory. Nodes are
//! real [`Node`]s funded with the ledgers' fake money.
//!
//! Needs `cdk-mintd`, `cdk-cli` and `bitcoind` on `PATH`, and
//! `fedimintd` at `$CASSIS_FEDIMINTD` or `<workspace>/tmp/fedimintd-v0.12.1`.
//!
//! Bitcoin itself and arkade operators (`arkd`, see [`LocalEnv::arkd`],
//! funding nodes with arknotes) run on the same regtest `bitcoind`,
//! read through an in-process Esplora API.

use cassis_arkade::ArkadeAdapter;
use cassis_bitcoin::BitcoinAdapter;
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

const ARKD_PASSWORD: &str = "password";
/// Signs the operator's side of VTXO trees and offchain transactions.
const ARKD_SIGNER_KEY: &str = "afcd3fa10f82a05fddc9574fdb13b3991b568e89cc39a72ba4401df8abef35f0";
/// On-chain coins the operator starts with, to fund batches.
const ARKD_OPERATOR_BTC: f64 = 10.0;

pub struct LocalEnv {
    root: PathBuf,
    relay: String,
    children: Mutex<Vec<Child>>,
    bitcoind: OnceCell<Bitcoind>,
    esplora: OnceCell<String>,
    arkd: OnceCell<Arkd>,
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
            esplora: OnceCell::new(),
            arkd: OnceCell::new(),
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

    /// Esplora REST API over the regtest bitcoind.
    async fn esplora(&self) -> Result<&str, String> {
        let bitcoind = self.bitcoind().await?;
        self.esplora
            .get_or_try_init(|| crate::esplora::serve(bitcoind.clone()))
            .await
            .map(String::as_str)
    }

    /// Bitcoin itself: the regtest chain, read through the in-process
    /// Esplora API. Lockups need a confirmation (see
    /// [`mine`](Self::mine)) before receivers act on them.
    pub async fn bitcoin(&self) -> Result<NetworkId, String> {
        self.esplora().await?;
        NetworkId::parse("bitcoin::regtest")
    }

    /// Mine `blocks` regtest blocks.
    pub async fn mine(&self, blocks: u64) -> Result<(), String> {
        self.bitcoind().await?.mine(blocks).await
    }

    /// An arkd operator on the regtest bitcoind, as an arkade network,
    /// its on-chain wallet funded to finance batches.
    ///
    /// Uses `$CASSIS_ARKD` or `<workspace>/target/arkd-light`, building
    /// it with `cassis-playground/arkd/build.sh` (needs `go`) if missing.
    pub async fn arkd(&self) -> Result<NetworkId, String> {
        let arkd = self.arkd.get_or_try_init(|| Arkd::start(self)).await?;
        NetworkId::parse(&format!("arkade::127.0.0.1:{}", arkd.port))
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
                "arkade" => Wallet::Arkade(Arc::new(
                    ArkadeAdapter::open_with_esplora(
                        network.clone(),
                        secret,
                        Some(self.esplora().await?),
                        &span,
                    )
                    .await?,
                )),
                "bitcoin" => Wallet::Bitcoin(Arc::new(BitcoinAdapter::open_with_esplora(
                    network.clone(),
                    secret,
                    Some(self.esplora().await?),
                    &span,
                )?)),
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

    /// Run `task` while mining a block every two seconds, so ledgers
    /// timed by the regtest chain (fedimint contract expirations, arkade
    /// refund locktimes) keep up with the wall clock.
    pub async fn mine_while<T>(&self, task: impl std::future::Future<Output = T>) -> T {
        let bitcoind = self.bitcoind().await.ok().cloned();
        let miner = async {
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                if let Some(bitcoind) = &bitcoind {
                    if let Err(error) = bitcoind.mine(1).await {
                        tracing::warn!("mining: {error}");
                    }
                }
            }
        };
        tokio::select! {
            result = task => result,
            _ = miner => unreachable!("the miner never stops"),
        }
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
            Wallet::Bitcoin(wallet) => {
                let bitcoind = self.bitcoind().await?;
                let btc = amount_msat.div_ceil(1000) as f64 / 1e8;
                bitcoind
                    .rpc("sendtoaddress", json!([wallet.deposit_address(), btc]))
                    .await?;
                bitcoind.mine(1).await?;
                wait_for("bitcoin deposit", || async {
                    wallet
                        .balance_msat()
                        .await
                        .is_ok_and(|balance| balance >= amount_msat)
                })
                .await?;
            }
            Wallet::Arkade(wallet) => {
                let arkd = self.arkd.get().ok_or("arkd is not running")?;
                let note = arkd.note(amount_msat.div_ceil(1000)).await?;
                wallet.redeem_note(&note).await.map_err(|e| e.to_string())?;
                // Confirm the batch.
                self.bitcoind().await?.mine(1).await?;
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
    Arkade(Arc<ArkadeAdapter>),
    Bitcoin(Arc<BitcoinAdapter>),
}

impl Wallet {
    fn network(&self) -> Arc<dyn Network> {
        match self {
            Wallet::Cashu(wallet) => wallet.clone(),
            Wallet::Fedimint(wallet) => wallet.clone(),
            Wallet::Arkade(wallet) => wallet.clone(),
            Wallet::Bitcoin(wallet) => wallet.clone(),
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
            Wallet::Arkade(wallet) => wallet.balance_msat().await.map_err(|e| e.to_string()),
            Wallet::Bitcoin(wallet) => wallet.balance_msat().await.map_err(|e| e.to_string()),
        }
    }

    /// Route between all of this node's networks, announcing on the
    /// environment's relay.
    pub fn route(&self, prepare_veto: Option<PrepareVeto>) {
        self.route_with(RoutingPolicy {
            prepare_veto,
            ..RoutingPolicy::default()
        });
    }

    /// [`route`](Self::route) under `policy`, announcing on the
    /// environment's relay whatever relays it names.
    pub fn route_with(&self, policy: RoutingPolicy) {
        self.node.start_routing(RoutingPolicy {
            nostr_relays: self.relays.clone(),
            ..policy
        });
    }

    /// Take the node down: it stops answering, routing and settling.
    pub async fn shutdown(&self) {
        self.node.shutdown().await;
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

#[derive(Clone)]
pub(crate) struct Bitcoind {
    url: String,
    http: reqwest::Client,
}

impl Bitcoind {
    pub(crate) async fn rpc(&self, method: &str, params: Value) -> Result<Value, String> {
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

/// An arkd operator: `arkd-light` (arkd with its wallet in-process on
/// Esplora) in light mode.
struct Arkd {
    port: u16,
    admin: String,
    http: reqwest::Client,
}

impl Arkd {
    async fn start(env: &LocalEnv) -> Result<Self, String> {
        let esplora = env.esplora().await?.to_string();
        let binary = arkd_path().await?;
        let dir = env.next_dir("arkd");
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let (port, admin_port) = (free_port()?, free_port()?);
        let mut command = Command::new(&binary);
        command
            .env("ARKD_DATADIR", &dir)
            .env("ARKD_PORT", port.to_string())
            .env("ARKD_ADMIN_PORT", admin_port.to_string())
            .env("ARKD_NO_TLS", "true")
            .env("ARKD_NO_MACAROONS", "true")
            .env("ARKD_LOG_LEVEL", "5")
            .env("ARKD_ESPLORA_URL", &esplora)
            .env("ARKD_WALLET_NETWORK", "regtest")
            .env("ARKD_WALLET_SIGNER_KEY", ARKD_SIGNER_KEY)
            // Light mode.
            .env("ARKD_LIVE_STORE_TYPE", "inmemory")
            .env("ARKD_DB_TYPE", "sqlite")
            .env("ARKD_EVENT_DB_TYPE", "badger")
            // Quick batches; delays and expiries in seconds (multiples
            // of 512), since blocks are only mined on demand.
            .env("ARKD_SESSION_DURATION", "5")
            .env("ARKD_UNILATERAL_EXIT_DELAY", "512")
            .env("ARKD_PUBLIC_UNILATERAL_EXIT_DELAY", "512")
            .env("ARKD_CHECKPOINT_EXIT_DELAY", "512")
            .env("ARKD_BOARDING_EXIT_DELAY", "1024")
            .env("ARKD_VTXO_TREE_EXPIRY", "3584");
        let log = dir.join("arkd.log");
        env.spawn(command, &log).await?;
        let arkd = Self {
            port,
            admin: format!("http://127.0.0.1:{admin_port}/v1/admin"),
            http: reqwest::Client::new(),
        };
        wait_for(&format!("arkd (see {})", log.display()), || async {
            arkd.get("/wallet/status").await.is_ok()
        })
        .await?;
        let seed = arkd.get("/wallet/seed").await?["seed"].clone();
        arkd.post(
            "/wallet/create",
            json!({"seed": seed, "password": ARKD_PASSWORD}),
        )
        .await?;
        arkd.post("/wallet/unlock", json!({"password": ARKD_PASSWORD}))
            .await?;
        let info = format!("http://127.0.0.1:{port}/v1/info");
        wait_for("arkd to be ready", || async {
            reqwest::get(&info)
                .await
                .is_ok_and(|response| response.status().is_success())
        })
        .await?;

        let bitcoind = env.bitcoind().await?;
        let address = arkd.get("/wallet/address").await?["address"].clone();
        bitcoind
            .rpc("sendtoaddress", json!([address, ARKD_OPERATOR_BTC]))
            .await?;
        bitcoind.mine(1).await?;
        wait_for("arkd operator funds", || async {
            arkd.balance_sats()
                .await
                .is_ok_and(|sats| sats as f64 >= ARKD_OPERATOR_BTC * 1e8)
        })
        .await?;
        info!("arkd up on port {port}");
        Ok(arkd)
    }

    async fn get(&self, path: &str) -> Result<Value, String> {
        self.request(self.http.get(format!("{}{path}", self.admin)))
            .await
    }

    async fn post(&self, path: &str, body: Value) -> Result<Value, String> {
        self.request(self.http.post(format!("{}{path}", self.admin)).json(&body))
            .await
    }

    async fn request(&self, request: reqwest::RequestBuilder) -> Result<Value, String> {
        let response = request.send().await.map_err(|e| format!("arkd: {e}"))?;
        let status = response.status();
        let body: Value = response.json().await.map_err(|e| format!("arkd: {e}"))?;
        if !status.is_success() {
            return Err(format!("arkd: {status}: {body}"));
        }
        Ok(body)
    }

    /// Spendable sats in the operator's on-chain wallet.
    async fn balance_sats(&self) -> Result<u64, String> {
        let balance = self.get("/wallet/balance").await?;
        let btc = balance["mainAccount"]["available"]
            .as_str()
            .ok_or_else(|| format!("arkd balance: {balance}"))?;
        let (whole, fraction) = btc.split_once('.').unwrap_or((btc, "0"));
        let parse = |digits: &str| digits.parse::<u64>().map_err(|e| format!("{btc}: {e}"));
        Ok(parse(whole)? * 100_000_000 + parse(&format!("{fraction:0<8}")[..8])?)
    }

    /// An arknote worth `sats`, redeemable into VTXOs.
    async fn note(&self, sats: u64) -> Result<String, String> {
        let notes = self
            .post("/note", json!({"amount": sats, "quantity": 1}))
            .await?;
        notes["notes"][0]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| format!("arkd issued no note: {notes}"))
    }
}

/// `$CASSIS_ARKD`, or `target/arkd-light`, built on first use.
async fn arkd_path() -> Result<PathBuf, String> {
    if let Some(path) = std::env::var_os("CASSIS_ARKD") {
        return Ok(PathBuf::from(path));
    }
    let path = workspace_dir().join("target/arkd-light");
    static BUILD: OnceCell<()> = OnceCell::const_new();
    BUILD
        .get_or_try_init(|| async {
            if path.exists() {
                return Ok(());
            }
            info!("building arkd-light (once)");
            let output = Command::new(workspace_dir().join("cassis-playground/arkd/build.sh"))
                .arg(&path)
                .output()
                .await
                .map_err(|e| format!("build arkd-light: {e}"))?;
            if !output.status.success() {
                return Err(format!(
                    "build arkd-light: {}",
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
            Ok(())
        })
        .await?;
    Ok(path)
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
