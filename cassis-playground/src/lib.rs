use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex as StdMutex};

use cassis_client::netspec::NetSpec;
use cassis_client::ops::{
    create_invoice_with_claim_pubkeys, init_node_home, load_and_derive, node_store_path,
    start_receive_with,
};
use cassis_client::store::CashuProofDb;
use cassis_client::CassisClient;
use cassis_core::logging::ScopeFields;
use cassis_core::{NetworkId, NetworkReceiverAdapter, NetworkRouterAdapter, NetworkSenderAdapter};
use cdk::nuts::Token;
use ritualistic::server::{CustomRelay, RelayInternals};
use ritualistic::{Event as NostrEvent, Filter as NostrFilter};
use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{Context, Editor, ExternalPrinter, Helper};
use sha2::{Digest, Sha256};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tracing::Instrument;
use tracing::{error, info, info_span, warn, Event, Span, Subscriber};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::layer::{Context as SubscriberContext, Layer};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;

const ROOT: &str = "tmp/playground";

/// Root directory for the e2e test environment. Kept in `target/` so
/// `cargo clean` wipes test state and normal builds never touch it.
pub const E2E_ROOT: &str = "target/e2e";
const COMMAND_HISTORY: &str = "commands.history";
pub const RELAY: &str = "ws://localhost:10000";
pub const DEFAULT_PREFUND_SEED: &str =
    "position emerge strong hawk clog educate suspect sport vast forward gesture absorb";
const DEFAULT_FUND_AMOUNT: u64 = 1000;

struct NetworkDef {
    id: &'static str,
    spec: &'static str,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct BalanceMsat(u64);

impl fmt::Display for BalanceMsat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let digits = self.0.to_string();
        for (index, digit) in digits.chars().enumerate() {
            if index > 0 && (digits.len() - index).is_multiple_of(3) {
                f.write_str("_")?;
            }
            write!(f, "{digit}")?;
        }
        f.write_str("msat")
    }
}

const NETWORKS: &[NetworkDef] = &[
    NetworkDef {
        id: "cashu_1",
        spec: "cashu::127.0.0.1:8091",
    },
    NetworkDef {
        id: "cashu_2",
        spec: "cashu::127.0.0.1:8092",
    },
    NetworkDef {
        id: "cashu_3",
        spec: "cashu::127.0.0.1:8093",
    },
    NetworkDef {
        id: "rootstock_testnet",
        spec: "rootstock::testnet",
    },
    NetworkDef {
        id: "arkade_testnet",
        spec: "arkade::mutinynet",
    },
    NetworkDef {
        id: "bitcoin_mutinynet",
        spec: "bitcoin::mutinynet",
    },
    NetworkDef {
        id: "liquid_testnet",
        spec: "liquid::testnet",
    },
];

const NODE_NAMES: &[&str] = &[
    "alice", "bob", "charlie", "derek", "ernest", "frank", "george",
];
/// Human-readable color names paired with their ANSI foreground codes,
/// index-aligned with [`NODE_NAMES`].
const NODE_COLORS: &[(&str, &str)] = &[
    ("red", "91"),
    ("green", "92"),
    ("blue", "94"),
    ("yellow", "93"),
    ("magenta", "95"),
    ("cyan", "96"),
    ("white", "97"),
];

#[derive(Clone, Debug)]
enum Status {
    Idle,
    Routing,
    Paying,
    Receiving,
}

impl Status {
    fn label(&self) -> &'static str {
        match self {
            Status::Idle => "idle",
            Status::Routing => "routing",
            Status::Paying => "paying",
            Status::Receiving => "listening",
        }
    }
}

/// One open network wallet for a node. Built once at playground
/// startup and shared by balance refresh, funding, paying, receiving
/// and routing: some networks (Liquid) hold an exclusive lock on
/// their wallet state, so reopening is not even possible while a
/// router runs.
#[derive(Clone)]
enum NodeWallet {
    Cashu(Arc<cassis_cashu::CashuAdapter>),
    Arkade(Arc<cassis_arkade::ArkadeAdapter>),
    Bitcoin(Arc<cassis_bitcoin::BitcoinAdapter>),
    Liquid(Arc<cassis_liquid::LiquidAdapter>),
    Rootstock(Arc<cassis_rootstock::RootstockAdapter>),
}

impl NodeWallet {
    fn router(&self) -> Arc<dyn NetworkRouterAdapter> {
        match self {
            NodeWallet::Cashu(a) => a.clone(),
            NodeWallet::Arkade(a) => a.clone(),
            NodeWallet::Bitcoin(a) => a.clone(),
            NodeWallet::Liquid(a) => a.clone(),
            NodeWallet::Rootstock(a) => a.clone(),
        }
    }

    fn receiver(&self) -> Arc<dyn NetworkReceiverAdapter> {
        match self {
            NodeWallet::Cashu(a) => a.clone(),
            NodeWallet::Arkade(a) => a.clone(),
            NodeWallet::Bitcoin(a) => a.clone(),
            NodeWallet::Liquid(a) => a.clone(),
            NodeWallet::Rootstock(a) => a.clone(),
        }
    }

    fn sender(&self) -> Arc<dyn NetworkSenderAdapter> {
        match self {
            NodeWallet::Cashu(a) => a.clone(),
            NodeWallet::Arkade(a) => a.clone(),
            NodeWallet::Bitcoin(a) => a.clone(),
            NodeWallet::Liquid(a) => a.clone(),
            NodeWallet::Rootstock(a) => a.clone(),
        }
    }

    async fn balance_msat(&self) -> Result<u64, String> {
        match self {
            NodeWallet::Cashu(a) => Ok(a
                .balance()
                .await
                .iter()
                .map(|p| u64::from(p.amount))
                .sum::<u64>()
                .saturating_mul(1000)),
            NodeWallet::Arkade(a) => a.balance_msat().await.map_err(|e| e.to_string()),
            NodeWallet::Bitcoin(a) => a.balance_msat().await.map_err(|e| e.to_string()),
            NodeWallet::Liquid(a) => a.balance_msat().await.map_err(|e| e.to_string()),
            NodeWallet::Rootstock(a) => a.balance_msat().await.map_err(|e| e.to_string()),
        }
    }
}

struct NodeState {
    id: String,
    span: Span,
    nostr_pubkey: String,
    iroh_id: String,
    memberships: Vec<String>,
    status: Status,
    /// Open network wallets, keyed by wire `NetworkId`.
    wallets: HashMap<NetworkId, NodeWallet>,
}

struct PlaygroundLogLayer {
    lines: Arc<StdMutex<VecDeque<String>>>,
    printer: Arc<StdMutex<Option<Box<dyn ExternalPrinter + Send>>>>,
}

impl<S> Layer<S> for PlaygroundLogLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &Event<'_>, ctx: SubscriberContext<'_, S>) {
        let metadata = event.metadata();
        if !matches!(
            *metadata.level(),
            tracing::Level::INFO | tracing::Level::WARN | tracing::Level::ERROR
        ) || metadata.target().starts_with("iroh")
        {
            return;
        }
        let mut message = String::new();
        event.record(&mut PlaygroundMessageVisitor(&mut message));
        if message.starts_with("request; method_names=")
            || message == "connection handled successfully"
        {
            return;
        }
        let trimmed = message.trim_end();
        if trimmed.ends_with(';') && !trimmed[..trimmed.len() - 1].contains(char::is_whitespace) {
            return;
        }
        // Walk the whole scope, not just the innermost span: an adapter
        // log is emitted inside a per-network span that is a *child* of
        // the node span, so the innermost span carries `network` while
        // only its parent carries `node`.
        let scope = ctx
            .event_scope(event)
            .map(ScopeFields::from_scope)
            .unwrap_or_default();
        let prefix = match (&scope.node, &scope.network) {
            (Some(node), Some(network)) => Some(format!(
                "{}/{}",
                colored_node_name(node),
                colored_network_name(network),
            )),
            (Some(node), None) => Some(colored_node_name(node)),
            (None, Some(network)) => Some(colored_network_name(network)),
            (None, None) => None,
        };
        let line = prefix
            .map(|prefix| format!("[{}] {}: {}", metadata.level(), prefix, message))
            .unwrap_or_else(|| format!("[{}] {}", metadata.level(), message));
        if let Ok(mut printer) = self.printer.lock() {
            if let Some(printer) = printer.as_mut() {
                let _ = printer.print(format!("{line}\n"));
                return;
            }
        }
        if let Ok(mut lines) = self.lines.lock() {
            lines.push_back(line);
            while lines.len() > 100 {
                lines.pop_front();
            }
        }
    }
}

struct PlaygroundMessageVisitor<'a>(&'a mut String);

impl tracing::field::Visit for PlaygroundMessageVisitor<'_> {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.0.push_str(value);
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
        if field.name() == "message" {
            use std::fmt::Write;
            let _ = write!(self.0, "{value:?}");
        }
    }
}

#[derive(Default)]
struct MemoryRelay {
    events: Vec<NostrEvent>,
}

impl CustomRelay for MemoryRelay {
    fn handle_event(&mut self, event: &NostrEvent) -> Result<(), String> {
        if !event.check_id() || !event.verify_signature() {
            return Err("invalid event".to_string());
        }
        if self.events.iter().any(|existing| existing.id == event.id) {
            return Err("duplicate event".to_string());
        }
        self.events.push(event.clone());
        Ok(())
    }

    fn handle_request(&mut self, filter: &NostrFilter) -> Result<Vec<NostrEvent>, String> {
        Ok(self
            .events
            .iter()
            .filter(|event| filter.matches(event))
            .cloned()
            .collect())
    }
}

pub struct Playground {
    root: PathBuf,
    nodes: Mutex<HashMap<String, NodeState>>,
    children: Mutex<Vec<Child>>,
    balances: Mutex<HashMap<(String, String), BalanceMsat>>,
    prefund_seed: String,
    prefund_liquid: Arc<cassis_liquid::LiquidAdapter>,
    prefund_arkade: Arc<cassis_arkade::ArkadeAdapter>,
    prefund_bitcoin: Arc<cassis_bitcoin::BitcoinAdapter>,
    prefund_rootstock: Arc<cassis_rootstock::RootstockAdapter>,
}

/// The three chain-network prefund wallets, built from a seed without
/// starting the playground's relay, mints or nodes. Used by the
/// standalone `cassis-prefund` wait script so it can report addresses
/// and poll balances while the operator funds them, and by the e2e
/// tests to move funds into node wallets.
pub struct PrefundWallets {
    pub liquid: Arc<cassis_liquid::LiquidAdapter>,
    pub arkade: Arc<cassis_arkade::ArkadeAdapter>,
    pub bitcoin: Arc<cassis_bitcoin::BitcoinAdapter>,
    pub rootstock: Arc<cassis_rootstock::RootstockAdapter>,
}

impl PrefundWallets {
    /// Build the three prefund wallets for `seed` under `root`. Mirrors
    /// the prefund section of [`Playground::new`].
    pub async fn build(root: &Path, seed: &str) -> Result<Self, String> {
        std::fs::create_dir_all(root).map_err(|e| e.to_string())?;
        std::fs::create_dir_all(prefund_store_path(root, seed).parent().unwrap_or(root))
            .map_err(|e| e.to_string())?;
        let span = info_span!("prefund");
        let liquid_spec = NetSpec::parse("liquid::testnet")?;
        let liquid = cassis_client::adapters::build_liquid_adapter(
            &liquid_spec,
            &prefund_keys(seed, &liquid_spec)?,
            &prefund_store_path(root, seed),
            span.clone(),
        )
        .await?;
        let arkade_spec = NetSpec::parse("arkade::mutinynet")?;
        let arkade = cassis_client::adapters::build_arkade_adapter(
            &arkade_spec,
            &prefund_keys(seed, &arkade_spec)?,
            span.clone(),
        )
        .await?;
        let bitcoin_spec = NetSpec::parse("bitcoin::mutinynet")?;
        let bitcoin = cassis_client::adapters::build_bitcoin_adapter(
            &bitcoin_spec,
            &prefund_keys(seed, &bitcoin_spec)?,
            span.clone(),
        )
        .await?;
        let rootstock_spec = NetSpec::parse("rootstock::testnet")?;
        let rootstock = cassis_client::adapters::build_rootstock_adapter(
            &rootstock_spec,
            &prefund_keys(seed, &rootstock_spec)?,
            span,
        )
        .await?;
        Ok(Self {
            liquid,
            arkade,
            bitcoin,
            rootstock,
        })
    }

    /// Deposit addresses, as `(network_id, address)` pairs. For arkade
    /// the boarding address is reported (deposits there settle into
    /// spendable VTXOs after `onboard`).
    pub async fn addresses(&self) -> Result<Vec<(String, String)>, String> {
        let liquid = self
            .liquid
            .deposit_address()
            .await
            .map_err(|e| e.to_string())?;
        let (boarding, _, _) = self
            .arkade
            .deposit_addresses()
            .await
            .map_err(|e| e.to_string())?;
        Ok(vec![
            ("liquid_testnet".to_string(), liquid),
            ("arkade_testnet".to_string(), boarding),
            (
                "bitcoin_mutinynet".to_string(),
                self.bitcoin.deposit_address(),
            ),
            (
                "rootstock_testnet".to_string(),
                self.rootstock.address().to_string(),
            ),
        ])
    }

    /// Current balance in msat for one chain network
    /// (`liquid_testnet`, `arkade_testnet` or `rootstock_testnet`).
    pub async fn balance_msat(&self, network: &str) -> Result<u64, String> {
        match network {
            "liquid_testnet" => self.liquid.balance_msat().await.map_err(|e| e.to_string()),
            "arkade_testnet" => self.arkade.balance_msat().await.map_err(|e| e.to_string()),
            "bitcoin_mutinynet" => self.bitcoin.balance_msat().await.map_err(|e| e.to_string()),
            "rootstock_testnet" => self
                .rootstock
                .balance_msat()
                .await
                .map_err(|e| e.to_string()),
            other => Err(format!("unknown prefund network '{other}'")),
        }
    }

    /// Best-effort arkade onboarding so a confirmed boarding deposit
    /// settles into spendable VTXOs. Returns the commitment txid when a
    /// swap was committed, `None` when there was nothing to settle.
    pub async fn onboard_arkade(&self) -> Result<Option<String>, String> {
        self.arkade
            .onboard()
            .await
            .map(|r| r.map(|txid| txid.to_string()))
            .map_err(|e| e.to_string())
    }
}

impl Playground {
    pub async fn new(prefund_seed: String, root: PathBuf) -> Result<Arc<Self>, String> {
        std::fs::create_dir_all(&root).map_err(|e| e.to_string())?;
        std::fs::create_dir_all(
            prefund_store_path(&root, &prefund_seed)
                .parent()
                .unwrap_or(&root),
        )
        .map_err(|e| e.to_string())?;
        let prefund = PrefundWallets::build(&root, &prefund_seed).await?;
        let prefund_liquid = prefund.liquid;
        let prefund_arkade = prefund.arkade;
        let prefund_bitcoin = prefund.bitcoin;
        let prefund_rootstock = prefund.rootstock;
        let network_ids = NETWORKS
            .iter()
            .map(|network| NetSpec::parse(network.spec).map(|spec| spec.network_id()))
            .collect::<Result<Vec<_>, _>>()?;
        let mut nodes = HashMap::new();
        let mut iroh_ids = HashSet::new();
        let mut nostr_pubkeys = HashSet::new();
        for (idx, id) in NODE_NAMES.iter().enumerate() {
            let home = node_home(&root, id);
            init_node_home(&home)?;
            let keys = load_and_derive(&home, network_ids.clone())?;
            let nostr_pubkey = keys.nostr.pubkey().to_hex();
            let iroh_id = keys.iroh.public().to_string();
            if !iroh_ids.insert(iroh_id.clone()) {
                return Err(format!("duplicate iroh identity for node {id}: {iroh_id}"));
            }
            if !nostr_pubkeys.insert(nostr_pubkey.clone()) {
                return Err(format!(
                    "duplicate nostr identity for node {id}: {nostr_pubkey}"
                ));
            }
            nodes.insert(
                (*id).to_string(),
                NodeState {
                    id: (*id).to_string(),
                    span: info_span!("node", node = *id),
                    nostr_pubkey,
                    iroh_id,
                    memberships: Vec::new(),
                    status: Status::Idle,
                    // Wallets open lazily on `open`, `fund` or `router`.
                    wallets: HashMap::new(),
                },
            );
            info!("created {id} ({})", NODE_COLORS[idx].0);
        }
        let playground = Arc::new(Self {
            root: root.clone(),
            nodes: Mutex::new(nodes),
            children: Mutex::new(Vec::new()),
            balances: Mutex::new(HashMap::new()),
            prefund_seed,
            prefund_liquid,
            prefund_arkade,
            prefund_bitcoin,
            prefund_rootstock,
        });
        playground.start_infrastructure().await?;
        Ok(playground)
    }

    async fn start_infrastructure(&self) -> Result<(), String> {
        let relay = RelayInternals {
            info: ritualistic::relay_information::RelayInformationDocument {
                url: RELAY.to_string(),
                name: "cassis playground".to_string(),
                description: "in-process relay".to_string(),
                ..Default::default()
            },
            custom_relay: Box::new(tokio::sync::Mutex::new(MemoryRelay::default())),
        };
        tokio::spawn(async move {
            if let Err(error) = ritualistic::server::start(
                Arc::new(relay),
                "127.0.0.1:10000".parse().expect("valid relay address"),
            )
            .await
            {
                tracing::error!("relay stopped: {error}");
            }
        });
        for network in NETWORKS {
            let NetSpec::Cashu { host, .. } = NetSpec::parse(network.spec)? else {
                continue;
            };
            let (listen_host, listen_port) = host
                .rsplit_once(':')
                .ok_or_else(|| format!("cashu spec '{}' needs host:port", network.spec))?;
            let dir = mint_dir(&self.root, network.id);
            std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
            let seed = dir.join("seed");
            if !seed.exists() {
                std::fs::write(
                    &seed,
                    "hire movie pyramid only journey sun eight stadium salt engage inmate enlist",
                )
                .map_err(|e| e.to_string())?;
            }
            let mut mint = Command::new("cdk-mintd");
            mint.arg("-w")
                .arg(&dir)
                .arg("--seed-file")
                .arg(&seed)
                .arg("--enable-logging")
                .env("CDK_MINTD_LISTEN_HOST", listen_host)
                .env("CDK_MINTD_LISTEN_PORT", listen_port)
                .env("CDK_MINTD_LN_BACKEND", "fakewallet")
                .env("CDK_MINTD_FAKE_WALLET_SUPPORTED_UNITS", "sat")
                .env("CDK_MINTD_FAKE_WALLET_FEE_PERCENT", "0")
                .env("CDK_MINTD_FAKE_WALLET_RESERVE_FEE_MIN", "0");
            self.spawn_child(mint, &format!("{} mint", network.id))
                .await?;
        }
        info!("infrastructure started; relay {RELAY}");
        Ok(())
    }

    async fn spawn_child(&self, mut command: Command, label: &str) -> Result<(), String> {
        command
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let child = command.spawn().map_err(|e| format!("{label}: {e}"))?;
        info!("started {label} pid={:?}", child.id());
        self.children.lock().await.push(child);
        Ok(())
    }

    async fn summary(&self) -> String {
        let mut output = String::new();
        let nodes = self.nodes.lock().await;
        let balances = self.balances.lock().await;
        let mut sorted_nodes: Vec<&NodeState> = nodes.values().collect();
        sorted_nodes.sort_by(|left, right| left.id.cmp(&right.id));
        for node in &sorted_nodes {
            output.push_str(&format!(
                "{} [pub:…{} iroh:…{}]\n",
                colored_node_name(&node.id),
                identity_suffix(&node.nostr_pubkey),
                identity_suffix(&node.iroh_id),
            ));
        }
        if !output.is_empty() {
            output.push('\n');
        }
        // The shared prefund wallet: always shown, it is where manual
        // test-coin deposits land before `fund` distributes them.
        output.push_str(&format!("{}:\n", colored_node_name("prefund")));
        for network_id in [
            "arkade_testnet",
            "bitcoin_mutinynet",
            "liquid_testnet",
            "rootstock_testnet",
        ] {
            let balance = balances
                .get(&("prefund".to_string(), network_id.to_string()))
                .map(|b| b.to_string())
                .unwrap_or_else(|| "?".to_string());
            output.push_str(&format!(
                "  {}: {}\n",
                colored_network_name(network_id),
                balance
            ));
        }
        output.push('\n');
        let mut network_ids: Vec<String> = nodes
            .values()
            .flat_map(|node| node.memberships.iter().cloned())
            .collect();
        network_ids.sort();
        network_ids.dedup();
        for network_id in network_ids {
            let mut lines: Vec<String> = Vec::new();
            for node in &sorted_nodes {
                if !node.memberships.iter().any(|m| m == &network_id) {
                    continue;
                }
                if let Some(balance) = balances.get(&(node.id.clone(), network_id.clone())) {
                    lines.push(format!(
                        "  {}: {} ({})",
                        colored_node_name(&node.id),
                        balance,
                        node.status.label()
                    ));
                }
            }
            if !lines.is_empty() {
                output.push_str(&format!("{}:\n", colored_network_name(&network_id)));
                output.push_str(&lines.join("\n"));
                output.push('\n');
            }
        }
        output
    }

    /// Recompute every displayed balance. Called once after a command
    /// completes, never from the render loop. Balances are fetched
    /// concurrently: each one is a network sync (esplora full scan,
    /// ark server, RPC), so serialising them multiplies latency.
    async fn refresh_balances(self: &Arc<Self>) {
        let entries: Vec<(String, String)> = {
            let nodes = self.nodes.lock().await;
            nodes
                .values()
                .flat_map(|node| {
                    node.memberships
                        .iter()
                        .map(|network| (node.id.clone(), network.clone()))
                        .collect::<Vec<_>>()
                })
                .collect()
        };
        let mut handles = Vec::with_capacity(entries.len());
        for (node_id, network_id) in entries {
            let playground = self.clone();
            handles.push(tokio::spawn(async move {
                let value = match playground.node_balance(&node_id, &network_id).await {
                    Ok(value) => value,
                    Err(error) => {
                        warn!("balance refresh failed for {node_id} on {network_id}: {error}");
                        BalanceMsat::default()
                    }
                };
                ((node_id, network_id), value)
            }));
        }
        // The prefund wallet rides along so `summary` always shows how
        // much test coin is available for distribution.
        for (network_id, wallet) in [
            (
                "arkade_testnet",
                NodeWallet::Arkade(self.prefund_arkade.clone()),
            ),
            (
                "bitcoin_mutinynet",
                NodeWallet::Bitcoin(self.prefund_bitcoin.clone()),
            ),
            (
                "liquid_testnet",
                NodeWallet::Liquid(self.prefund_liquid.clone()),
            ),
            (
                "rootstock_testnet",
                NodeWallet::Rootstock(self.prefund_rootstock.clone()),
            ),
        ] {
            handles.push(tokio::spawn(async move {
                let value = match wallet.balance_msat().await {
                    Ok(value) => BalanceMsat(value),
                    Err(error) => {
                        warn!("prefund balance refresh failed on {network_id}: {error}");
                        BalanceMsat::default()
                    }
                };
                (("prefund".to_string(), network_id.to_string()), value)
            }));
        }
        let mut balances = self.balances.lock().await;
        for handle in handles {
            if let Ok((key, value)) = handle.await {
                balances.insert(key, value);
            }
        }
    }

    /// Best-effort onboarding of the prefund arkade wallet: joins the
    /// next batch swap when confirmed boarding outputs (or recoverable
    /// VTXOs) exist, so `fund ... arkade_testnet` can spend them.
    async fn auto_onboard_prefund(&self) {
        match self.prefund_arkade.onboard().await {
            Ok(Some(txid)) => info!(
                "prefund: boarding outputs onboarded (commitment {txid}); \
                 coins are spendable after the batch swap confirms"
            ),
            Ok(None) => {}
            Err(error) => warn!("prefund: onboard check failed: {error}"),
        }
    }

    /// The node's open wallet for `network_id`, opening it on first
    /// use. Idempotent: concurrent callers racing on the same network
    /// share whichever adapter landed in the map first.
    async fn ensure_wallet(
        &self,
        node_id: &str,
        network_id: &NetworkId,
    ) -> Result<NodeWallet, String> {
        {
            let nodes = self.nodes.lock().await;
            if let Some(wallet) = nodes
                .get(node_id)
                .ok_or_else(|| format!("unknown node '{node_id}'"))?
                .wallets
                .get(network_id)
            {
                return Ok(wallet.clone());
            }
        }
        let spec = NETWORKS
            .iter()
            .filter_map(|n| NetSpec::parse(n.spec).ok())
            .find(|s| s.network_id() == *network_id)
            .ok_or_else(|| format!("unknown network '{network_id}'"))?;
        let wallet = self.open_wallet(node_id, &spec).await?;
        let mut nodes = self.nodes.lock().await;
        let node = nodes
            .get_mut(node_id)
            .ok_or_else(|| format!("unknown node '{node_id}'"))?;
        match node.wallets.get(network_id) {
            Some(existing) => Ok(existing.clone()),
            None => {
                node.wallets.insert(network_id.clone(), wallet.clone());
                Ok(wallet)
            }
        }
    }

    /// Build a fresh adapter for `node_id`/`spec` from the node's
    /// derived keys. Does not register it; callers use
    /// [`Playground::ensure_wallet`].
    async fn open_wallet(&self, node_id: &str, spec: &NetSpec) -> Result<NodeWallet, String> {
        let home = node_home(&self.root, node_id);
        let derived = load_and_derive(&home, vec![spec.network_id()])?;
        let span = self.node_span(node_id).await;
        let network_id = spec.network_id();
        let wallet = match spec {
            NetSpec::Cashu { mint_url, .. } => {
                let sk = derived
                    .networks
                    .get(&network_id)
                    .map(|k| *k.as_bytes())
                    .ok_or_else(|| format!("no key derived for {network_id}"))?;
                let store: Arc<dyn cassis_cashu::CashuProofStore> =
                    Arc::new(CashuProofDb::new(node_store_path(&home)));
                NodeWallet::Cashu(Arc::new(
                    cassis_cashu::CashuAdapter::new(
                        network_id.clone(),
                        mint_url.clone(),
                        sk,
                        derived.invoice.pubkey(),
                        store,
                        span,
                    )
                    .map_err(|e| format!("cashu adapter init failed: {e}"))?,
                ))
            }
            NetSpec::Arkade { .. } => NodeWallet::Arkade(
                cassis_client::adapters::build_arkade_adapter(spec, &derived, span).await?,
            ),
            NetSpec::Bitcoin { .. } => NodeWallet::Bitcoin(
                cassis_client::adapters::build_bitcoin_adapter(spec, &derived, span).await?,
            ),
            NetSpec::Liquid { .. } => NodeWallet::Liquid(
                cassis_client::adapters::build_liquid_adapter(
                    spec,
                    &derived,
                    &node_store_path(&home),
                    span,
                )
                .await?,
            ),
            NetSpec::Rootstock { .. } => NodeWallet::Rootstock(
                cassis_client::adapters::build_rootstock_adapter(spec, &derived, span).await?,
            ),
            NetSpec::Lightning => {
                return Err("playground does not support the 'lightning' network yet".into());
            }
            NetSpec::Fedimint { .. } => {
                return Err("playground does not support the 'fedimint' network yet".into());
            }
        };
        Ok(wallet)
    }

    async fn node_balance(&self, node_id: &str, network_id: &str) -> Result<BalanceMsat, String> {
        let spec = NetSpec::parse(network(network_id)?.spec)?;
        // Read-only: balance refresh must not open wallets, otherwise
        // `summary` would connect to every chain for every node.
        let wallet = {
            let nodes = self.nodes.lock().await;
            nodes
                .get(node_id)
                .ok_or_else(|| format!("unknown node '{node_id}'"))?
                .wallets
                .get(&spec.network_id())
                .cloned()
                .ok_or_else(|| format!("node {node_id} has no open wallet for {network_id}"))?
        };
        Ok(BalanceMsat(wallet.balance_msat().await?))
    }

    /// Public balance check in msat, opening the node's wallet for
    /// `network_id` if it is not already open. Used by e2e tests to
    /// assert a node has enough funds before a payment is attempted.
    pub async fn balance_msat(&self, node_id: &str, network_id: &str) -> Result<u64, String> {
        let spec = NetSpec::parse(network(network_id)?.spec)?;
        let wallet = self.ensure_wallet(node_id, &spec.network_id()).await?;
        wallet.balance_msat().await
    }

    /// Prefund-wallet balance in msat for a chain network
    /// (`liquid_testnet`, `arkade_testnet` or `rootstock_testnet`).
    pub async fn prefund_balance_msat(&self, network: &str) -> Result<u64, String> {
        match network {
            "liquid_testnet" => self
                .prefund_liquid
                .balance_msat()
                .await
                .map_err(|e| e.to_string()),
            "arkade_testnet" => self
                .prefund_arkade
                .balance_msat()
                .await
                .map_err(|e| e.to_string()),
            "bitcoin_mutinynet" => self
                .prefund_bitcoin
                .balance_msat()
                .await
                .map_err(|e| e.to_string()),
            "rootstock_testnet" => self
                .prefund_rootstock
                .balance_msat()
                .await
                .map_err(|e| e.to_string()),
            other => Err(format!("unknown prefund network '{other}'")),
        }
    }

    async fn node_span(&self, node_id: &str) -> Span {
        self.nodes
            .lock()
            .await
            .get(node_id)
            .map(|node| node.span.clone())
            .unwrap_or_else(Span::none)
    }
}

fn colored_node_name(name: &str) -> String {
    let code = NODE_NAMES
        .iter()
        .position(|candidate| *candidate == name)
        .and_then(|index| NODE_COLORS.get(index))
        .map_or("0", |(_, code)| *code);
    format!("\x1b[{code}m{name}\x1b[0m")
}

fn colored_network_name(name: &str) -> String {
    let background = if name.starts_with("cashu") { 44 } else { 41 };
    let foreground = match name {
        "cashu_1" => 97,
        "cashu_2" => 93,
        "cashu_3" => 96,
        // Both the playground's own id and the wire `NetworkId`, since
        // adapter spans carry the latter.
        "rootstock_testnet" | "rootstock::testnet" => 97,
        "arkade_testnet" | "arkade::mutinynet" => 94,
        "bitcoin_mutinynet" | "bitcoin::mutinynet" => 35,
        "liquid_testnet" | "liquid::testnet" => 92,
        _ => 37,
    };
    format!("\x1b[{background};{foreground}m{name}\x1b[0m")
}

fn identity_suffix(identity: &str) -> &str {
    identity
        .get(identity.len().saturating_sub(4)..)
        .unwrap_or(identity)
}

fn network(id: &str) -> Result<&'static NetworkDef, String> {
    NETWORKS
        .iter()
        .find(|n| n.id == id)
        .ok_or_else(|| format!("unknown network '{id}'"))
}

fn parse_specs(network_ids: &[String]) -> Result<Vec<NetSpec>, String> {
    network_ids
        .iter()
        .map(|id| NetSpec::parse(network(id)?.spec))
        .collect()
}

fn prefund_keys(prefund_seed: &str, spec: &NetSpec) -> Result<cassis_keys::DerivedKeys, String> {
    cassis_keys::derive_keys(prefund_seed, vec![spec.network_id()]).map_err(|e| e.to_string())
}

pub fn node_home(root: &Path, id: &str) -> PathBuf {
    root.join("nodes").join(id)
}
fn mint_dir(root: &Path, id: &str) -> PathBuf {
    root.join("mints").join(id)
}
fn cdk_dir(root: &Path, id: &str) -> PathBuf {
    root.join("cdk").join(id)
}

fn prefund_store_path(root: &Path, seed: &str) -> PathBuf {
    let digest = Sha256::digest(seed.as_bytes());
    root.join("prefund/liquid")
        .join(format!("{:x}", digest))
        .join("store.db")
}

pub async fn command_fund(
    playground: &Playground,
    node_id: &str,
    network_id: &str,
    amount: u64,
) -> Result<(), String> {
    let spec = NetSpec::parse(network(network_id)?.spec)?;
    // Open before joining: membership implies an open wallet, which
    // is what balance refresh assumes.
    let wallet = playground
        .ensure_wallet(node_id, &spec.network_id())
        .await?;
    ensure_membership(playground, node_id, network_id).await?;
    match &spec {
        NetSpec::Cashu { mint_url, .. } => {
            fund_cashu(
                &playground.root,
                node_id,
                network_id,
                wallet,
                mint_url,
                amount,
            )
            .await
        }
        NetSpec::Arkade { .. } => {
            fund_arkade(&playground.prefund_arkade, node_id, &wallet, amount).await
        }
        NetSpec::Bitcoin { .. } => {
            fund_bitcoin(&playground.prefund_bitcoin, node_id, &wallet, amount).await
        }
        NetSpec::Liquid { .. } => {
            fund_liquid(&playground.prefund_liquid, node_id, &wallet, amount).await
        }
        NetSpec::Rootstock { .. } => {
            fund_rootstock(&playground.prefund_rootstock, node_id, &wallet, amount).await
        }
        NetSpec::Lightning => Err("playground does not support funding 'lightning'".into()),
        NetSpec::Fedimint { .. } => Err("playground does not support funding 'fedimint'".into()),
    }
}

async fn fund_bitcoin(
    source: &cassis_bitcoin::BitcoinAdapter,
    node_id: &str,
    target: &NodeWallet,
    amount_msat: u64,
) -> Result<(), String> {
    let NodeWallet::Bitcoin(adapter) = target else {
        return Err("target wallet is not bitcoin".into());
    };
    let txid = source
        .transfer_to_address(&adapter.deposit_address(), amount_msat)
        .await
        .map_err(|e| e.to_string())?;
    info!(
        "funded {node_id} on {}: {amount_msat} msat, tx {txid}",
        colored_network_name("bitcoin_mutinynet"),
    );
    Ok(())
}

async fn fund_liquid(
    source: &cassis_liquid::LiquidAdapter,
    node_id: &str,
    target: &NodeWallet,
    amount_msat: u64,
) -> Result<(), String> {
    let NodeWallet::Liquid(adapter) = target else {
        return Err("target wallet is not liquid".into());
    };
    let address = adapter.deposit_address().await.map_err(|e| e.to_string())?;
    let txid = source
        .transfer_to_address(&address, amount_msat)
        .await
        .map_err(|e| e.to_string())?;
    info!(
        "funded {node_id} on {}: {amount_msat} sat, tx {txid}",
        colored_network_name("liquid_testnet"),
    );
    Ok(())
}

async fn fund_arkade(
    source: &cassis_arkade::ArkadeAdapter,
    node_id: &str,
    target: &NodeWallet,
    amount_msat: u64,
) -> Result<(), String> {
    let NodeWallet::Arkade(adapter) = target else {
        return Err("target wallet is not arkade".into());
    };
    let (_, _, arkade) = adapter
        .deposit_addresses()
        .await
        .map_err(|e| e.to_string())?;
    let txid = source
        .transfer_to_ark_address(&arkade, amount_msat)
        .await
        .map_err(|e| e.to_string())?;
    info!(
        "funded {node_id} on {}: {amount_msat} sat, tx {txid}",
        colored_network_name("arkade_testnet"),
    );
    Ok(())
}

async fn ensure_membership(
    playground: &Playground,
    node_id: &str,
    network_id: &str,
) -> Result<(), String> {
    let mut nodes = playground.nodes.lock().await;
    let node = nodes
        .get_mut(node_id)
        .ok_or_else(|| format!("unknown node '{node_id}'"))?;
    if !node.memberships.iter().any(|x| x == network_id) {
        node.memberships.push(network_id.to_string());
    }
    Ok(())
}

async fn fund_cashu(
    root: &Path,
    node_id: &str,
    network_id: &str,
    wallet: NodeWallet,
    mint_url: &str,
    amount_msat: u64,
) -> Result<(), String> {
    let cdk = cdk_dir(root, network_id);
    std::fs::create_dir_all(&cdk).map_err(|e| e.to_string())?;
    let mint = Command::new("cdk-cli")
        .arg("-w")
        .arg(&cdk)
        .arg("-n")
        .arg("mint")
        .arg(mint_url)
        .arg((amount_msat / 1000).to_string())
        .output()
        .await
        .map_err(|e| e.to_string())?;
    if !mint.status.success() {
        return Err(String::from_utf8_lossy(&mint.stderr).to_string());
    }
    let send = Command::new("cdk-cli")
        .arg("-w")
        .arg(&cdk)
        .arg("-n")
        .arg("send")
        .arg("-a")
        .arg((amount_msat / 1000).to_string())
        .arg("--mint-url")
        .arg(mint_url)
        .output()
        .await
        .map_err(|e| e.to_string())?;
    if !send.status.success() {
        return Err(String::from_utf8_lossy(&send.stderr).to_string());
    }
    let token = String::from_utf8_lossy(&send.stdout)
        .lines()
        .find(|l| l.starts_with("cashuB") || l.starts_with("cashuA"))
        .ok_or("cdk-cli returned no cashu token")?
        .to_string();
    let parsed = token.parse::<Token>().map_err(|e| e.to_string())?;
    let NodeWallet::Cashu(adapter) = &wallet else {
        return Err("target wallet is not cashu".into());
    };
    let keysets = adapter.keysets().await.map_err(|e| e.to_string())?;
    let incoming = parsed.proofs(&keysets).map_err(|e| e.to_string())?;
    let received = adapter
        .redeem_proofs(incoming)
        .await
        .map_err(|e| e.to_string())?;
    info!(
        "funded {node_id} on {}: {} sat",
        colored_network_name(network_id),
        received.iter().map(|p| u64::from(p.amount)).sum::<u64>()
    );
    Ok(())
}

async fn fund_rootstock(
    source: &cassis_rootstock::RootstockAdapter,
    node_id: &str,
    target: &NodeWallet,
    amount_msat: u64,
) -> Result<(), String> {
    let NodeWallet::Rootstock(adapter) = target else {
        return Err("target wallet is not rootstock".into());
    };
    let tx = source
        .transfer(&adapter.address().to_string(), amount_msat)
        .await
        .map_err(|e| e.to_string())?;
    info!(
        "funded {node_id} on {}: tx {tx}",
        colored_network_name("rootstock_testnet")
    );
    Ok(())
}

/// Show the prefund wallet addresses per network so test coins can be
/// sent to them manually (faucets, another wallet, ...); the `fund`
/// command then spends them from here into nodes. For arkade only the
/// boarding address is shown: deposits there are settled into
/// spendable VTXOs by the `onboard` command.
async fn command_prefund(
    prefund_seed: &str,
    prefund_liquid: &cassis_liquid::LiquidAdapter,
    prefund_rootstock: &cassis_rootstock::RootstockAdapter,
    prefund_arkade: &cassis_arkade::ArkadeAdapter,
    prefund_bitcoin: &cassis_bitcoin::BitcoinAdapter,
) -> Result<(), String> {
    let mut output = format!("prefund seed: {prefund_seed}\n");

    output.push_str(&format!(
        "{}: {}\n",
        colored_network_name("rootstock_testnet"),
        prefund_rootstock.address()
    ));

    let address = prefund_liquid
        .deposit_address()
        .await
        .map_err(|e| e.to_string())?;
    output.push_str(&format!(
        "{}: {address}\n",
        colored_network_name("liquid_testnet"),
    ));

    let (boarding, _, _) = prefund_arkade
        .deposit_addresses()
        .await
        .map_err(|e| e.to_string())?;
    output.push_str(&format!(
        "{}: {boarding}\n",
        colored_network_name("arkade_testnet"),
    ));

    output.push_str(&format!(
        "{}: {}\n",
        colored_network_name("bitcoin_mutinynet"),
        prefund_bitcoin.deposit_address(),
    ));

    info!("send test coins to:\n{output}");
    Ok(())
}

/// Join the next arkade batch swap so confirmed boarding outputs (and
/// recoverable VTXOs) settle into spendable offchain coins.
async fn command_onboard(
    adapter: &cassis_arkade::ArkadeAdapter,
    label: &str,
) -> Result<(), String> {
    match adapter.onboard().await.map_err(|e| e.to_string())? {
        Some(txid) => info!(
            "{label}: onboard committed {txid}; coins are spendable after the batch swap confirms"
        ),
        None => info!(
            "{label}: nothing to onboard (no confirmed boarding outputs or recoverable VTXOs)"
        ),
    }
    Ok(())
}

pub async fn command_onboard_node(playground: &Playground, node_id: &str) -> Result<(), String> {
    let spec = NetSpec::parse("arkade::mutinynet")?;
    let wallet = playground
        .ensure_wallet(node_id, &spec.network_id())
        .await?;
    match &wallet {
        NodeWallet::Arkade(adapter) => command_onboard(adapter, node_id).await,
        _ => Err(format!("node {node_id} has no arkade wallet")),
    }
}

async fn command_open(
    playground: &Playground,
    node_id: &str,
    network_id: &str,
) -> Result<(), String> {
    let spec = NetSpec::parse(network(network_id)?.spec)?;
    let already_open = {
        let nodes = playground.nodes.lock().await;
        nodes
            .get(node_id)
            .ok_or_else(|| format!("unknown node '{node_id}'"))?
            .wallets
            .contains_key(&spec.network_id())
    };
    playground
        .ensure_wallet(node_id, &spec.network_id())
        .await?;
    ensure_membership(playground, node_id, network_id).await?;
    if already_open {
        info!(
            "{} wallet for {} already open",
            colored_network_name(&spec.network_id().0),
            colored_node_name(node_id),
        );
    } else {
        info!(
            "opened {} wallet for {}",
            colored_network_name(&spec.network_id().0),
            colored_node_name(node_id),
        );
    }
    Ok(())
}

pub async fn command_router(
    playground: &Playground,
    node_id: &str,
    network_ids: Vec<String>,
) -> Result<(), String> {
    command_router_with_veto(playground, node_id, network_ids, None).await
}

/// [`command_router`] with a caller-supplied PREPARE veto hook. The
/// hook runs on the router for every incoming PREPARE and may reject
/// it for arbitrary reasons; used by e2e tests to force payment
/// failures through a specific hop.
pub async fn command_router_with_veto(
    playground: &Playground,
    node_id: &str,
    network_ids: Vec<String>,
    prepare_veto: Option<cassis_router::PrepareVeto>,
) -> Result<(), String> {
    if !playground.nodes.lock().await.contains_key(node_id) {
        return Err(format!("unknown node '{node_id}'"));
    }
    let specs = parse_specs(&network_ids)?;
    if specs.len() < 2 {
        return Err("router needs at least two networks".into());
    }
    // Membership after wallet open, same invariant as `fund`.
    let mut prebuilt_adapters = Vec::with_capacity(specs.len());
    for spec in &specs {
        prebuilt_adapters.push(
            playground
                .ensure_wallet(node_id, &spec.network_id())
                .await?
                .router(),
        );
    }
    for id in &network_ids {
        ensure_membership(playground, node_id, id).await?;
    }
    let home = node_home(&playground.root, node_id);
    let derived = load_and_derive(&home, specs.iter().map(|s| s.network_id()).collect())?;
    let router_span = playground.node_span(node_id).await;
    let config = cassis_router::RouterConfig {
        // `NetworkDef::spec` is already the canonical router spec
        // string, and `parse_specs` above validated every id.
        network_specs: network_ids
            .iter()
            .map(|id| network(id).map(|def| def.spec.to_string()))
            .collect::<Result<_, _>>()?,
        nostr_relays: vec![RELAY.to_string()],
        derived_keys: derived,
        span: router_span.clone(),
        cashu_store: Arc::new(CashuProofDb::new(node_store_path(&home))),
        liquid_store_dir: None,
        prebuilt_adapters,
        prepare_veto,
    };
    tokio::spawn(
        async move {
            if let Err(e) = cassis_router::run_router(config).await {
                warn!("router failed: {e}");
            }
        }
        .instrument(router_span),
    );
    set_status(playground, node_id, Status::Routing).await;
    info!("router started for {node_id}");
    Ok(())
}

pub async fn command_pay(
    playground: &Playground,
    sender: &str,
    target: &str,
    amount: u64,
) -> Result<(), String> {
    let (sender_networks, target_networks) = {
        let nodes = playground.nodes.lock().await;
        (
            nodes
                .get(sender)
                .ok_or("unknown sender")?
                .memberships
                .clone(),
            nodes
                .get(target)
                .ok_or("unknown target")?
                .memberships
                .clone(),
        )
    };
    let sender_specs = parse_specs(&sender_networks)?;
    let target_specs = parse_specs(&target_networks)?;
    let sender_spec = sender_specs.first().ok_or("sender has no networks")?;
    let target_spec = target_specs.first().ok_or("target has no networks")?;
    let target_home = node_home(&playground.root, target);
    let target_network = target_spec.network_id();
    // Resolve the claim identity from the target's already-open
    // receiver instead of rebuilding one.
    let claim_pubkeys = playground
        .ensure_wallet(target, &target_network)
        .await?
        .receiver()
        .claim_pubkey()
        .map(|pubkey| vec![(target_network.clone(), pubkey)])
        .unwrap_or_default();
    let (invoice, _, _) = create_invoice_with_claim_pubkeys(
        &target_home,
        target_network,
        amount,
        claim_pubkeys,
        None,
    )
    .await?;
    let mut receivers = HashMap::new();
    for spec in &target_specs {
        receivers.insert(
            spec.network_id(),
            playground
                .ensure_wallet(target, &spec.network_id())
                .await?
                .receiver(),
        );
    }
    // The listener keeps running detached; dropping the handle does
    // not stop the task.
    let _listener = start_receive_with(
        &target_home,
        Arc::new(receivers),
        &target_specs,
        playground.node_span(target).await,
    )
    .await?;
    let mut senders = HashMap::new();
    for spec in &sender_specs {
        senders.insert(
            spec.network_id(),
            playground
                .ensure_wallet(sender, &spec.network_id())
                .await?
                .sender(),
        );
    }
    let client = CassisClient::new(senders, vec![RELAY.to_string()]).await;
    set_status(playground, sender, Status::Paying).await;
    set_status(playground, target, Status::Receiving).await;
    let result = client
        .pay(invoice, sender_spec.network_id())
        .await
        .map_err(|e| e.to_string());
    set_status(playground, sender, Status::Idle).await;
    set_status(playground, target, Status::Idle).await;
    info!("payment complete: {:?}", result?.status);
    Ok(())
}

async fn set_status(playground: &Playground, id: &str, status: Status) {
    if let Some(n) = playground.nodes.lock().await.get_mut(id) {
        n.status = status;
    }
}

#[derive(Clone, Default)]
struct CommandHelper;

impl Completer for CommandHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        let start = line[..pos].rfind(char::is_whitespace).map_or(0, |i| i + 1);
        let word = &line[start..pos];
        let candidates = [
            "fund", "router", "pay", "route", "summary", "prefund", "onboard", "open", "help",
            "quit", "exit",
        ]
        .into_iter()
        .chain(NODE_NAMES.iter().copied())
        .chain(NETWORKS.iter().map(|network| network.id))
        .filter(|candidate| candidate.starts_with(word))
        .map(|candidate| Pair {
            display: candidate.to_string(),
            replacement: candidate.to_string(),
        })
        .collect();
        Ok((start, candidates))
    }
}

impl Hinter for CommandHelper {
    type Hint = String;
}

impl Highlighter for CommandHelper {}
impl Validator for CommandHelper {}
impl Helper for CommandHelper {}

async fn route_node_name(playground: &Playground, pubkey: ritualistic::PubKey) -> String {
    let hex = pubkey.to_hex();
    let nodes = playground.nodes.lock().await;
    nodes
        .values()
        .find(|node| node.nostr_pubkey == hex)
        .map(|node| node.id.clone())
        .unwrap_or_else(|| hex[..8].to_string())
}

async fn first_membership(playground: &Playground, node_id: &str) -> Result<String, String> {
    playground
        .nodes
        .lock()
        .await
        .get(node_id)
        .ok_or_else(|| format!("unknown node '{node_id}'"))?
        .memberships
        .first()
        .cloned()
        .ok_or_else(|| format!("{node_id} has no networks"))
}

async fn command_route(
    playground: &Playground,
    sender: &str,
    target: &str,
    amount_msat: u64,
) -> Result<(), String> {
    let sender_network = first_membership(playground, sender).await?;
    let destination_network = first_membership(playground, target).await?;
    let sender_network = NetSpec::parse(network(&sender_network)?.spec)?.network_id();
    let destination_network = NetSpec::parse(network(&destination_network)?.spec)?.network_id();
    let route = cassis_client::find_route(
        &[RELAY.to_string()],
        &destination_network,
        amount_msat,
        &sender_network,
    )
    .await
    .map_err(|error| error.to_string())?;
    if route.is_empty() {
        return Err("no route found".to_string());
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let destination_delta = cassis_routing::fallback_incoming_delta(&destination_network)
        .saturating_add(cassis_routing::fallback_transit_slack(&destination_network));
    let mut expiries = vec![now.saturating_add(destination_delta)];
    for hop in route.iter().rev() {
        let delta = if hop.node.incoming_delta_secs > 0 {
            hop.node.incoming_delta_secs
        } else {
            cassis_routing::fallback_incoming_delta(&hop.incoming)
        };
        let slack = if hop.node.transit_slack_secs > 0 {
            hop.node.transit_slack_secs
        } else {
            cassis_routing::fallback_transit_slack(&hop.incoming)
        };
        expiries.push(
            expiries
                .last()
                .copied()
                .unwrap_or(now)
                .saturating_add(delta)
                .saturating_add(slack),
        );
    }
    expiries.reverse();
    expiries.push(now);

    let mut amounts = vec![(0, 0); route.len()];
    let mut outgoing = amount_msat;
    for (index, hop) in route.iter().enumerate().rev() {
        let fee = hop
            .node
            .fee_base_msat
            .saturating_add(hop.node.fee_ppm.saturating_mul(outgoing) / 1_000_000);
        let incoming = outgoing.saturating_add(fee);
        amounts[index] = (incoming, outgoing);
        outgoing = incoming;
    }

    info!("route {sender} -> {target}: {} msat", outgoing);
    for (index, hop) in route.iter().enumerate() {
        let name = route_node_name(playground, hop.node.node_pubkey).await;
        let (incoming, outgoing) = amounts[index];
        info!(
            "  hop {}: {} ({}) -> ({})\n    incoming: amount={} msat locktime={}\n    outgoing: amount={} msat locktime={}",
            index + 1,
            colored_node_name(&name),
            colored_network_name(&hop.incoming.to_string()),
            colored_network_name(&hop.outgoing.to_string()),
            incoming,
            expiries[index],
            outgoing,
            expiries[index + 1],
        );
    }
    Ok(())
}

/// Run one command future inside `node_id`'s span, logging a failure
/// as `<verb> failed: <error>`.
async fn run_command(
    playground: &Playground,
    verb: &str,
    node_id: &str,
    command: impl std::future::Future<Output = Result<(), String>>,
) {
    let span = playground.node_span(node_id).await;
    async {
        if let Err(error) = command.await {
            error!("{verb} failed: {error}");
        }
    }
    .instrument(span)
    .await;
}

async fn execute_line(playground: Arc<Playground>, line: String) {
    info!("{line}");
    let parts: Vec<&str> = line.split_whitespace().collect();
    match parts.as_slice() {
        [] => {}
        ["fund", node, network_id, rest @ ..] if rest.len() <= 1 => {
            match rest.first().map_or(Ok(DEFAULT_FUND_AMOUNT), |v| v.parse()) {
                Ok(amount) => {
                    run_command(
                        &playground,
                        "fund",
                        node,
                        command_fund(&playground, node, network_id, amount),
                    )
                    .await
                }
                Err(_) => warn!("fund failed: amount must be an integer"),
            }
        }
        ["fund", ..] => info!("usage: fund <node_id> <network_id> [amount]"),
        ["router", node, networks @ ..] => {
            let networks = networks.iter().map(|s| s.to_string()).collect();
            run_command(
                &playground,
                "router",
                node,
                command_router(&playground, node, networks),
            )
            .await
        }
        ["router"] => info!("usage: router <node_id> [<network_id> ...]"),
        ["pay", sender, target, amount] => match amount.parse::<u64>() {
            Ok(amount) => {
                run_command(
                    &playground,
                    "pay",
                    sender,
                    command_pay(&playground, sender, target, amount),
                )
                .await
            }
            Err(_) => info!("usage: pay <node_id_sender> <node_id_target> <amount_msat>"),
        },
        ["pay", ..] => info!("usage: pay <node_id_sender> <node_id_target> <amount_msat>"),
        ["open", node, network_id] => {
            run_command(
                &playground,
                "open",
                node,
                command_open(&playground, node, network_id),
            )
            .await
        }
        ["open", ..] => info!("usage: open <node_id> <network_id>"),
        ["route", sender, target, amount] => match amount.parse::<u64>() {
            Ok(amount) => {
                run_command(
                    &playground,
                    "route",
                    sender,
                    command_route(&playground, sender, target, amount),
                )
                .await
            }
            Err(_) => info!("usage: route <sender> <target> <amount_msat>"),
        },
        ["route", ..] => info!("usage: route <sender> <target> <amount_msat>"),
        ["prefund", ..] => {
            async {
                if let Err(e) = command_prefund(
                    &playground.prefund_seed,
                    &playground.prefund_liquid,
                    &playground.prefund_rootstock,
                    &playground.prefund_arkade,
                    &playground.prefund_bitcoin,
                )
                .await
                {
                    error!("prefund failed: {e}");
                }
            }
            .instrument(info_span!("prefund"))
            .await
        }
        ["onboard", node] => {
            run_command(
                &playground,
                "onboard",
                node,
                command_onboard_node(&playground, node),
            )
            .await
        }
        ["onboard"] => {
            if let Err(e) = command_onboard(&playground.prefund_arkade, "prefund").await {
                error!("onboard failed: {e}");
            }
        }
        ["onboard", ..] => info!("usage: onboard [node]"),
        ["summary", ..] => {}
        ["help", ..] => info!(
            "commands:\n  fund <node> <network> [amount_msat]\n  router <node> [network...]\n  pay <sender> <target> <amount_msat>\n  summary\n  route <sender> <target> <amount_msat>\n  prefund\n  onboard [node]\n  open <node> <network>\n  quit"
        ),
        ["quit", ..] | ["exit", ..] => info!("use Ctrl-C to exit"),
        [other, ..] => info!("unknown command '{other}'; try help"),
    }
    let verb = parts.first().copied();
    if matches!(
        verb,
        Some("fund" | "router" | "pay" | "summary" | "prefund" | "onboard")
    ) {
        // `summary` and `prefund` opportunistically settle any coins
        // sitting in the prefund boarding address before showing
        // balances.
        if matches!(verb, Some("summary" | "prefund")) {
            playground.auto_onboard_prefund().await;
        }
        playground.refresh_balances().await;
        info!("summary:\n{}", playground.summary().await);
    }
}

fn parse_prefund_seed_arg() -> Result<String, String> {
    let mut args = std::env::args().skip(1);
    let mut prefund_seed = DEFAULT_PREFUND_SEED.to_string();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--prefund-seed" => {
                prefund_seed = args
                    .next()
                    .ok_or("--prefund-seed requires a seed phrase argument")?;
            }
            other => {
                return Err(format!(
                    "unknown argument '{other}'; usage: cassis-playground [--prefund-seed <mnemonic>]"
                ));
            }
        }
    }
    Ok(prefund_seed)
}

pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let prefund_seed = parse_prefund_seed_arg()?;
    let logs = Arc::new(StdMutex::new(VecDeque::new()));
    let printer = Arc::new(StdMutex::new(None));
    tracing_subscriber::registry()
        // Captures `node` / `network` off each span so the layer below
        // can resolve them when formatting an event.
        .with(cassis_core::logging::ScopeLayer)
        .with(PlaygroundLogLayer {
            lines: logs.clone(),
            printer: printer.clone(),
        })
        .init();
    let playground = Playground::new(prefund_seed, PathBuf::from(ROOT)).await?;

    let mut editor = Editor::<CommandHelper, rustyline::history::DefaultHistory>::new()?;
    editor.set_helper(Some(CommandHelper));
    let history_path = Path::new(ROOT).join(COMMAND_HISTORY);
    let _ = editor.load_history(&history_path);
    *printer.lock().unwrap() = Some(Box::new(editor.create_external_printer()?));
    if let Ok(lines) = logs.lock() {
        if let Ok(mut printer) = printer.lock() {
            if let Some(printer) = printer.as_mut() {
                for line in lines.iter() {
                    let _ = printer.print(line.clone());
                    let _ = printer.print("\n".to_string());
                }
            }
        }
    }

    loop {
        match editor.readline("cassis ~> ") {
            Ok(line) => {
                if !line.trim().is_empty() {
                    editor.add_history_entry(line.as_str())?;
                    let pg = playground.clone();
                    tokio::spawn(execute_line(pg, line));
                }
            }
            Err(ReadlineError::Interrupted | ReadlineError::Eof) => break,
            Err(error) => return Err(error.into()),
        }
    }
    editor.append_history(&history_path)?;
    Ok(())
}
