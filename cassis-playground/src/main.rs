use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex as StdMutex};

use cassis_client::adapters::{build_cashu_adapter, build_senders};
use cassis_client::netspec::NetSpec;
use cassis_client::ops::{
    create_invoice_for, init_node_home, load_and_derive, node_store_path, start_receive,
};
use cassis_client::store::CashuProofDb;
use cassis_client::CassisClient;
use cdk::nuts::Token;
use log::{info, warn, Level, LevelFilter, Log, Metadata, Record};
use ritualistic::server::{CustomRelay, RelayInternals};
use ritualistic::{Event as NostrEvent, Filter as NostrFilter};
use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{Context, Editor, ExternalPrinter, Helper};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;

const ROOT: &str = "/tmp/cassis-playground";
const COMMAND_HISTORY: &str = "commands.history";
const RELAY: &str = "ws://localhost:10000";
const RSK_SEED: &str = "tmp/rsk-seed";

#[derive(Clone)]
struct NetworkDef {
    id: &'static str,
    spec: &'static str,
    mint_url: Option<&'static str>,
}

const NETWORKS: &[NetworkDef] = &[
    NetworkDef {
        id: "cashu_1",
        spec: "cashu::127.0.0.1:8091",
        mint_url: Some("http://127.0.0.1:8091"),
    },
    NetworkDef {
        id: "cashu_2",
        spec: "cashu::127.0.0.1:8092",
        mint_url: Some("http://127.0.0.1:8092"),
    },
    NetworkDef {
        id: "cashu_3",
        spec: "cashu::127.0.0.1:8093",
        mint_url: Some("http://127.0.0.1:8093"),
    },
    NetworkDef {
        id: "rootstock_testnet",
        spec: "rootstock::testnet",
        mint_url: None,
    },
];

const NODE_NAMES: &[&str] = &["alice", "bob", "charlie", "derek", "ernest"];
const NODE_COLORS: &[&str] = &["red", "green", "blue", "yellow", "magenta"];

#[derive(Clone, Debug)]
enum Status {
    Idle,
    Routing,
    Paying,
    Receiving,
}

struct NodeState {
    id: String,
    memberships: Vec<String>,
    status: Status,
    #[allow(dead_code)]
    receive_tasks: Vec<tokio::task::JoinHandle<()>>,
    router_tasks: Vec<tokio::task::JoinHandle<()>>,
}

struct LogSink {
    lines: Arc<StdMutex<VecDeque<String>>>,
    printer: Arc<StdMutex<Option<Box<dyn ExternalPrinter + Send>>>>,
}

impl Log for LogSink {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.level() != Level::Trace && !metadata.target().starts_with("iroh")
    }
    fn log(&self, record: &Record<'_>) {
        let message = record.args().to_string();
        // Drop bare span names leaked from the tracing bridge ("QADv4;",
        // "tx;", "upnp;", ...): a single token terminated by ';'.
        let trimmed = message.trim_end();
        if trimmed.ends_with(';') && !trimmed[..trimmed.len() - 1].contains(char::is_whitespace) {
            return;
        }
        let line = format!("[{}] {}", record.level(), message);
        if let Ok(mut printer) = self.printer.lock() {
            if let Some(printer) = printer.as_mut() {
                let _ = printer.print(line.clone());
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
    fn flush(&self) {}
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

struct Playground {
    nodes: Mutex<HashMap<String, NodeState>>,
    children: Mutex<Vec<Child>>,
    relay_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    balances: Mutex<HashMap<(String, String), String>>,
}

impl Playground {
    async fn new() -> Result<Arc<Self>, String> {
        std::fs::create_dir_all(Path::new(ROOT)).map_err(|e| e.to_string())?;
        let playground = Arc::new(Self {
            nodes: Mutex::new(HashMap::new()),
            children: Mutex::new(Vec::new()),
            relay_task: Mutex::new(None),
            balances: Mutex::new(HashMap::new()),
        });
        for (idx, id) in NODE_NAMES.iter().enumerate() {
            let home = node_home(id);
            init_node_home(&home)?;
            playground.nodes.lock().await.insert(
                (*id).to_string(),
                NodeState {
                    id: (*id).to_string(),
                    memberships: Vec::new(),
                    status: Status::Idle,
                    receive_tasks: Vec::new(),
                    router_tasks: Vec::new(),
                },
            );
            info!("created {id} ({})", NODE_COLORS[idx]);
        }
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
        let task = tokio::spawn(async move {
            if let Err(error) = ritualistic::server::start(
                Arc::new(relay),
                "127.0.0.1:10000".parse().expect("valid relay address"),
            )
            .await
            {
                log::error!("relay stopped: {error}");
            }
        });
        *self.relay_task.lock().await = Some(task);
        for (idx, network) in NETWORKS
            .iter()
            .enumerate()
            .filter(|(_, n)| n.mint_url.is_some())
        {
            let dir = mint_dir(network.id);
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
                .env("CDK_MINTD_LISTEN_HOST", "127.0.0.1")
                .env("CDK_MINTD_LISTEN_PORT", (8091 + idx as u16).to_string())
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
                "{}: {}\n",
                colored_node_name(&node.id),
                status_text(&node.status, &node.memberships)
            ));
            for network_id in &node.memberships {
                let balance = balances
                    .get(&(node.id.clone(), network_id.clone()))
                    .map(String::as_str)
                    .unwrap_or("(not refreshed)");
                output.push_str(&format!("  {network_id}: {balance}\n"));
            }
        }
        if !output.is_empty() {
            output.push('\n');
        }
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
                let balance = balances.get(&(node.id.clone(), network_id.clone()));
                if !matches!(node.status, Status::Idle) || balance_is_positive(balance) {
                    lines.push(format!(
                        "  {}: {}",
                        colored_node_name(&node.id),
                        status_word(&node.status)
                    ));
                }
            }
            if !lines.is_empty() {
                output.push_str(&format!("{network_id}:\n"));
                output.push_str(&lines.join("\n"));
                output.push('\n');
            }
        }
        output
    }

    /// Recompute every displayed balance. Called once after a command
    /// completes, never from the render loop.
    async fn refresh_balances(&self) {
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
        let mut refreshed = Vec::with_capacity(entries.len());
        for (node_id, network_id) in entries {
            let value = self
                .node_balance(&node_id, &network_id)
                .await
                .unwrap_or_else(|e| format!("error: {e}"));
            refreshed.push(((node_id, network_id), value));
        }
        let mut balances = self.balances.lock().await;
        for (key, value) in refreshed {
            balances.insert(key, value);
        }
    }

    async fn node_balance(&self, node_id: &str, network_id: &str) -> Result<String, String> {
        let network = network(network_id)?;
        let home = node_home(node_id);
        let spec = NetSpec::parse(network.spec)?;
        let ids = vec![spec.network_id()];
        let derived = load_and_derive(&home, ids)?;
        match network.mint_url {
            Some(_) => {
                let adapter = build_cashu_adapter(&spec, &derived, &node_store_path(&home)).await?;
                let total: u64 = adapter
                    .balance()
                    .await
                    .iter()
                    .map(|p| u64::from(p.amount))
                    .sum();
                Ok(format!("{total} sat"))
            }
            None => {
                let adapter =
                    cassis_client::adapters::build_rootstock_adapter(&spec, &derived).await?;
                let msat = adapter.balance_msat().await.map_err(|e| e.to_string())?;
                Ok(format!("{msat} msat"))
            }
        }
    }
}

fn status_text(status: &Status, memberships: &[String]) -> String {
    match status {
        Status::Idle => "idle".to_string(),
        Status::Routing => format!("routing ({})", memberships.join(", ")),
        Status::Paying => "paying".to_string(),
        Status::Receiving => "receiving".to_string(),
    }
}

fn status_word(status: &Status) -> &'static str {
    match status {
        Status::Idle => "idle",
        Status::Routing => "routing",
        Status::Paying => "paying",
        Status::Receiving => "listening",
    }
}

fn balance_is_positive(balance: Option<&String>) -> bool {
    balance
        .and_then(|value| value.split_whitespace().next())
        .and_then(|amount| amount.parse::<u64>().ok())
        .is_some_and(|amount| amount > 0)
}

fn node_color(name: &str) -> &'static str {
    NODE_NAMES
        .iter()
        .position(|candidate| *candidate == name)
        .and_then(|index| NODE_COLORS.get(index))
        .copied()
        .unwrap_or("reset")
}

fn colored_node_name(name: &str) -> String {
    let code = match node_color(name) {
        "red" => "31",
        "green" => "32",
        "blue" => "34",
        "yellow" => "33",
        "magenta" => "35",
        _ => "0",
    };
    format!("\x1b[{code}m{name}\x1b[0m")
}

fn network(id: &str) -> Result<&'static NetworkDef, String> {
    NETWORKS
        .iter()
        .find(|n| n.id == id)
        .ok_or_else(|| format!("unknown network '{id}'"))
}

fn node_home(id: &str) -> PathBuf {
    PathBuf::from(ROOT).join("nodes").join(id)
}
fn mint_dir(id: &str) -> PathBuf {
    PathBuf::from(ROOT).join("mints").join(id)
}
fn cdk_dir(id: &str) -> PathBuf {
    PathBuf::from(ROOT).join("cdk").join(id)
}

async fn command_fund(
    playground: &Playground,
    node_id: &str,
    network_id: &str,
) -> Result<(), String> {
    if !playground.nodes.lock().await.contains_key(node_id) {
        return Err(format!("unknown node '{node_id}'"));
    }
    let net = network(network_id)?.clone();
    ensure_membership(playground, node_id, network_id).await?;
    match net.mint_url {
        Some(mint_url) => fund_cashu(node_id, network_id, mint_url).await,
        None => fund_rootstock(node_id).await,
    }
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

async fn fund_cashu(node_id: &str, network_id: &str, mint_url: &str) -> Result<(), String> {
    let cdk = cdk_dir(network_id);
    std::fs::create_dir_all(&cdk).map_err(|e| e.to_string())?;
    let mint = Command::new("cdk-cli")
        .arg("-w")
        .arg(&cdk)
        .arg("-n")
        .arg("mint")
        .arg(mint_url)
        .arg("1000")
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
        .arg("1000")
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
    let host = cassis_client::adapters::mint_url_to_host(mint_url)?;
    let spec = NetSpec::parse(&format!("cashu::{host}"))?;
    let home = node_home(node_id);
    let derived = load_and_derive(&home, vec![spec.network_id()])?;
    let adapter = build_cashu_adapter(&spec, &derived, &node_store_path(&home)).await?;
    let keysets = adapter.keysets().await.map_err(|e| e.to_string())?;
    let incoming = parsed.proofs(&keysets).map_err(|e| e.to_string())?;
    let received = adapter
        .redeem_proofs(incoming)
        .await
        .map_err(|e| e.to_string())?;
    info!(
        "funded {node_id} on {network_id}: {} sat",
        received.iter().map(|p| u64::from(p.amount)).sum::<u64>()
    );
    Ok(())
}

async fn fund_rootstock(node_id: &str) -> Result<(), String> {
    let source_mnemonic =
        std::fs::read_to_string(RSK_SEED).map_err(|e| format!("read {RSK_SEED}: {e}"))?;
    let source_spec = NetSpec::parse("rootstock::testnet")?;
    let source_keys = cassis_keys::derive_keys(&source_mnemonic, vec![source_spec.network_id()])
        .map_err(|e| e.to_string())?;
    let source =
        cassis_client::adapters::build_rootstock_adapter(&source_spec, &source_keys).await?;
    let target_home = node_home(node_id);
    let target_keys = load_and_derive(&target_home, vec![source_spec.network_id()])?;
    let target =
        cassis_client::adapters::build_rootstock_adapter(&source_spec, &target_keys).await?;
    let tx = source
        .transfer(&target.address().to_string(), 1000)
        .await
        .map_err(|e| e.to_string())?;
    info!("funded {node_id} on rootstock_testnet: tx {tx}");
    Ok(())
}

async fn command_router(
    playground: &Playground,
    node_id: &str,
    network_ids: Vec<String>,
) -> Result<(), String> {
    if !playground.nodes.lock().await.contains_key(node_id) {
        return Err(format!("unknown node '{node_id}'"));
    }
    for id in &network_ids {
        network(id)?;
        ensure_membership(playground, node_id, id).await?;
    }
    if network_ids.len() < 2 {
        return Err("router needs at least two networks".into());
    }
    let specs: Vec<NetSpec> = network_ids
        .iter()
        .map(|id| NetSpec::parse(network(id).unwrap().spec))
        .collect::<Result<_, _>>()?;
    let home = node_home(node_id);
    let ids = specs.iter().map(|s| s.network_id()).collect();
    let derived = load_and_derive(&home, ids)?;
    let store_path = node_store_path(&home);
    let network_specs = specs
        .iter()
        .map(|s| match s {
            NetSpec::Cashu { host, .. } => format!("cashu::{host}"),
            NetSpec::Rootstock { testnet: true } => "rootstock::testnet".into(),
            NetSpec::Rootstock { testnet: false } => "rootstock".into(),
        })
        .collect();
    let cashu_store: Arc<dyn cassis_cashu::CashuProofStore> =
        Arc::new(CashuProofDb::new(store_path));
    let jh = tokio::spawn(async move {
        let config = cassis_router::RouterConfig {
            network_specs,
            nostr_relays: vec![RELAY.to_string()],
            derived_keys: derived,
            cashu_store,
        };
        if let Err(e) = cassis_router::run_router(config).await {
            warn!("router failed: {e}");
        }
    });
    let mut nodes = playground.nodes.lock().await;
    let node = nodes.get_mut(node_id).unwrap();
    node.status = Status::Routing;
    node.router_tasks.push(jh);
    info!("router started for {node_id}");
    Ok(())
}

async fn command_pay(
    playground: &Playground,
    sender: &str,
    target: &str,
    amount: u64,
) -> Result<(), String> {
    let target_specs = {
        let nodes = playground.nodes.lock().await;
        nodes
            .get(target)
            .ok_or("unknown target")?
            .memberships
            .clone()
    };
    let sender_specs = {
        let nodes = playground.nodes.lock().await;
        nodes
            .get(sender)
            .ok_or("unknown sender")?
            .memberships
            .clone()
    };
    let target_id = target_specs.first().ok_or("target has no networks")?;
    let sender_id = sender_specs.first().ok_or("sender has no networks")?;
    let target_spec = NetSpec::parse(network(target_id)?.spec)?;
    let sender_spec = NetSpec::parse(network(sender_id)?.spec)?;
    let target_home = node_home(target);
    let sender_home = node_home(sender);
    let target_network = target_spec.network_id();
    let (invoice, _, _) =
        create_invoice_for(&target_home, target_network, target_spec.clone(), amount).await?;
    let listener = start_receive(
        &target_home,
        &target_specs
            .iter()
            .map(|id| NetSpec::parse(network(id).unwrap().spec))
            .collect::<Result<Vec<_>, _>>()?,
    )
    .await?;
    playground
        .nodes
        .lock()
        .await
        .get_mut(target)
        .ok_or("unknown target")?
        .receive_tasks
        .push(listener);
    let sender_specs_parsed: Vec<NetSpec> = sender_specs
        .iter()
        .map(|id| NetSpec::parse(network(id).unwrap().spec))
        .collect::<Result<_, _>>()?;
    let sender_ids = sender_specs_parsed.iter().map(|s| s.network_id()).collect();
    let derived = load_and_derive(&sender_home, sender_ids)?;
    let senders = build_senders(
        &sender_specs_parsed,
        &derived,
        &node_store_path(&sender_home),
    )
    .await?;
    let client = CassisClient::new(senders, vec![RELAY.to_string()]).await;
    set_status(playground, sender, Status::Paying).await;
    set_status(playground, target, Status::Receiving).await;
    let result = client
        .pay(invoice, sender_spec.network_id())
        .await
        .map_err(|e| e.to_string());
    set_status(playground, sender, Status::Idle).await;
    set_status(playground, target, Status::Idle).await;
    let result = result?;
    info!("payment complete: {:?}", result.status);
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
            "fund", "router", "pay", "route", "summary", "help", "quit", "exit",
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
    let network_ids = NETWORKS
        .iter()
        .map(|network| NetSpec::parse(network.spec).map(|spec| spec.network_id()))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_default();
    let nodes = playground.nodes.lock().await;
    for node in nodes.values() {
        if let Ok(keys) = load_and_derive(&node_home(&node.id), network_ids.clone()) {
            if keys.nostr.pubkey() == pubkey {
                return node.id.clone();
            }
        }
    }
    pubkey.to_hex()[..8].to_string()
}

async fn command_route(
    playground: &Playground,
    sender: &str,
    target: &str,
    amount_msat: u64,
) -> Result<(), String> {
    let (sender_network, destination_network) = {
        let nodes = playground.nodes.lock().await;
        let sender_network = nodes
            .get(sender)
            .and_then(|node| node.memberships.first())
            .ok_or_else(|| format!("{sender} has no networks"))?
            .clone();
        let destination_network = nodes
            .get(target)
            .and_then(|node| node.memberships.first())
            .ok_or_else(|| format!("{target} has no networks"))?
            .clone();
        (sender_network, destination_network)
    };
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
            hop.incoming,
            hop.outgoing,
            incoming,
            expiries[index],
            outgoing,
            expiries[index + 1],
        );
    }
    Ok(())
}

async fn execute_line(playground: Arc<Playground>, line: String) {
    info!("{line}");
    let mut parts = line.split_whitespace();
    let verb = parts.next();
    match verb {
        Some("fund") => match (parts.next(), parts.next()) {
            (Some(node), Some(network)) => {
                if let Err(e) = command_fund(&playground, node, network).await {
                    warn!("fund failed: {e}");
                }
            }
            _ => info!("usage: fund <node_id> <network_id>"),
        },
        Some("router") => match parts.next() {
            Some(node) => {
                let networks = parts.map(str::to_string).collect();
                if let Err(e) = command_router(&playground, node, networks).await {
                    warn!("router failed: {e}");
                }
            }
            None => info!("usage: router <node_id> [<network_id> ...]"),
        },
        Some("pay") => match (
            parts.next(),
            parts.next(),
            parts.next().and_then(|s| s.parse::<u64>().ok()),
        ) {
            (Some(sender), Some(target), Some(amount)) => {
                if let Err(e) = command_pay(&playground, sender, target, amount).await {
                    warn!("pay failed: {e}");
                }
            }
            _ => info!("usage: pay <node_id_sender> <node_id_target> <amount_msat>"),
        },
        Some("summary") => {}
        Some("route") => match (
            parts.next(),
            parts.next(),
            parts.next().and_then(|s| s.parse::<u64>().ok()),
        ) {
            (Some(sender), Some(target), Some(amount)) => {
                if let Err(e) = command_route(&playground, sender, target, amount).await {
                    warn!("route failed: {e}");
                }
            }
            _ => info!("usage: route <sender> <target> <amount_msat>"),
        },
        Some("help") => info!(
            "fund <node> <network> | router <node> [network...] | pay <sender> <target> <amount_msat> | summary | route <sender> <target> <amount_msat> | quit"
        ),
        Some("quit") | Some("exit") => info!("use Ctrl-C to exit"),
        Some(other) => info!("unknown command '{other}'; try help"),
        None => {}
    }
    if matches!(
        verb,
        Some("fund") | Some("router") | Some("pay") | Some("summary")
    ) {
        playground.refresh_balances().await;
        info!("summary:\n{}", playground.summary().await);
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let logs = Arc::new(StdMutex::new(VecDeque::new()));
    let printer = Arc::new(StdMutex::new(None));
    log::set_boxed_logger(Box::new(LogSink {
        lines: logs.clone(),
        printer: printer.clone(),
    }))?;
    log::set_max_level(LevelFilter::Info);
    let playground = Playground::new().await?;

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
    info!(
        "fund <node> <network> | router <node> [network...] | pay <sender> <target> <amount_msat> | summary | route <sender> <target> <amount_msat> | quit"
    );

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
