use std::collections::{HashMap, VecDeque};
use std::io;
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
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use log::{info, warn, LevelFilter, Log, Metadata, Record};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    text::Text,
    widgets::{Block, Borders, Paragraph, Wrap},
    Terminal,
};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tui_input::{backend::crossterm::EventHandler, Input};

const ROOT: &str = "/tmp/cassis-playground";
const RELAY: &str = "ws://localhost:10547";
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

const NODE_NAMES: &[&str] = &["node_a", "node_b", "node_c", "node_d", "node_e"];
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
}

impl Log for LogSink {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }
    fn log(&self, record: &Record<'_>) {
        let line = format!("[{}] {}", record.level(), record.args());
        if let Ok(mut lines) = self.lines.lock() {
            lines.push_back(line);
            while lines.len() > 100 {
                lines.pop_front();
            }
        }
    }
    fn flush(&self) {}
}

struct Playground {
    nodes: Mutex<HashMap<String, NodeState>>,
    children: Mutex<Vec<Child>>,
}

impl Playground {
    async fn new() -> Result<Arc<Self>, String> {
        std::fs::create_dir_all(Path::new(ROOT)).map_err(|e| e.to_string())?;
        let playground = Arc::new(Self {
            nodes: Mutex::new(HashMap::new()),
            children: Mutex::new(Vec::new()),
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
        let mut relay = Command::new("nak");
        relay.arg("serve").arg("--port").arg("10547");
        self.spawn_child(relay, "nak relay").await?;
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
        let mut nodes = self.nodes.lock().await;
        for node in nodes.values_mut() {
            output.push_str(&format!(
                "{}: {}\n",
                node.id,
                status_text(&node.status, &node.memberships)
            ));
            for network_id in node.memberships.clone() {
                let balance = match self.node_balance(&node.id, &network_id).await {
                    Ok(value) => value,
                    Err(e) => format!("error: {e}"),
                };
                output.push_str(&format!("  {network_id}: {balance}\n"));
            }
        }
        output
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

fn draw(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    summary: &str,
    logs: &Arc<StdMutex<VecDeque<String>>>,
    input: &Input,
) -> io::Result<()> {
    let log_text = logs
        .lock()
        .map(|lines| lines.iter().cloned().collect::<Vec<_>>().join("\n"))
        .unwrap_or_default();
    terminal.draw(|frame| {
        let summary_height = summary.lines().count().max(1) as u16 + 2;
        let areas = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(summary_height),
                Constraint::Min(3),
                Constraint::Length(3),
            ])
            .split(frame.area());
        frame.render_widget(
            Paragraph::new(Text::from(summary))
                .block(Block::default().borders(Borders::ALL).title("nodes")),
            areas[0],
        );
        frame.render_widget(
            Paragraph::new(Text::from(log_text))
                .wrap(Wrap { trim: false })
                .block(Block::default().borders(Borders::ALL).title("events")),
            areas[1],
        );
        frame.render_widget(
            Paragraph::new(input.value())
                .style(Style::default().fg(Color::Cyan))
                .block(Block::default().borders(Borders::ALL).title("command")),
            areas[2],
        );
        frame.set_cursor_position((
            areas[2].x + 1 + input.visual_cursor() as u16,
            areas[2].y + 1,
        ));
    })?;
    Ok(())
}

async fn execute_line(playground: Arc<Playground>, line: String) {
    let mut parts = line.split_whitespace();
    match parts.next() {
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
        Some("help") => info!(
            "fund <node> <network> | router <node> [network...] | pay <sender> <target> <amount_msat> | quit"
        ),
        Some("quit") | Some("exit") => info!("use Ctrl-C to exit"),
        Some(other) => info!("unknown command '{other}'; try help"),
        None => {}
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let logs = Arc::new(StdMutex::new(VecDeque::new()));
    log::set_boxed_logger(Box::new(LogSink {
        lines: logs.clone(),
    }))?;
    log::set_max_level(LevelFilter::Info);
    let playground = Playground::new().await?;

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let mut input = Input::default();
    let result = loop {
        let summary = playground.summary().await;
        draw(&mut terminal, &summary, &logs, &input)?;
        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(KeyEvent {
                code, modifiers, ..
            }) = event::read()?
            {
                if code == KeyCode::Char('c') && modifiers.contains(KeyModifiers::CONTROL) {
                    break Ok(());
                }
                if code == KeyCode::Enter {
                    let line = input.value().to_string();
                    input.reset();
                    let pg = playground.clone();
                    tokio::spawn(execute_line(pg, line));
                } else {
                    input.handle_event(&Event::Key(KeyEvent {
                        code,
                        modifiers,
                        kind: event::KeyEventKind::Press,
                        state: event::KeyEventState::NONE,
                    }));
                }
            }
        }
    };
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}
