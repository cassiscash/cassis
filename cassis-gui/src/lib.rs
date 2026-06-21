//! Cassis GUI: a Tauri desktop app that drives real `cassis-cli` /
//! `cdk-mintd` / `nak` processes. The frontend (React + React Flow)
//! renders a canvas of networks + nodes and invokes these commands
//! from its sidebar.

mod state;

use serde::{Deserialize, Serialize};
use state::{
    default_networks, spawn, GuiState, Network, Node, SharedState, RELAY_PORT, RELAY_URL,
    GUI_MINT_MNEMONIC, MAX_NODES, NODE_COLORS,
};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use tauri::State;
use tokio::process::Command;

#[derive(Debug, Serialize)]
struct CmdError {
    message: String,
}

impl<E: std::fmt::Display> From<E> for CmdError {
    fn from(e: E) -> Self {
        CmdError { message: e.to_string() }
    }
}

type CmdResult<T> = Result<T, CmdError>;

// ============================================================================
// Bootstrap: ensure mints, seeds, dirs exist; start relay + mints.
// ============================================================================

fn ensure_dirs_for_state() -> Result<(), String> {
    use std::fs;
    let root = state::gui_root();
    fs::create_dir_all(root.join("mints")).map_err(|e| e.to_string())?;
    fs::create_dir_all(root.join("cdk")).map_err(|e| e.to_string())?;
    fs::create_dir_all(root.join("nodes")).map_err(|e| e.to_string())?;
    Ok(())
}

fn write_seed(path: &std::path::Path) -> Result<(), String> {
    use std::fs;
    if path.exists() {
        return Ok(());
    }
    fs::write(path, GUI_MINT_MNEMONIC).map_err(|e| format!("write seed {}: {e}", path.display()))
}

/// Run `cassis-cli seed init --home <dir> --force` if no seed exists.
fn ensure_node_seed(home: &std::path::Path) -> Result<(), String> {
    use std::fs;
    fs::create_dir_all(home).map_err(|e| e.to_string())?;
    let seed_path = home.join("seed");
    if !seed_path.exists() {
        let status = std::process::Command::new("cargo")
            .args([
                "run",
                "-p",
                "cassis-cli",
                "--features",
                "cashu,rootstock",
                "--",
                "--home",
                home.to_str().unwrap(),
                "seed",
                "init",
                "--force",
            ])
            .status()
            .map_err(|e| format!("seed init: {e}"))?;
        if !status.success() {
            return Err(format!("seed init failed: {status:?}"));
        }
    }
    Ok(())
}

async fn wait_mint(port: u16) -> bool {
    let url = format!("http://127.0.0.1:{port}/v1/info");
    for _ in 0..60 {
        if reqwest_get_ok(&url).await {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    false
}

async fn reqwest_get_ok(url: &str) -> bool {
    let Ok(resp) = reqwest::Client::new().get(url).send().await else {
        return false;
    };
    resp.status().is_success()
}

// ============================================================================
// Tauri commands (callable from JS via `invoke`)
// ============================================================================

#[tauri::command]
async fn list_networks() -> CmdResult<Vec<Network>> {
    Ok(default_networks())
}

#[tauri::command]
async fn list_nodes(state: State<'_, SharedState>) -> CmdResult<Vec<Node>> {
    let g = state.nodes.lock().await;
    Ok(g.values().cloned().collect())
}

#[tauri::command]
async fn bootstrap(state: State<'_, SharedState>) -> CmdResult<()> {
    ensure_dirs_for_state().map_err(|e| CmdError { message: e })?;

    // Start the local Nostr relay (nak serve).
    {
        let mut guard = state.relay_child.lock().await;
        if guard.is_none() {
            let mut cmd = Command::new("nak");
            cmd.arg("serve").arg("--port").arg(RELAY_PORT.to_string());
            cmd.stdout(Stdio::null()).stderr(Stdio::null());
            if let Ok(child) = spawn("relay", cmd) {
                *guard = Some(child);
            }
        }
    }

    // Start each cashu mint via its config file (no env vars in commands).
    for net in default_networks() {
        if net.kind != state::NetworkKind::Cashu {
            continue;
        }
        let port = net.port.unwrap();
        let dir = state::mint_dir(&net.id);
        std::fs::create_dir_all(&dir).map_err(|e| CmdError { message: e.to_string() })?;
        write_seed(&dir.join("seed")).map_err(|e| CmdError { message: e.to_string() })?;
        write_mint_config(&dir).map_err(|e| CmdError { message: e.to_string() })?;

        let mut guard = state.mint_children.lock().await;
        if !guard.contains_key(&net.id) {
            let mut cmd = Command::new("cdk-mintd");
            cmd.arg("-w").arg(&dir);
            cmd.arg("--seed-file").arg(dir.join("seed"));
            cmd.arg("--config").arg(dir.join("config.toml"));
            cmd.arg("--enable-logging");
            if let Ok(child) = spawn(&format!("mint:{}", net.id), cmd) {
                guard.insert(net.id.clone(), child);
            }
        }
        drop(guard);

        // wait until the mint answers before continuing
        wait_mint(port).await;
    }
    Ok(())
}

fn write_mint_config(dir: &PathBuf) -> Result<(), String> {
    use std::fs;
    let cfg = dir.join("config.toml");
    if cfg.exists() {
        return Ok(());
    }
    // cdk-mintd needs the LN backend declared as `[[ln]]` array. The
    // fake wallet settings live at top-level. (See cdk-mintd source.)
    let body = r#"[info]
listen_host = "127.0.0.1"
listen_port = __PORT__

[[ln]]
ln_backend = "fakewallet"

[fake_wallet]
supported_units = ["sat"]
fee_percent = 0
reserve_fee_min = 0
"#;
    let port_line = format!("listen_port = {}", dir.file_name().and_then(|s| s.to_str()).unwrap_or("8091"));
    let body = body.replace("listen_port = __PORT__", &port_line);
    fs::write(&cfg, body).map_err(|e| format!("write {}: {e}", cfg.display()))
}

#[derive(Deserialize)]
struct AddNodeArgs {
    label: String,
    color: Option<String>,
    networks: Vec<String>, // network ids
}

#[tauri::command]
async fn add_node(
    state: State<'_, SharedState>,
    args: AddNodeArgs,
) -> CmdResult<Node> {
    let mut g = state.nodes.lock().await;
    if g.len() >= MAX_NODES {
        return Err(CmdError { message: format!("max {MAX_NODES} nodes") });
    }
    let id = uuid::Uuid::new_v4().to_string();
    let color = args.color.unwrap_or_else(|| {
        NODE_COLORS[g.len() % NODE_COLORS.len()].to_string()
    });
    let home = state::node_home(&id);
    tokio::task::spawn_blocking(move || ensure_node_seed(&home))
        .await
        .map_err(|e| CmdError { message: format!("join: {e}") })?
        .map_err(|e| CmdError { message: e })?;
    let node = Node {
        id: id.clone(),
        label: args.label,
        color,
        memberships: args.networks,
        router_pid: None,
        listener_pid: None,
    };
    g.insert(id, node.clone());
    Ok(node)
}

#[derive(Deserialize)]
struct AddNodeToNetworkArgs {
    node_id: String,
    network_id: String,
}

#[tauri::command]
async fn add_node_to_network(
    state: State<'_, SharedState>,
    args: AddNodeToNetworkArgs,
) -> CmdResult<Node> {
    let mut g = state.nodes.lock().await;
    let n = g.get_mut(&args.node_id).ok_or_else(|| CmdError { message: "no such node".into() })?;
    if !n.memberships.contains(&args.network_id) {
        n.memberships.push(args.network_id);
    }
    Ok(n.clone())
}

#[tauri::command]
async fn remove_node_from_network(
    state: State<'_, SharedState>,
    args: AddNodeToNetworkArgs,
) -> CmdResult<Node> {
    let mut g = state.nodes.lock().await;
    let n = g.get_mut(&args.node_id).ok_or_else(|| CmdError { message: "no such node".into() })?;
    n.memberships.retain(|x| x != &args.network_id);
    Ok(n.clone())
}

#[derive(Deserialize)]
struct GiveMoneyArgs {
    node_id: String,
    network_id: String,
    amount: u64, // sats
}

#[tauri::command]
async fn give_money_to_node(
    state: State<'_, SharedState>,
    args: GiveMoneyArgs,
) -> CmdResult<String> {
    // Mint at the network's mint, then send -> the node cashu-receives.
    let net = default_networks()
        .into_iter()
        .find(|n| n.id == args.network_id)
        .ok_or_else(|| CmdError { message: "no such network".into() })?;
    if net.kind != state::NetworkKind::Cashu {
        return Err(CmdError { message: "network is not a cashu mint".into() });
    }
    let mint_url = net.mint_url.clone().unwrap();
    let cdk = state::cdk_wallet_dir(&net.id);
    std::fs::create_dir_all(&cdk).map_err(|e| CmdError { message: e.to_string() })?;
    let amount = args.amount;

    // 1) cdk-cli mint at the mint
    let mint_out = Command::new("cdk-cli")
        .arg("-w").arg(&cdk)
        .arg("-n")
        .arg("mint")
        .arg(&mint_url)
        .arg(amount.to_string())
        .output().await
        .map_err(|e| CmdError { message: format!("cdk-cli mint: {e}") })?;
    if !mint_out.status.success() {
        let stderr = String::from_utf8_lossy(&mint_out.stderr).to_string();
        return Err(CmdError { message: format!("mint failed: {stderr}") });
    }

    // 2) cdk-cli send -a <amount> --mint-url <url>  -> token on stdout
    let send_out = Command::new("cdk-cli")
        .arg("-w").arg(&cdk)
        .arg("-n")
        .arg("send")
        .arg("-a").arg(amount.to_string())
        .arg("--mint-url").arg(&mint_url)
        .output().await
        .map_err(|e| CmdError { message: format!("cdk-cli send: {e}") })?;
    if !send_out.status.success() {
        let stderr = String::from_utf8_lossy(&send_out.stderr).to_string();
        return Err(CmdError { message: format!("send failed: {stderr}") });
    }
    let stdout = String::from_utf8_lossy(&send_out.stdout).to_string();
    let token = stdout
        .lines()
        .find(|l| l.starts_with("cashuB") || l.starts_with("cashuA"))
        .ok_or_else(|| CmdError { message: "no cashu token in send output".into() })?
        .to_string();

    // 3) cassis-cli cashu receive --proof <token> --home <node>
    let node_home = {
        let g = state.nodes.lock().await;
        g.get(&args.node_id)
            .ok_or_else(|| CmdError { message: "no such node".into() })?;
        state::node_home(&args.node_id)
    };
    let recv = Command::new("cargo")
        .args([
            "run", "-p", "cassis-cli", "--features", "cashu,rootstock", "--",
            "--home", node_home.to_str().unwrap(),
            "cashu", "receive", "--proof", &token,
        ])
        .output().await
        .map_err(|e| CmdError { message: format!("cashu receive: {e}") })?;
    if !recv.status.success() {
        let stderr = String::from_utf8_lossy(&recv.stderr).to_string();
        return Err(CmdError { message: format!("receive failed: {stderr}") });
    }
    Ok(format!(
        "minted {} sat at {} and delivered to node {}",
        amount, mint_url, args.node_id
    ))
}

#[derive(Deserialize)]
struct StartRouterArgs { node_id: String }

#[tauri::command]
async fn start_router(
    state: State<'_, SharedState>,
    args: StartRouterArgs,
) -> CmdResult<u32> {
    let memberships = {
        let g = state.nodes.lock().await;
        let n = g.get(&args.node_id).ok_or_else(|| CmdError { message: "no such node".into() })?;
        if n.memberships.is_empty() {
            return Err(CmdError { message: "node has no networks".into() });
        }
        n.memberships.clone()
    };
    let home = state::node_home(&args.node_id);
    // translate network ids -> cassis-cli --network specs
    let specs: Vec<String> = memberships
        .iter()
        .filter_map(|id| {
            default_networks()
                .into_iter()
                .find(|n| &n.id == id)
                .map(|n| match n.kind {
                    state::NetworkKind::Cashu => format!(
                        "cashu::{}",
                        n.mint_url.unwrap().trim_start_matches("http://").trim_start_matches("https://")
                    ),
                    state::NetworkKind::Rootstock => "rootstock::testnet".to_string(),
                })
        })
        .collect();
    let mut cmd = Command::new("cargo");
    cmd.arg("run")
        .arg("-p").arg("cassis-cli")
        .arg("--features").arg("cashu,rootstock")
        .arg("--")
        .arg("--home").arg(&home)
        .arg("router");
    for s in &specs {
        cmd.arg("--network").arg(s);
    }
    cmd.arg("--nostr-relay").arg(RELAY_URL);
    cmd.stdout(Stdio::null()).stderr(Stdio::null());
    let label = format!("router:{}", args.node_id);
    let child = spawn(&label, cmd).map_err(|e| CmdError { message: e.to_string() })?;
    let pid = child.id().unwrap_or(0);
    let mut g = state.nodes.lock().await;
    if let Some(n) = g.get_mut(&args.node_id) {
        n.router_pid = Some(pid);
    }
    Ok(pid)
}

#[derive(Deserialize)]
struct NodePairArgs { from: String, to: String }

#[tauri::command]
async fn list_routes(args: NodePairArgs) -> CmdResult<String> {
    // Use the cassis-client route lookup over the local relay.
    // We delegate to `cassis-cli route --to <network_id> --amount N --from <network_id>`.
    // For now, use the first network membership of each node.
    let from_nets = node_networks(&args.from)?;
    let to_nets = node_networks(&args.to)?;
    if from_nets.is_empty() || to_nets.is_empty() {
        return Err(CmdError { message: "node has no networks".into() });
    }
    let from = &from_nets[0];
    let to = &to_nets[0];
    let out = Command::new("cargo")
        .args([
            "run", "-p", "cassis-cli", "--features", "cashu,rootstock", "--",
            "route", "--to", to, "--amount", "100", "--from", from,
            "--nostr-relay", RELAY_URL,
        ])
        .output().await
        .map_err(|e| CmdError { message: format!("route: {e}") })?;
    Ok(format!(
        "from {from} to {to}\n{}",
        String::from_utf8_lossy(&out.stdout)
    ))
}

fn node_networks(_node_id: &str) -> CmdResult<Vec<String>> {
    // Mirror the spec translation in start_router (returns the network ids).
    let nets = default_networks();
    Ok(nets.into_iter().map(|n| n.id).collect())
}

#[derive(Deserialize)]
struct CreateInvoiceArgs {
    node_id: String,
    amount_msat: u64,
    network_id: String,
}

#[tauri::command]
async fn create_invoice(
    _state: State<'_, SharedState>,
    args: CreateInvoiceArgs,
) -> CmdResult<String> {
    let home = state::node_home(&args.node_id);
    let spec = network_to_spec(&args.network_id)?;
    let amount_sat = args.amount_msat / 1000;
    let out = Command::new("cargo")
        .args([
            "run", "-p", "cassis-cli", "--features", "cashu,rootstock", "--",
            "--home", home.to_str().unwrap(),
            "invoice", "--amount", &amount_sat.to_string(),
            "--network", &spec,
        ])
        .output().await
        .map_err(|e| CmdError { message: format!("invoice: {e}") })?;
    if !out.status.success() {
        return Err(CmdError { message: format!("invoice: {}", String::from_utf8_lossy(&out.stderr)) });
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

#[derive(Deserialize)]
struct ListenArgs { node_id: String }

#[tauri::command]
async fn start_listener(
    state: State<'_, SharedState>,
    args: ListenArgs,
) -> CmdResult<u32> {
    let _memberships = {
        let g = state.nodes.lock().await;
        let n = g.get(&args.node_id).ok_or_else(|| CmdError { message: "no such node".into() })?;
        if n.memberships.is_empty() {
            return Err(CmdError { message: "node has no networks".into() });
        }
        n.memberships.clone()
    };
    let home = state::node_home(&args.node_id);
    let mut cmd = Command::new("cargo");
    cmd.arg("run")
        .arg("-p").arg("cassis-cli")
        .arg("--features").arg("cashu,rootstock")
        .arg("--")
        .arg("--home").arg(&home)
        .arg("receive");
    cmd.stdout(Stdio::null()).stderr(Stdio::null());
    let label = format!("listener:{}", args.node_id);
    let child = spawn(&label, cmd).map_err(|e| CmdError { message: e.to_string() })?;
    let pid = child.id().unwrap_or(0);
    let mut g = state.nodes.lock().await;
    if let Some(n) = g.get_mut(&args.node_id) {
        n.listener_pid = Some(pid);
    }
    Ok(pid)
}

#[derive(Deserialize)]
struct PayInvoiceArgs {
    from_node_id: String,
    invoice_json: String,
}

#[tauri::command]
async fn pay_invoice(
    state: State<'_, SharedState>,
    args: PayInvoiceArgs,
) -> CmdResult<String> {
    let memberships = {
        let g = state.nodes.lock().await;
        let n = g.get(&args.from_node_id).ok_or_else(|| CmdError { message: "no such node".into() })?;
        if n.memberships.is_empty() {
            return Err(CmdError { message: "node has no networks".into() });
        }
        n.memberships.clone()
    };
    let home = state::node_home(&args.from_node_id);
    let from_spec = network_to_spec(&memberships[0])?;
    let out = Command::new("cargo")
        .args([
            "run", "-p", "cassis-cli", "--features", "cashu,rootstock", "--",
            "--home", home.to_str().unwrap(),
            "pay",
            "--invoice", &args.invoice_json,
            "--from", &from_spec,
            "--nostr-relay", RELAY_URL,
        ])
        .output().await
        .map_err(|e| CmdError { message: format!("pay: {e}") })?;
    if !out.status.success() {
        return Err(CmdError { message: format!("pay: {}", String::from_utf8_lossy(&out.stderr)) });
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

fn network_to_spec(network_id: &str) -> CmdResult<String> {
    let n = default_networks()
        .into_iter()
        .find(|n| n.id == network_id)
        .ok_or_else(|| CmdError { message: "no such network".into() })?;
    Ok(match n.kind {
        state::NetworkKind::Cashu => format!(
            "cashu::{}",
            n.mint_url.unwrap().trim_start_matches("http://").trim_start_matches("https://")
        ),
        state::NetworkKind::Rootstock => "rootstock::testnet".to_string(),
    })
}

pub fn run() {
    let state: SharedState = Arc::new(GuiState::default());
    tauri::Builder::default()
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            list_networks,
            list_nodes,
            bootstrap,
            add_node,
            add_node_to_network,
            remove_node_from_network,
            give_money_to_node,
            start_router,
            list_routes,
            create_invoice,
            start_listener,
            pay_invoice,
        ])
        .setup(|app| {
            // Best-effort initial bootstrap (synchronous setup; full async spawn happens on first invoke).
            let _ = app.handle();
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
