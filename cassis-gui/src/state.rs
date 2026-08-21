use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::process::{Child, Command};
use tokio::sync::Mutex;

pub const MAX_NODES: usize = 10;
pub const RELAY_PORT: u16 = 10547;
pub const RELAY_URL: &str = "ws://localhost:10547";

/// One cashu mint (cdk-mintd) or the rootstock testnet (no mint dir).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Network {
    pub id: String,
    pub label: String,
    pub kind: NetworkKind,        // Cashu | Rootstock
    pub port: Option<u16>,        // cashu mint listen port
    pub mint_url: Option<String>, // http(s)://...:port, if cashu
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum NetworkKind {
    Cashu,
    Rootstock,
}

/// A canvas node (peer). May be a member of multiple networks.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Node {
    pub id: String,
    pub label: String,
    pub color: String,
    pub memberships: Vec<String>, // network ids
    /// running router child (None when not started)
    pub router_pid: Option<u32>,
    /// running invoice-listener child (None when not started)
    pub listener_pid: Option<u32>,
}

#[derive(Default)]
pub struct GuiState {
    pub nodes: Mutex<HashMap<String, Node>>,
    pub relay_child: Mutex<Option<Child>>,
    pub mint_children: Mutex<HashMap<String, Child>>, // network_id -> child
}

pub type SharedState = Arc<GuiState>;

/// Layout (prearranged network rectangles). Coordinates in canvas pixels.
pub fn default_networks() -> Vec<Network> {
    vec![
        Network {
            id: "cashu1".into(),
            label: "cashu 1".into(),
            kind: NetworkKind::Cashu,
            port: Some(8091),
            mint_url: Some("http://127.0.0.1:8091".into()),
        },
        Network {
            id: "cashu2".into(),
            label: "cashu 2".into(),
            kind: NetworkKind::Cashu,
            port: Some(8092),
            mint_url: Some("http://127.0.0.1:8092".into()),
        },
        Network {
            id: "cashu3".into(),
            label: "cashu 3".into(),
            kind: NetworkKind::Cashu,
            port: Some(8093),
            mint_url: Some("http://127.0.0.1:8093".into()),
        },
        Network {
            id: "rootstock_testnet".into(),
            label: "rootstock testnet".into(),
            kind: NetworkKind::Rootstock,
            port: None,
            mint_url: None,
        },
    ]
}

pub const NODE_COLORS: &[&str] = &[
    "#e6194B", "#3cb44b", "#4363d8", "#f58231", "#911eb4", "#42d4f4", "#f032e6", "#9A6324",
    "#469990", "#800000",
];

/// Root directory the GUI uses for its runtime state (dirs, seeds, cdk wallets).
pub fn gui_root() -> PathBuf {
    PathBuf::from("tmp").join("gui")
}

pub fn node_home(node_id: &str) -> PathBuf {
    gui_root().join("nodes").join(node_id)
}

pub fn mint_dir(network_id: &str) -> PathBuf {
    gui_root().join("mints").join(network_id)
}

pub fn cdk_wallet_dir(network_id: &str) -> PathBuf {
    gui_root().join("cdk").join(network_id)
}

/// Shared mnemonic for every GUI mint (deterministic across runs, like the
/// justfile setup). Mints use this to derive their own keyset.
pub const GUI_MINT_MNEMONIC: &str =
    "hire movie pyramid only journey sun eight stadium salt engage inmate enlist";

/// Spawn a child process, logging stderr/stdout to the GUI stderr.
pub fn spawn(label: &str, mut cmd: Command) -> std::io::Result<Child> {
    cmd.kill_on_drop(true);
    let child = cmd.spawn()?;
    eprintln!("[gui] spawned {label} (pid={:?})", child.id());
    Ok(child)
}
