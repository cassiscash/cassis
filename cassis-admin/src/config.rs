//! The `config.toml` of a daemon ([`ConfigFile`]), and its admin section:
//!
//! ```toml
//! [admin]
//! # listen = "127.0.0.1:7980"      # open admin page over HTTP; "" turns it off
//! # iroh = true                    # admin page over iroh, for `peers`
//! # peers = ["<64 hex>"]           # iroh keys of renderers let in
//! ```

use hypereffect::Value;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;
use toml_edit::{DocumentMut, Item, TableLike};
use tracing::{info, warn};

pub const DEFAULT_LISTEN: &str = "127.0.0.1:7979";
pub const FILE: &str = "config.toml";

#[derive(Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminConfig {
    /// Loopback address of the admin page over HTTP, open to anyone on
    /// this machine; empty turns it off.
    #[serde(default = "default_listen")]
    pub listen: String,
    /// Serve the admin page over iroh, to `peers` only.
    #[serde(default = "yes")]
    pub iroh: bool,
    /// Hex iroh keys of the renderers let in over iroh.
    #[serde(default)]
    pub peers: Vec<String>,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            iroh: true,
            peers: Vec::new(),
        }
    }
}

fn default_listen() -> String {
    DEFAULT_LISTEN.to_string()
}

fn yes() -> bool {
    true
}

impl AdminConfig {
    pub fn listen_addr(&self) -> Result<Option<SocketAddr>, String> {
        if self.listen.is_empty() {
            return Ok(None);
        }
        let addr: SocketAddr = self
            .listen
            .parse()
            .map_err(|e| format!("admin.listen {}: {e}", self.listen))?;
        if !addr.ip().is_loopback() {
            return Err(format!(
                "admin.listen {addr}: the HTTP admin page is open, so it only listens on loopback"
            ));
        }
        Ok(Some(addr))
    }

    /// Whether what is served differs from what `other` asks for.
    pub fn moved_from(&self, other: &AdminConfig) -> bool {
        self.listen != other.listen || self.iroh != other.iroh
    }

    pub fn check(&self) -> Result<(), String> {
        self.listen_addr()?;
        for peer in &self.peers {
            peer_key(peer).map_err(|e| format!("admin.peers {e}"))?;
        }
        Ok(())
    }
}

/// A change to the admin section.
pub enum AdminEdit {
    /// `listen`, and `iroh`, unset by `None` inside.
    Set {
        listen: Option<String>,
        iroh: Option<Option<bool>>,
    },
    /// A renderer's iroh key, which [`peer_key`] made canonical.
    AddPeer(String),
    RemovePeer(String),
}

impl AdminEdit {
    /// Make the change in the table of the admin section, leaving what
    /// it does not name as it is, comments included.
    pub fn apply(&self, admin: &mut dyn TableLike) -> Result<(), String> {
        match self {
            AdminEdit::Set { listen, iroh } => {
                if let Some(listen) = listen {
                    put(admin, "listen", Some(listen.clone().into()));
                }
                if let Some(iroh) = iroh {
                    put(admin, "iroh", iroh.filter(|b| !b).map(Value::from));
                }
            }
            AdminEdit::AddPeer(key) => {
                let peers = peers(admin)?;
                if !peers.iter().any(|peer| peer.as_str() == Some(key)) {
                    peers.push(key);
                }
            }
            AdminEdit::RemovePeer(key) => {
                let peers = peers(admin)?;
                let before = peers.len();
                peers.retain(|peer| peer.as_str() != Some(key));
                if peers.len() == before {
                    return Err(format!("{key} is not a peer"));
                }
            }
        }
        Ok(())
    }
}

/// A renderer key in its canonical form: lowercase hex.
pub fn peer_key(key: &str) -> Result<String, String> {
    key.trim()
        .parse::<iroh::PublicKey>()
        .map(|key| key.to_string())
        .map_err(|e| format!("{key}: not an iroh key: {e}"))
}

fn peers(admin: &mut dyn TableLike) -> Result<&mut toml_edit::Array, String> {
    if admin.get("peers").is_none() {
        admin.insert("peers", toml_edit::value(toml_edit::Array::new()));
    }
    admin
        .get_mut("peers")
        .and_then(Item::as_array_mut)
        .ok_or_else(|| "admin.peers is not a list".to_string())
}

/// The table under `key`, made with `new` if missing.
pub fn child<'a>(
    table: &'a mut dyn TableLike,
    key: &str,
    new: fn() -> Item,
) -> Result<&'a mut dyn TableLike, String> {
    if table.get(key).is_none() {
        table.insert(key, new());
    }
    table
        .get_mut(key)
        .and_then(Item::as_table_like_mut)
        .ok_or_else(|| format!("{key} is not a table"))
}

/// A table written only through the tables under it.
pub fn implicit_table() -> Item {
    let mut table = toml_edit::Table::new();
    table.set_implicit(true);
    Item::Table(table)
}

/// Sets `key` to `change` if given, or removes it if empty.
pub fn put_text(table: &mut dyn TableLike, key: &str, change: Option<String>) {
    if let Some(text) = change {
        put(table, key, (!text.is_empty()).then(|| text.into()));
    }
}

/// Sets or removes `key`, keeping the comments around its old value
/// and above its key.
pub fn put(table: &mut dyn TableLike, key: &str, value: Option<Value>) {
    let Some(value) = value else {
        table.remove(key);
        return;
    };
    let mut value = toml_value(value);
    match table.get_mut(key).and_then(Item::as_value_mut) {
        Some(old) => {
            *value.decor_mut() = old.decor().clone();
            *old = value;
        }
        None => {
            table.insert(key, Item::Value(value));
        }
    }
}

fn toml_value(value: Value) -> toml_edit::Value {
    match value {
        Value::Bool(b) => b.into(),
        Value::Number(n) => n.as_i64().map_or_else(|| n.to_string().into(), Into::into),
        Value::String(text) => text.into(),
        Value::Array(items) => items
            .into_iter()
            .map(toml_value)
            .collect::<toml_edit::Array>()
            .into(),
        other => other.to_string().into(),
    }
}

/// Replace `path` with `text` at once, readable by its owner only.
pub fn write_private(path: &Path, text: &str) -> Result<(), String> {
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension("toml.tmp");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(&tmp)
        .map_err(|e| format!("create {}: {e}", tmp.display()))?;
    file.write_all(text.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("replace {}: {e}", path.display()))
}

/// The admin section as a daemon with its own default address reads it.
#[derive(Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminSection {
    listen: Option<String>,
    iroh: Option<bool>,
    #[serde(default)]
    peers: Vec<String>,
}

impl AdminSection {
    /// The section, listening on `default_listen` unless it says
    /// otherwise.
    pub fn resolve(&self, default_listen: &str) -> AdminConfig {
        AdminConfig {
            listen: self
                .listen
                .clone()
                .unwrap_or_else(|| default_listen.to_string()),
            iroh: self.iroh.unwrap_or(true),
            peers: self.peers.clone(),
        }
    }
}

/// What a [`ConfigFile`] holds.
pub trait DaemonConfig: DeserializeOwned + Clone + Send + 'static {
    /// Whether what parsed makes sense, as more than its types say.
    fn check(&self) -> Result<(), String>;
}

/// A daemon's config file, `<dir>/config.toml`, also edited by its admin
/// interface, which keeps its comments.
pub struct ConfigFile<T> {
    path: PathBuf,
    state: Mutex<(T, Option<SystemTime>)>,
}

impl<T: DaemonConfig> ConfigFile<T> {
    /// Read `<dir>/config.toml`, writing `template` there first if there
    /// is none.
    pub fn load_or_create(dir: &Path, template: &str) -> Result<Self, String> {
        let path = dir.join(FILE);
        if !path.exists() {
            write_private(&path, template)?;
            warn!(
                "wrote a new config to {}: add networks to it, or from the admin interface",
                path.display()
            );
        }
        let config = read(&path)?;
        Ok(Self {
            state: Mutex::new((config, modified(&path))),
            path,
        })
    }

    pub fn get(&self) -> T {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .0
            .clone()
    }

    /// Apply `change` to the file as it is on disk now, keeping its
    /// comments and layout, and write it back if the result is valid.
    pub fn edit(
        &self,
        change: impl FnOnce(&mut DocumentMut) -> Result<(), String>,
    ) -> Result<(), String> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let text = std::fs::read_to_string(&self.path)
            .map_err(|e| format!("read {}: {e}", self.path.display()))?;
        let mut doc: DocumentMut = text
            .parse()
            .map_err(|e| format!("{}: {e}", self.path.display()))?;
        change(&mut doc)?;
        let text = doc.to_string();
        let config = parse(&text)?;
        write_private(&self.path, &text)?;
        *state = (config, modified(&self.path));
        Ok(())
    }

    /// Change the admin section as `edit` says.
    pub fn edit_admin(&self, edit: &AdminEdit) -> Result<(), String> {
        self.edit(|doc| edit.apply(child(doc.as_table_mut(), "admin", toml_edit::table)?))
    }

    /// Pick up edits made to the file by hand. Whether it changed.
    pub fn reload_if_modified(&self) -> bool {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let modified = modified(&self.path);
        if modified == state.1 {
            return false;
        }
        state.1 = modified;
        match read(&self.path) {
            Ok(config) => {
                info!("admin: {} changed, reloaded it", self.path.display());
                state.0 = config;
                true
            }
            Err(error) => {
                warn!("admin: keeping the config as it was: {error}");
                false
            }
        }
    }
}

fn modified(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .ok()
}

fn read<T: DaemonConfig>(path: &Path) -> Result<T, String> {
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    parse(&text).map_err(|e| format!("{}: {e}", path.display()))
}

fn parse<T: DaemonConfig>(text: &str) -> Result<T, String> {
    let config: T = toml::from_str(text).map_err(|e| e.to_string())?;
    config.check()?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Fake {
        #[serde(default)]
        admin: AdminSection,
    }

    impl DaemonConfig for Fake {
        fn check(&self) -> Result<(), String> {
            self.admin.resolve("127.0.0.1:7980").check()
        }
    }

    #[test]
    fn the_file_keeps_comments_and_refuses_what_is_wrong() {
        let dir = std::env::temp_dir().join(format!("cassis-admin-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = ConfigFile::<Fake>::load_or_create(&dir, "# mine\n[admin]\n").unwrap();
        let admin = || file.get().admin.resolve("127.0.0.1:7980");
        assert!(admin().listen == "127.0.0.1:7980" && admin().iroh);

        let key = iroh::SecretKey::from([7; 32]).public().to_string();
        file.edit_admin(&AdminEdit::AddPeer(key.clone())).unwrap();
        assert_eq!(admin().peers, std::slice::from_ref(&key));

        file.edit_admin(&AdminEdit::Set {
            listen: Some("127.0.0.1:2".into()),
            iroh: Some(Some(false)),
        })
        .unwrap();
        let text = std::fs::read_to_string(dir.join(FILE)).unwrap();
        assert!(text.starts_with("# mine\n"), "{text}");
        assert!(!admin().iroh);
        file.edit_admin(&AdminEdit::RemovePeer(key.clone()))
            .unwrap();
        assert!(file.edit_admin(&AdminEdit::RemovePeer(key)).is_err());
        assert!(file
            .edit_admin(&AdminEdit::Set {
                listen: Some("0.0.0.0:2".into()),
                iroh: None
            })
            .is_err());
        assert_eq!(admin().listen, "127.0.0.1:2");

        // Edits by hand: bad ones are ignored, until fixed.
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(dir.join(FILE), "nonsense = 1\n").unwrap();
        assert!(!file.reload_if_modified());
        assert_eq!(admin().listen, "127.0.0.1:2");
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(dir.join(FILE), "[admin]\nlisten = \"127.0.0.1:3\"\n").unwrap();
        assert!(file.reload_if_modified());
        assert_eq!(admin().listen, "127.0.0.1:3");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
