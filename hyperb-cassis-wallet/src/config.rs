//! The config file the wallets are kept in: a table of networks, each
//! with its wallet key, in the shape `cassis-wallet` uses, so a Cassis
//! home's `config.toml` is a valid file for it (its table is `networks`).
//! Any other file works too, with a table of any name: the rest of the
//! file is left as it is, comments included.
//!
//! ```toml
//! [networks."cashu::mint.example"]
//! mnemonic = "twelve words ..."    # wallet on this network, 12 or 24 words
//!
//! [networks.arkade]
//! mnemonic = "twelve words ..."
//! esplora_url = "https://..."      # chain API of arkade and bitcoin
//!
//! [networks.lightning]
//! mnemonic = "twelve words ..."
//! lnd = { rest_url = "https://127.0.0.1:8080", tls_cert_path = "...", macaroon_path = "..." }
//! # or: bark = {}                  # Second's server, or { server_url, esplora_url }
//! ```

use cassis_core::NetworkId;
use cassis_core::keys::{generate_mnemonic, parse_wallet_mnemonic};
use cassis_networks::NetworkSettings;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use toml_edit::{DocumentMut, InlineTable, Item, Table};

/// How one network is opened.
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
pub struct Entry {
    /// BIP39 mnemonic (12 or 24 words) of the wallet on this network,
    /// written when it is added.
    pub mnemonic: Option<String>,
    /// Chain API of `arkade` and `bitcoin`, instead of the public one.
    pub esplora_url: Option<String>,
    /// The LND node of a `lightning` network.
    pub lnd: Option<Lnd>,
    /// The Ark server of a `lightning` network going through bark.
    pub bark: Option<Bark>,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
#[cfg_attr(not(feature = "lightning"), allow(dead_code))]
pub struct Lnd {
    pub rest_url: String,
    pub tls_cert_path: Option<PathBuf>,
    pub macaroon_path: Option<PathBuf>,
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[cfg_attr(not(feature = "bark-lightning"), allow(dead_code))]
pub struct Bark {
    /// Second's server for mainnet and signet when unset.
    pub server_url: Option<String>,
    pub esplora_url: Option<String>,
}

impl Entry {
    /// What opening `network` takes, its wallet kept under `dir`
    /// (`<dir>/<kind>/<variant>`). `$CASSIS_ESPLORA_URL` stands in for
    /// an `esplora_url` the entry does not set, as it does for
    /// `cassis-wallet`.
    #[allow(unused_variables)]
    pub fn settings(&self, network: &NetworkId, dir: &Path) -> Result<NetworkSettings, String> {
        let mnemonic = parse_wallet_mnemonic(
            self.mnemonic
                .as_deref()
                .ok_or_else(|| format!("{network} has no mnemonic"))?,
        )
        .map_err(|e| format!("{network} mnemonic: {e}"))?;
        #[cfg(not(feature = "lightning"))]
        if self.lnd.is_some() {
            return Err(format!("{network}: this build has no LND support"));
        }
        #[cfg(not(feature = "bark-lightning"))]
        if self.bark.is_some() {
            return Err(format!("{network}: this build has no bark support"));
        }
        #[cfg(feature = "bark-lightning")]
        let bark = match &self.bark {
            None => None,
            Some(bark) => {
                let default = cassis_networks::bark_lightning::BarkConfig::default_for(network);
                Some(cassis_networks::bark_lightning::BarkConfig {
                    server_url: bark
                        .server_url
                        .clone()
                        .or_else(|| default.as_ref().map(|d| d.server_url.clone()))
                        .ok_or_else(|| format!("{network} has no default Ark server"))?,
                    esplora_url: bark
                        .esplora_url
                        .clone()
                        .or_else(|| default.as_ref().map(|d| d.esplora_url.clone()))
                        .ok_or_else(|| format!("{network} has no default Esplora"))?,
                })
            }
        };
        let mut esplora_url = self.esplora_url.clone();
        if esplora_url.is_none() && matches!(network.kind(), "arkade" | "bitcoin") {
            esplora_url = std::env::var("CASSIS_ESPLORA_URL").ok();
        }
        // Over `new`, as `cassis-networks` may have more networks built
        // than this crate does, when another crate turns them on.
        #[allow(unused_mut)]
        let mut settings = NetworkSettings {
            esplora_url,
            ..NetworkSettings::new(mnemonic, cassis_networks::network_dir(dir, network))
        };
        #[cfg(feature = "lightning")]
        {
            settings.lnd = self.lnd.as_ref().map(|lnd| {
                cassis_networks::lnd::LndConfig::new(
                    lnd.rest_url.clone(),
                    lnd.tls_cert_path.clone(),
                    lnd.macaroon_path.clone(),
                )
            });
        }
        #[cfg(feature = "bark-lightning")]
        {
            settings.bark = bark;
        }
        Ok(settings)
    }
}

/// The file, and the name of the table in it that holds the networks.
#[derive(Clone, Debug)]
pub struct ConfigFile {
    path: PathBuf,
    table: String,
}

impl ConfigFile {
    pub fn new(path: impl Into<PathBuf>, table: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            table: table.into(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The networks in the file. A file that is not there has none.
    pub fn read(&self) -> Result<BTreeMap<String, Entry>, String> {
        let text = self.text()?;
        self.parse(&text)
    }

    fn text(&self) -> Result<String, String> {
        match std::fs::read_to_string(&self.path) {
            Ok(text) => Ok(text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
            Err(e) => Err(format!("read {}: {e}", self.path.display())),
        }
    }

    fn parse(&self, text: &str) -> Result<BTreeMap<String, Entry>, String> {
        let mut file: toml::Table =
            toml::from_str(text).map_err(|e| format!("{}: {e}", self.path.display()))?;
        let Some(table) = file.remove(&self.table) else {
            return Ok(BTreeMap::new());
        };
        let networks: BTreeMap<String, Entry> = table
            .try_into()
            .map_err(|e| format!("{} [{}]: {e}", self.path.display(), self.table))?;
        for id in networks.keys() {
            NetworkId::parse(id)
                .map_err(|e| format!("{} [{}]: {e}", self.path.display(), self.table))?;
        }
        Ok(networks)
    }

    /// Apply `change` to the file as it is on disk now, keeping its
    /// comments and layout, and write it back, readable by its owner
    /// only, if the result is valid.
    pub fn edit(
        &self,
        change: impl FnOnce(&mut Table) -> Result<(), String>,
    ) -> Result<(), String> {
        let text = self.text()?;
        let mut doc: DocumentMut = text
            .parse()
            .map_err(|e| format!("{}: {e}", self.path.display()))?;
        let networks = child(doc.as_table_mut(), &self.table, implicit_table)?;
        change(networks)?;
        let text = doc.to_string();
        self.parse(&text)?;
        write_private(&self.path, &text)
    }
}

fn implicit_table() -> Item {
    let mut table = Table::new();
    table.set_implicit(true);
    Item::Table(table)
}

fn child<'a>(
    parent: &'a mut Table,
    key: &str,
    make: fn() -> Item,
) -> Result<&'a mut Table, String> {
    parent
        .entry(key)
        .or_insert_with(make)
        .as_table_mut()
        .ok_or_else(|| format!("{key} is not a table"))
}

/// Write `text` to `path`, readable by its owner only.
fn write_private(path: &Path, text: &str) -> Result<(), String> {
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(".tmp");
    let temporary = PathBuf::from(temporary);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(&temporary)
        .map_err(|e| format!("create {}: {e}", temporary.display()))?;
    file.write_all(text.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("write {}: {e}", temporary.display()))?;
    std::fs::rename(&temporary, path).map_err(|e| format!("write {}: {e}", path.display()))
}

/// What a form says about a network. Empty means not set.
#[derive(Clone, Debug, Default)]
pub struct Fields {
    pub esplora_url: String,
    pub lnd_rest_url: String,
    pub lnd_tls_cert_path: String,
    pub lnd_macaroon_path: String,
    pub bark_server_url: String,
    pub bark_esplora_url: String,
}

fn put(table: &mut Table, key: &str, text: &str) {
    match text.trim() {
        "" => {
            table.remove(key);
        }
        text => {
            table.insert(key, toml_edit::value(text));
        }
    }
}

fn inline(pairs: &[(&str, &str)]) -> Item {
    let mut table = InlineTable::new();
    for (key, text) in pairs {
        if !text.trim().is_empty() {
            table.insert(*key, text.trim().into());
        }
    }
    Item::Value(table.into())
}

/// Write what `fields` say into the table of `id`, adding the network
/// with a fresh wallet key if it is missing. The kind of a `lightning`
/// network (LND or bark) is that of its entry, or `bark` if `bark`.
pub fn set(
    networks: &mut Table,
    id: &NetworkId,
    fields: &Fields,
    bark: bool,
) -> Result<(), String> {
    let table = child(networks, &id.0, toml_edit::table)?;
    if !table.contains_key("mnemonic") {
        table.insert("mnemonic", toml_edit::value(generate_mnemonic()));
    }
    match id.kind() {
        "arkade" | "bitcoin" => put(table, "esplora_url", &fields.esplora_url),
        "lightning" if bark || table.contains_key("bark") => {
            table.remove("lnd");
            table.insert(
                "bark",
                inline(&[
                    ("server_url", &fields.bark_server_url),
                    ("esplora_url", &fields.bark_esplora_url),
                ]),
            );
        }
        "lightning" => {
            if fields.lnd_rest_url.trim().is_empty() {
                return Err("the LND REST URL is required".into());
            }
            table.insert(
                "lnd",
                inline(&[
                    ("rest_url", &fields.lnd_rest_url),
                    ("tls_cert_path", &fields.lnd_tls_cert_path),
                    ("macaroon_path", &fields.lnd_macaroon_path),
                ]),
            );
        }
        _ => {}
    }
    Ok(())
}

/// Remove `id`, and its wallet key with it.
pub fn remove(networks: &mut Table, id: &NetworkId) -> Result<(), String> {
    networks
        .remove(&id.0)
        .map(|_| ())
        .ok_or_else(|| format!("{id} is not in the config file"))
}

/// A kind of network to add: its name, and its label.
pub type Kind = (&'static str, &'static str);

/// Every kind of network.
pub const KINDS: [Kind; 11] = [
    ("arkade", "Arkade"),
    ("cashu", "Cashu"),
    ("liquid", "Liquid"),
    ("lnd", "Lightning (LND)"),
    ("bark", "Lightning (bark)"),
    ("fedimint", "Fedimint"),
    ("bitcoin", "Bitcoin"),
    ("rootstock", "Rootstock"),
    ("citrea", "Citrea"),
    ("starknet-wbtc", "WBTC on Starknet"),
    ("solana-wbtc", "WBTC on Solana"),
];

/// The chains a kind runs on, the first its default.
pub fn chains(kind: &str) -> &'static [&'static str] {
    match kind {
        "arkade" => &["mainnet", "mutinynet"],
        "bitcoin" => &["mainnet", "mutinynet", "regtest"],
        "liquid" | "rootstock" | "citrea" => &["mainnet", "testnet"],
        "starknet-wbtc" => &["mainnet", "sepolia"],
        "solana-wbtc" => &["mainnet"],
        "lnd" | "bark" => &["mainnet", "signet", "mutinynet", "regtest"],
        _ => &[],
    }
}

/// The id of the network of `kind` (one of [`KINDS`]) on `chain` (one of
/// its [`chains`], or empty for the first), or for `cashu` on the mint
/// `mint` and for `fedimint` with the invite `invite`.
pub fn network_id(kind: &str, chain: &str, mint: &str, invite: &str) -> Result<NetworkId, String> {
    let (_, label) = KINDS
        .iter()
        .find(|(name, _)| *name == kind)
        .ok_or_else(|| format!("unknown kind of network {kind:?}"))?;
    if !cassis_networks::built(kind) {
        return Err(format!("this build has no {label} support"));
    }
    let spec = match kind {
        "cashu" => {
            let mint = mint.trim();
            if mint.is_empty() {
                return Err("the mint is required".into());
            }
            let host = mint
                .strip_prefix("https://")
                .or_else(|| mint.strip_prefix("http://"))
                .unwrap_or(mint)
                .trim_end_matches('/');
            format!("cashu::{host}")
        }
        "fedimint" => match invite.trim() {
            "" => return Err("the invite code is required".into()),
            invite => format!("fedimint::{invite}"),
        },
        kind => {
            let chains = chains(kind);
            let chain = match chain.trim() {
                "" => chains[0],
                chain => chain,
            };
            if !chains.contains(&chain) {
                return Err(format!(
                    "{label} runs on {}, not {chain}",
                    chains.join(", ")
                ));
            }
            let kind = if matches!(kind, "lnd" | "bark") {
                "lightning"
            } else {
                kind
            };
            match chain {
                "mainnet" => kind.to_string(),
                chain => format!("{kind}::{chain}"),
            }
        }
    };
    NetworkId::parse(&spec)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(name: &str, text: &str) -> ConfigFile {
        let path = std::env::temp_dir().join(format!("hcw-{}-{name}.toml", std::process::id()));
        std::fs::write(&path, text).unwrap();
        ConfigFile::new(path, "networks")
    }

    #[test]
    fn adding_keeps_the_rest_of_the_file() {
        let file = file("add", "# mine\nmnemonic = \"x\"\n");
        let id = NetworkId::parse("arkade").unwrap();
        file.edit(|t| set(t, &id, &Fields::default(), false))
            .unwrap();
        let mnemonic = file.read().unwrap()["arkade"].mnemonic.clone().unwrap();
        assert_eq!(mnemonic.split_whitespace().count(), 12);
        // saving again keeps the key
        let fields = Fields {
            esplora_url: "https://esplora.example".into(),
            ..Fields::default()
        };
        file.edit(|t| set(t, &id, &fields, false)).unwrap();
        let entry = file.read().unwrap().remove("arkade").unwrap();
        assert_eq!(entry.mnemonic.as_deref(), Some(mnemonic.as_str()));
        assert_eq!(
            entry.esplora_url.as_deref(),
            Some("https://esplora.example")
        );
        let text = std::fs::read_to_string(file.path()).unwrap();
        assert!(text.starts_with("# mine\nmnemonic"));
        file.edit(|t| remove(t, &id)).unwrap();
        assert!(file.read().unwrap().is_empty());
    }

    #[test]
    fn an_invalid_edit_writes_nothing() {
        let file = file("bad", "");
        let id = NetworkId::parse("lightning").unwrap();
        assert!(
            file.edit(|t| set(t, &id, &Fields::default(), false))
                .is_err()
        );
        assert!(file.read().unwrap().is_empty());
    }
}
