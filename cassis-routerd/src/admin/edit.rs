//! The arguments of admin actions, and the edits they make to the
//! config document. Each edit leaves what its arguments do not name as
//! it is, comments included.

use cassis_core::node::RouteOffer;
use cassis_core::NetworkId;
use hypereffect::{Action, Map, Value};
use toml_edit::{DocumentMut, InlineTable, Item, Table, TableLike};

/// An action's payload, over the fields of the draft it names with
/// `draft` (the signal `d.<draft>`). Fields come as JSON values or as
/// the strings inputs hold: absent means unchanged, and `null` or empty
/// unsets what is optional.
pub struct Args(Map<String, Value>);

impl Args {
    pub fn of(action: &Action) -> Self {
        let mut payload = match &action.payload {
            Some(Value::Object(payload)) => payload.clone(),
            _ => Map::new(),
        };
        let mut args = payload
            .remove("draft")
            .and_then(|draft| {
                action
                    .signal(&format!("d.{}", draft.as_str()?))?
                    .as_object()
                    .cloned()
            })
            .unwrap_or_default();
        args.extend(payload);
        Args(args)
    }

    /// Whether the payload named the draft `draft`.
    pub fn draft(action: &Action) -> Option<&str> {
        action.payload.as_ref()?.get("draft")?.as_str()
    }

    pub fn text(&self, key: &str) -> Result<Option<String>, String> {
        Ok(match self.0.get(key) {
            None => None,
            Some(Value::Null) => Some(String::new()),
            Some(Value::String(text)) => Some(text.trim().to_string()),
            Some(Value::Number(n)) => Some(n.to_string()),
            Some(Value::Bool(b)) => Some(b.to_string()),
            Some(_) => return Err(format!("{key}: expected text")),
        })
    }

    pub fn required(&self, key: &str) -> Result<String, String> {
        self.text(key)?
            .filter(|text| !text.is_empty())
            .ok_or_else(|| format!("{key} is required"))
    }

    pub fn number(&self, key: &str) -> Result<Option<Option<u64>>, String> {
        let bad = || format!("{key}: expected a whole number");
        Ok(match self.0.get(key) {
            None => None,
            Some(Value::Null) => Some(None),
            Some(Value::Number(n)) => Some(Some(match n.as_u64() {
                Some(n) => n,
                None => n
                    .as_f64()
                    .filter(|f| *f >= 0.0 && f.fract() == 0.0 && *f <= i64::MAX as f64)
                    .ok_or_else(bad)? as u64,
            })),
            Some(Value::String(text)) if text.trim().is_empty() => Some(None),
            Some(Value::String(text)) => Some(Some(text.trim().parse().map_err(|_| bad())?)),
            Some(_) => return Err(bad()),
        })
    }

    /// A boolean, or `inherit` (like empty) for unset.
    pub fn flag(&self, key: &str) -> Result<Option<Option<bool>>, String> {
        Ok(match self.0.get(key) {
            None => None,
            Some(Value::Null) => Some(None),
            Some(Value::Bool(b)) => Some(Some(*b)),
            Some(Value::String(text)) => Some(match text.trim() {
                "" | "inherit" => None,
                "true" | "yes" | "on" => Some(true),
                "false" | "no" | "off" => Some(false),
                _ => return Err(format!("{key}: expected true or false")),
            }),
            Some(_) => return Err(format!("{key}: expected true or false")),
        })
    }

    /// A list of strings, or one string of them separated by spaces or
    /// commas.
    pub fn list(&self, key: &str) -> Result<Option<Option<Vec<String>>>, String> {
        let items: Vec<String> = match self.0.get(key) {
            None => return Ok(None),
            Some(Value::Null) => Vec::new(),
            Some(Value::String(text)) => text
                .split(|c: char| c == ',' || c.is_whitespace())
                .filter(|item| !item.is_empty())
                .map(str::to_string)
                .collect(),
            Some(Value::Array(items)) => items
                .iter()
                .map(|item| item.as_str().map(|item| item.trim().to_string()))
                .collect::<Option<_>>()
                .ok_or_else(|| format!("{key}: expected a list of text"))?,
            Some(_) => return Err(format!("{key}: expected a list of text")),
        };
        Ok(Some((!items.is_empty()).then_some(items)))
    }
}

/// `nostr_relays`, `test_money`, `max_reservations`.
pub fn settings(doc: &mut DocumentMut, args: &Args) -> Result<(), String> {
    let root = doc.as_table_mut();
    put_list(root, "nostr_relays", args.list("nostr_relays")?);
    if let Some(test_money) = args.flag("test_money")? {
        put(
            root,
            "test_money",
            test_money.filter(|b| *b).map(Value::from),
        );
    }
    put_number(root, "max_reservations", args.number("max_reservations")?)?;
    Ok(())
}

/// `listen`, `iroh`.
pub fn admin(doc: &mut DocumentMut, args: &Args) -> Result<(), String> {
    let admin = child(doc.as_table_mut(), "admin", toml_edit::table)?;
    if let Some(listen) = args.text("listen")? {
        put(admin, "listen", Some(listen.into()));
    }
    if let Some(iroh) = args.flag("iroh")? {
        put(admin, "iroh", iroh.filter(|b| !b).map(Value::from));
    }
    Ok(())
}

/// Adds `id` if missing. Fields: `max_incoming_lifetime_secs`,
/// `esplora_url`, `maintenance`, `backend` (`lnd`, `bark` or `none`),
/// and the `lnd_*` and `bark_*` fields of whichever backend the network
/// has.
pub fn network(doc: &mut DocumentMut, id: &NetworkId, args: &Args) -> Result<(), String> {
    let networks = child(doc.as_table_mut(), "networks", implicit_table)?;
    let network = child(networks, &id.0, toml_edit::table)?;
    put_number(
        network,
        "max_incoming_lifetime_secs",
        args.number("max_incoming_lifetime_secs")?,
    )?;
    put_text(network, "esplora_url", args.text("esplora_url")?);
    if let Some(maintenance) = args.flag("maintenance")? {
        put(
            network,
            "maintenance",
            maintenance.filter(|b| !b).map(Value::from),
        );
    }
    match args.text("backend")?.as_deref() {
        None => {}
        Some("" | "none") => {
            network.remove("lnd");
            network.remove("bark");
        }
        Some("lnd") => {
            network.remove("bark");
            child(network, "lnd", inline_table)?;
        }
        Some("bark") => {
            network.remove("lnd");
            child(network, "bark", inline_table)?;
        }
        Some(other) => return Err(format!("backend {other}: expected lnd, bark or none")),
    }
    if let Some(lnd) = network.get_mut("lnd").and_then(Item::as_table_like_mut) {
        if let Some(url) = args.text("lnd_rest_url")? {
            put(lnd, "rest_url", Some(url.into()));
        }
        put_text(lnd, "tls_cert_path", args.text("lnd_tls_cert_path")?);
        put_text(lnd, "macaroon_path", args.text("lnd_macaroon_path")?);
    }
    if let Some(bark) = network.get_mut("bark").and_then(Item::as_table_like_mut) {
        put_text(bark, "server_url", args.text("bark_server_url")?);
        put_text(bark, "esplora_url", args.text("bark_esplora_url")?);
    }
    Ok(())
}

pub fn remove_network(doc: &mut DocumentMut, id: &NetworkId) -> Result<(), String> {
    let routes = routes(doc)?;
    if routes.iter().any(|route| {
        route_end(route, "from") == Some(&id.0) || route_end(route, "to") == Some(&id.0)
    }) {
        return Err(format!("{id} has routes: remove them first"));
    }
    let removed = doc
        .get_mut("networks")
        .and_then(Item::as_table_like_mut)
        .and_then(|networks| networks.remove(&id.0));
    removed
        .map(|_| ())
        .ok_or_else(|| format!("{id} is not under [networks]"))
}

/// Adds `from -> to` if missing, at the default fees unless given.
/// Fields: `fee_base_msat`, `fee_ppm`, `transit_slack_secs`,
/// `nostr_relays`, `test_money` (`inherit` for the default).
pub fn route(
    doc: &mut DocumentMut,
    from: &NetworkId,
    to: &NetworkId,
    args: &Args,
) -> Result<(), String> {
    let routes = routes(doc)?;
    let at = match find_route(routes, from, to) {
        Some(at) => at,
        None => {
            let defaults = RouteOffer::new(from.clone(), to.clone());
            let mut route = Table::new();
            route.insert("from", toml_edit::value(&from.0));
            route.insert("to", toml_edit::value(&to.0));
            route.insert(
                "fee_base_msat",
                toml_edit::value(toml_int(defaults.fee_base_msat)?),
            );
            route.insert("fee_ppm", toml_edit::value(toml_int(defaults.fee_ppm)?));
            routes.push(route);
            routes.len() - 1
        }
    };
    let route = routes.get_mut(at).expect("found or pushed");
    for key in ["fee_base_msat", "fee_ppm"] {
        match args.number(key)? {
            Some(None) => return Err(format!("{key} is required")),
            fee => put_number(route, key, fee)?,
        }
    }
    put_number(
        route,
        "transit_slack_secs",
        args.number("transit_slack_secs")?,
    )?;
    put_list(route, "nostr_relays", args.list("nostr_relays")?);
    if let Some(test_money) = args.flag("test_money")? {
        put(route, "test_money", test_money.map(Value::from));
    }
    Ok(())
}

pub fn remove_route(doc: &mut DocumentMut, from: &NetworkId, to: &NetworkId) -> Result<(), String> {
    let routes = routes(doc)?;
    let at = find_route(routes, from, to).ok_or_else(|| format!("no route {from} -> {to}"))?;
    routes.remove(at);
    Ok(())
}

/// `key`: a renderer's iroh key, which [`peer_key`] made canonical.
pub fn add_peer(doc: &mut DocumentMut, key: &str) -> Result<(), String> {
    let peers = peers(doc)?;
    if !peers.iter().any(|peer| peer.as_str() == Some(key)) {
        peers.push(key);
    }
    Ok(())
}

pub fn remove_peer(doc: &mut DocumentMut, key: &str) -> Result<(), String> {
    let peers = peers(doc)?;
    let before = peers.len();
    peers.retain(|peer| peer.as_str() != Some(key));
    if peers.len() == before {
        return Err(format!("{key} is not a peer"));
    }
    Ok(())
}

/// A renderer key in its canonical form: lowercase hex.
pub fn peer_key(key: &str) -> Result<String, String> {
    key.trim()
        .parse::<iroh::PublicKey>()
        .map(|key| key.to_string())
        .map_err(|e| format!("{key}: not an iroh key: {e}"))
}

fn peers(doc: &mut DocumentMut) -> Result<&mut toml_edit::Array, String> {
    let admin = child(doc.as_table_mut(), "admin", toml_edit::table)?;
    if admin.get("peers").is_none() {
        admin.insert("peers", toml_edit::value(toml_edit::Array::new()));
    }
    admin
        .get_mut("peers")
        .and_then(Item::as_array_mut)
        .ok_or_else(|| "admin.peers is not a list".to_string())
}

fn routes(doc: &mut DocumentMut) -> Result<&mut toml_edit::ArrayOfTables, String> {
    if doc.get("routes").is_none() {
        doc.insert("routes", Item::ArrayOfTables(Default::default()));
    }
    doc.get_mut("routes")
        .and_then(Item::as_array_of_tables_mut)
        .ok_or_else(|| "routes are not written as [[routes]] tables: edit them by hand".into())
}

fn route_end<'a>(route: &'a Table, end: &str) -> Option<&'a str> {
    route.get(end).and_then(Item::as_str)
}

fn find_route(
    routes: &toml_edit::ArrayOfTables,
    from: &NetworkId,
    to: &NetworkId,
) -> Option<usize> {
    routes.iter().position(|route| {
        route_end(route, "from") == Some(&from.0) && route_end(route, "to") == Some(&to.0)
    })
}

fn implicit_table() -> Item {
    let mut table = Table::new();
    table.set_implicit(true);
    Item::Table(table)
}

fn inline_table() -> Item {
    toml_edit::value(InlineTable::new())
}

/// The table under `key`, made with `new` if missing.
fn child<'a>(
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

/// Sets or removes `key`, keeping the comments around its old value.
fn put(table: &mut dyn TableLike, key: &str, value: Option<Value>) {
    let Some(value) = value else {
        table.remove(key);
        return;
    };
    let mut value = toml_value(value);
    if let Some(old) = table.get(key).and_then(Item::as_value) {
        *value.decor_mut() = old.decor().clone();
    }
    table.insert(key, Item::Value(value));
}

fn put_text(table: &mut dyn TableLike, key: &str, change: Option<String>) {
    if let Some(text) = change {
        put(table, key, (!text.is_empty()).then(|| text.into()));
    }
}

fn put_number(
    table: &mut dyn TableLike,
    key: &str,
    change: Option<Option<u64>>,
) -> Result<(), String> {
    if let Some(number) = change {
        if let Some(n) = number {
            toml_int(n)?;
        }
        put(table, key, number.map(Value::from));
    }
    Ok(())
}

fn put_list(table: &mut dyn TableLike, key: &str, change: Option<Option<Vec<String>>>) {
    if let Some(items) = change {
        put(table, key, items.map(Value::from));
    }
}

fn toml_int(n: u64) -> Result<i64, String> {
    i64::try_from(n).map_err(|_| format!("{n} is too large"))
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

#[cfg(test)]
mod tests {
    use super::*;
    use hypereffect::json;

    fn args(payload: Value) -> Args {
        Args::of(&Action {
            name: "test".into(),
            payload: Some(payload),
            signals: Map::new(),
        })
    }

    fn id(spec: &str) -> NetworkId {
        NetworkId::parse(spec).unwrap()
    }

    #[test]
    fn edits_keep_comments_and_unnamed_fields() {
        let mut doc: DocumentMut = "# top\nmnemonic = \"x\"\n\n[[routes]]\nfrom = \"arkade\"\nto = \"lightning\"\nfee_base_msat = 1 # base\nfee_ppm = 2\n"
            .parse()
            .unwrap();
        let (from, to) = (id("arkade"), id("lightning"));
        route(
            &mut doc,
            &from,
            &to,
            &args(json!({"fee_base_msat": "7", "nostr_relays": "wss://a, wss://b"})),
        )
        .unwrap();
        let text = doc.to_string();
        assert!(text.contains("# top\n"));
        assert!(text.contains("fee_base_msat = 7 # base\n"));
        assert!(text.contains("fee_ppm = 2\n"));
        assert!(text.contains("nostr_relays = [\"wss://a\", \"wss://b\"]"));
        // Empty unsets what is optional, and is refused for what is not.
        route(&mut doc, &from, &to, &args(json!({"nostr_relays": ""}))).unwrap();
        assert!(!doc.to_string().contains("nostr_relays"));
        assert!(route(&mut doc, &from, &to, &args(json!({"fee_ppm": null}))).is_err());
        remove_route(&mut doc, &from, &to).unwrap();
        assert!(!doc.to_string().contains("[[routes]]"));
    }

    #[test]
    fn networks_and_backends() {
        let mut doc = DocumentMut::new();
        let lightning = id("lightning");
        let lnd = json!({"backend": "lnd", "lnd_rest_url": "https://127.0.0.1:8080", "bark_server_url": "ignored"});
        network(&mut doc, &lightning, &args(lnd)).unwrap();
        network(
            &mut doc,
            &id("cashu::mint.example"),
            &args(json!({"maintenance": false})),
        )
        .unwrap();
        assert_eq!(
            doc.to_string(),
            "[networks.lightning]\nlnd = { rest_url = \"https://127.0.0.1:8080\" }\n\n[networks.\"cashu::mint.example\"]\nmaintenance = false\n"
        );
        network(&mut doc, &lightning, &args(json!({"backend": "bark"}))).unwrap();
        assert!(doc.to_string().contains("bark = {}"));
        assert!(!doc.to_string().contains("lnd"));
    }

    #[test]
    fn drafts_under_payloads() {
        let mut signals = Map::new();
        signals.insert("d".into(), json!({"f": {"a": "draft", "b": "draft"}}));
        let args = Args::of(&Action {
            name: "test".into(),
            payload: Some(json!({"draft": "f", "b": "payload"})),
            signals,
        });
        assert_eq!(args.text("a").unwrap().as_deref(), Some("draft"));
        assert_eq!(args.text("b").unwrap().as_deref(), Some("payload"));
        assert_eq!(args.text("draft").unwrap(), None);
    }
}
