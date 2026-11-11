//! The arguments of admin actions, and the edits they make to the
//! config document. Each edit leaves what its arguments do not name as
//! it is, comments included.

use cassis_admin::config::{child, implicit_table, put, put_text};
use cassis_admin::Args;
use cassis_core::NetworkId;
use cassis_routerd::router::RouteOffer;
use cassis_wallet::config::new_secret;
use hypereffect::Value;
use toml_edit::{DocumentMut, InlineTable, Item, Table, TableLike};

/// `name`, `nostr_relays`, `max_reservations`.
pub fn settings(doc: &mut DocumentMut, args: &Args) -> Result<(), String> {
    let root = doc.as_table_mut();
    put_text(root, "name", args.text("name")?);
    match args.list("nostr_relays")? {
        Some(None) => return Err("nostr_relays: name at least one relay".into()),
        relays => put_list(root, "nostr_relays", relays),
    }
    put_number(root, "max_reservations", args.number("max_reservations")?)?;
    Ok(())
}

/// Adds the network `new_network_id` describes, with the fields of
/// [`network`] and the backend its kind says.
pub fn add_network(doc: &mut DocumentMut, id: &NetworkId, args: &Args) -> Result<(), String> {
    if doc
        .get("networks")
        .and_then(Item::as_table_like)
        .is_some_and(|networks| networks.contains_key(&id.0))
    {
        return Err(format!("{id} is added already"));
    }
    let mut args = Args(args.0.clone());
    let kind = args.required("kind")?;
    if matches!(kind.as_str(), "lnd" | "bark") {
        args.0.insert("backend".into(), kind.into());
    }
    network(doc, id, &args)
}

/// Adds `id` if missing, with a fresh wallet key. Fields:
/// `esplora_url`, `backend` (`lnd`, `bark` or `none`), and the `lnd_*`
/// and `bark_*` fields of whichever backend the network has.
pub fn network(doc: &mut DocumentMut, id: &NetworkId, args: &Args) -> Result<(), String> {
    let networks = child(doc.as_table_mut(), "networks", implicit_table)?;
    let network = child(networks, &id.0, toml_edit::table)?;
    if !network.contains_key("secret") {
        put(network, "secret", Some(new_secret().into()));
    }
    put_text(network, "esplora_url", args.text("esplora_url")?);
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
/// `test_money`.
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
    if let Some(test_money) = args.flag("test_money")? {
        put(
            route,
            "test_money",
            test_money.filter(|b| *b).map(Value::from),
        );
    }
    Ok(())
}

pub fn remove_route(doc: &mut DocumentMut, from: &NetworkId, to: &NetworkId) -> Result<(), String> {
    let routes = routes(doc)?;
    let at = find_route(routes, from, to).ok_or_else(|| format!("no route {from} -> {to}"))?;
    routes.remove(at);
    Ok(())
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

fn inline_table() -> Item {
    toml_edit::value(InlineTable::new())
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

#[cfg(test)]
mod tests {
    use super::*;
    use cassis_admin::networks::{new_network_id, ALL_KINDS};
    use hypereffect::{json, Action, Map};

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
            &args(json!({"fee_base_msat": "7", "transit_slack_secs": 600, "test_money": true})),
        )
        .unwrap();
        let text = doc.to_string();
        assert!(text.contains("# top\n"));
        assert!(text.contains("fee_base_msat = 7 # base\n"));
        assert!(text.contains("fee_ppm = 2\n"));
        assert!(text.contains("transit_slack_secs = 600\n"));
        assert!(text.contains("test_money = true\n"));
        // Empty unsets what is optional, and is refused for what is not.
        route(
            &mut doc,
            &from,
            &to,
            &args(json!({"transit_slack_secs": "", "test_money": false})),
        )
        .unwrap();
        assert!(!doc.to_string().contains("transit_slack_secs"));
        assert!(!doc.to_string().contains("test_money"));
        assert!(route(&mut doc, &from, &to, &args(json!({"fee_ppm": null}))).is_err());
        remove_route(&mut doc, &from, &to).unwrap();
        assert!(!doc.to_string().contains("[[routes]]"));
    }

    #[test]
    fn rewritten_keys_keep_the_comments_above_them() {
        let mut doc: DocumentMut =
            "# about the file\n\n# relays\nnostr_relays = [\"wss://a\"]\nmnemonic = \"x\"\n"
                .parse()
                .unwrap();
        settings(
            &mut doc,
            &args(json!({"nostr_relays": "wss://b", "name": "r"})),
        )
        .unwrap();
        assert_eq!(
            doc.to_string(),
            "# about the file\n\n# relays\nnostr_relays = [\"wss://b\"]\nmnemonic = \"x\"\nname = \"r\"\n"
        );
    }

    #[test]
    fn networks_and_backends() {
        let mut doc = DocumentMut::new();
        let lightning = id("lightning");
        let lnd = json!({"backend": "lnd", "lnd_rest_url": "https://127.0.0.1:8080", "bark_server_url": "ignored"});
        network(&mut doc, &lightning, &args(lnd)).unwrap();
        let cashu = args(json!({"kind": "cashu", "mint": "https://mint.example/"}));
        let cashu_id = new_network_id(&cashu, &ALL_KINDS).unwrap();
        assert_eq!(cashu_id, id("cashu::mint.example"));
        add_network(&mut doc, &cashu_id, &cashu).unwrap();
        assert!(add_network(&mut doc, &cashu_id, &cashu).is_err());
        // Each network gets a key of its own.
        let text = doc.to_string();
        let secrets: Vec<&str> = text
            .lines()
            .filter(|line| line.starts_with("secret = "))
            .collect();
        assert_eq!(secrets.len(), 2);
        assert_ne!(secrets[0], secrets[1]);
        let rest: String = text
            .lines()
            .filter(|line| !line.starts_with("secret = "))
            .map(|line| format!("{line}\n"))
            .collect();
        assert_eq!(
            rest,
            "[networks.lightning]\nlnd = { rest_url = \"https://127.0.0.1:8080\" }\n\n[networks.\"cashu::mint.example\"]\n"
        );
        network(&mut doc, &lightning, &args(json!({"backend": "bark"}))).unwrap();
        assert!(doc.to_string().contains("bark = {}"));
        assert!(!doc.to_string().contains("lnd"));
    }

    #[test]
    fn new_network_ids() {
        let new = |payload| new_network_id(&args(payload), &ALL_KINDS);
        if cfg!(feature = "arkade") {
            assert_eq!(new(json!({"kind": "arkade"})), Ok(id("arkade")));
            assert_eq!(
                new(json!({"kind": "arkade", "chain": "mutinynet"})),
                Ok(id("arkade::mutinynet"))
            );
            assert!(new(json!({"kind": "arkade", "chain": "regtest"})).is_err());
        }
        if cfg!(feature = "bark-lightning") {
            assert_eq!(
                new(json!({"kind": "bark", "chain": "signet"})),
                Ok(id("lightning::signet"))
            );
        }
        assert!(new(json!({"kind": "dogecoin"})).is_err());
    }
}
