//! The arguments of admin actions, and the edits they make to the
//! config document. Each edit leaves what its arguments do not name as
//! it is, comments included.

use cassis_admin::config::{put, put_text};
use cassis_admin::Args;
use cassis_core::NetworkId;
use cassis_routerd::router::RouteOffer;
use hypereffect::Value;
use toml_edit::{DocumentMut, Item, Table, TableLike};

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

/// Adds `from -> to` if missing, at the default fees unless given.
/// Fields: `fee_base_msat`, `fee_ppm`, `incoming_delta_secs`,
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
        "incoming_delta_secs",
        args.number("incoming_delta_secs")?,
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
            &args(json!({"fee_base_msat": "7", "incoming_delta_secs": 600, "test_money": true})),
        )
        .unwrap();
        let text = doc.to_string();
        assert!(text.contains("# top\n"));
        assert!(text.contains("fee_base_msat = 7 # base\n"));
        assert!(text.contains("fee_ppm = 2\n"));
        assert!(text.contains("incoming_delta_secs = 600\n"));
        assert!(text.contains("test_money = true\n"));
        // Empty unsets what is optional, and is refused for what is not.
        route(
            &mut doc,
            &from,
            &to,
            &args(json!({"incoming_delta_secs": "", "test_money": false})),
        )
        .unwrap();
        assert!(!doc.to_string().contains("incoming_delta_secs"));
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
}
