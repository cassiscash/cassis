//! The router's tabs on its admin page, as a function of the config and
//! of what the daemon runs. Elements that do something have ids naming
//! what they act on, and send actions whose payloads name it too; what a
//! form edits is in its draft, the signal `d.<draft>` (see [`drafts`]).

use super::Nostr;
use crate::config::{Config, RouteConfig};
use cassis_admin::view::{act, ago, fact, field, number, options, short_hash, submit};
use cassis_core::NetworkId;
use cassis_core::OperationId;
use cassis_core::routing::{ANNOUNCEMENT_MAX_AGE_SECS, route_d_tag};
use cassis_routerd::db::{Hop, HopState};
use cassis_wallet::stored::StoredFailReason;
use hypereffect::vtree::{Node, badge, card, checkbox, column, list, row, select, tab, text};
use hypereffect::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};

/// What the page shows, besides the config.
pub struct Context<'a> {
    pub config: &'a Config,
    /// The page of the wallets, which keep the networks.
    pub wallets: Vec<Node>,
    /// The name the router goes by: its own, else its autoname.
    pub name: String,
    pub autoname: String,
    /// Networks the node has open.
    pub open: BTreeSet<String>,
    pub hops: Hops,
    pub node_pubkey: String,
    pub iroh_peer_id: String,
    pub nostr: &'a Nostr,
    /// Unix seconds.
    pub now: u64,
}

/// The hops the router routed.
#[derive(Default)]
pub struct Hops {
    pub in_flight: Vec<Hop>,
    pub settled: usize,
    /// Failed by reason.
    pub failed: BTreeMap<String, usize>,
}

impl Hops {
    fn total(&self) -> usize {
        self.in_flight.len() + self.settled + self.failed.values().sum::<usize>()
    }
}

/// How a hop that failed for `reason` is counted.
pub fn fail_kind(reason: &StoredFailReason) -> &'static str {
    match reason {
        StoredFailReason::PreimageNotReceived => "refunded",
        _ => "failed",
    }
}

impl Context<'_> {
    fn is_open(&self, id: &str) -> bool {
        self.open.contains(id)
    }
}

/// The signal path segment of the draft of a route's form.
pub fn route_draft(from: &str, to: &str) -> String {
    format!("r_{}", short_hash(&format!("{from}\n{to}")))
}

/// The drafts of the forms that edit the config, as it is.
pub fn drafts(config: &Config) -> Map<String, Value> {
    let mut drafts = Map::new();
    drafts.insert(
        "settings".into(),
        json!({
            "name": config.name.clone().unwrap_or_default(),
            "nostr_relays": config.nostr_relays.join(" "),
            "max_reservations": config.max_reservations,
        }),
    );
    for route in &config.routes {
        drafts.insert(route_draft(&route.from, &route.to), route_values(route));
    }
    drafts
}

fn route_values(route: &RouteConfig) -> Value {
    json!({
        "fee_base_msat": route.base_fee_msat(),
        "fee_ppm": route.fee_ppm,
        "incoming_delta_secs": route.incoming_delta_secs,
        "test_money": route.test_money,
    })
}

/// The drafts of the forms that add to the config, empty.
pub fn new_drafts(config: &Config) -> Map<String, Value> {
    let mut ids = config.networks.keys();
    let from = ids.next().cloned().unwrap_or_default();
    let to = ids.next().cloned().unwrap_or_default();
    let base = NetworkId::parse(&from).map_or(0, |id| id.default_base_fee_msat());
    let mut drafts = Map::new();
    drafts.insert(
        "new_route".into(),
        json!({
            "from": from,
            "to": to,
            "fee_base_msat": base,
            "fee_ppm": 500,
            "test_money": false,
        }),
    );
    drafts
}

/// `from → to` of a `d` tag.
fn hop_name(d_tag: &str) -> String {
    match d_tag.split_once("->") {
        Some((from, to)) => format!("{from} → {to}"),
        None => d_tag.to_string(),
    }
}

/// The tabs of the page, with the `access` one.
pub fn tabs(ctx: &Context, access: Node) -> Vec<Node> {
    vec![
        overview(ctx),
        networks(ctx),
        routes(ctx),
        access,
        settings(ctx),
    ]
}

fn overview(ctx: &Context) -> Node {
    let identity = card("identity").title("Identity").children([
        fact("identity/name", "Name", &ctx.name),
        fact(
            "identity/node",
            "Node key (signs route announcements)",
            &ctx.node_pubkey,
        ),
        fact("identity/iroh", "Iroh id (cassis-hop)", &ctx.iroh_peer_id),
    ]);
    let state_name = |state: &HopState| match state {
        HopState::Verifying => "verifying",
        HopState::Funding => "funding",
        HopState::Forwarded => "forwarded",
        HopState::Settled => "settled",
        HopState::Failed { .. } => "failed",
    };
    let in_flight = ["verifying", "funding", "forwarded"].map(|name| {
        let count = ctx
            .hops
            .in_flight
            .iter()
            .filter(|hop| state_name(&hop.state) == name)
            .count();
        (name, count)
    });
    let ended = [
        ("settled", ctx.hops.settled),
        (
            "refunded",
            ctx.hops.failed.get("refunded").copied().unwrap_or(0),
        ),
        (
            "failed",
            ctx.hops.failed.get("failed").copied().unwrap_or(0),
        ),
    ];
    let counts = in_flight
        .into_iter()
        .chain(ended)
        .filter(|(_, count)| *count > 0)
        .map(|(name, count)| {
            badge(format!("hops/count/{name}"))
                .variant(match name {
                    "settled" => "success",
                    "failed" => "failure",
                    "refunded" => "warning",
                    _ => "info",
                })
                .text(format!("{count} {name}"))
        });
    let active = ctx.hops.in_flight.iter().map(|hop| {
        text(format!("hop/{}", OperationId(hop.operation_id.0))).text(format!(
            "{} → {} · {} msat · {}",
            hop.incoming_network,
            hop.outgoing_network,
            hop.outgoing_amount_msat,
            state_name(&hop.state)
        ))
    });
    let hops = card("hops")
        .title(format!("Hops · {}", ctx.hops.total()))
        .child(row("hops/counts").wrap(true).children(counts))
        .child(
            list("hops/active")
                .empty("No hop in flight.")
                .children(active),
        );
    tab("tab/overview")
        .label("Overview")
        .children([identity, hops])
}

fn networks(ctx: &Context) -> Node {
    tab("tab/networks")
        .label("Networks")
        .children(ctx.wallets.clone())
}

fn routes(ctx: &Context) -> Node {
    let config = ctx.config;
    let cards = config.routes.iter().map(|route| {
        let (from, to) = (&route.from, &route.to);
        let draft = route_draft(from, to);
        let d = |field: &str| format!("d.{draft}.{field}");
        let el = |part: &str| format!("route/{from}/{to}/{part}");
        let closed: Vec<&str> = [from, to]
            .into_iter()
            .filter(|id| !ctx.is_open(id))
            .map(String::as_str)
            .collect();
        let status = if closed.is_empty() {
            badge(el("status")).variant("success").text("routed")
        } else {
            badge(el("status"))
                .variant("warning")
                .text(format!("not routed: {} not open", closed.join(" and ")))
        };
        card(format!("route/{from}/{to}"))
            .title(format!("{from} → {to}"))
            .children([
                status,
                fees(&el(""), &d("")),
                number(
                    el("incoming_delta_secs"),
                    "Incoming delta (seconds)",
                    &d("incoming_delta_secs"),
                )
                .placeholder("what the networks need"),
                test_money(&el(""), &d("")),
                row(el("actions")).children([
                    submit(
                        el("save"),
                        "Save",
                        "route.set",
                        json!({"draft": draft, "from": from, "to": to}),
                        "false",
                    ),
                    act(
                        el("remove"),
                        "Remove",
                        "route.remove",
                        json!({"from": from, "to": to}),
                    )
                    .variant("failure"),
                ]),
            ])
    });
    let networks = options(config.networks.keys().map(|id| (id.as_str(), id.as_str())));
    let add = if config.networks.len() < 2 {
        card("route/new")
            .title("Add a route")
            .child(text("route/new/help").text("A route needs two networks: add them first."))
    } else {
        card("route/new").title("Add a route").children([
            row("route/new/ends").wrap(true).children([
                select("route/new/from")
                    .label("Receive on")
                    .bind("d.new_route.from")
                    .options(networks.clone()),
                select("route/new/to")
                    .label("Send on")
                    .bind("d.new_route.to")
                    .options(networks),
            ]),
            fees("route/new/", "d.new_route."),
            test_money("route/new/", "d.new_route."),
            submit(
                "route/new/add",
                "Add",
                "route.set",
                json!({"draft": "new_route"}),
                "s.d.new_route.from == s.d.new_route.to",
            ),
        ])
    };
    tab("tab/routes").label("Routes").children([
        announcements(ctx),
        list("routes")
            .empty("No routes: this router forwards nothing.")
            .children(cards),
        add,
    ])
}

/// The fee inputs of a route form, under the element id prefix `el` and
/// the signal path prefix `d`.
fn fees(el: &str, d: &str) -> Node {
    row(format!("{el}fees")).wrap(true).children([
        number(
            format!("{el}fee_base_msat"),
            "Base fee (msat)",
            &format!("{d}fee_base_msat"),
        ),
        number(
            format!("{el}fee_ppm"),
            "Proportional fee (ppm)",
            &format!("{d}fee_ppm"),
        ),
    ])
}

/// A route's test money switch, like [`fees`].
fn test_money(el: &str, d: &str) -> Node {
    checkbox(format!("{el}test_money"))
        .label("Test money: announce it as such")
        .bind(format!("{d}test_money"))
}

/// What the relays keep of this router's announcements, and the button
/// to announce again.
fn announcements(ctx: &Context) -> Node {
    let nostr = ctx.nostr;
    let status = match (nostr.busy, nostr.checked_at) {
        (Some(doing), _) => badge("announcements/status")
            .variant("info")
            .text(format!("{doing}…")),
        (None, Some(at)) => badge("announcements/status")
            .variant("info")
            .text(format!("Relays checked {}", ago(ctx.now, at))),
        (None, None) => badge("announcements/status")
            .variant("info")
            .text("Relays not checked yet"),
    };
    let relays = ctx.config.nostr_relays.iter().map(|relay| {
        let el = |part: &str| format!("announcements/{relay}/{part}");
        let found = nostr.found.get(relay);
        let error = match found {
            Some(Err(error)) => Some(badge(el("error")).variant("failure").text(error.as_str())),
            _ => None,
        };
        let published = match found {
            Some(Ok(published)) => published.as_slice(),
            _ => &[],
        };
        let mut hops: Vec<Node> = Vec::new();
        for route in &ctx.config.routes {
            let d_tag = match (NetworkId::parse(&route.from), NetworkId::parse(&route.to)) {
                (Ok(from), Ok(to)) => route_d_tag(&from, &to),
                _ => continue,
            };
            let state = match published.iter().find(|p| p.d_tag == d_tag) {
                Some(p) if ctx.now.saturating_sub(p.created_at) > ANNOUNCEMENT_MAX_AGE_SECS => (
                    "warning",
                    format!("expired: published {}", ago(ctx.now, p.created_at)),
                ),
                Some(p) => (
                    "success",
                    format!("published {}", ago(ctx.now, p.created_at)),
                ),
                None if !ctx.is_open(&route.from) || !ctx.is_open(&route.to) => {
                    ("warning", "not announced: a network is not open".into())
                }
                None if found.is_some_and(|found| found.is_ok()) => ("warning", "not found".into()),
                None => ("info", "not checked".into()),
            };
            hops.push(announced(&el(&d_tag), &d_tag, state));
        }
        for p in published {
            let routed = ctx
                .config
                .routes
                .iter()
                .any(|route| format!("{}->{}", route.from, route.to) == p.d_tag);
            if !routed {
                let state = (
                    "warning",
                    format!(
                        "not routed, deleted on the next announcement: published {}",
                        ago(ctx.now, p.created_at)
                    ),
                );
                hops.push(announced(&el(&p.d_tag), &p.d_tag, state));
            }
        }
        column(format!("announcements/{relay}"))
            .gap("small")
            .child(
                row(el("header"))
                    .child(text(el("name")).variant("code").text(relay.as_str()))
                    .children(error),
            )
            .child(
                list(el("hops"))
                    .empty("Nothing found on this relay.")
                    .children(hops),
            )
    });
    card("announcements")
        .title("Announcements")
        .child(text("announcements/help").variant("caption").text(
            "Routes are announced on these relays when they change and every few hours; \
             payers ignore announcements older than a day. Relays are set in Settings.",
        ))
        .child(status)
        .children(relays)
        .child(
            row("announcements/actions").children([
                act(
                    "routes/announce",
                    "Announce routes now",
                    "routes.announce",
                    json!({}),
                )
                .variant("primary"),
                act(
                    "announcements/check",
                    "Check relays",
                    "announcements.check",
                    json!({}),
                ),
            ]),
        )
}

/// One hop as a relay keeps it.
fn announced(id: &str, d_tag: &str, (variant, state): (&str, String)) -> Node {
    row(id).justify("between").wrap(true).children([
        text(format!("{id}/hop")).text(hop_name(d_tag)),
        badge(format!("{id}/state")).variant(variant).text(state),
    ])
}

fn settings(ctx: &Context) -> Node {
    let router = card("settings").title("Router").children([
        field("settings/name", "Name", "d.settings.name")
            .placeholder(format!("{}, from its key", ctx.autoname)),
        field(
            "settings/nostr_relays",
            "Relays routes are announced on",
            "d.settings.nostr_relays",
        )
        .placeholder("wss://relay.example …"),
        number(
            "settings/max_reservations",
            "Most hops reserved at once",
            "d.settings.max_reservations",
        ),
        submit(
            "settings/save",
            "Save",
            "settings.set",
            json!({"draft": "settings"}),
            "false",
        ),
    ]);
    tab("tab/settings").label("Settings").child(router)
}
