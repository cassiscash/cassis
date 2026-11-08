//! The router's tabs on its admin page, as a function of the config and
//! of what the daemon runs. Elements that do something have ids naming
//! what they act on, and send actions whose payloads name it too; what a
//! form edits is in its draft, the signal `d.<draft>` (see [`drafts`]).

use super::Nostr;
use crate::config::{Config, NetworkConfig, RouteConfig};
use cassis_admin::networks::{
    bark_fields, closing_notice, lnd_fields, network_card as card_of, network_draft, new_network,
    new_network_draft, NetworkCard, Status, ALL_KINDS,
};
use cassis_admin::view::{act, ago, fact, field, number, options, quote, short_hash, submit};
use cassis_admin::wallets::{self, Funds};
use cassis_core::node::{HopRecord, HopState};
use cassis_core::routing::{route_d_tag, ANNOUNCEMENT_MAX_AGE_SECS};
use cassis_core::NetworkId;
use cassis_networks::Can;
use hypereffect::vtree::{badge, card, checkbox, column, list, row, select, tab, text, Node};
use hypereffect::{cel, json, Map, Value};
use std::collections::BTreeMap;

/// What the page shows, besides the config.
pub struct Context<'a> {
    pub config: &'a Config,
    /// The networks the daemon has.
    pub networks: BTreeMap<String, Network>,
    /// The name the router goes by: its own, else its autoname.
    pub name: String,
    pub autoname: String,
    /// Networks the node has open, with the longest an incoming HTLC
    /// may run on each.
    pub open: BTreeMap<String, Option<u64>>,
    pub hops: Vec<HopRecord>,
    pub node_pubkey: String,
    pub iroh_peer_id: String,
    pub nostr: &'a Nostr,
    /// Unix seconds.
    pub now: u64,
}

/// One network as the daemon has it.
pub struct Network {
    /// The config it was opened, or last tried, with.
    pub config: NetworkConfig,
    pub status: Status,
    /// What its wallet can do, while open.
    pub can: Option<Can>,
    pub funds: Funds,
}

impl Context<'_> {
    fn is_open(&self, id: &str) -> bool {
        self.open.contains_key(id)
    }

    /// What a route's incoming lifetime is when it sets none.
    fn lifetime_default(&self, from: &str) -> String {
        match self.open.get(from) {
            Some(Some(secs)) => format!("{secs}, the most {from} allows"),
            Some(None) => format!("no limit: {from} sets none now"),
            None => format!("what {from} allows once open"),
        }
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
    for (id, network) in &config.networks {
        drafts.insert(network_draft(id), network_values(network));
        drafts.extend(wallets::drafts(id));
    }
    for route in &config.routes {
        drafts.insert(route_draft(&route.from, &route.to), route_values(route));
    }
    drafts
}

fn network_values(network: &NetworkConfig) -> Value {
    let text = |value: &Option<String>| value.clone().unwrap_or_default();
    let path = |value: &Option<std::path::PathBuf>| {
        value
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_default()
    };
    let lnd = network.lnd.as_ref();
    let bark = network.bark.as_ref();
    json!({
        "esplora_url": text(&network.esplora_url),
        "backend": if lnd.is_some() { "lnd" } else if bark.is_some() { "bark" } else { "none" },
        "lnd_rest_url": lnd.map(|lnd| lnd.rest_url.clone()).unwrap_or_default(),
        "lnd_tls_cert_path": path(&lnd.and_then(|lnd| lnd.tls_cert_path.clone())),
        "lnd_macaroon_path": path(&lnd.and_then(|lnd| lnd.macaroon_path.clone())),
        "bark_server_url": text(&bark.and_then(|bark| bark.server_url.clone())),
        "bark_esplora_url": text(&bark.and_then(|bark| bark.esplora_url.clone())),
    })
}

fn route_values(route: &RouteConfig) -> Value {
    json!({
        "fee_base_msat": route.fee_base_msat,
        "fee_ppm": route.fee_ppm,
        "transit_slack_secs": route.transit_slack_secs,
        "max_incoming_lifetime_secs": route.max_incoming_lifetime_secs,
        "test_money": route.test_money,
    })
}

/// The drafts of the forms that add to the config, empty.
pub fn new_drafts(config: &Config) -> Map<String, Value> {
    let mut ids = config.networks.keys();
    let from = ids.next().cloned().unwrap_or_default();
    let to = ids.next().cloned().unwrap_or_default();
    let mut drafts = Map::new();
    let (name, draft) = new_network_draft();
    drafts.insert(name, draft);
    drafts.insert(
        "new_route".into(),
        json!({
            "from": from,
            "to": to,
            "fee_base_msat": 1000,
            "fee_ppm": 500,
            "max_incoming_lifetime_secs": null,
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
    const STATES: [&str; 6] = [
        "verifying",
        "funding",
        "forwarded",
        "settled",
        "refunded",
        "failed",
    ];
    let state_name = |state: &HopState| match state {
        HopState::Verifying => "verifying",
        HopState::Funding => "funding",
        HopState::Forwarded => "forwarded",
        HopState::Settled => "settled",
        HopState::Refunded => "refunded",
        HopState::Failed(_) => "failed",
    };
    let counts = STATES.iter().filter_map(|name| {
        let count = ctx
            .hops
            .iter()
            .filter(|hop| state_name(&hop.state) == *name)
            .count();
        (count > 0).then(|| {
            badge(format!("hops/count/{name}"))
                .variant(match *name {
                    "settled" => "success",
                    "failed" => "failure",
                    "refunded" => "warning",
                    _ => "info",
                })
                .text(format!("{count} {name}"))
        })
    });
    let active = ctx
        .hops
        .iter()
        .filter(|hop| {
            matches!(
                hop.state,
                HopState::Verifying | HopState::Funding | HopState::Forwarded
            )
        })
        .map(|hop| {
            let prepare = &hop.prepare;
            text(format!("hop/{}", hop.operation_id)).text(format!(
                "{} → {} · {} msat · {}",
                prepare.incoming_network,
                prepare.outgoing_network,
                prepare.outgoing_amount_msat,
                state_name(&hop.state)
            ))
        });
    let hops = card("hops")
        .title(format!("Hops · {}", ctx.hops.len()))
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
    let cards = ctx
        .config
        .networks
        .iter()
        .map(|(id, network)| network_card(ctx, id, network));
    // Removed from the config, still open for the hops through them.
    let closing = ctx.networks.iter().filter_map(|(id, network)| {
        let Status::Waiting(hops) = &network.status else {
            return None;
        };
        (!ctx.config.networks.contains_key(id)).then(|| closing_notice(id, *hops, "hop"))
    });
    tab("tab/networks")
        .label("Networks")
        .children(closing)
        .children([
            list("networks")
                .empty("No networks yet: add one below.")
                .children(cards),
            new_network(&ALL_KINDS),
        ])
}

fn network_card(ctx: &Context, id: &str, network: &NetworkConfig) -> Node {
    let draft = network_draft(id);
    let d = |field: &str| format!("d.{draft}.{field}");
    let el = |part: &str| format!("network/{id}/{part}");
    let kind = id.split_once("::").map_or(id, |(kind, _)| kind);
    let opened = ctx.networks.get(id);
    let fields: Vec<Node> = match kind {
        "arkade" | "bitcoin" => vec![field(el("esplora_url"), "Esplora URL", &d("esplora_url"))
            .placeholder("the public one")],
        "lightning" => {
            let backend = |name: &str| cel(format!("s.d.{draft}.backend == '{name}'"));
            vec![
                select(el("backend"))
                    .label("Through")
                    .variant("segmented")
                    .bind(d("backend"))
                    .options(options([("lnd", "LND"), ("bark", "Bark")])),
                column(el("lnd"))
                    .visible(backend("lnd"))
                    .children(lnd_fields(&el, &d)),
                column(el("bark"))
                    .visible(backend("bark"))
                    .children(bark_fields(&el, &d)),
            ]
        }
        _ => Vec::new(),
    };
    let wallet = opened
        .and_then(|opened| {
            Some(wallets::view(
                ctx.now,
                id,
                opened.can.as_ref()?,
                &opened.funds,
            ))
        })
        .unwrap_or_default();
    card_of(NetworkCard {
        id,
        status: opened.map(|opened| &opened.status),
        applied: opened.is_some_and(|opened| opened.config == *network),
        unit: "hop",
        fields,
        wallet,
    })
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
                    el("transit_slack_secs"),
                    "Transit slack (seconds)",
                    &d("transit_slack_secs"),
                ),
                lifetime(&el(""), &d("")).placeholder(ctx.lifetime_default(from)),
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
        // The default of the network picked, without a round trip.
        let defaults = config
            .networks
            .keys()
            .map(|id| format!("{}: {}", quote(id), quote(&ctx.lifetime_default(id))))
            .collect::<Vec<_>>()
            .join(", ");
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
            lifetime("route/new/", "d.new_route.")
                .placeholder(cel(format!("{{{defaults}}}[s.d.new_route.from]"))),
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

/// A route's incoming lifetime input, like [`fees`].
fn lifetime(el: &str, d: &str) -> Node {
    number(
        format!("{el}max_incoming_lifetime_secs"),
        "Longest incoming HTLC (seconds)",
        &format!("{d}max_incoming_lifetime_secs"),
    )
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
