//! The admin page, as a function of the config and of what the daemon
//! runs. Elements that do something have ids naming what they act on,
//! and send actions whose payloads name it too; what a form edits is in
//! its draft, the signal `d.<draft>` (see [`drafts`]).

use super::{Access, Running};
use crate::config::{Config, NetworkConfig};
use cassis_core::node::{HopRecord, HopState};
use cassis_core::routing::{DEFAULT_NOSTR_RELAYS, TEST_NOSTR_RELAYS};
use cassis_core::NetworkId;
use hypereffect::vtree::{
    badge, button, card, checkbox, column, input, list, notice, row, select, tab, tabs, text, Node,
};
use hypereffect::{cel, json, Handler, Map, Value};
use sha2::{Digest, Sha256};

/// What the page shows, besides the config.
pub struct Context<'a> {
    pub config: &'a Config,
    pub running: &'a Running,
    /// Networks the node has open.
    pub open: Vec<NetworkId>,
    pub hops: Vec<HopRecord>,
    pub node_pubkey: String,
    pub iroh_peer_id: String,
    pub http_url: Option<String>,
    pub iroh_url: Option<String>,
    pub pairing_link: Option<String>,
}

impl Context<'_> {
    fn is_open(&self, id: &str) -> bool {
        self.open.iter().any(|open| open.0 == id)
    }

    /// What a restart would change.
    fn pending(&self) -> Vec<String> {
        let mut pending = Vec::new();
        for (id, network) in &self.config.networks {
            match self.running.networks.get(id) {
                None => pending.push(format!("open {id}")),
                Some(running) if running != network => pending.push(format!("reopen {id}")),
                Some(_) => {}
            }
        }
        for id in self.running.networks.keys() {
            if !self.config.networks.contains_key(id) {
                pending.push(format!("close {id}"));
            }
        }
        if self.running.admin.listen != self.config.admin.listen
            || self.running.admin.iroh != self.config.admin.iroh
        {
            pending.push("move the admin interface".into());
        }
        pending
    }
}

/// The signal path segment of the draft of a network's form.
pub fn network_draft(id: &str) -> String {
    format!("n_{}", short_hash(id))
}

/// The signal path segment of the draft of a route's form.
pub fn route_draft(from: &str, to: &str) -> String {
    format!("r_{}", short_hash(&format!("{from}\n{to}")))
}

fn short_hash(text: &str) -> String {
    lowercase_hex::encode(&Sha256::digest(text.as_bytes())[..6])
}

/// The drafts of the forms that edit the config, as it is.
pub fn drafts(config: &Config) -> Map<String, Value> {
    let mut drafts = Map::new();
    drafts.insert(
        "settings".into(),
        json!({
            "nostr_relays": config.nostr_relays.as_deref().map(join).unwrap_or_default(),
            "test_money": config.test_money,
            "max_reservations": config.max_reservations,
        }),
    );
    drafts.insert(
        "admin".into(),
        json!({"listen": config.admin.listen, "iroh": config.admin.iroh}),
    );
    for (id, network) in &config.networks {
        drafts.insert(network_draft(id), network_values(network));
    }
    for route in &config.routes {
        drafts.insert(
            route_draft(&route.from, &route.to),
            json!({
                "fee_base_msat": route.fee_base_msat,
                "fee_ppm": route.fee_ppm,
                "transit_slack_secs": route.transit_slack_secs,
                "nostr_relays": route.nostr_relays.as_deref().map(join).unwrap_or_default(),
                "test_money": match route.test_money {
                    None => "inherit",
                    Some(true) => "true",
                    Some(false) => "false",
                },
            }),
        );
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
        "max_incoming_lifetime_secs": network.max_incoming_lifetime_secs,
        "esplora_url": text(&network.esplora_url),
        "maintenance": network.maintenance,
        "backend": if lnd.is_some() { "lnd" } else if bark.is_some() { "bark" } else { "none" },
        "lnd_rest_url": lnd.map(|lnd| lnd.rest_url.clone()).unwrap_or_default(),
        "lnd_tls_cert_path": path(&lnd.and_then(|lnd| lnd.tls_cert_path.clone())),
        "lnd_macaroon_path": path(&lnd.and_then(|lnd| lnd.macaroon_path.clone())),
        "bark_server_url": text(&bark.and_then(|bark| bark.server_url.clone())),
        "bark_esplora_url": text(&bark.and_then(|bark| bark.esplora_url.clone())),
    })
}

/// The drafts of the forms that add to the config, empty.
pub fn new_drafts(config: &Config) -> Map<String, Value> {
    let mut ids = config.networks.keys();
    let from = ids.next().cloned().unwrap_or_default();
    let to = ids.next().cloned().unwrap_or_default();
    let mut drafts = Map::new();
    drafts.insert("new_network".into(), json!({"id": ""}));
    drafts.insert(
        "new_route".into(),
        json!({"from": from, "to": to, "fee_base_msat": 1000, "fee_ppm": 500}),
    );
    drafts.insert("new_peer".into(), json!({"key": ""}));
    drafts
}

fn join(items: &[String]) -> String {
    items.join(" ")
}

/// A button sending `name` with `payload`, disabled while an action of
/// this session is on its way.
fn act(id: impl Into<String>, label: &str, name: &str, payload: Value) -> Node {
    button(id)
        .label(label)
        .disabled(cel("s._busy"))
        .on_press(Handler::action(name).payload(payload).indicator("_busy"))
}

/// A form's submit button, also disabled while `blocked` (an expression
/// over the signals) holds.
fn submit(id: impl Into<String>, label: &str, name: &str, payload: Value, blocked: &str) -> Node {
    act(id, label, name, payload)
        .variant("primary")
        .disabled(cel(format!("s._busy || ({blocked})")))
}

fn field(id: impl Into<String>, label: &str, path: &str) -> Node {
    input(id).label(label).bind(path)
}

fn number(id: impl Into<String>, label: &str, path: &str) -> Node {
    field(id, label, path).variant("number")
}

fn options<'a>(items: impl IntoIterator<Item = (&'a str, &'a str)>) -> Value {
    Value::Array(
        items
            .into_iter()
            .map(|(value, label)| json!({"value": value, "label": label}))
            .collect(),
    )
}

/// A label over a value to copy.
fn fact(id: &str, label: &str, value: impl Into<String>) -> Node {
    column(id).gap("none").children([
        text(format!("{id}/label")).variant("caption").text(label),
        text(format!("{id}/value"))
            .variant("code")
            .text(value.into()),
    ])
}

/// The page `access` gets.
pub fn page(
    ctx: &Context,
    access: &Access,
    allowed: bool,
    flash: Option<&Result<String, String>>,
) -> Vec<Node> {
    let flash = flash.map(|result| match result {
        Ok(message) => notice("result").variant("success").text(message.as_str()),
        Err(error) => notice("result").variant("failure").text(error.as_str()),
    });
    if !allowed {
        return vec![locked(access, flash)];
    }
    let pending = ctx.pending();
    let header = row("header").justify("between").children([
        text("title").variant("h1").text("Cassis router"),
        act("daemon/restart", "Restart", "daemon.restart", json!({})).variant(
            if pending.is_empty() {
                "secondary"
            } else {
                "primary"
            },
        ),
    ]);
    let pending = (!pending.is_empty()).then(|| {
        notice("restart-needed")
            .variant("warning")
            .title("Saved, applies on restart")
            .text(format!("Restarting will {}.", pending.join(", ")))
    });
    vec![column("page")
        .child(header)
        .children(flash)
        .children(pending)
        .child(tabs("tabs").bind("_tab").children([
            overview(ctx),
            networks(ctx),
            routes(ctx),
            access_tab(ctx, access),
            settings(ctx),
        ]))]
}

fn locked(access: &Access, flash: Option<Node>) -> Node {
    let key = match access {
        Access::Local => "",
        Access::Peer(key) => key.as_str(),
    };
    column("page")
        .child(text("title").variant("h1").text("Cassis router"))
        .children(flash)
        .children([
            notice("locked")
                .variant("warning")
                .title("Not let in")
                .text(
                    "This router does not know your key. Open the pairing link it prints on its \
             console, or add your key from its admin page on its own machine.",
                ),
            fact("locked/key", "Your key", key),
        ])
}

fn overview(ctx: &Context) -> Node {
    let identity = card("identity").title("Identity").children([
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
    let actions = row("overview/actions").child(act(
        "routes/announce",
        "Announce routes now",
        "routes.announce",
        json!({}),
    ));
    tab("tab/overview")
        .label("Overview")
        .children([identity, hops, actions])
}

fn networks(ctx: &Context) -> Node {
    let cards = ctx
        .config
        .networks
        .iter()
        .map(|(id, network)| network_card(ctx, id, network));
    let add = card("network/new").title("Add a network").children([
        field("network/new/id", "Network", "d.new_network.id")
            .placeholder("cashu::mint.example, arkade, lightning, …"),
        submit(
            "network/new/add",
            "Add",
            "network.set",
            json!({"draft": "new_network"}),
            "s.d.new_network.id.trim() == ''",
        ),
    ]);
    tab("tab/networks").label("Networks").children([
        list("networks")
            .empty("No networks yet: add one below.")
            .children(cards),
        add,
    ])
}

fn network_card(ctx: &Context, id: &str, network: &NetworkConfig) -> Node {
    let draft = network_draft(id);
    let d = |field: &str| format!("d.{draft}.{field}");
    let el = |part: &str| format!("network/{id}/{part}");
    let kind = id.split_once("::").map_or(id, |(kind, _)| kind);
    let (variant, status) = if let Some(error) = ctx.running.failed.get(id) {
        ("failure", format!("failed to open: {error}"))
    } else if !ctx.running.networks.contains_key(id) {
        ("warning", "opens on restart".to_string())
    } else if ctx.running.networks.get(id) != Some(network) {
        ("warning", "open, changes apply on restart".to_string())
    } else if ctx.is_open(id) {
        ("success", "open".to_string())
    } else {
        ("warning", "not open".to_string())
    };
    let esplora = matches!(kind, "arkade" | "bitcoin").then(|| {
        field(el("esplora_url"), "Esplora URL", &d("esplora_url")).placeholder("the public one")
    });
    let lightning = (kind == "lightning").then(|| {
        let backend = |name: &str| cel(format!("s.d.{draft}.backend == '{name}'"));
        column(el("backend-settings")).children([
            select(el("backend"))
                .label("Backend")
                .variant("segmented")
                .bind(d("backend"))
                .options(options([
                    ("lnd", "LND"),
                    ("bark", "Bark"),
                    ("none", "None"),
                ])),
            column(el("lnd")).visible(backend("lnd")).children([
                field(el("lnd_rest_url"), "LND REST URL", &d("lnd_rest_url"))
                    .placeholder("https://127.0.0.1:8080"),
                field(
                    el("lnd_tls_cert_path"),
                    "TLS certificate",
                    &d("lnd_tls_cert_path"),
                ),
                field(el("lnd_macaroon_path"), "Macaroon", &d("lnd_macaroon_path")),
            ]),
            column(el("bark")).visible(backend("bark")).children([
                field(el("bark_server_url"), "Ark server", &d("bark_server_url"))
                    .placeholder("Second's server"),
                field(
                    el("bark_esplora_url"),
                    "Esplora URL",
                    &d("bark_esplora_url"),
                )
                .placeholder("the default one"),
            ]),
        ])
    });
    let maintain = ctx.is_open(id).then(|| {
        act(
            el("maintain"),
            "Run upkeep now",
            "network.maintain",
            json!({"id": id}),
        )
    });
    card(format!("network/{id}"))
        .title(id)
        .child(badge(el("status")).variant(variant).text(status))
        .child(
            number(
                el("max_incoming_lifetime_secs"),
                "Longest incoming HTLC (seconds)",
                &d("max_incoming_lifetime_secs"),
            )
            .placeholder("no limit"),
        )
        .children(esplora)
        .child(
            checkbox(el("maintenance"))
                .variant("switch")
                .label("Wallet upkeep")
                .bind(d("maintenance")),
        )
        .children(lightning)
        .child(
            row(el("actions"))
                .child(submit(
                    el("save"),
                    "Save",
                    "network.set",
                    json!({"draft": draft, "id": id}),
                    "false",
                ))
                .children(maintain)
                .child(
                    act(el("remove"), "Remove", "network.remove", json!({"id": id}))
                        .variant("failure"),
                ),
        )
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
            badge(el("status")).variant("success").text("announced")
        } else {
            badge(el("status"))
                .variant("warning")
                .text(format!("not announced: {} not open", closed.join(" and ")))
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
                field(el("nostr_relays"), "Relays", &d("nostr_relays"))
                    .placeholder(join(&config.default_relays())),
                select(el("test_money"))
                    .label("Test money")
                    .bind(d("test_money"))
                    .options(options([
                        (
                            "inherit",
                            if config.test_money {
                                "As in settings (yes)"
                            } else {
                                "As in settings (no)"
                            },
                        ),
                        ("true", "Yes"),
                        ("false", "No"),
                    ])),
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

fn access_tab(ctx: &Context, access: &Access) -> Node {
    let addresses = card("access/addresses").title("Addresses").children([
        fact(
            "access/http",
            "On this machine, open to anyone on it",
            ctx.http_url.as_deref().unwrap_or("off"),
        ),
        fact(
            "access/iroh",
            "Over iroh, to peers only",
            ctx.iroh_url.as_deref().unwrap_or("off"),
        ),
    ]);
    let pairing = ctx.pairing_link.as_ref().map(|link| {
        card("access/pairing").title("Pairing link").children([
            text("access/pairing/help").text(
                "Lets in the first renderer that opens it, which is then a peer. A new \
                 link replaces it, here and on the console.",
            ),
            text("access/pairing/link")
                .variant("code")
                .text(link.as_str()),
            act("pairing/rotate", "New link", "pairing.rotate", json!({})),
        ])
    });
    let peers = ctx.config.admin.peers.iter().map(|key| {
        let you = (*access == Access::Peer(key.clone()))
            .then(|| badge(format!("peer/{key}/you")).variant("info").text("you"));
        row(format!("peer/{key}"))
            .justify("between")
            .child(
                text(format!("peer/{key}/key"))
                    .variant("code")
                    .text(key.as_str()),
            )
            .children(you)
            .child(
                act(
                    format!("peer/{key}/remove"),
                    "Remove",
                    "peer.remove",
                    json!({"key": key}),
                )
                .variant("failure"),
            )
    });
    let peers = card("access/peers").title("Peers").children([
        list("peers").empty("No peers yet.").children(peers),
        row("peer/new").children([
            field("peer/new/key", "Renderer key", "d.new_peer.key")
                .placeholder("64 hex characters"),
            submit(
                "peer/new/add",
                "Add",
                "peer.add",
                json!({"draft": "new_peer"}),
                "s.d.new_peer.key.trim() == ''",
            ),
        ]),
    ]);
    tab("tab/access")
        .label("Access")
        .child(addresses)
        .children(pairing)
        .child(peers)
}

fn settings(ctx: &Context) -> Node {
    let routing = card("settings").title("Routing").children([
        field(
            "settings/nostr_relays",
            "Relays of routes that name none",
            "d.settings.nostr_relays",
        )
        .placeholder(
            if ctx.config.test_money {
                TEST_NOSTR_RELAYS
            } else {
                DEFAULT_NOSTR_RELAYS
            }
            .join(" "),
        ),
        checkbox("settings/test_money")
            .label("Test money, unless a route says otherwise")
            .bind("d.settings.test_money"),
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
    let admin = card("admin").title("Admin interface").children([
        text("admin/help")
            .variant("caption")
            .text("Applies on restart."),
        field(
            "admin/listen",
            "HTTP address, on loopback (empty for none)",
            "d.admin.listen",
        ),
        checkbox("admin/iroh")
            .variant("switch")
            .label("Over iroh, to peers")
            .bind("d.admin.iroh"),
        submit(
            "admin/save",
            "Save",
            "admin.set",
            json!({"draft": "admin"}),
            "false",
        ),
    ]);
    tab("tab/settings")
        .label("Settings")
        .children([routing, admin])
}
