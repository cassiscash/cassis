//! The admin page, as a function of the config and of what the daemon
//! runs. Elements that do something have ids naming what they act on,
//! and send actions whose payloads name it too; what a form edits is in
//! its draft, the signal `d.<draft>` (see [`drafts`]).

use super::edit::{chains, KINDS};
use super::{Access, Nostr};
use crate::config::{AdminConfig, Config, NetworkConfig, RouteConfig};
use crate::networks::Status;
use cassis_core::node::{HopRecord, HopState};
use cassis_core::routing::{route_d_tag, ANNOUNCEMENT_MAX_AGE_SECS};
use cassis_core::NetworkId;
use hypereffect::vtree::{
    badge, button, card, checkbox, column, input, list, notice, row, select, tab, tabs, text, Node,
};
use hypereffect::{cel, json, Handler, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// What the page shows, besides the config.
pub struct Context<'a> {
    pub config: &'a Config,
    /// The admin section served, which changes apply to on restart.
    pub serving: &'a AdminConfig,
    /// The networks the daemon has, with the config they were opened,
    /// or last tried, with.
    pub networks: BTreeMap<String, (NetworkConfig, Status)>,
    /// The name the router goes by: its own, else its autoname.
    pub name: String,
    pub autoname: String,
    /// Networks the node has open, with the longest an incoming HTLC
    /// may run on each.
    pub open: BTreeMap<String, Option<u64>>,
    pub hops: Vec<HopRecord>,
    pub node_pubkey: String,
    pub iroh_peer_id: String,
    pub http_url: Option<String>,
    pub iroh_url: Option<String>,
    pub pairing_link: Option<String>,
    pub nostr: &'a Nostr,
    /// Unix seconds.
    pub now: u64,
}

impl Context<'_> {
    fn is_open(&self, id: &str) -> bool {
        self.open.contains_key(id)
    }

    /// What a restart would change.
    fn pending(&self) -> Vec<String> {
        let mut pending = Vec::new();
        if self.serving.listen != self.config.admin.listen
            || self.serving.iroh != self.config.admin.iroh
        {
            pending.push("move the admin interface".into());
        }
        pending
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
            "name": config.name.clone().unwrap_or_default(),
            "nostr_relays": config.nostr_relays.join(" "),
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
    drafts.insert(
        "new_network".into(),
        json!({
            "kind": "",
            "chain": "",
            "mint": "",
            "invite": "",
            "esplora_url": "",
            "lnd_rest_url": "",
            "lnd_tls_cert_path": "",
            "lnd_macaroon_path": "",
            "bark_server_url": "",
            "bark_esplora_url": "",
        }),
    );
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
    drafts.insert("new_peer".into(), json!({"key": ""}));
    drafts
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

/// A CEL string literal.
fn quote(text: &str) -> String {
    format!("'{}'", text.replace('\\', "\\\\").replace('\'', "\\'"))
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

/// How long ago `then` was, coarsely.
fn ago(now: u64, then: u64) -> String {
    match now.saturating_sub(then) {
        0..=59 => "just now".into(),
        secs @ 60..=3_599 => format!("{} min ago", secs / 60),
        secs @ 3_600..=86_399 => format!("{} h ago", secs / 3_600),
        secs => format!("{} days ago", secs / 86_400),
    }
}

/// `from → to` of a `d` tag.
fn hop_name(d_tag: &str) -> String {
    match d_tag.split_once("->") {
        Some((from, to)) => format!("{from} → {to}"),
        None => d_tag.to_string(),
    }
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
        return vec![locked(ctx, access, flash)];
    }
    let pending = ctx.pending();
    let header = row("header").justify("between").children([
        title(ctx),
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

fn title(ctx: &Context) -> Node {
    column("title").gap("none").children([
        text("title/name").variant("h1").text(ctx.name.as_str()),
        text("title/what").variant("caption").text("Cassis router"),
    ])
}

fn locked(ctx: &Context, access: &Access, flash: Option<Node>) -> Node {
    let key = match access {
        Access::Local => "",
        Access::Peer(key) => key.as_str(),
    };
    column("page").child(title(ctx)).children(flash).children([
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
    let closing = ctx.networks.iter().filter_map(|(id, (_, status))| {
        let Status::Waiting(hops) = status else {
            return None;
        };
        (!ctx.config.networks.contains_key(id)).then(|| {
            notice(format!("network/{id}/closing"))
                .variant("warning")
                .text(format!(
                    "{id} closes once its {hops} hop(s) in flight settle."
                ))
        })
    });
    tab("tab/networks")
        .label("Networks")
        .children(closing)
        .children([
            list("networks")
                .empty("No networks yet: add one below.")
                .children(cards),
            new_network(),
        ])
}

/// The picker of a network's kind, then what that kind needs.
fn new_network() -> Node {
    let kind_is = |kind: &str| format!("s.d.new_network.kind == {}", quote(kind));
    let picker = KINDS.iter().map(|(kind, label, built)| {
        let chain = chains(kind).first().copied().unwrap_or_default();
        button(format!("network/new/kind/{kind}"))
            .label(*label)
            .variant(cel(format!("{} ? 'primary' : 'secondary'", kind_is(kind))))
            .disabled(!built)
            .on_press(Handler::patch(
                json!({"d": {"new_network": {"kind": kind, "chain": chain}}}),
            ))
    });
    let missing = KINDS.iter().any(|(.., built)| !built).then(|| {
        text("network/new/missing")
            .variant("caption")
            .text("Greyed out: not compiled into this build.")
    });
    let details = KINDS.iter().map(|(kind, _, _)| {
        let el = |part: &str| format!("network/new/{kind}/{part}");
        let d = |field: &str| format!("d.new_network.{field}");
        let chains = chains(kind);
        let chain = (!chains.is_empty()).then(|| {
            select(el("chain"))
                .label("Chain")
                .variant("segmented")
                .bind(d("chain"))
                .options(options(
                    chains.iter().map(|chain| (*chain, chain_label(chain))),
                ))
        });
        let fields: Vec<Node> = match *kind {
            "cashu" => {
                vec![field(el("mint"), "Mint URL", &d("mint")).placeholder("https://mint.example")]
            }
            "fedimint" => {
                vec![field(el("invite"), "Invite code", &d("invite")).placeholder("fed1…")]
            }
            "arkade" | "bitcoin" => {
                vec![field(el("esplora_url"), "Esplora URL", &d("esplora_url"))
                    .placeholder("the public one")]
            }
            "lnd" => lnd_fields(&el, &d),
            "bark" => bark_fields(&el, &d),
            _ => Vec::new(),
        };
        column(format!("network/new/{kind}"))
            .visible(cel(kind_is(kind)))
            .children(chain)
            .children(fields)
    });
    card("network/new")
        .title("Add a network")
        .child(row("network/new/kinds").wrap(true).children(picker))
        .children(missing)
        .children(details)
        .child(submit(
            "network/new/add",
            "Add",
            "network.add",
            json!({"draft": "new_network"}),
            "s.d.new_network.kind == '' \
             || (s.d.new_network.kind == 'cashu' && s.d.new_network.mint.trim() == '') \
             || (s.d.new_network.kind == 'fedimint' && s.d.new_network.invite.trim() == '')",
        ))
}

fn chain_label(chain: &str) -> &str {
    match chain {
        "mainnet" => "Mainnet",
        "mutinynet" => "Mutinynet",
        "signet" => "Signet",
        "testnet" => "Testnet",
        "regtest" => "Regtest",
        other => other,
    }
}

/// The inputs of an LND node, under element ids from `el` and signal
/// paths from `d`.
fn lnd_fields(el: &dyn Fn(&str) -> String, d: &dyn Fn(&str) -> String) -> Vec<Node> {
    vec![
        field(el("lnd_rest_url"), "LND REST URL", &d("lnd_rest_url"))
            .placeholder("https://127.0.0.1:8080"),
        field(
            el("lnd_tls_cert_path"),
            "TLS certificate",
            &d("lnd_tls_cert_path"),
        )
        .placeholder("/path/to/tls.cert"),
        field(el("lnd_macaroon_path"), "Macaroon", &d("lnd_macaroon_path"))
            .placeholder("/path/to/admin.macaroon"),
    ]
}

/// The inputs of an Ark server for bark, like [`lnd_fields`].
fn bark_fields(el: &dyn Fn(&str) -> String, d: &dyn Fn(&str) -> String) -> Vec<Node> {
    vec![
        field(el("bark_server_url"), "Ark server", &d("bark_server_url"))
            .placeholder("Second's server"),
        field(
            el("bark_esplora_url"),
            "Esplora URL",
            &d("bark_esplora_url"),
        )
        .placeholder("the default one"),
    ]
}

fn network_card(ctx: &Context, id: &str, network: &NetworkConfig) -> Node {
    let draft = network_draft(id);
    let d = |field: &str| format!("d.{draft}.{field}");
    let el = |part: &str| format!("network/{id}/{part}");
    let kind = id.split_once("::").map_or(id, |(kind, _)| kind);
    let status = ctx.networks.get(id).map(|(_, status)| status);
    let applied = ctx
        .networks
        .get(id)
        .is_some_and(|(opened, _)| opened == network);
    let (variant, status_text) = match status {
        None | Some(Status::Opening) => ("info", "opening…".to_string()),
        Some(Status::Open) if !applied => ("info", "applying changes…".to_string()),
        Some(Status::Open) => ("success", "open".to_string()),
        Some(Status::Failed(error)) => ("failure", format!("failed to open: {error}")),
        Some(Status::Waiting(hops)) => (
            "warning",
            format!("open, changes apply once its {hops} hop(s) in flight settle"),
        ),
    };
    let reopen = match status {
        Some(Status::Failed(_)) => Some("Retry"),
        Some(Status::Open) => Some("Reopen"),
        _ => None,
    }
    .map(|label| act(el("open"), label, "network.open", json!({"id": id})));
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
    let save = (!fields.is_empty()).then(|| {
        submit(
            el("save"),
            "Save",
            "network.set",
            json!({"draft": draft, "id": id}),
            "false",
        )
    });
    card(format!("network/{id}"))
        .title(id)
        .child(badge(el("status")).variant(variant).text(status_text))
        .children(fields)
        .child(row(el("actions")).children(save).children(reopen).child(
            act(el("remove"), "Remove", "network.remove", json!({"id": id})).variant("failure"),
        ))
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
    tab("tab/access")
        .label("Access")
        .child(addresses)
        .children(pairing)
        .child(peers)
        .child(admin)
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
