//! The gateway's admin interface (see [`cassis_admin`]): what it
//! forwards, the standing authorizations it holds, its
//! networks with the funds it pays payees from, and the terms it accepts,
//! over its [`config`](crate::config). Besides what every daemon has:
//!
//! | action                 | payload                                                 |
//! | ---------------------- | ------------------------------------------------------- |
//! | `terms.set`            | `max_final_timeout_secs`, `max_authorization_secs`, `default_invoice_expiry_secs`, `forward_slack_secs`, `final_slack_secs` |
//! | `authorization.forget` | `id`                                                    |
//! | `network.*`            | see [`cassis_admin::networks`]                          |
//! | `wallet.*`             | see [`cassis_admin::wallets`]                           |
//!
//! Changes are written to the config and apply at once: a network with
//! payments in flight closes or reopens once they settle.

use crate::config::Config;
use crate::db::{HandledDelegation, PayeeHtlc, PayeeOutcome};
use crate::{Gateway, INTERRUPTED_FUNDING};
use cassis_admin::config::{child, put};
use cassis_admin::networks::{
    config_cards, config_drafts, new_network, new_network_draft, Daemon, NetworkConfig, Networks,
    Opened, Opener, OFFLINE_KINDS,
};
use cassis_admin::view::{act, ago, fact, number, sat, span, stat, submit, until};
use cassis_admin::{AdminConfig, AdminEdit, App, Args, ConfigFile, Identity, Refresh};
use cassis_core::offline::ReceiveAuthorization;
use cassis_core::routing::{autohue, autoname};
use cassis_core::{unix_now, Bytes32, Network, NetworkId, XOnlyPubKey};
use futures::future::BoxFuture;
use hypereffect::vtree::{badge, card, column, list, notice, row, tab, text, Node};
use hypereffect::{json, Map, Value};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use toml_edit::DocumentMut;
use tracing::{info, warn, Span};

/// The most forwards a tab lists, newest first.
const LISTED: usize = 100;

/// Opens a network with the key its config gives, its wallet under
/// `dir`.
pub struct GatewayOpener {
    pub dir: PathBuf,
    pub span: Span,
}

impl Opener<NetworkConfig> for GatewayOpener {
    fn open<'a>(
        &'a self,
        id: &'a NetworkId,
        config: &'a NetworkConfig,
    ) -> BoxFuture<'a, Result<Opened, String>> {
        Box::pin(async move {
            let settings = config.settings(id, &self.dir)?;
            let (network, wallet) = cassis_networks::open_wallet(id, &settings, &self.span).await?;
            Ok(Opened {
                network,
                wallet: Some(wallet),
            })
        })
    }
}

impl Daemon for Gateway {
    fn in_flight(&self, id: &NetworkId) -> usize {
        Gateway::in_flight(self, id)
    }

    fn add_network(&self, network: Arc<dyn Network>) {
        Gateway::add_network(self, network);
    }

    fn remove_network(&self, id: &NetworkId) {
        Gateway::remove_network(self, id);
    }
}

pub struct GatewayAdmin {
    gateway: Gateway,
    file: ConfigFile<Config>,
    networks: Arc<Networks<NetworkConfig>>,
    relay: Option<String>,
    refresh: Refresh,
}

impl GatewayAdmin {
    /// The interface of `gateway`, over its `file` and the `networks` it
    /// has. `relay` is its home relay.
    pub fn new(
        gateway: Gateway,
        file: ConfigFile<Config>,
        networks: Arc<Networks<NetworkConfig>>,
        relay: Option<String>,
        refresh: Refresh,
    ) -> Arc<Self> {
        Arc::new(Self {
            gateway,
            file,
            networks,
            relay,
            refresh,
        })
    }

    /// Run as the config says now.
    fn apply(&self) {
        let config = self.file.get();
        self.gateway.set_policy(config.terms);
        self.networks
            .sync_in_background(config.networks, None, &self.refresh);
    }

    fn key(&self) -> XOnlyPubKey {
        XOnlyPubKey(*self.gateway.key().as_bytes())
    }

    /// A store that cannot be read leaves its tab empty, and says so in
    /// the log.
    fn listed<T>(&self, what: &str, list: Result<Vec<T>, String>) -> Vec<T> {
        list.unwrap_or_else(|error| {
            warn!("admin: listing {what}: {error}");
            Vec::new()
        })
    }

    fn overview(&self, forwards: &[PayeeHtlc], now: u64) -> Node {
        let identity = card("identity").title("Identity").children([
            fact(
                "identity/key",
                "Key and iroh id (signs its invoices; payees authorize it)",
                self.gateway.peer_id(),
            ),
            fact(
                "identity/relay",
                "Home relay",
                self.relay.as_deref().unwrap_or("unknown"),
            ),
        ]);
        let settled: Vec<&PayeeHtlc> = forwards.iter().filter(|forward| forward.settled).collect();
        let locked: u64 = forwards
            .iter()
            .filter(|forward| forward.outcome.is_none())
            .filter_map(|forward| forward.htlc.as_ref())
            .map(|htlc| htlc.amount_msat)
            .sum();
        let figures = row("figures").gap("large").wrap(true).children([
            stat(
                "figures/settled",
                "Forwarded",
                sat(settled.iter().map(|f| f.incoming.amount_msat).sum()),
            ),
            stat("figures/count", "Payments", settled.len().to_string()),
            stat("figures/locked", "Locked to payees", sat(locked)),
        ]);
        let counts = STATES.iter().filter_map(|name| {
            let count = forwards.iter().filter(|f| state_name(f) == *name).count();
            (count > 0).then(|| {
                badge(format!("forwards/count/{name}"))
                    .variant(state_variant(name))
                    .text(format!("{count} {name}"))
            })
        });
        let active = forwards
            .iter()
            .filter(|forward| !forward.settled && forward.failed.is_none())
            .take(LISTED)
            .map(|forward| forward_row("active", forward, now));
        let activity = card("activity")
            .title("Activity")
            .child(figures)
            .child(row("forwards/counts").wrap(true).children(counts))
            .child(
                list("forwards/active")
                    .empty("No forward in flight.")
                    .children(active),
            );
        tab("tab/overview")
            .label("Overview")
            .children(self.gateway.network_ids().is_empty().then(|| {
                notice("no-networks")
                    .variant("warning")
                    .title("On no network")
                    .text("It can issue no invoice until it is on one: add one under Networks.")
            }))
            .children(
                forwards
                    .iter()
                    .filter_map(|forward| attention(forward, now)),
            )
            .children([identity, activity])
    }

    fn networks(&self, now: u64) -> Node {
        let config = self.file.get();
        let (closing, cards) = config_cards(&self.networks, &config.networks, "payment", now);
        tab("tab/networks")
            .label("Networks")
            .child(text("networks/help").variant("caption").text(
                "The gateway is paid and pays payees on these. Payments only go through on \
                 networks it has funds on. A network closes or reopens once the payments \
                 through it settle, which waits for payees to claim or for their HTLCs to \
                 expire.",
            ))
            .children(closing)
            .children([
                list("networks")
                    .empty("No networks yet: add one below.")
                    .children(cards),
                new_network(&OFFLINE_KINDS),
            ])
    }

    fn forwards(&self, forwards: &[PayeeHtlc], now: u64) -> Node {
        tab("tab/forwards")
            .label("Forwards")
            .child(shown("forwards", forwards.len()))
            .child(
                list("forwards").empty("Nothing forwarded yet.").children(
                    forwards
                        .iter()
                        .take(LISTED)
                        .map(|forward| forward_row("forward", forward, now)),
                ),
            )
    }

    fn authorizations(&self, now: u64) -> Node {
        let mut records = self.listed("authorizations", self.gateway.delegations());
        records.sort_by_key(|record| std::cmp::Reverse(record.registered_at));
        tab("tab/authorizations")
            .label("Authorizations")
            .child(text("authorizations/help").variant("caption").text(
                "Payees who let this gateway issue invoices in their name while they are \
                 offline. Forgetting one stops new invoices under it, and leaves those already \
                 issued payable; the payee can register it again until it ends.",
            ))
            .child(
                list("authorizations")
                    .empty("No payee gave a standing authorization yet.")
                    .children(records.iter().filter_map(|r| authorization_row(r, now))),
            )
    }

    fn terms(&self) -> Node {
        let term = |key: &str, label: &str| {
            number(format!("terms/{key}"), label, &format!("d.terms.{key}"))
        };
        tab("tab/terms").label("Terms").child(
            card("terms")
                .title("Terms it accepts from payees")
                .children([
                    text("terms/help").variant("caption").text(
                        "In seconds, empty for the default. They apply to what comes next: \
                         authorizations and invoices it took already stay as they are.",
                    ),
                    term(
                        "max_final_timeout_secs",
                        "Longest final timeout a payee may ask for",
                    ),
                    term(
                        "max_authorization_secs",
                        "Longest a standing authorization may run",
                    ),
                    term(
                        "default_invoice_expiry_secs",
                        "Default expiry of invoices under one",
                    ),
                    term("forward_slack_secs", "Margin asked of payers"),
                    term(
                        "final_slack_secs",
                        "Margin on top of the payee's final timeout",
                    ),
                    submit(
                        "terms/save",
                        "Save",
                        "terms.set",
                        json!({"draft": "terms"}),
                        "false",
                    ),
                ]),
        )
    }
}

/// `max_final_timeout_secs`, `max_authorization_secs`,
/// `default_invoice_expiry_secs`, `forward_slack_secs`,
/// `final_slack_secs`: empty unsets one, for its default.
fn set_terms(doc: &mut DocumentMut, args: &Args) -> Result<(), String> {
    let terms = child(doc.as_table_mut(), "terms", toml_edit::table)?;
    for key in [
        "max_final_timeout_secs",
        "max_authorization_secs",
        "default_invoice_expiry_secs",
        "forward_slack_secs",
        "final_slack_secs",
    ] {
        if let Some(secs) = args.number(key)? {
            put(terms, key, secs.map(Value::from));
        }
    }
    Ok(())
}

impl App for GatewayAdmin {
    fn identity(&self) -> Identity {
        Identity {
            name: autoname(&self.key()),
            what: "gateway",
            description: "Run this Cassis gateway",
            hue: autohue(&self.key()),
        }
    }

    fn admin(&self) -> AdminConfig {
        self.file.get().admin.resolve(crate::config::DEFAULT_LISTEN)
    }

    fn edit_admin(self: Arc<Self>, edit: &AdminEdit) -> Result<(), String> {
        self.file.edit_admin(edit)
    }

    fn drafts(&self) -> Map<String, Value> {
        let config = self.file.get();
        let terms = config.terms;
        let mut drafts = config_drafts(&config.networks, true);
        drafts.insert(
            "terms".into(),
            json!({
                "max_final_timeout_secs": terms.max_final_timeout_secs,
                "max_authorization_secs": terms.max_authorization_secs,
                "default_invoice_expiry_secs": terms.default_invoice_expiry_secs,
                "forward_slack_secs": terms.forward_slack_secs,
                "final_slack_secs": terms.final_slack_secs,
            }),
        );
        drafts
    }

    fn new_drafts(&self) -> Map<String, Value> {
        Map::from_iter([new_network_draft()])
    }

    fn tabs(&self, access: Node) -> Vec<Node> {
        let now = unix_now();
        let mut forwards = self.listed("forwards", self.gateway.payee_htlcs());
        forwards.sort_by_key(|forward| std::cmp::Reverse(forward.created_at));
        vec![
            self.overview(&forwards, now),
            self.networks(now),
            self.forwards(&forwards, now),
            self.authorizations(now),
            access,
            self.terms(),
        ]
    }

    fn act(self: Arc<Self>, name: &str, args: &Args) -> Result<String, String> {
        match name {
            "authorization.forget" => {
                let id = Bytes32::from_str(&args.required("id")?)?;
                self.gateway.forget_delegation(&id)?;
                info!("admin: forgot authorization {id}");
                Ok("Authorization forgotten".into())
            }
            "terms.set" => {
                self.file.edit(|doc| set_terms(doc, args))?;
                self.apply();
                Ok("Terms saved".into())
            }
            name if name.starts_with("network.") => self.networks.act(
                name,
                args,
                &self.file,
                |config: &Config| &config.networks,
                &OFFLINE_KINDS,
                &self.refresh,
            ),
            name if name.starts_with("wallet.") => {
                self.networks.wallets.act(name, args, &self.refresh)
            }
            other => Err(format!("unknown action {other}")),
        }
    }

    fn tick(self: Arc<Self>, pages_open: bool) {
        self.file.reload_if_modified();
        // Also picks up changes left waiting for payments to settle.
        self.apply();
        if pages_open {
            self.networks.wallets.keep_fresh(&self.refresh);
        }
    }
}

/// What a forward's states are called, in the order they come.
const STATES: [&str; 5] = ["funding", "releasing", "claiming", "settled", "failed"];

fn state_name(forward: &PayeeHtlc) -> &'static str {
    if forward.settled {
        "settled"
    } else if forward.failed.is_some() {
        "failed"
    } else if forward.preimage.is_some() {
        "claiming"
    } else if forward.htlc.is_some() {
        "releasing"
    } else {
        "funding"
    }
}

fn state_variant(name: &str) -> &'static str {
    match name {
        "settled" => "success",
        "failed" => "failure",
        _ => "info",
    }
}

/// How many of `total` a list shows, when not all.
fn shown(what: &str, total: usize) -> Node {
    text(format!("{what}/shown"))
        .variant("caption")
        .visible(total > LISTED)
        .text(format!("The latest {LISTED} of {total}."))
}

/// A row saying what to do about `forward`, if it needs someone to look
/// at it: it may have cost the gateway money.
fn attention(forward: &PayeeHtlc, now: u64) -> Option<Node> {
    let reason = forward.failed.as_ref()?;
    let hash = payment_hash(forward)?;
    let out = &forward.network;
    let id = format!("attention/{hash}");
    if reason == INTERRUPTED_FUNDING {
        return Some(
            notice(id)
                .variant("failure")
                .title(format!("Payment {} needs checking", hash.short()))
                .text(format!(
                    "The gateway stopped while paying the payee on {out}, and cannot tell \
                     whether it did: check that wallet for a lock with this hash ({hash})."
                )),
        );
    }
    let htlc = forward.htlc.as_ref()?;
    if forward.outcome.is_some() {
        return None;
    }
    Some(
        notice(id)
            .variant("warning")
            .title(format!(
                "Payment {} failed after paying the payee",
                hash.short()
            ))
            .text(format!(
                "{} locked on {out} is refunded {} unless the payee claims it, which also \
                 lets the gateway claim what it was paid. {reason}",
                sat(htlc.amount_msat),
                until(now, htlc.expiry)
            )),
    )
}

fn forward_row(prefix: &str, forward: &PayeeHtlc, now: u64) -> Node {
    let hash = &forward.payment_hash.0;
    let el = |part: &str| format!("{prefix}/{hash}/{part}");
    let name = state_name(forward);
    let to = &forward.network;
    let outgoing = forward.htlc.as_ref().map(|htlc| {
        let (variant, label) = match forward.outcome {
            Some(PayeeOutcome::Claimed) => ("success", "payee claimed".to_string()),
            Some(PayeeOutcome::Refunded) => ("warning", "refunded to the gateway".to_string()),
            None => (
                "info",
                format!("waiting for the payee, refund {}", until(now, htlc.expiry)),
            ),
        };
        badge(el("outgoing")).variant(variant).text(label)
    });
    let failed = forward
        .failed
        .as_ref()
        .map(|reason| text(el("reason")).variant("caption").text(reason.as_str()));
    column(format!("{prefix}/{hash}"))
        .gap("small")
        .child(
            row(el("line")).justify("between").wrap(true).children([
                text(el("route")).text(format!(
                    "{} → {to} · {}",
                    forward.incoming_network,
                    sat(forward.incoming.amount_msat)
                )),
                row(el("states"))
                    .wrap(true)
                    .child(badge(el("state")).variant(state_variant(name)).text(name))
                    .children(outgoing),
            ]),
        )
        .children(failed)
        .child(
            text(el("hash"))
                .variant("caption")
                .text(format!("{hash} · {}", ago(now, forward.created_at))),
        )
}

/// The payment hash of `forward`, as stored.
fn payment_hash(forward: &PayeeHtlc) -> Option<Bytes32> {
    forward.payment_hash.0.parse().ok()
}

/// A standing authorization, unless its signed terms no longer give an
/// id: then it could not have been stored under one.
fn authorization_row(record: &HandledDelegation, now: u64) -> Option<Node> {
    let authorization = &ReceiveAuthorization::try_from(&record.authorization).ok()?;
    let id = authorization.id().ok()?;
    let el = |part: &str| format!("authorization/{id}/{part}");
    let ended = authorization.valid_until <= now;
    let destinations = authorization
        .destinations
        .iter()
        .map(|destination| destination.network.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    Some(
        column(format!("authorization/{id}"))
            .gap("small")
            .child(
                row(el("line")).justify("between").wrap(true).children([
                    text(el("amounts")).text(format!(
                        "{} to {} on {destinations}",
                        sat(authorization.min_amount_msat),
                        sat(authorization.max_amount_msat)
                    )),
                    badge(el("status"))
                        .variant(if ended { "neutral" } else { "success" })
                        .text(if ended {
                            format!("ended {}", ago(now, authorization.valid_until))
                        } else {
                            format!("ends {}", until(now, authorization.valid_until))
                        }),
                ]),
            )
            .child(
                text(el("payee"))
                    .variant("code")
                    .text(authorization.payee.to_string()),
            )
            .child(text(el("server")).variant("caption").text(format!(
                "preimage server {} · final timeout {} · registered {}",
                authorization.preimage_server,
                span(authorization.min_final_timeout_secs),
                ago(now, record.registered_at)
            )))
            .child(
                act(
                    el("forget"),
                    "Forget",
                    "authorization.forget",
                    json!({"id": id.to_string()}),
                )
                .variant("failure"),
            ),
    )
}
