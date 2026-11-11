//! The preimage server's admin interface (see [`cassis_admin`]): what it
//! released, for whom, and the networks it verifies HTLCs on, over its
//! [`config`](crate::config). It issues hashes without keeping them, so
//! those show as counts since it started. Preimages stay out of the page:
//! payees fetch them, nobody else needs them. Besides what every daemon
//! has: `network.*`, see [`cassis_admin::networks`].

use crate::config::Config;
use crate::db::{Payee, Payment};
use crate::PreimageServer;
use cassis_admin::networks::{
    config_cards, config_drafts, new_network, new_network_draft, Daemon, NetworkConfig, Networks,
    Opened, Opener, OFFLINE_KINDS,
};
use cassis_admin::view::{ago, fact, sat, stat, until};
use cassis_admin::{AdminConfig, AdminEdit, App, Args, ConfigFile, Identity, Refresh};
use cassis_core::routing::{autohue, autoname};
use cassis_core::{unix_now, Network, NetworkId, XOnlyPubKey};
use futures::future::BoxFuture;
use hypereffect::vtree::{badge, card, column, list, notice, row, tab, text, Node};
use hypereffect::{Map, Value};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{warn, Span};

/// The most payments a tab lists, newest first.
const LISTED: usize = 100;

/// Opens a network with the key its config gives, its data under `dir`.
/// It only verifies HTLCs paying others, so it has no use for its
/// wallet.
pub struct PreimageOpener {
    pub dir: PathBuf,
    pub span: Span,
}

impl Opener<NetworkConfig> for PreimageOpener {
    fn open<'a>(
        &'a self,
        id: &'a NetworkId,
        config: &'a NetworkConfig,
    ) -> BoxFuture<'a, Result<Opened, String>> {
        Box::pin(async move {
            if id.kind() == "lightning" {
                return Err(
                    "lightning cannot go through a preimage server: its hold invoices need the \
                     payee online"
                        .into(),
                );
            }
            let settings = config.settings(id, &self.dir)?;
            Ok(Opened {
                network: cassis_networks::open(id, &settings, &self.span).await?,
                wallet: None,
            })
        })
    }
}

impl Daemon for PreimageServer {
    /// None: it answers a gateway at a time, on the network it has then,
    /// and keeps nothing going on any.
    fn in_flight(&self, _id: &NetworkId) -> usize {
        0
    }

    fn add_network(&self, network: Arc<dyn Network>) {
        PreimageServer::add_network(self, network);
    }

    fn remove_network(&self, id: &NetworkId) {
        PreimageServer::remove_network(self, id);
    }
}

pub struct PreimageAdmin {
    server: PreimageServer,
    file: ConfigFile<Config>,
    networks: Arc<Networks<NetworkConfig>>,
    relay: Option<String>,
    refresh: Refresh,
}

impl PreimageAdmin {
    /// The interface of `server`, over its `file` and the `networks` it
    /// has. `relay` is its home relay.
    pub fn new(
        server: PreimageServer,
        file: ConfigFile<Config>,
        networks: Arc<Networks<NetworkConfig>>,
        relay: Option<String>,
        refresh: Refresh,
    ) -> Arc<Self> {
        Arc::new(Self {
            server,
            file,
            networks,
            relay,
            refresh,
        })
    }

    fn key(&self) -> XOnlyPubKey {
        XOnlyPubKey(*self.server.key().as_bytes())
    }

    fn overview(&self, payments: &[Payment], payees: &[Payee], now: u64) -> Node {
        let identity = card("identity").title("Identity").children([
            fact(
                "identity/key",
                "Key and iroh id (signs its hashes; payees authorize it)",
                self.server.peer_id(),
            ),
            fact(
                "identity/relay",
                "Home relay",
                self.relay.as_deref().unwrap_or("unknown"),
            ),
        ]);
        let released = card("released").title("Released").children([
            row("released/figures").gap("large").wrap(true).children([
                stat(
                    "released/amount",
                    "Paid to payees",
                    sat(payments.iter().map(|payment| payment.amount_msat).sum()),
                ),
                stat("released/payments", "Payments", payments.len().to_string()),
                stat("released/payees", "Payees", payees.len().to_string()),
            ]),
            text("released/open").variant("caption").text(format!(
                "{} of their HTLCs have not reached their expiry yet.",
                payments.iter().filter(|p| p.expiry > now).count()
            )),
        ]);
        let stats = self.server.stats();
        let since_start = card("since-start").title("Since it started").children([
            row("since-start/figures")
                .gap("large")
                .wrap(true)
                .children([
                    stat(
                        "since-start/issued",
                        "Hashes issued",
                        stats.issued.to_string(),
                    ),
                    stat(
                        "since-start/released",
                        "Released",
                        stats.released.to_string(),
                    ),
                    stat("since-start/refused", "Refused", stats.refused.to_string()),
                ]),
            text("since-start/help")
                .variant("caption")
                .text("Why it refused goes to its log."),
        ]);
        tab("tab/overview")
            .label("Overview")
            .children(self.server.network_ids().is_empty().then(|| {
                notice("no-networks")
                    .variant("warning")
                    .title("On no network")
                    .text("It refuses every payee until it is on one: add one under Networks.")
            }))
            .children([identity, released, since_start])
    }

    fn networks(&self, now: u64) -> Node {
        let config = self.file.get();
        let (closing, cards) = config_cards(&self.networks, &config.networks, "payment", now);
        tab("tab/networks")
            .label("Networks")
            .child(text("networks/help").variant("caption").text(
                "It verifies HTLCs to payees on these. Removing one refuses payees receiving \
                 on it, those whose invoices are still unpaid included.",
            ))
            .children(closing)
            .children([
                list("networks")
                    .empty("No networks yet: add one below.")
                    .children(cards),
                new_network(&OFFLINE_KINDS),
            ])
    }
}

impl App for PreimageAdmin {
    fn identity(&self) -> Identity {
        Identity {
            name: autoname(&self.key()),
            what: "preimage server",
            description: "Run this Cassis preimage server",
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
        config_drafts(&self.file.get().networks, false)
    }

    fn new_drafts(&self) -> Map<String, Value> {
        Map::from_iter([new_network_draft()])
    }

    fn tabs(&self, access: Node) -> Vec<Node> {
        let now = unix_now();
        let listed = |what: &str, error: String| warn!("admin: listing {what}: {error}");
        let mut payments = self
            .server
            .all_payments()
            .inspect_err(|error| listed("payments", error.clone()))
            .unwrap_or_default();
        payments.sort_by_key(|payment| std::cmp::Reverse(payment.released_at));
        let mut payees = self
            .server
            .all_payees()
            .inspect_err(|error| listed("payees", error.clone()))
            .unwrap_or_default();
        payees.sort_by_key(|payee| std::cmp::Reverse(payee.first_paid_at));
        vec![
            self.overview(&payments, &payees, now),
            payments_tab(&payments, now),
            payees_tab(&payees, &payments, now),
            self.networks(now),
            access,
        ]
    }

    fn act(self: Arc<Self>, name: &str, args: &Args) -> Result<String, String> {
        self.networks.act(
            name,
            args,
            &self.file,
            |config: &Config| &config.networks,
            &OFFLINE_KINDS,
            &self.refresh,
        )
    }

    fn tick(self: Arc<Self>, _pages_open: bool) {
        self.file.reload_if_modified();
        self.networks
            .sync_in_background(self.file.get().networks, None, &self.refresh);
    }
}

fn payments_tab(payments: &[Payment], now: u64) -> Node {
    let shown = text("payments/shown")
        .variant("caption")
        .visible(payments.len() > LISTED)
        .text(format!("The latest {LISTED} of {}.", payments.len()));
    let rows = payments.iter().take(LISTED).map(|payment| {
        let hash = &payment.payment_hash.0;
        let el = |part: &str| format!("payment/{hash}/{part}");
        let expiry = if payment.expiry > now {
            badge(el("expiry"))
                .variant("info")
                .text(format!("claimable, expires {}", until(now, payment.expiry)))
        } else {
            badge(el("expiry")).text(format!("expired {}", ago(now, payment.expiry)))
        };
        column(format!("payment/{hash}"))
            .gap("small")
            .child(row(el("line")).justify("between").wrap(true).children([
                text(el("amount")).text(format!(
                    "{} on {}",
                    sat(payment.amount_msat),
                    payment.network
                )),
                expiry,
            ]))
            .child(text(el("payee")).variant("caption").text(format!(
                "payee {} · released {}",
                payment.payee.0,
                ago(now, payment.released_at)
            )))
            .child(text(el("hash")).variant("caption").text(hash.as_str()))
    });
    tab("tab/payments")
        .label("Payments")
        .child(text("payments/help").variant("caption").text(
            "HTLCs gateways funded to payees, whose preimage was released. Payees claim them \
             on their network before they expire, which this server does not see.",
        ))
        .child(shown)
        .child(
            list("payments")
                .empty("Nothing released yet.")
                .children(rows),
        )
}

fn payees_tab(payees: &[Payee], payments: &[Payment], now: u64) -> Node {
    let mut totals: BTreeMap<&str, (u64, usize)> = BTreeMap::new();
    for payment in payments {
        let total = totals.entry(payment.payee.0.as_str()).or_default();
        total.0 += payment.amount_msat;
        total.1 += 1;
    }
    let rows = payees.iter().map(|payee| {
        let key = &payee.key.0;
        let el = |part: &str| format!("payee/{key}/{part}");
        let (amount, count) = totals.get(key.as_str()).copied().unwrap_or_default();
        column(format!("payee/{key}")).gap("small").children([
            text(el("key")).variant("code").text(key.as_str()),
            text(el("totals")).variant("caption").text(format!(
                "{} over {count} payment(s) · first paid {}",
                sat(amount),
                ago(now, payee.first_paid_at)
            )),
        ])
    });
    tab("tab/payees")
        .label("Payees")
        .child(list("payees").empty("Nobody was paid yet.").children(rows))
}
