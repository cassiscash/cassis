//! The [`Wallet`]s of a daemon's open networks on its admin page: what
//! each holds and what it last did ([`Funds`], read now and then and
//! moved in and out with [`Wallets::run`]), the actions that do it
//! ([`Wallets::act`]) and the part of a network's card that shows it
//! ([`view`]).
//!
//! | action           | payload                  |
//! | ---------------- | ------------------------ |
//! | `wallet.refresh` | `id`                     |
//! | `wallet.address` | `id`                     |
//! | `wallet.send`    | `id`, `to`, `amount_sat` |
//! | `wallet.issue`   | `id`, `amount_sat`       |
//! | `wallet.redeem`  | `id`, `token`            |
//! | `wallet.onboard` | `id`                     |
//! | `wallet.invoice` | `id`, `amount_sat`       |
//! | `wallet.pay`     | `id`, `invoice`          |
//! | `wallet.deposit` | `id`                     |
//! | `wallet.dismiss` | `id`                     |
//!
//! They move funds as far as the wallet can (see [`Can`]), in the
//! background: what they did, and what they hand out (a token, an
//! invoice), shows in the network's card, as do its balances, read every
//! minute while a page is open (`wallet.refresh` reads them now), and
//! its deposit addresses (`wallet.address` asks for new ones).

use crate::view::{act, ago, fact, field, number, sat, short_hash, submit};
use crate::{Args, Refresh};
use cassis_core::{unix_now, NetworkId};
use cassis_networks::{Address, Balance, Can, Op, Wallet};
use hypereffect::vtree::{badge, column, notice, row, tab, tabs, text, Node};
use hypereffect::{json, Value};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};
use tracing::{info, warn};

/// How often the balances of the wallets are read while a page is open.
const FUNDS_INTERVAL: u64 = 60;

/// What is known of a network's wallet, for the admin interface.
#[derive(Clone, Default)]
pub struct Funds {
    /// As last read.
    pub balances: Option<Result<Vec<Balance>, String>>,
    /// When the balances were last read, in unix seconds.
    pub read_at: Option<u64>,
    pub reading: bool,
    pub addresses: Option<Result<Vec<Address>, String>>,
    /// The operation running, if any.
    pub busy: Option<&'static str>,
    /// Payments and deposits waited for.
    pub waiting: usize,
    /// What the last operation did.
    pub outcome: Option<Result<String, String>>,
    /// What an operation handed out, until dismissed: a token is money.
    pub output: Option<Address>,
}

struct Slot {
    wallet: Wallet,
    funds: Funds,
}

/// The wallets of the networks a daemon has open, by network id.
#[derive(Default)]
pub struct Wallets(Mutex<BTreeMap<String, Slot>>);

impl Wallets {
    fn slots(&self) -> MutexGuard<'_, BTreeMap<String, Slot>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Start keeping the wallet of `id`, knowing nothing of it yet.
    pub fn insert(&self, id: String, wallet: Wallet) {
        self.slots().insert(
            id,
            Slot {
                wallet,
                funds: Funds::default(),
            },
        );
    }

    pub fn remove(&self, id: &str) {
        self.slots().remove(id);
    }

    /// Whether `id` is open, with its wallet.
    pub fn has(&self, id: &str) -> bool {
        self.slots().contains_key(id)
    }

    /// What `id`'s wallet can do and what is known of it, while open.
    pub fn get(&self, id: &str) -> Option<(Can, Funds)> {
        self.slots()
            .get(id)
            .map(|slot| (slot.wallet.can(), slot.funds.clone()))
    }

    /// The wallets whose balances were never read, or not for `max_age`
    /// seconds.
    fn stale(&self, max_age: u64) -> Vec<String> {
        let now = unix_now();
        self.slots()
            .iter()
            .filter(|(_, slot)| {
                !slot.funds.reading
                    && slot
                        .funds
                        .read_at
                        .is_none_or(|at| now.saturating_sub(at) >= max_age)
            })
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Read the wallets not read for a while, in the background.
    pub fn keep_fresh(self: &Arc<Self>, refresh: &Refresh) {
        for id in self.stale(FUNDS_INTERVAL) {
            self.read_in_background(id, false, refresh);
        }
    }

    /// Read the balances of `id`'s wallet, and its addresses when asked
    /// or not read yet, calling `progress` after.
    #[allow(unused_variables, unreachable_code)]
    pub async fn read_funds(&self, id: &str, addresses: bool, progress: &(dyn Fn() + Sync)) {
        let (wallet, addresses) = {
            let mut slots = self.slots();
            let Some(slot) = slots.get_mut(id) else {
                return;
            };
            if slot.funds.reading {
                return;
            }
            slot.funds.reading = true;
            let addresses = addresses || !matches!(slot.funds.addresses, Some(Ok(_)));
            (slot.wallet.clone(), addresses)
        };
        let balances = wallet.balances().await;
        let addresses = match addresses {
            true => Some(wallet.addresses().await),
            false => None,
        };
        if let Some(slot) = self.slots().get_mut(id) {
            if let Err(error) = &balances {
                warn!("reading the wallet of {id}: {error}");
            }
            slot.funds.balances = Some(balances);
            slot.funds.read_at = Some(unix_now());
            slot.funds.reading = false;
            if addresses.is_some() {
                slot.funds.addresses = addresses;
            }
        }
        progress();
    }

    /// Start `op` on `id`'s wallet, saying it is `doing` it, unless it
    /// is busy. The wallet to run it on with [`Wallets::run`].
    #[allow(unreachable_code)]
    fn start(&self, id: &str, doing: &'static str) -> Result<Wallet, String> {
        let mut slots = self.slots();
        let slot = slots
            .get_mut(id)
            .ok_or_else(|| format!("{id} is not open"))?;
        if let Some(busy) = slot.funds.busy {
            return Err(format!("{id} is busy: {busy}"));
        }
        slot.funds.busy = Some(doing);
        Ok(slot.wallet.clone())
    }

    /// Run `op` on `wallet`, `id`'s from [`Wallets::start`], and on
    /// what it then waits for, keeping what it did and reading the funds
    /// again after, calling `progress` after each step.
    async fn run(&self, id: &str, wallet: Wallet, op: Op, progress: &(dyn Fn() + Sync)) {
        let done = wallet.run(op).await;
        let then = {
            let mut slots = self.slots();
            let Some(funds) = slots.get_mut(id).map(|slot| &mut slot.funds) else {
                return;
            };
            funds.busy = None;
            match done {
                Ok(done) => {
                    info!("{id}: {}", done.message);
                    funds.outcome = Some(Ok(done.message));
                    if done.output.is_some() {
                        funds.output = done.output;
                    }
                    if done.then.is_some() {
                        funds.waiting += 1;
                    }
                    done.then
                }
                Err(error) => {
                    warn!("{id}: {error}");
                    funds.outcome = Some(Err(error));
                    None
                }
            }
        };
        self.read_funds(id, false, progress).await;
        let Some(then) = then else {
            return;
        };
        let result = then.await;
        if let Some(funds) = self.slots().get_mut(id).map(|slot| &mut slot.funds) {
            funds.waiting = funds.waiting.saturating_sub(1);
            match &result {
                Ok(message) => info!("{id}: {message}"),
                Err(error) => warn!("{id}: {error}"),
            }
            funds.outcome = Some(result);
        }
        self.read_funds(id, false, progress).await;
    }

    /// Forget what `id`'s wallet handed out.
    fn dismiss(&self, id: &str) {
        if let Some(slot) = self.slots().get_mut(id) {
            slot.funds.output = None;
            slot.funds.outcome = None;
        }
    }

    /// Do what the `wallet.*` action `name` says, returning what
    /// happened.
    pub fn act(
        self: &Arc<Self>,
        name: &str,
        args: &Args,
        refresh: &Refresh,
    ) -> Result<String, String> {
        let network = || NetworkId::parse(&args.required("id")?);
        let amount = || {
            args.number("amount_sat")?
                .flatten()
                .filter(|amount| *amount > 0)
                .ok_or_else(|| "amount_sat is required".to_string())
        };
        match name {
            "wallet.refresh" | "wallet.address" => {
                let id = network()?;
                if !self.has(&id.0) {
                    return Err(format!("{id} is not open"));
                }
                self.read_in_background(id.0.clone(), name == "wallet.address", refresh);
                Ok(match name {
                    "wallet.address" => format!("Asking {id} for new addresses"),
                    _ => format!("Reading the wallet of {id}"),
                })
            }
            "wallet.send" => self.op(
                network()?,
                "Sending",
                Op::Send {
                    to: args.required("to")?,
                    amount_sat: amount()?,
                },
                refresh,
            ),
            "wallet.issue" => self.op(
                network()?,
                "Taking funds out",
                Op::Issue {
                    amount_sat: amount()?,
                },
                refresh,
            ),
            "wallet.redeem" => self.op(
                network()?,
                "Redeeming",
                Op::Redeem {
                    token: args.required("token")?,
                },
                refresh,
            ),
            "wallet.onboard" => self.op(network()?, "Onboarding", Op::Onboard, refresh),
            "wallet.invoice" => self.op(
                network()?,
                "Creating an invoice",
                Op::Invoice {
                    amount_sat: amount()?,
                },
                refresh,
            ),
            "wallet.pay" => self.op(
                network()?,
                "Paying",
                Op::Pay {
                    invoice: args.required("invoice")?,
                },
                refresh,
            ),
            "wallet.deposit" => self.op(
                network()?,
                "Creating a deposit address",
                Op::Deposit,
                refresh,
            ),
            "wallet.dismiss" => {
                let id = network()?;
                self.dismiss(&id.0);
                Ok(format!("{id}: dismissed"))
            }
            other => Err(format!("unknown action {other}")),
        }
    }

    /// Start `op` on the wallet of `id`, saying it is `doing` it, and run
    /// it in the background.
    fn op(
        self: &Arc<Self>,
        id: NetworkId,
        doing: &'static str,
        op: Op,
        refresh: &Refresh,
    ) -> Result<String, String> {
        let wallet = self.start(&id.0, doing)?;
        let wallets = self.clone();
        let refresh = refresh.clone();
        let network = id.0.clone();
        tokio::spawn(async move {
            wallets.run(&network, wallet, op, &|| refresh.now()).await;
        });
        Ok(format!("{id}: {doing}…"))
    }

    fn read_in_background(self: &Arc<Self>, id: String, addresses: bool, refresh: &Refresh) {
        let wallets = self.clone();
        let refresh = refresh.clone();
        tokio::spawn(async move {
            wallets.read_funds(&id, addresses, &|| refresh.now()).await;
        });
    }
}

/// The signal path segment of the draft of a form of a network's
/// wallet, `form` being the action it sends without `wallet.`.
pub fn wallet_draft(id: &str, form: &str) -> String {
    format!("w_{}_{form}", short_hash(id))
}

/// The drafts of the forms of `id`'s wallet, empty.
pub fn drafts(id: &str) -> impl Iterator<Item = (String, Value)> {
    let forms = [
        ("send", json!({"to": "", "amount_sat": null})),
        ("issue", json!({"amount_sat": null})),
        ("redeem", json!({"token": ""})),
        ("invoice", json!({"amount_sat": null})),
        ("pay", json!({"invoice": ""})),
    ];
    let id = id.to_string();
    forms
        .into_iter()
        .map(move |(form, values)| (wallet_draft(&id, form), values))
}

/// What a network's wallet holds, what it last did, and the forms that
/// move funds in and out of it, as far as it `can`, at unix time `now`.
pub fn view(now: u64, id: &str, can: &Can, funds: &Funds) -> Vec<Node> {
    let el = |part: &str| format!("network/{id}/wallet/{part}");
    let busy = funds.busy.is_some();
    // A button running an operation, sending the draft of `form` if any.
    let run = |form: &str, label: &str, draft: bool, blocked: &str| {
        let mut payload = json!({"id": id});
        if draft {
            payload["draft"] = wallet_draft(id, form).into();
        }
        submit(
            el(form),
            label,
            &format!("wallet.{form}"),
            payload,
            &format!("{busy} || ({blocked})"),
        )
    };
    let d = |form: &str, field: &str| format!("d.{}.{field}", wallet_draft(id, form));
    let empty = |form: &str, field: &str| format!("s.{}.trim() == ''", d(form, field));
    let amount = |form: &str| {
        number(
            el(&format!("{form}/amount_sat")),
            "Amount (sat)",
            &d(form, "amount_sat"),
        )
    };

    let mut nodes = Vec::new();
    let amounts: Vec<Node> = match &funds.balances {
        Some(Ok(balances)) => balances
            .iter()
            .enumerate()
            .map(|(i, balance)| {
                let el = |part: &str| el(&format!("balance/{i}/{part}"));
                column(el("")).gap("none").children([
                    text(el("label")).variant("caption").text(balance.label),
                    text(el("amount"))
                        .variant(if i == 0 { "h2" } else { "h3" })
                        .text(sat(balance.msat)),
                ])
            })
            .collect(),
        _ => Vec::new(),
    };
    let read = match (funds.reading, funds.read_at) {
        (true, _) => "Reading…".to_string(),
        (false, Some(at)) => format!("Read {}", ago(now, at)),
        (false, None) => "Not read yet".to_string(),
    };
    nodes.push(row(el("balances")).justify("between").wrap(true).children([
        row(el("amounts")).gap("large").wrap(true).children(amounts),
        row(el("read")).children([
            text(el("read/when")).variant("caption").text(read),
            act(
                el("refresh"),
                "Refresh",
                "wallet.refresh",
                json!({"id": id}),
            ),
        ]),
    ]));
    if let Some(Err(error)) = &funds.balances {
        nodes.push(
            notice(el("balances/error"))
                .variant("failure")
                .title("Could not read the balance")
                .text(error.as_str()),
        );
    }
    let doing = funds
        .busy
        .map(|doing| badge(el("busy")).variant("info").text(format!("{doing}…")));
    let waiting = (funds.waiting > 0).then(|| {
        badge(el("waiting"))
            .variant("info")
            .text(format!("waiting for {} payment(s)", funds.waiting))
    });
    if doing.is_some() || waiting.is_some() {
        nodes.push(row(el("doing")).children(doing).children(waiting));
    }
    if let Some(outcome) = &funds.outcome {
        let (variant, message) = match outcome {
            Ok(message) => ("success", message),
            Err(error) => ("failure", error),
        };
        nodes.push(
            notice(el("outcome"))
                .variant(variant)
                .text(message.as_str()),
        );
    }
    if let Some(output) = &funds.output {
        nodes.push(
            column(el("output")).gap("small").children([
                text(el("output/label"))
                    .variant("caption")
                    .text(format!("{}: copy it now, it is not kept", output.label)),
                text(el("output/value"))
                    .variant("code")
                    .text(output.address.as_str()),
                act(
                    el("dismiss"),
                    "Hide it",
                    "wallet.dismiss",
                    json!({"id": id}),
                ),
            ]),
        );
    }

    let mut receive = Vec::new();
    match &funds.addresses {
        Some(Ok(addresses)) => {
            for (i, address) in addresses.iter().enumerate() {
                receive.push(fact(
                    &el(&format!("address/{i}")),
                    address.label,
                    address.address.as_str(),
                ));
            }
            if can.new_addresses && !addresses.is_empty() {
                receive.push(act(
                    el("address"),
                    "New address",
                    "wallet.address",
                    json!({"id": id}),
                ));
            }
        }
        Some(Err(error)) => receive.extend([
            notice(el("addresses/error"))
                .variant("failure")
                .title("Could not get a deposit address")
                .text(error.as_str()),
            act(el("address"), "Retry", "wallet.address", json!({"id": id})),
        ]),
        None => {}
    }
    if let Some(deposit) = can.deposit {
        receive.push(run(
            "deposit",
            &format!("New {}", deposit.to_lowercase()),
            false,
            "false",
        ));
    }
    if can.lightning {
        receive.push(row(el("invoice/form")).align("end").wrap(true).children([
            amount("invoice"),
            run("invoice", "Create invoice", true, "false"),
        ]));
    }
    if let Some(redeem) = can.redeem {
        receive.extend([
            field(el("redeem/token"), redeem, &d("redeem", "token")).variant("multiline"),
            run("redeem", "Redeem", true, &empty("redeem", "token")),
        ]);
    }
    if can.onboard {
        receive.push(run("onboard", "Onboard", false, "false"));
    }

    let mut send = Vec::new();
    if let Some(to) = can.send {
        send.extend([
            field(el("send/to"), to, &d("send", "to")),
            row(el("send/form")).align("end").wrap(true).children([
                amount("send"),
                run("send", "Send", true, &empty("send", "to")),
            ]),
        ]);
    }
    if can.lightning {
        send.extend([
            field(el("pay/invoice"), "Lightning invoice", &d("pay", "invoice"))
                .placeholder("lnbc…"),
            run("pay", "Pay", true, &empty("pay", "invoice")),
        ]);
    }
    if let Some(issue) = can.issue {
        send.push(row(el("issue/form")).align("end").wrap(true).children([
            amount("issue"),
            run(
                "issue",
                &format!("Take out as {}", issue.to_lowercase()),
                true,
                "false",
            ),
        ]));
    }

    let note = can
        .note
        .map(|note| text(el("note")).variant("caption").text(note));
    nodes.push(
        tabs(el("tabs"))
            .bind(format!("_wallet_{}", short_hash(id)))
            .children([
                tab(el("tab/receive"))
                    .label("Receive")
                    .children(receive)
                    .children(note),
                tab(el("tab/send")).label("Send").children(send),
            ]),
    );
    nodes
}
