//! The page: a card per network with its wallet, and the form that adds
//! one. Elements that do something have ids naming what they act on, and
//! their actions carry it in the payload; what a form edits is in its
//! draft, the signal `hw.<draft>`.

use crate::args::Args;
use crate::config::{self, Entry, Fields};
use crate::{abilities, Funds, Slot, State, Status};
use cassis_core::NetworkId;
use cassis_networks::Can;
use hypereffect::vtree::{
    badge, button, card, column, divider, input, notice, row, select, tab, tabs, text, Node,
};
use hypereffect::{cel, json, Handler, Value};

/// A short stable id for what cannot go in a signal path as it is.
fn hash(text: &str) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in text.bytes() {
        hash = (hash ^ u64::from(byte)).wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

/// The draft of the form that edits the config of a network.
pub fn network_draft(id: &str) -> String {
    format!("n_{}", hash(id))
}

fn wallet_draft(id: &str, form: &str) -> String {
    format!("w_{}_{form}", hash(id))
}

pub fn new_network_draft() -> (String, Value) {
    (
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
    )
}

pub fn entry_draft(entry: &Entry) -> Value {
    let path = |path: &Option<std::path::PathBuf>| {
        path.as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_default()
    };
    let lnd = entry.lnd.as_ref();
    let bark = entry.bark.as_ref();
    json!({
        "esplora_url": entry.esplora_url.clone().unwrap_or_default(),
        "lnd_rest_url": lnd.map(|lnd| lnd.rest_url.clone()).unwrap_or_default(),
        "lnd_tls_cert_path": lnd.map(|lnd| path(&lnd.tls_cert_path)).unwrap_or_default(),
        "lnd_macaroon_path": lnd.map(|lnd| path(&lnd.macaroon_path)).unwrap_or_default(),
        "bark_server_url": bark.and_then(|bark| bark.server_url.clone()).unwrap_or_default(),
        "bark_esplora_url": bark.and_then(|bark| bark.esplora_url.clone()).unwrap_or_default(),
    })
}

/// The drafts of the forms of `id`'s wallet, empty.
pub fn wallet_drafts(id: &str) -> impl Iterator<Item = (String, Value)> {
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

pub fn fields(args: &Args) -> Fields {
    Fields {
        esplora_url: args.text("esplora_url"),
        lnd_rest_url: args.text("lnd_rest_url"),
        lnd_tls_cert_path: args.text("lnd_tls_cert_path"),
        lnd_macaroon_path: args.text("lnd_macaroon_path"),
        bark_server_url: args.text("bark_server_url"),
        bark_esplora_url: args.text("bark_esplora_url"),
    }
}

// building blocks

/// A button sending `name` with `payload`.
fn act(id: impl Into<String>, label: &str, name: &str, payload: Value) -> Node {
    button(id)
        .label(label)
        .on_press(Handler::action(name).payload(payload))
}

/// A form's submit button, disabled while `blocked` (an expression over
/// the signals) holds, if it is given.
fn submit(
    id: impl Into<String>,
    label: &str,
    name: &str,
    payload: Value,
    blocked: Option<String>,
) -> Node {
    let node = act(id, label, name, payload).variant("primary");
    match blocked {
        Some(blocked) => node.disabled(cel(blocked)),
        None => node,
    }
}

fn field(id: impl Into<String>, label: &str, path: &str) -> Node {
    input(id).label(label).bind(path)
}

fn fact(id: &str, label: &str, value: impl Into<String>) -> Node {
    column(id).gap("none").children([
        text(format!("{id}/label")).variant("caption").text(label),
        text(format!("{id}/value")).variant("code").text(value.into()),
    ])
}

fn quote(text: &str) -> String {
    format!("'{}'", text.replace('\\', "\\\\").replace('\'', "\\'"))
}

fn ago(now: u64, then: u64) -> String {
    match now.saturating_sub(then) {
        0..=59 => "just now".into(),
        secs @ 60..=3_599 => format!("{} min ago", secs / 60),
        secs @ 3_600..=86_399 => format!("{} h ago", secs / 3_600),
        secs => format!("{} days ago", secs / 86_400),
    }
}

/// `msat` in sats, thousands apart.
fn sat(msat: u64) -> String {
    let digits = (msat / 1000).to_string();
    let mut grouped = String::new();
    for (i, digit) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            grouped.push(',');
        }
        grouped.push(digit);
    }
    match msat % 1000 {
        0 => format!("{grouped} sat"),
        rest => format!("{grouped}.{rest:03} sat"),
    }
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

fn options<'a>(items: impl IntoIterator<Item = (&'a str, &'a str)>) -> Value {
    Value::Array(
        items
            .into_iter()
            .map(|(value, label)| json!({"value": value, "label": label}))
            .collect(),
    )
}

// the page

pub fn page(now: u64, state: &State, file: String) -> Vec<Node> {
    let mut nodes = Vec::new();
    if let Some(result) = &state.result {
        let (variant, message) = match result {
            Ok(message) => ("success", message),
            Err(error) => ("failure", error),
        };
        if !message.is_empty() {
            nodes.push(notice("hw/result").variant(variant).text(message.as_str()));
        }
    }
    if let Some(error) = &state.config_error {
        nodes.push(
            notice("hw/config-error")
                .variant("failure")
                .title("The config file cannot be read")
                .text(error.as_str()),
        );
    }
    nodes.push(
        text("hw/file")
            .variant("caption")
            .text(format!("Wallets are kept in {file}. Back it up: it holds the keys.")),
    );
    for (id, entry) in &state.wanted {
        nodes.push(network_card(now, id, entry, state.slots.get(id)));
    }
    for (id, slot) in &state.slots {
        if let (Status::Waiting(count), false) = (&slot.status, state.wanted.contains_key(id)) {
            nodes.push(
                notice(format!("hw/{id}/closing"))
                    .variant("warning")
                    .text(format!("{id} closes once its {count} payment(s) in flight settle.")),
            );
        }
    }
    nodes.push(new_network());
    nodes
}

fn network_card(now: u64, id: &str, entry: &Entry, slot: Option<&Slot>) -> Node {
    let el = |part: &str| format!("hw/{id}/{part}");
    let status = slot.map(|slot| &slot.status);
    let (variant, status_text) = match status {
        None | Some(Status::Opening) => ("info", "opening…".to_string()),
        Some(Status::Open) if slot.is_some_and(|slot| slot.entry != *entry) => {
            ("info", "applying changes…".to_string())
        }
        Some(Status::Open) => ("success", "open".to_string()),
        Some(Status::Failed(error)) => ("failure", format!("failed to open: {error}")),
        Some(Status::Waiting(count)) => (
            "warning",
            format!("open, changes apply once its {count} payment(s) in flight settle"),
        ),
    };
    // A network the manager has not got to yet has nothing but its entry.
    let unopened;
    let slot = match slot {
        Some(slot) => slot,
        None => {
            unopened = Slot::new(entry.clone(), Status::Opening);
            &unopened
        }
    };
    let body = match &slot.wallet {
        Some(wallet) => wallet_card(now, id, wallet.can(), &slot.funds, details(id, entry, slot)),
        None => details(id, entry, slot),
    };
    card(format!("hw/{id}"))
        .title(id)
        .child(badge(el("status")).variant(variant).text(status_text))
        .children(body)
}

/// What a network's wallet holds, what it last did, and the forms that
/// move funds in and out of it, as far as it `can`, with `details` in a
/// tab of its own.
fn wallet_card(now: u64, id: &str, can: Can, funds: &Funds, details: Vec<Node>) -> Vec<Node> {
    let el = |part: &str| format!("hw/{id}/wallet/{part}");
    let busy = funds.busy.is_some();
    // A button running an operation, sending the draft of `form` if any.
    let run = |form: &str, label: &str, draft: bool, blocked: Option<String>| {
        let mut payload = json!({"id": id});
        if draft {
            payload["draft"] = wallet_draft(id, form).into();
        }
        let node = submit(el(form), label, &format!("wallet.{form}"), payload, blocked);
        match busy {
            true => node.disabled(true),
            false => node,
        }
    };
    let d = |form: &str, field: &str| format!("hw.{}.{field}", wallet_draft(id, form));
    let empty = |form: &str, field: &str| Some(format!("s.{}.trim() == ''", d(form, field)));
    let amount = |form: &str| {
        field(el(&format!("{form}/amount_sat")), "Amount (sat)", &d(form, "amount_sat"))
            .variant("number")
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
            act(el("refresh"), "Refresh", "wallet.refresh", json!({"id": id})),
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
        nodes.push(notice(el("outcome")).variant(variant).text(message.as_str()));
    }
    if let Some(output) = &funds.output {
        nodes.push(
            column(el("output")).gap("small").children([
                text(el("output/label"))
                    .variant("caption")
                    .text(format!("{}: copy it now, it is not kept", output.label)),
                text(el("output/value")).variant("code").text(output.address.as_str()),
                act(el("dismiss"), "Hide it", "wallet.dismiss", json!({"id": id})),
            ]),
        );
    }

    // Deposits: how money gets into the wallet.
    let mut receive = Vec::new();
    match &funds.addresses {
        Some(Ok(addresses)) => {
            for (i, address) in addresses.iter().enumerate() {
                receive.push(fact(&el(&format!("address/{i}")), address.label, address.address.as_str()));
            }
            if can.new_addresses && !addresses.is_empty() {
                receive.push(act(el("address"), "New address", "wallet.address", json!({"id": id})));
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
        receive.push(run("deposit", &format!("New {}", deposit.to_lowercase()), false, None));
    }
    if can.lightning {
        receive.push(row(el("invoice/form")).align("end").wrap(true).children([
            amount("invoice"),
            run("invoice", "Create invoice", true, None),
        ]));
    }
    if let Some(redeem) = can.redeem {
        receive.extend([
            field(el("redeem/token"), redeem, &d("redeem", "token")).variant("multiline"),
            run("redeem", "Redeem", true, empty("redeem", "token")),
        ]);
    }
    if can.onboard {
        receive.push(run("onboard", "Onboard", false, None));
    }

    // Withdrawals: how money gets out.
    let mut send = Vec::new();
    if let Some(to) = can.send {
        send.extend([
            field(el("send/to"), to, &d("send", "to")),
            row(el("send/form")).align("end").wrap(true).children([
                amount("send"),
                run("send", "Send", true, empty("send", "to")),
            ]),
        ]);
    }
    if can.lightning {
        send.extend([
            field(el("pay/invoice"), "Lightning invoice", &d("pay", "invoice")).placeholder("lnbc…"),
            run("pay", "Pay", true, empty("pay", "invoice")),
        ]);
    }
    if let Some(issue) = can.issue {
        send.push(row(el("issue/form")).align("end").wrap(true).children([
            amount("issue"),
            run("issue", &format!("Take out as {}", issue.to_lowercase()), true, None),
        ]));
    }

    let note = can
        .note
        .map(|note| text(el("note")).variant("caption").text(note));
    nodes.push(
        tabs(el("tabs"))
            .bind(format!("_hw_tab_{}", hash(id)))
            .children([
                tab(el("tab/receive")).label("Deposit").children(receive).children(note),
                tab(el("tab/send")).label("Withdraw").children(send),
                tab(el("tab/details")).label("Details").children(details),
            ]),
    );
    nodes
}

/// The internals of a network: where it is, what its wallet can do, what
/// it is configured with and its key, and the buttons that reopen and
/// remove it.
fn details(id: &str, entry: &Entry, slot: &Slot) -> Vec<Node> {
    let el = |part: &str| format!("hw/{id}/details/{part}");
    let network = NetworkId::parse(id).ok();
    let mut nodes = vec![fact(&el("id"), "Network", id)];
    if let Some(network) = &network {
        nodes.push(fact(&el("kind"), "Kind", network.kind()));
        if let Some(param) = network.param() {
            nodes.push(fact(&el("param"), "Variant", param));
        }
    }
    if let Some(wallet) = &slot.wallet {
        let abilities = abilities(&wallet.can());
        if !abilities.is_empty() {
            nodes.push(fact(&el("can"), "The wallet can", abilities.join("; ")));
        }
    }
    let summary = |label: &str, value: Option<String>| value.map(|value| (label.to_string(), value));
    let path = |path: &Option<std::path::PathBuf>| path.as_ref().map(|path| path.display().to_string());
    let configured = [
        summary("Esplora URL", entry.esplora_url.clone()),
        summary("LND REST URL", entry.lnd.as_ref().map(|lnd| lnd.rest_url.clone())),
        summary("LND TLS certificate", entry.lnd.as_ref().and_then(|lnd| path(&lnd.tls_cert_path))),
        summary("LND macaroon", entry.lnd.as_ref().and_then(|lnd| path(&lnd.macaroon_path))),
        summary("Ark server (bark)", entry.bark.as_ref().map(|bark| bark.server_url.clone().unwrap_or("Second's".into()))),
    ];
    for (i, (label, value)) in configured.into_iter().flatten().enumerate() {
        nodes.push(fact(&el(&format!("config/{i}")), &label, value));
    }
    nodes.push(fact(
        &el("key"),
        "Wallet mnemonic",
        match (slot.reveal, &entry.mnemonic) {
            (true, Some(mnemonic)) => mnemonic.as_str(),
            (true, None) => "none",
            (false, _) => "hidden",
        },
    ));
    nodes.push(match slot.reveal {
        true => act(el("hide"), "Hide the mnemonic", "network.hide", json!({"id": id})),
        false => act(el("reveal"), "Show the mnemonic", "network.reveal", json!({"id": id})),
    });
    nodes.push(
        text(el("key/note"))
            .variant("caption")
            .text("Whoever has the mnemonic controls the funds on this network."),
    );

    let form = edit_fields(id, entry);
    if !form.is_empty() {
        nodes.push(divider(el("divider")));
        nodes.extend(form);
        nodes.push(submit(
            el("save"),
            "Save",
            "network.set",
            json!({"draft": network_draft(id), "id": id}),
            None,
        ));
    }

    let reopen = match slot.status {
        Status::Failed(_) => Some("Retry"),
        Status::Open => Some("Reopen"),
        _ => None,
    }
    .map(|label| act(el("open"), label, "network.open", json!({"id": id})));
    nodes.push(divider(el("divider/actions")));
    if slot.confirm_remove {
        let funds = match &slot.funds.balances {
            Some(Ok(balances)) if balances.iter().any(|b| b.msat > 0) => {
                " It still holds funds: take them out first, or they are lost."
            }
            _ => "",
        };
        nodes.push(
            notice(el("confirm"))
                .variant("warning")
                .text(format!("Remove {id}? Its mnemonic is deleted from the config file.{funds}")),
        );
        nodes.push(row(el("confirm/buttons")).children([
            act(el("remove/confirm"), "Remove and delete its mnemonic", "network.remove.confirm", json!({"id": id}))
                .variant("failure"),
            act(el("remove/cancel"), "Keep it", "network.remove.cancel", json!({"id": id})),
        ]));
    } else {
        nodes.push(row(el("actions")).children(reopen).child(
            act(el("remove"), "Remove", "network.remove", json!({"id": id})).variant("failure"),
        ));
    }
    nodes
}

/// The inputs of the config of a network.
fn edit_fields(id: &str, entry: &Entry) -> Vec<Node> {
    let el = |part: &str| format!("hw/{id}/details/{part}");
    let d = |field: &str| format!("hw.{}.{field}", network_draft(id));
    match id.split_once("::").map_or(id, |(kind, _)| kind) {
        "arkade" | "bitcoin" => vec![field(el("esplora_url"), "Esplora URL", &d("esplora_url"))
            .placeholder("the public one")],
        "lightning" if entry.bark.is_some() => bark_fields(&el, &d),
        "lightning" => lnd_fields(&el, &d),
        _ => Vec::new(),
    }
}

fn lnd_fields(el: &dyn Fn(&str) -> String, d: &dyn Fn(&str) -> String) -> Vec<Node> {
    vec![
        field(el("lnd_rest_url"), "LND REST URL", &d("lnd_rest_url"))
            .placeholder("https://127.0.0.1:8080"),
        field(el("lnd_tls_cert_path"), "TLS certificate", &d("lnd_tls_cert_path"))
            .placeholder("/path/to/tls.cert"),
        field(el("lnd_macaroon_path"), "Macaroon", &d("lnd_macaroon_path"))
            .placeholder("/path/to/admin.macaroon"),
    ]
}

fn bark_fields(el: &dyn Fn(&str) -> String, d: &dyn Fn(&str) -> String) -> Vec<Node> {
    vec![
        field(el("bark_server_url"), "Ark server", &d("bark_server_url"))
            .placeholder("Second's server"),
        field(el("bark_esplora_url"), "Esplora URL", &d("bark_esplora_url"))
            .placeholder("the default one"),
    ]
}

/// The picker of the kind of a network to add, then what that kind needs.
fn new_network() -> Node {
    let kind_is = |kind: &str| format!("s.hw.new_network.kind == {}", quote(kind));
    let picker = config::KINDS.iter().map(|(kind, label)| {
        let chain = config::chains(kind).first().copied().unwrap_or_default();
        button(format!("hw/new/kind/{kind}"))
            .label(*label)
            .variant(cel(format!("{} ? 'primary' : 'secondary'", kind_is(kind))))
            .disabled(!cassis_networks::built(kind))
            .on_press(Handler::patch(
                json!({"hw": {"new_network": {"kind": kind, "chain": chain}}}),
            ))
    });
    let missing = config::KINDS
        .iter()
        .any(|(kind, _)| !cassis_networks::built(kind))
        .then(|| {
            text("hw/new/missing")
                .variant("caption")
                .text("Greyed out: not compiled into this build.")
        });
    let details = config::KINDS.iter().map(|(kind, _)| {
        let el = |part: &str| format!("hw/new/{kind}/{part}");
        let d = |field: &str| format!("hw.new_network.{field}");
        let chains = config::chains(kind);
        let chain = (!chains.is_empty()).then(|| {
            select(el("chain"))
                .label("Chain")
                .variant("segmented")
                .bind(d("chain"))
                .options(options(chains.iter().map(|chain| (*chain, chain_label(chain)))))
        });
        let fields: Vec<Node> = match *kind {
            "cashu" => vec![field(el("mint"), "Mint URL", &d("mint")).placeholder("https://mint.example")],
            "fedimint" => vec![field(el("invite"), "Invite code", &d("invite")).placeholder("fed1…")],
            "arkade" | "bitcoin" => vec![field(el("esplora_url"), "Esplora URL", &d("esplora_url"))
                .placeholder("the public one")],
            "lnd" => lnd_fields(&el, &d),
            "bark" => bark_fields(&el, &d),
            _ => Vec::new(),
        };
        column(format!("hw/new/{kind}"))
            .visible(cel(kind_is(kind)))
            .children(chain)
            .children(fields)
    });
    card("hw/new")
        .title("Add a network")
        .child(text("hw/new/note").variant("caption").text(
            "A new wallet mnemonic is made for it and written to the config file.",
        ))
        .child(row("hw/new/kinds").wrap(true).children(picker))
        .children(missing)
        .children(details)
        .child(submit(
            "hw/new/add",
            "Add",
            "network.add",
            json!({"draft": "new_network"}),
            Some(
                "s.hw.new_network.kind == '' \
                 || (s.hw.new_network.kind == 'cashu' && s.hw.new_network.mint.trim() == '') \
                 || (s.hw.new_network.kind == 'fedimint' && s.hw.new_network.invite.trim() == '')"
                    .into(),
            ),
        ))
}
