//! The parts of an admin page every daemon shares: its frame and the
//! Access tab, and the helpers to build the rest. Elements that do
//! something have ids naming what they act on, and send actions whose
//! payloads name it too; what a form edits is in its draft, the signal
//! `d.<draft>`.

use crate::{Access, AdminConfig, Identity};
use hypereffect::vtree::{
    badge, button, card, checkbox, column, input, list, notice, row, tabs, text, Node,
};
use hypereffect::{cel, json, Handler, Value};
use sha2::{Digest, Sha256};

/// A button sending `name` with `payload`, disabled while an action of
/// this session is on its way.
pub fn act(id: impl Into<String>, label: &str, name: &str, payload: Value) -> Node {
    button(id)
        .label(label)
        .disabled(cel("s._busy"))
        .on_press(Handler::action(name).payload(payload).indicator("_busy"))
}

/// A form's submit button, also disabled while `blocked` (an expression
/// over the signals) holds.
pub fn submit(
    id: impl Into<String>,
    label: &str,
    name: &str,
    payload: Value,
    blocked: &str,
) -> Node {
    act(id, label, name, payload)
        .variant("primary")
        .disabled(cel(format!("s._busy || ({blocked})")))
}

pub fn field(id: impl Into<String>, label: &str, path: &str) -> Node {
    input(id).label(label).bind(path)
}

pub fn number(id: impl Into<String>, label: &str, path: &str) -> Node {
    field(id, label, path).variant("number")
}

pub fn options<'a>(items: impl IntoIterator<Item = (&'a str, &'a str)>) -> Value {
    Value::Array(
        items
            .into_iter()
            .map(|(value, label)| json!({"value": value, "label": label}))
            .collect(),
    )
}

/// A CEL string literal.
pub fn quote(text: &str) -> String {
    format!("'{}'", text.replace('\\', "\\\\").replace('\'', "\\'"))
}

/// A label over a value to copy.
pub fn fact(id: &str, label: &str, value: impl Into<String>) -> Node {
    column(id).gap("none").children([
        text(format!("{id}/label")).variant("caption").text(label),
        text(format!("{id}/value"))
            .variant("code")
            .text(value.into()),
    ])
}

/// A label over a figure.
pub fn stat(id: &str, label: &str, value: impl Into<String>) -> Node {
    column(id).gap("none").children([
        text(format!("{id}/label")).variant("caption").text(label),
        text(format!("{id}/value")).variant("h2").text(value.into()),
    ])
}

/// How long ago `then` was, coarsely.
pub fn ago(now: u64, then: u64) -> String {
    match now.saturating_sub(then) {
        0..=59 => "just now".into(),
        secs @ 60..=3_599 => format!("{} min ago", secs / 60),
        secs @ 3_600..=86_399 => format!("{} h ago", secs / 3_600),
        secs => format!("{} days ago", secs / 86_400),
    }
}

/// How long until `then`, coarsely, or how long ago if it passed.
pub fn until(now: u64, then: u64) -> String {
    match then.saturating_sub(now) {
        0 => ago(now, then),
        secs @ 1..=59 => format!("in {secs} s"),
        secs @ 60..=3_599 => format!("in {} min", secs / 60),
        secs @ 3_600..=86_399 => format!("in {} h", secs / 3_600),
        secs => format!("in {} days", secs / 86_400),
    }
}

/// A span of seconds, in the largest unit that divides it.
pub fn span(secs: u64) -> String {
    match secs {
        secs if secs >= 86_400 && secs % 86_400 == 0 => format!("{} days", secs / 86_400),
        secs if secs >= 3_600 && secs % 3_600 == 0 => format!("{} h", secs / 3_600),
        secs if secs >= 60 && secs % 60 == 0 => format!("{} min", secs / 60),
        secs => format!("{secs} s"),
    }
}

/// `msat` in sats, thousands apart.
pub fn sat(msat: u64) -> String {
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

/// A short stable id for what cannot go in a signal path as it is.
pub fn short_hash(text: &str) -> String {
    lowercase_hex::encode(&Sha256::digest(text.as_bytes())[..6])
}

fn flash_notice(flash: Option<&Result<String, String>>) -> Option<Node> {
    flash.map(|result| match result {
        Ok(message) => notice("result").variant("success").text(message.as_str()),
        Err(error) => notice("result").variant("failure").text(error.as_str()),
    })
}

fn title(identity: &Identity) -> Node {
    column("title").gap("none").children([
        text("title/name")
            .variant("h1")
            .text(identity.name.as_str()),
        text("title/what")
            .variant("caption")
            .text(format!("Cassis {}", identity.what)),
    ])
}

/// The page of a session let in, around the `tabs` of its daemon.
pub(crate) fn page(
    identity: &Identity,
    pending: bool,
    flash: Option<&Result<String, String>>,
    children: Vec<Node>,
) -> Vec<Node> {
    let header = row("header").justify("between").children([
        title(identity),
        act("daemon/restart", "Restart", "daemon.restart", json!({})).variant(if pending {
            "primary"
        } else {
            "secondary"
        }),
    ]);
    let pending = pending.then(|| {
        notice("restart-needed")
            .variant("warning")
            .title("Saved, applies on restart")
            .text("Restarting will move the admin interface.")
    });
    vec![column("page")
        .child(header)
        .children(flash_notice(flash))
        .children(pending)
        .child(tabs("tabs").bind("_tab").children(children))]
}

/// The page of a session not let in.
pub(crate) fn locked(
    identity: &Identity,
    access: &Access,
    flash: Option<&Result<String, String>>,
) -> Vec<Node> {
    let key = match access {
        Access::Local => "",
        Access::Peer(key) => key.as_str(),
    };
    vec![column("page")
        .child(title(identity))
        .children(flash_notice(flash))
        .children([
            notice("locked")
                .variant("warning")
                .title("Not let in")
                .text(format!(
                    "This {} does not know your key. Open the pairing link it prints on its \
                     console, or add your key from its admin page on its own machine.",
                    identity.what
                )),
            fact("locked/key", "Your key", key),
        ])]
}

/// What the Access tab shows.
pub(crate) struct AccessInfo<'a> {
    pub access: &'a Access,
    pub config: &'a AdminConfig,
    pub http_url: Option<&'a str>,
    pub iroh_url: Option<String>,
    pub pairing_link: Option<String>,
}

pub(crate) fn access_tab(info: &AccessInfo) -> Node {
    let addresses = card("access/addresses").title("Addresses").children([
        fact(
            "access/http",
            "On this machine, open to anyone on it",
            info.http_url.unwrap_or("off"),
        ),
        fact(
            "access/iroh",
            "Over iroh, to peers only",
            info.iroh_url.as_deref().unwrap_or("off"),
        ),
    ]);
    let pairing = info.pairing_link.as_ref().map(|link| {
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
    let peers = info.config.peers.iter().map(|key| {
        let you = (*info.access == Access::Peer(key.clone()))
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
    hypereffect::vtree::tab("tab/access")
        .label("Access")
        .child(addresses)
        .children(pairing)
        .child(peers)
        .child(admin)
}
