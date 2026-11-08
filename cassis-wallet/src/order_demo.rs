//! `cassis-wallet order-demo`: a small Cassis Order Protocol server, to try
//! wallets against. It sells coffee: the payer fills a cart, pays an
//! invoice this node issues and claims, and can ask for a refund, which
//! the server offers with an `invoicerequest` and pays from this node.
//!
//! The page is hypereffect: each state of the order is a [`vtree`] and
//! only the difference to the previous one is sent. Orders are
//! remembered by the `(claim, id)` parameters of the `hello` for as long
//! as the process runs, so reconnecting with the same pair shows the
//! order again. A flow without an `id` gets an order of its own.

use cassis_core::node::{InvoiceRecord, InvoiceStatus, Node};
use cassis_core::{unix_now, Invoice};
use hypereffect::message::{encode_line, parse_line};
use hypereffect::vtree::{self, button, card, column, input, list, notice, text};
use hypereffect::{json, Action, Handler, Metadata, RendererMessage, ServerMessage};
use iroh::endpoint::{presets, RecvStream, SendStream};
use iroh::{Endpoint, SecretKey};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::Mutex as AsyncMutex;
use tracing::{info, warn};

const ALPN: &[u8] = b"cassis-order";
const CLAIM: &str = "counter-1";
const MENU: &[(&str, &str, u64)] = &[
    ("espresso", "Espresso", 1_500),
    ("latte", "Latte", 2_500),
    ("croissant", "Croissant", 1_800),
];
const REFUND_SATS: u64 = 1_000;
const INVOICE_TTL_SECS: u64 = 15 * 60;
const REFUND_TTL_SECS: u64 = 15 * 60;

#[derive(Clone, Default)]
struct Order {
    items: Vec<&'static str>,
    note: String,
    /// The invoice of the order, once the payer asked to pay.
    invoice: Option<Invoice>,
    paid: bool,
    refunded: bool,
}

type Orders = Arc<Mutex<HashMap<(String, String), Arc<Mutex<Order>>>>>;

pub async fn run(node: Node, secret: [u8; 32], name: &str) -> Result<(), String> {
    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(SecretKey::from(secret))
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await
        .map_err(|e| format!("bind iroh endpoint: {e}"))?;
    let _ = tokio::time::timeout(Duration::from_secs(10), endpoint.online()).await;
    let mut uri = format!("cop://{}", endpoint.id());
    if let Some(relay) = endpoint.addr().relay_urls().next() {
        uri.push_str(&format!("?_relay={}", encode(&relay.to_string())));
    }
    uri.push_str(&format!("#claim={CLAIM}&name={}", encode(name)));
    println!("{uri}");
    info!("serving orders; Ctrl-C to stop");

    let orders: Orders = Default::default();
    let name: Arc<str> = name.into();
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                let node = node.clone();
                let orders = orders.clone();
                let name = name.clone();
                tokio::spawn(async move {
                    let connection = match incoming.await {
                        Ok(connection) => connection,
                        Err(error) => return warn!("order connection failed: {error}"),
                    };
                    let Ok((send, recv)) = connection.accept_bi().await else { return };
                    if let Err(error) = serve_flow(node, orders, name, send, recv).await {
                        warn!("order flow ended: {error}");
                    }
                    connection.close(0u32.into(), b"done");
                });
            }
        }
    }
    endpoint.close().await;
    Ok(())
}

fn encode(text: &str) -> String {
    text.bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (byte as char).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

/// The stream to the client, and the page it was last sent.
struct Out {
    send: SendStream,
    page: Option<vtree::Node>,
}

#[derive(Clone)]
struct Flow {
    node: Node,
    name: Arc<str>,
    /// The order id, for logs.
    id: String,
    order: Arc<Mutex<Order>>,
    out: Arc<AsyncMutex<Out>>,
}

async fn serve_flow(
    node: Node,
    orders: Orders,
    name: Arc<str>,
    send: SendStream,
    recv: RecvStream,
) -> Result<(), String> {
    let mut lines = BufReader::new(recv).lines();
    let params = match lines.next_line().await.map_err(|e| e.to_string())? {
        Some(line) => match RendererMessage::parse(&line) {
            Ok(RendererMessage::Hello { params }) => params,
            _ => return Err("the flow does not start with a hello".into()),
        },
        None => return Ok(()),
    };
    let claim = params.get("claim").cloned().unwrap_or_default();
    let (id, order) = match params.get("id").filter(|id| !id.is_empty()) {
        Some(id) => {
            let order = orders
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .entry((claim, id.clone()))
                .or_default()
                .clone();
            (id.clone(), order)
        }
        None => ("(no id)".to_string(), Default::default()),
    };
    let flow = Flow {
        node,
        name,
        id,
        order,
        out: Arc::new(AsyncMutex::new(Out { send, page: None })),
    };
    info!("order flow {} opened", flow.id);
    let order = flow.order();
    let metadata = Metadata::new()
        .name(&*flow.name)
        .description("Coffee and pastries, paid with Cassis");
    let mut opening = ServerMessage::from(metadata).to_line();
    opening.push_str(&ServerMessage::signal(json!({"order": {"note": order.note}})).to_line());
    flow.send(opening).await?;
    flow.redraw(&order).await?;
    if order.invoice.is_some() && !order.paid {
        flow.send_invoice_and_watch(&order).await?;
    }

    while let Some(line) = lines.next_line().await.map_err(|e| e.to_string())? {
        if line.is_empty() {
            continue;
        }
        // `invoice` is COP's, not hypereffect's: look at it first.
        if let Ok(("invoice", body)) = parse_line(&line) {
            flow.on_refund_invoice(body.get("invoice").cloned().unwrap_or_default())
                .await?;
            continue;
        }
        match RendererMessage::parse(&line) {
            Ok(RendererMessage::Action(action)) => flow.on_action(&action).await?,
            Ok(RendererMessage::Hello { .. }) => warn!("ignoring a second hello"),
            Err(error) => warn!("ignoring message: {error}"),
        }
    }
    Ok(())
}

fn total_sats(order: &Order) -> u64 {
    order
        .items
        .iter()
        .filter_map(|item| MENU.iter().find(|(id, _, _)| id == item))
        .map(|(_, _, sats)| sats)
        .sum()
}

fn summary(order: &Order) -> String {
    if order.items.is_empty() {
        return "Your cart is empty.".into();
    }
    let names: Vec<&str> = order
        .items
        .iter()
        .filter_map(|item| MENU.iter().find(|(id, _, _)| id == item))
        .map(|(_, name, _)| *name)
        .collect();
    format!("{} — {} sats", names.join(", "), total_sats(order))
}

/// The whole page for the order's current state.
fn page(name: &str, order: &Order) -> vtree::Node {
    if order.paid {
        let refund = if order.refunded {
            notice("refunded")
                .variant("success")
                .text(format!("A refund of {REFUND_SATS} sats was sent."))
        } else {
            button("refund")
                .variant("plain")
                .label(format!("Ask for a {REFUND_SATS} sats refund"))
                .on_press(Handler::action("refund"))
        };
        return column("page").children([
            text("paid-title").variant("h1").text("Paid, thank you!"),
            text("receipt").text(summary(order)),
            text("reopen")
                .variant("caption")
                .text("Reopen this order any time to see it again."),
            refund,
        ]);
    }
    column("page").children([
        text("title").variant("h1").text(name),
        list("menu").children(MENU.iter().map(|(id, name, sats)| {
            button(format!("add-{id}"))
                .label(format!("{name} — {sats} sats"))
                .on_press(Handler::action("add").payload(json!({"item": id})))
        })),
        card("cart")
            .title("Your order")
            .child(text("cart-summary").text(summary(order))),
        input("note")
            .label("Note for the barista")
            .bind("order.note"),
        button("pay")
            .variant("primary")
            .label(format!("Pay {} sats", total_sats(order)))
            .disabled(order.items.is_empty())
            .on_press(Handler::action("pay")),
    ])
}

impl Flow {
    fn order(&self) -> Order {
        self.order.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn update(&self, change: impl FnOnce(&mut Order)) -> Order {
        let mut order = self.order.lock().unwrap_or_else(|e| e.into_inner());
        change(&mut order);
        order.clone()
    }

    async fn send(&self, lines: String) -> Result<(), String> {
        self.out
            .lock()
            .await
            .send
            .write_all(lines.as_bytes())
            .await
            .map_err(|e| format!("send: {e}"))
    }

    /// Send what changed on the page since it was last sent.
    async fn redraw(&self, order: &Order) -> Result<(), String> {
        let new = page(&self.name, order);
        let mut out = self.out.lock().await;
        let messages = match &out.page {
            Some(old) => vtree::diff(old, &new),
            None => vtree::render(&new),
        };
        let lines: String = messages.iter().map(ServerMessage::to_line).collect();
        out.send
            .write_all(lines.as_bytes())
            .await
            .map_err(|e| format!("send: {e}"))?;
        out.page = Some(new);
        Ok(())
    }

    async fn on_action(&self, action: &Action) -> Result<(), String> {
        match action.name.as_str() {
            "add" => {
                let item = action
                    .payload
                    .as_ref()
                    .and_then(|payload| payload["item"].as_str())
                    .unwrap_or_default();
                let Some((id, _, _)) = MENU.iter().find(|(id, _, _)| *id == item) else {
                    return Ok(());
                };
                let order = self.update(|order| {
                    if !order.paid {
                        order.items.push(id);
                        order.invoice = None;
                    }
                });
                self.redraw(&order).await
            }
            "pay" => {
                let note = action
                    .signal("order.note")
                    .and_then(|note| note.as_str())
                    .unwrap_or_default()
                    .to_string();
                let order = self.update(|order| order.note = note);
                if order.paid || order.items.is_empty() {
                    return self.redraw(&order).await;
                }
                let invoice = match &order.invoice {
                    Some(invoice) if invoice.body.expires_at > unix_now() + 60 => invoice.clone(),
                    _ => {
                        let networks = self.node.network_ids();
                        let mut description = summary(&order);
                        if !order.note.is_empty() {
                            description.push_str(&format!(" ({})", order.note));
                        }
                        self.node
                            .create_invoice(
                                &networks,
                                total_sats(&order) * 1000,
                                unix_now() + INVOICE_TTL_SECS,
                                Some(description),
                                None,
                            )
                            .await?
                    }
                };
                let order = self.update(|order| order.invoice = Some(invoice));
                self.send_invoice_and_watch(&order).await
            }
            "refund" => {
                let order = self.order();
                if !order.paid || order.refunded {
                    return self.redraw(&order).await;
                }
                let networks: Vec<String> = self
                    .node
                    .network_ids()
                    .iter()
                    .map(|network| network.to_string())
                    .collect();
                self.send(encode_line(
                    "invoicerequest",
                    &json!({
                        "amount": REFUND_SATS,
                        "networks": networks,
                        "memo": format!("{} refund", self.name),
                        "expiresIn": REFUND_TTL_SECS,
                    }),
                ))
                .await
            }
            other => {
                warn!("unknown action {other}");
                Ok(())
            }
        }
    }

    /// Send the order's invoice, and redraw the page as paid once this
    /// node claims it.
    async fn send_invoice_and_watch(&self, order: &Order) -> Result<(), String> {
        let Some(invoice) = &order.invoice else {
            return Ok(());
        };
        self.send(encode_line(
            "invoice",
            &json!({"invoice": invoice, "memo": summary(order)}),
        ))
        .await?;
        let flow = self.clone();
        let payment_hash = invoice.body.payment_hash;
        let key = payment_hash.to_string();
        let expires_at = invoice.body.expires_at;
        tokio::spawn(async move {
            while unix_now() < expires_at {
                let order = flow.order();
                // Superseded by a newer invoice, or paid through another flow.
                if order.paid
                    || order.invoice.as_ref().map(|i| i.body.payment_hash) != Some(payment_hash)
                {
                    return;
                }
                let record: Option<InvoiceRecord> =
                    flow.node.store().get("invoices", &key).ok().flatten();
                if record.is_some_and(|record| record.status == InvoiceStatus::Claimed) {
                    let order = flow.update(|order| order.paid = true);
                    info!("order {} paid", flow.id);
                    let _ = flow.redraw(&order).await;
                    return;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
        Ok(())
    }

    async fn on_refund_invoice(&self, invoice: hypereffect::Value) -> Result<(), String> {
        let order = self.order();
        if !order.paid || order.refunded {
            return Ok(());
        }
        let invoice: Invoice = serde_json::from_value(invoice)
            .map_err(|e| format!("refund invoice is not a cassis invoice: {e}"))?;
        if invoice.body.amount_msat != REFUND_SATS * 1000 {
            return Err(format!(
                "refund invoice asks for {} msat",
                invoice.body.amount_msat
            ));
        }
        let ours = self.node.network_ids();
        let from = invoice
            .body
            .networks
            .iter()
            .map(|entry| entry.network.clone())
            .find(|network| ours.contains(network))
            .ok_or("the refund invoice is on none of this node's networks")?;
        info!("paying refund for order {} on {from}", self.id);
        self.node.pay(&invoice, &from, &[]).await?;
        let order = self.update(|order| order.refunded = true);
        self.redraw(&order).await
    }
}
