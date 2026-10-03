//! `cassis-cli order-demo`: a small Cassis Order Protocol server, to try
//! wallets against. It sells coffee: the payer fills a cart, pays an
//! invoice this node issues and claims, and can ask for a refund, which
//! the server offers with an `invoiceRequest` and pays from this node.
//!
//! Orders are remembered by `(claim, id)` for as long as the process
//! runs, so reconnecting with the same pair shows the order again.

use cassis_core::node::{InvoiceRecord, InvoiceStatus, Node};
use cassis_core::{unix_now, Invoice};
use iroh::endpoint::{presets, RecvStream, SendStream};
use iroh::{Endpoint, SecretKey};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader, Lines};
use tokio::sync::Mutex as AsyncMutex;
use tracing::{info, warn};

const ALPN: &[u8] = b"cassis-order";
const SURFACE: &str = "coffee";
const MENU: &[(&str, &str, u64)] = &[
    ("espresso", "Espresso", 1_500),
    ("latte", "Latte", 2_500),
    ("croissant", "Croissant", 1_800),
];
const REFUND_SATS: u64 = 1_000;
const INVOICE_TTL_SECS: u64 = 15 * 60;

#[derive(Clone, Default)]
struct Order {
    items: Vec<&'static str>,
    note: String,
    /// The invoice of the order, once the payer asked to pay.
    invoice: Option<Invoice>,
    paid: bool,
    refunded: bool,
}

type Orders = Arc<Mutex<HashMap<(String, String), Order>>>;

pub async fn run(node: Node, secret: [u8; 32], name: &str) -> Result<(), String> {
    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(SecretKey::from(secret))
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await
        .map_err(|e| format!("bind iroh endpoint: {e}"))?;
    let _ = tokio::time::timeout(Duration::from_secs(10), endpoint.online()).await;
    let mut uri = format!("cop:{}?claim=counter-1", endpoint.id());
    if let Some(relay) = endpoint.addr().relay_urls().next() {
        uri.push_str(&format!("&relay={}", encode(&relay.to_string())));
    }
    uri.push_str(&format!("&name={}", encode(name)));
    println!("{uri}");
    info!("serving orders; Ctrl-C to stop");

    let orders: Orders = Default::default();
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                let node = node.clone();
                let orders = orders.clone();
                tokio::spawn(async move {
                    let connection = match incoming.await {
                        Ok(connection) => connection,
                        Err(error) => return warn!("order connection failed: {error}"),
                    };
                    let Ok((send, recv)) = connection.accept_bi().await else { return };
                    if let Err(error) = serve_flow(node, orders, send, recv).await {
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

struct Flow {
    node: Node,
    orders: Orders,
    key: (String, String),
    send: Arc<AsyncMutex<SendStream>>,
}

async fn serve_flow(
    node: Node,
    orders: Orders,
    send: SendStream,
    recv: RecvStream,
) -> Result<(), String> {
    let mut lines: Lines<BufReader<RecvStream>> = BufReader::new(recv).lines();
    let handshake: Value = match lines.next_line().await.map_err(|e| e.to_string())? {
        Some(line) => serde_json::from_str(&line).map_err(|e| format!("bad handshake: {e}"))?,
        None => return Ok(()),
    };
    let field = |name: &str| handshake[name].as_str().unwrap_or_default().to_string();
    // A flow without an id cannot be found again: give it one of its own.
    let id = match field("id") {
        id if id.is_empty() => format!("anonymous-{}", rand_id()),
        id => id,
    };
    let flow = Flow {
        node,
        orders,
        key: (field("claim"), id),
        send: Arc::new(AsyncMutex::new(send)),
    };
    let order = flow.order();
    info!("order flow {} opened", flow.key.1);
    flow.message(json!({"createSurface": {
        "surfaceId": SURFACE,
        "components": components(&order),
        "dataModel": data_model(&order),
    }}))
    .await?;
    if order.invoice.is_some() && !order.paid {
        flow.resend_invoice_and_watch(&order).await?;
    }

    while let Some(line) = lines.next_line().await.map_err(|e| e.to_string())? {
        let message: Value = match serde_json::from_str(&line) {
            Ok(message) => message,
            Err(error) => {
                warn!("ignoring malformed message: {error}");
                continue;
            }
        };
        if let Some(action) = message.get("action") {
            flow.on_action(action).await?;
        } else if let Some(invoice) = message.get("invoice") {
            flow.on_refund_invoice(invoice).await?;
        }
    }
    Ok(())
}

fn rand_id() -> String {
    format!("{:016x}", rand_u64())
}

fn rand_u64() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u64(unix_now());
    hasher.finish()
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

fn data_model(order: &Order) -> Value {
    json!({
        "cart": {"summary": summary(order), "count": order.items.len()},
        "order": {"note": order.note},
    })
}

/// The whole surface for the order's current state.
fn components(order: &Order) -> Value {
    if order.paid {
        let mut children = vec!["title", "receipt", "thanks"];
        let mut components = vec![
            json!({"id": "title", "component": "Text", "text": "# Paid, thank you!"}),
            json!({"id": "receipt", "component": "Text", "text": {"path": "/cart/summary"}}),
            json!({"id": "thanks", "component": "Text", "variant": "caption",
                   "text": "Reopen this order any time to see it again."}),
        ];
        if order.refunded {
            children.push("refunded");
            components.push(json!({"id": "refunded", "component": "Text",
                                   "text": format!("A refund of {REFUND_SATS} sats was sent.")}));
        } else {
            children.push("refund");
            components.push(
                json!({"id": "refund", "component": "Button", "variant": "borderless",
                                   "child": "refund_label",
                                   "action": {"event": {"name": "refund", "context": {}}}}),
            );
            components.push(json!({"id": "refund_label", "component": "Text",
                                   "text": format!("Ask for a {REFUND_SATS} sats refund")}));
        }
        components.push(json!({"id": "root", "component": "Column", "children": children}));
        return Value::Array(components);
    }
    let mut components = vec![
        json!({"id": "root", "component": "Column",
               "children": ["title", "menu", "cart", "note", "pay"]}),
        json!({"id": "title", "component": "Text", "text": "# Cassis Coffee"}),
        json!({"id": "menu", "component": "List",
               "children": MENU.iter().map(|(id, _, _)| format!("{id}_button")).collect::<Vec<_>>()}),
        json!({"id": "cart", "component": "Card", "child": "cart_text"}),
        json!({"id": "cart_text", "component": "Text", "text": {"path": "/cart/summary"}}),
        json!({"id": "note", "component": "TextField", "label": "Note for the barista",
               "value": {"path": "/order/note"}}),
        json!({"id": "pay", "component": "Button", "variant": "primary", "child": "pay_label",
               "checks": [{"condition": {"call": "numeric",
                                         "args": {"value": {"path": "/cart/count"}, "min": 1}},
                           "message": "Add something first"}],
               "action": {"event": {"name": "pay",
                                    "context": {"note": {"path": "/order/note"}}}}}),
        json!({"id": "pay_label", "component": "Text", "text": "Pay"}),
    ];
    for (id, name, sats) in MENU {
        components.push(json!({"id": format!("{id}_button"), "component": "Button",
                               "child": format!("{id}_label"),
                               "action": {"event": {"name": "add", "context": {"item": id}}}}));
        components.push(json!({"id": format!("{id}_label"), "component": "Text",
                               "text": format!("{name} — {sats} sats")}));
    }
    Value::Array(components)
}

impl Flow {
    fn order(&self) -> Order {
        self.orders
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(self.key.clone())
            .or_default()
            .clone()
    }

    fn update(&self, change: impl FnOnce(&mut Order)) -> Order {
        let mut orders = self.orders.lock().unwrap_or_else(|e| e.into_inner());
        let order = orders.entry(self.key.clone()).or_default();
        change(order);
        order.clone()
    }

    async fn message(&self, message: Value) -> Result<(), String> {
        let mut message = message;
        message["version"] = json!("v1.0");
        let mut line = serde_json::to_vec(&message).map_err(|e| e.to_string())?;
        line.push(b'\n');
        self.send
            .lock()
            .await
            .write_all(&line)
            .await
            .map_err(|e| format!("send: {e}"))
    }

    async fn redraw(&self, order: &Order) -> Result<(), String> {
        self.message(json!({"updateComponents": {
            "surfaceId": SURFACE, "components": components(order)}}))
            .await?;
        self.message(json!({"updateDataModel": {
            "surfaceId": SURFACE, "value": data_model(order)}}))
            .await
    }

    async fn on_action(&self, action: &Value) -> Result<(), String> {
        let context = &action["context"];
        match action["name"].as_str().unwrap_or_default() {
            "add" => {
                let item = context["item"].as_str().unwrap_or_default();
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
                let note = context["note"].as_str().unwrap_or_default().to_string();
                let order = self.update(|order| order.note = note);
                if order.paid || order.items.is_empty() {
                    return self.redraw(&order).await;
                }
                let invoice = match &order.invoice {
                    Some(invoice) if invoice.expires_at > unix_now() + 60 => invoice.clone(),
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
                self.resend_invoice_and_watch(&order).await
            }
            "refund" => {
                let order = self.order();
                if !order.paid || order.refunded {
                    return self.redraw(&order).await;
                }
                self.message(json!({"invoiceRequest": {
                    "amount": REFUND_SATS.to_string(),
                    "currency": "SAT",
                    "memo": "Cassis Coffee refund",
                    "expiresIn": "PT15M",
                }}))
                .await
            }
            other => {
                warn!("unknown action {other}");
                Ok(())
            }
        }
    }

    /// Send the order's invoice, and redraw the surface as paid once this
    /// node claims it.
    async fn resend_invoice_and_watch(&self, order: &Order) -> Result<(), String> {
        let Some(invoice) = &order.invoice else {
            return Ok(());
        };
        let encoded = serde_json::to_string(invoice).map_err(|e| e.to_string())?;
        self.message(json!({"invoice": {"invoice": encoded, "memo": summary(order)}}))
            .await?;
        let flow = Flow {
            node: self.node.clone(),
            orders: self.orders.clone(),
            key: self.key.clone(),
            send: self.send.clone(),
        };
        let key = invoice.payment_hash.to_string();
        let expires_at = invoice.expires_at;
        tokio::spawn(async move {
            while unix_now() < expires_at {
                let record: Option<InvoiceRecord> =
                    flow.node.store().get("invoices", &key).ok().flatten();
                if record.is_some_and(|record| record.status == InvoiceStatus::Claimed) {
                    let order = flow.update(|order| order.paid = true);
                    info!("order {} paid", flow.key.1);
                    let _ = flow.redraw(&order).await;
                    return;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
        Ok(())
    }

    async fn on_refund_invoice(&self, message: &Value) -> Result<(), String> {
        let order = self.order();
        if !order.paid || order.refunded {
            return Ok(());
        }
        let invoice: Invoice = match message["invoice"]
            .as_str()
            .map(serde_json::from_str)
            .transpose()
        {
            Ok(Some(invoice)) => invoice,
            _ => return Err("refund invoice is not a cassis invoice".into()),
        };
        if invoice.amount_msat != REFUND_SATS * 1000 {
            return Err(format!(
                "refund invoice asks for {} msat",
                invoice.amount_msat
            ));
        }
        let ours = self.node.network_ids();
        let from = invoice
            .networks
            .iter()
            .map(|entry| entry.network.clone())
            .find(|network| ours.contains(network))
            .ok_or("the refund invoice is on none of this node's networks")?;
        info!("paying refund for order {} on {from}", self.key.1);
        self.node.pay(&invoice, &from, &[]).await?;
        let order = self.update(|order| order.refunded = true);
        self.redraw(&order).await
    }
}
