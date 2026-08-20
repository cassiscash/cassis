//! Browser bindings for Cassis wallets.
//!
//! A wallet built on top of these bindings keeps its own payer and payee
//! logic and its own network adapters; this crate gives it what has no
//! JS equivalent:
//!
//! * an iroh [`CassisEndpoint`] (relay-only in browsers), to send
//!   `cassis-hop` requests to a payee, to answer COMMITs as a payee and
//!   to open Cassis Order Protocol streams to an order server;
//! * the wire types, parsed and checked by `cassis-core` so the JS side
//!   cannot drift from the Rust protocol: every request leaving and
//!   every response arriving goes through [`Request`] / [`Response`].
//!
//! Everything crosses the boundary as JSON strings in the serde shape of
//! the `cassis-core` types; `index.d.ts` describes them (see the custom
//! TypeScript section below).

use cassis_core::protocol::{Invoice, Request, Response};
use cassis_core::{unix_now, NetworkId};
use futures::lock::Mutex;
use iroh::endpoint::{presets, Connection, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr, PublicKey, RelayUrl, SecretKey};
use n0_future::time::timeout;
use std::rc::Rc;
use std::str::FromStr;
use std::time::Duration;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::{future_to_promise, spawn_local};

/// ALPN of the Cassis Order Protocol.
pub const ORDER_ALPN: &[u8] = b"cassis-order";

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// Same bound as the native transport: EXECUTE and COMMIT answer
/// `Pending` rather than wait, so answers are quick.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(180);
const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
/// A single COP line (one JSON message) may not grow past this.
const MAX_LINE_BYTES: usize = 1024 * 1024;

#[wasm_bindgen(typescript_custom_section)]
const TS_TYPES: &'static str = r#"
/** Canonical network id: `arkade`, `arkade::mutinynet`, `arkade::<host>`, ... */
export type NetworkId = string;
export type HtlcTarget =
  | { XOnlyPubKey: string }
  | { PubKey: string }
  | { LightningInvoice: string };
export type HtlcDescriptor =
  | {
      Arkade: {
        sender: string;
        refund_locktime: number;
        unilateral_claim_delay: number;
        unilateral_refund_delay: number;
        unilateral_refund_without_receiver_delay: number;
      };
    }
  | { [kind: string]: unknown };
export interface InvoiceNetwork {
  network: NetworkId;
  target: HtlcTarget;
  incoming_delta_secs?: number;
}
export interface Invoice {
  payment_hash: string;
  amount_msat: number;
  payee: string;
  expires_at: number;
  networks: InvoiceNetwork[];
  description: string | null;
  autocommit: boolean;
  iroh_peer_id?: string;
  iroh_relay?: string;
}
export interface Commit {
  payment_hash: string;
  network: NetworkId;
  expiry: number;
  descriptor: HtlcDescriptor;
}
/** Only COMMIT is used without routers; the other requests are routing. */
export type Request = { Commit: Commit } | { [kind: string]: unknown };
export type Response =
  | { Committed: string }
  | "Pending"
  | { Error: string }
  | { [kind: string]: unknown };
/** Answers one request; `peer` is the authenticated iroh id of the sender. */
export type HopHandler = (request: string, peer: string) => Promise<string>;
"#;

fn js_error(message: impl std::fmt::Display) -> JsValue {
    JsError::new(&message.to_string()).into()
}

fn endpoint_addr(peer: &str, relay: Option<&str>) -> Result<EndpointAddr, String> {
    let id = PublicKey::from_str(peer).map_err(|e| format!("peer id {peer}: {e}"))?;
    let mut addr = EndpointAddr::new(id);
    if let Some(relay) = relay {
        addr = addr
            .with_relay_url(RelayUrl::from_str(relay).map_err(|e| format!("relay {relay}: {e}"))?);
    }
    Ok(addr)
}

/// Parse and check an invoice: well-formed JSON in the `cassis-core`
/// shape, valid network ids, a positive amount, not expired. Returns it
/// re-serialized, so callers read exactly what the Rust side would.
#[wasm_bindgen(js_name = parseInvoice, unchecked_return_type = "string")]
pub fn parse_invoice(json: &str) -> Result<String, JsValue> {
    let invoice: Invoice =
        serde_json::from_str(json).map_err(|e| js_error(format!("invalid invoice: {e}")))?;
    for entry in &invoice.networks {
        NetworkId::parse(&entry.network.0).map_err(js_error)?;
    }
    if invoice.amount_msat == 0 {
        return Err(js_error("invoice amount is zero"));
    }
    if invoice.expires_at <= unix_now() {
        return Err(js_error("invoice expired"));
    }
    if invoice.networks.is_empty() {
        return Err(js_error("invoice names no network"));
    }
    serde_json::to_string(&invoice).map_err(js_error)
}

/// Validate a network id spec, returning it unchanged.
#[wasm_bindgen(js_name = parseNetworkId)]
pub fn parse_network_id(spec: &str) -> Result<String, JsValue> {
    NetworkId::parse(spec).map(|id| id.0).map_err(js_error)
}

/// The default safety margin (seconds) of an HTLC received on `network`.
#[wasm_bindgen(js_name = defaultIncomingDelta)]
pub fn default_incoming_delta(network: &str) -> Result<u32, JsValue> {
    let id = NetworkId::parse(network).map_err(js_error)?;
    Ok(id.default_incoming_delta() as u32)
}

/// The `cassis-hop` ALPN, as a string.
#[wasm_bindgen(js_name = hopAlpn)]
pub fn hop_alpn() -> String {
    String::from_utf8_lossy(cassis_core::protocol::ALPN).into_owned()
}

/// The Cassis Order Protocol ALPN, as a string.
#[wasm_bindgen(js_name = orderAlpn)]
pub fn order_alpn() -> String {
    String::from_utf8_lossy(ORDER_ALPN).into_owned()
}

/// An iroh endpoint. In browsers it reaches peers through relays only.
#[wasm_bindgen]
pub struct CassisEndpoint {
    endpoint: Endpoint,
}

#[wasm_bindgen]
impl CassisEndpoint {
    /// Bind an endpoint. With a 32-byte `secret` it has that stable
    /// identity and accepts `cassis-hop` requests (see
    /// [`CassisEndpoint::serve_hop`]); without, it is an ephemeral
    /// client-only endpoint.
    #[wasm_bindgen(unchecked_return_type = "Promise<CassisEndpoint>")]
    pub fn bind(secret: Option<Vec<u8>>) -> js_sys::Promise {
        future_to_promise(async move {
            let mut builder = Endpoint::builder(presets::N0);
            if let Some(secret) = secret {
                let secret: [u8; 32] = secret
                    .try_into()
                    .map_err(|_| js_error("endpoint secret must be 32 bytes"))?;
                builder = builder
                    .secret_key(SecretKey::from(secret))
                    .alpns(vec![cassis_core::protocol::ALPN.to_vec()]);
            }
            let endpoint = builder
                .bind()
                .await
                .map_err(|e| js_error(format!("bind iroh endpoint: {e}")))?;
            Ok(CassisEndpoint { endpoint }.into())
        })
    }

    /// This endpoint's id (its public key, hex).
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> String {
        self.endpoint.id().to_string()
    }

    /// The relay peers can reach this endpoint through, once known
    /// (waits up to 10s), or `undefined`.
    #[wasm_bindgen(js_name = homeRelay, unchecked_return_type = "Promise<string | undefined>")]
    pub fn home_relay(&self) -> js_sys::Promise {
        let endpoint = self.endpoint.clone();
        future_to_promise(async move {
            if timeout(Duration::from_secs(10), endpoint.online())
                .await
                .is_err()
            {
                return Ok(JsValue::UNDEFINED);
            }
            Ok(endpoint
                .addr()
                .relay_urls()
                .next()
                .map(|url| JsValue::from_str(&url.to_string()))
                .unwrap_or(JsValue::UNDEFINED))
        })
    }

    /// Send one `cassis-hop` request (JSON of a `Request`) to `peer` and
    /// return its JSON `Response`. Both are checked against the
    /// `cassis-core` types.
    #[wasm_bindgen(js_name = hopRequest, unchecked_return_type = "Promise<string>")]
    pub fn hop_request(
        &self,
        peer: String,
        relay: Option<String>,
        request: String,
    ) -> js_sys::Promise {
        let endpoint = self.endpoint.clone();
        future_to_promise(async move {
            let request: Request = serde_json::from_str(&request)
                .map_err(|e| js_error(format!("invalid request: {e}")))?;
            let response = hop_request(&endpoint, &peer, relay.as_deref(), &request)
                .await
                .map_err(js_error)?;
            serde_json::to_string(&response)
                .map(|json| JsValue::from_str(&json))
                .map_err(js_error)
        })
    }

    /// Answer `cassis-hop` requests until the endpoint closes. Needs an
    /// endpoint bound with a secret. Each request is checked against
    /// `Request` before `handler` sees it, and the handler's answer
    /// against `Response`; a handler that throws or answers garbage
    /// sends `Response::Error`.
    #[wasm_bindgen(js_name = serveHop)]
    pub fn serve_hop(
        &self,
        #[wasm_bindgen(unchecked_param_type = "HopHandler")] handler: js_sys::Function,
    ) {
        let endpoint = self.endpoint.clone();
        let handler = Rc::new(handler);
        spawn_local(async move {
            while let Some(incoming) = endpoint.accept().await {
                let handler = handler.clone();
                spawn_local(async move {
                    if let Ok(connection) = incoming.await {
                        let _ = answer_hop(connection, &handler).await;
                    }
                });
            }
        });
    }

    /// Open a Cassis Order Protocol flow: dial `peer` (through `relay`
    /// when given), open the flow's stream and send `handshake` as its
    /// first line.
    #[wasm_bindgen(js_name = openOrder, unchecked_return_type = "Promise<OrderStream>")]
    pub fn open_order(
        &self,
        peer: String,
        relay: Option<String>,
        handshake: String,
    ) -> js_sys::Promise {
        let endpoint = self.endpoint.clone();
        future_to_promise(async move {
            serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&handshake)
                .map_err(|e| js_error(format!("handshake must be a JSON object: {e}")))?;
            let connection = connect(&endpoint, &peer, relay.as_deref(), ORDER_ALPN)
                .await
                .map_err(js_error)?;
            let (send, recv) = connection
                .open_bi()
                .await
                .map_err(|e| js_error(format!("open stream: {e}")))?;
            let stream = OrderStream {
                connection,
                send: Rc::new(Mutex::new(send)),
                recv: Rc::new(Mutex::new(LineReader::new(recv))),
            };
            stream.write_line(handshake).await.map_err(js_error)?;
            Ok(stream.into())
        })
    }

    /// Close the endpoint: connections drop and peers can no longer
    /// reach it.
    #[wasm_bindgen(unchecked_return_type = "Promise<void>")]
    pub fn close(&self) -> js_sys::Promise {
        let endpoint = self.endpoint.clone();
        future_to_promise(async move {
            endpoint.close().await;
            Ok(JsValue::UNDEFINED)
        })
    }
}

async fn connect(
    endpoint: &Endpoint,
    peer: &str,
    relay: Option<&str>,
    alpn: &[u8],
) -> Result<Connection, String> {
    timeout(
        CONNECT_TIMEOUT,
        endpoint.connect(endpoint_addr(peer, relay)?, alpn),
    )
    .await
    .map_err(|_| format!("connect to {peer} timed out"))?
    .map_err(|e| format!("connect to {peer}: {e:#}"))
}

/// One request per connection and stream, as the native transport does.
async fn hop_request(
    endpoint: &Endpoint,
    peer: &str,
    relay: Option<&str>,
    request: &Request,
) -> Result<Response, String> {
    let connection = connect(endpoint, peer, relay, cassis_core::protocol::ALPN).await?;
    let (mut send, mut receive) = connection
        .open_bi()
        .await
        .map_err(|e| format!("open stream: {e}"))?;
    let bytes = serde_json::to_vec(request).map_err(|e| format!("encode request: {e}"))?;
    send.write_all(&bytes)
        .await
        .map_err(|e| format!("send request: {e}"))?;
    let _ = send.finish();
    let reply = timeout(RESPONSE_TIMEOUT, receive.read_to_end(MAX_MESSAGE_BYTES))
        .await
        .map_err(|_| format!("no response from {peer} in time"))?
        .map_err(|e| format!("read response: {e}"))?;
    connection.close(0u32.into(), b"done");
    serde_json::from_slice(&reply).map_err(|e| format!("decode response: {e}"))
}

async fn answer_hop(connection: Connection, handler: &js_sys::Function) -> Result<(), String> {
    let peer = connection.remote_id().to_string();
    let (mut send, mut receive) = timeout(CONNECT_TIMEOUT, connection.accept_bi())
        .await
        .map_err(|_| "no stream opened".to_string())?
        .map_err(|e| format!("accept stream: {e}"))?;
    let bytes = timeout(CONNECT_TIMEOUT, receive.read_to_end(MAX_MESSAGE_BYTES))
        .await
        .map_err(|_| "request not received in time".to_string())?
        .map_err(|e| format!("read request: {e}"))?;
    let response = match serde_json::from_slice::<Request>(&bytes) {
        Ok(request) => call_handler(handler, &request, &peer)
            .await
            .unwrap_or_else(Response::Error),
        Err(error) => Response::Error(format!("malformed request: {error}")),
    };
    let bytes = serde_json::to_vec(&response).map_err(|e| format!("encode response: {e}"))?;
    send.write_all(&bytes)
        .await
        .map_err(|e| format!("send response: {e}"))?;
    let _ = send.finish();
    // Dropping the connection before the peer read everything would
    // reset the stream; wait for it to close its side.
    connection.closed().await;
    Ok(())
}

async fn call_handler(
    handler: &js_sys::Function,
    request: &Request,
    peer: &str,
) -> Result<Response, String> {
    let json = serde_json::to_string(request).map_err(|e| e.to_string())?;
    let promise = handler
        .call2(
            &JsValue::NULL,
            &JsValue::from_str(&json),
            &JsValue::from_str(peer),
        )
        .map_err(describe)?;
    let answer = wasm_bindgen_futures::JsFuture::from(js_sys::Promise::resolve(&promise))
        .await
        .map_err(describe)?;
    let answer = answer
        .as_string()
        .ok_or("handler did not answer with a string")?;
    serde_json::from_str(&answer).map_err(|e| format!("handler answered an invalid response: {e}"))
}

fn describe(error: JsValue) -> String {
    error
        .dyn_ref::<js_sys::Error>()
        .map(|error| String::from(error.message()))
        .or_else(|| error.as_string())
        .unwrap_or_else(|| "handler failed".into())
}

/// One Cassis Order Protocol flow: newline-delimited JSON both ways on
/// a single stream.
#[wasm_bindgen]
pub struct OrderStream {
    connection: Connection,
    send: Rc<Mutex<SendStream>>,
    recv: Rc<Mutex<LineReader>>,
}

impl OrderStream {
    async fn write_line(&self, line: String) -> Result<(), String> {
        if line.contains('\n') {
            return Err("a message must fit on one line".into());
        }
        let mut send = self.send.lock().await;
        send.write_all(line.as_bytes())
            .await
            .map_err(|e| format!("send: {e}"))?;
        send.write_all(b"\n")
            .await
            .map_err(|e| format!("send: {e}"))
    }
}

#[wasm_bindgen]
impl OrderStream {
    /// The server's endpoint id, authenticated by iroh.
    #[wasm_bindgen(getter)]
    pub fn peer(&self) -> String {
        self.connection.remote_id().to_string()
    }

    /// Send one message (a JSON object, without newlines).
    #[wasm_bindgen(unchecked_return_type = "Promise<void>")]
    pub fn send(&self, message: String) -> js_sys::Promise {
        let stream = self.clone_handles();
        future_to_promise(async move {
            serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&message)
                .map_err(|e| js_error(format!("message must be a JSON object: {e}")))?;
            stream.write_line(message).await.map_err(js_error)?;
            Ok(JsValue::UNDEFINED)
        })
    }

    /// The next message from the server, or `undefined` once the server
    /// finished the stream or closed the connection.
    #[wasm_bindgen(unchecked_return_type = "Promise<string | undefined>")]
    pub fn next(&self) -> js_sys::Promise {
        let recv = self.recv.clone();
        future_to_promise(async move {
            let line = recv.lock().await.next_line().await.map_err(js_error)?;
            Ok(line
                .map(|line| JsValue::from_str(&line))
                .unwrap_or(JsValue::UNDEFINED))
        })
    }

    /// End the flow.
    pub fn close(&self) {
        self.connection.close(0u32.into(), b"done");
    }
}

impl OrderStream {
    fn clone_handles(&self) -> OrderStream {
        OrderStream {
            connection: self.connection.clone(),
            send: self.send.clone(),
            recv: self.recv.clone(),
        }
    }
}

/// Splits a receive stream into lines, skipping blank ones.
struct LineReader {
    recv: RecvStream,
    buffer: Vec<u8>,
    finished: bool,
}

impl LineReader {
    fn new(recv: RecvStream) -> Self {
        Self {
            recv,
            buffer: Vec::new(),
            finished: false,
        }
    }

    async fn next_line(&mut self) -> Result<Option<String>, String> {
        loop {
            if let Some(end) = self.buffer.iter().position(|&byte| byte == b'\n') {
                let line: Vec<u8> = self.buffer.drain(..=end).collect();
                let line = String::from_utf8(line).map_err(|_| "line is not UTF-8")?;
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                return Ok(Some(line.to_string()));
            }
            if self.finished {
                let rest = std::mem::take(&mut self.buffer);
                let rest = String::from_utf8(rest).map_err(|_| "line is not UTF-8")?;
                let rest = rest.trim();
                return Ok((!rest.is_empty()).then(|| rest.to_string()));
            }
            if self.buffer.len() > MAX_LINE_BYTES {
                return Err("message too long".into());
            }
            let mut chunk = [0u8; 16 * 1024];
            match self.recv.read(&mut chunk).await {
                Ok(Some(read)) => self.buffer.extend_from_slice(&chunk[..read]),
                Ok(None) => self.finished = true,
                // A closed connection ends the flow like a finished stream.
                Err(_) if !self.buffer.is_empty() => self.finished = true,
                Err(_) => return Ok(None),
            }
        }
    }
}
