//! LND-backed Lightning adapter.
//!
//! The adapter talks to LND's authenticated REST API. Incoming payments use
//! LND hold invoices: the route hash is registered before funding and the
//! invoice is settled only after the downstream adapter reveals the preimage.
//! Outgoing payments always use the downstream BOLT11 request carried by the
//! Cassis HTLC descriptor; raw hash-only sends are deliberately rejected
//! because modern LND invoices require their payment secret.

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use cassis_core::{
    Bytes32, HtlcDescriptor, HtlcError, HtlcTarget, NetworkId, NetworkRouterAdapter, OutgoingHtlc,
    OutgoingPayment, WatchError, XOnlyPubKey,
};
use lightning_invoice::Bolt11Invoice;
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::StatusCode;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, Notify};
use tracing::{debug, Span};

const DEFAULT_INCOMING_DELTA_SECS: u64 = 30;
const SEND_TIMEOUT_SECS: i32 = 60;

#[derive(Clone, Debug)]
pub struct LndConfig {
    /// LND REST base URL, normally `https://127.0.0.1:8080`.
    pub rest_url: String,
    /// Path to LND's self-signed `tls.cert`. `None` is useful only for an
    /// HTTPS endpoint whose certificate is already trusted, or for tests.
    pub tls_cert_path: Option<PathBuf>,
    /// Path to the macaroon used for REST authentication.
    pub macaroon_path: Option<PathBuf>,
}

impl LndConfig {
    pub fn new(
        rest_url: impl Into<String>,
        tls_cert_path: Option<PathBuf>,
        macaroon_path: Option<PathBuf>,
    ) -> Self {
        Self {
            rest_url: rest_url.into(),
            tls_cert_path,
            macaroon_path,
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid parameters: {0}")]
    InvalidParams(String),
    #[error("file error: {0}")]
    File(String),
    #[error("http error: {0}")]
    Http(String),
    #[error("LND API error: {0}")]
    Api(String),
    #[error("no incoming HTLC for {0}")]
    NoIncoming(String),
    #[error("no outgoing HTLC for {0}")]
    NoOutgoing(String),
}

impl From<Error> for HtlcError {
    fn from(error: Error) -> Self {
        match error {
            Error::InvalidParams(message)
            | Error::NoIncoming(message)
            | Error::NoOutgoing(message) => HtlcError::InvalidParams(message),
            other => HtlcError::Network(other.to_string()),
        }
    }
}

impl From<Error> for WatchError {
    fn from(error: Error) -> Self {
        WatchError::Network(error.to_string())
    }
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
struct PendingIncoming {
    amount_msat: u64,
    deadline: u64,
    payment_request: String,
}

#[derive(Clone, Debug)]
enum OutgoingState {
    Pending,
    Succeeded(Bytes32),
    Failed(String),
    Cancelled,
}

#[derive(Clone)]
#[allow(dead_code)]
struct PendingOutgoing {
    amount_msat: u64,
    expiry: u64,
    payment_request: String,
    state: Arc<Mutex<OutgoingState>>,
    changed: Arc<Notify>,
    cancel: Arc<Notify>,
}

pub struct LndAdapter {
    config: LndConfig,
    network_id: NetworkId,
    invoice_pubkey: XOnlyPubKey,
    client: reqwest::Client,
    span: Span,
    incoming: Mutex<HashMap<Bytes32, PendingIncoming>>,
    outgoing: Mutex<HashMap<Bytes32, PendingOutgoing>>,
}

impl std::fmt::Debug for LndAdapter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LndAdapter")
            .field("network_id", &self.network_id)
            .field("rest_url", &self.config.rest_url)
            .field("invoice_pubkey", &self.invoice_pubkey)
            .finish()
    }
}

#[derive(Deserialize)]
struct GetInfoResponse {
    identity_pubkey: String,
}

#[derive(Deserialize)]
struct AddHoldInvoiceResponse {
    payment_request: String,
}

#[derive(Deserialize)]
struct InvoiceLookup {
    payment_request: Option<String>,
    settled: Option<bool>,
    state: Option<String>,
    value_msat: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct PaymentUpdate {
    status: Value,
    payment_preimage: Option<String>,
    failure_reason: Option<Value>,
}

#[derive(Serialize)]
struct AddHoldInvoiceRequest {
    hash: String,
    value_msat: String,
    memo: String,
    expiry: String,
}

#[derive(Serialize)]
struct HashRequest {
    #[serde(rename = "payment_hash")]
    payment_hash: String,
}

#[derive(Serialize)]
struct PreimageRequest {
    preimage: String,
}

#[derive(Serialize)]
struct SendPaymentRequest<'a> {
    payment_request: &'a str,
    fee_limit_msat: String,
    timeout_seconds: i32,
    no_inflight_updates: bool,
    cancelable: bool,
}

impl LndAdapter {
    pub async fn new(
        network_id: NetworkId,
        config: LndConfig,
        span: Span,
    ) -> Result<Arc<Self>, Error> {
        let mut builder = reqwest::Client::builder();
        if let Some(path) = &config.tls_cert_path {
            let pem = tokio::fs::read(path).await.map_err(|error| {
                Error::File(format!("read TLS certificate {}: {error}", path.display()))
            })?;
            let certificate = reqwest::Certificate::from_pem(&pem)
                .map_err(|error| Error::InvalidParams(format!("parse TLS certificate: {error}")))?;
            builder = builder.add_root_certificate(certificate);
        }

        let mut headers = HeaderMap::new();
        if let Some(path) = &config.macaroon_path {
            let macaroon = tokio::fs::read(path).await.map_err(|error| {
                Error::File(format!("read macaroon {}: {error}", path.display()))
            })?;
            let encoded = lowercase_hex::encode(macaroon);
            let value = HeaderValue::from_str(&encoded).map_err(|error| {
                Error::InvalidParams(format!("invalid macaroon header: {error}"))
            })?;
            headers.insert("grpc-metadata-macaroon", value);
        }
        let client = builder
            .default_headers(headers)
            .build()
            .map_err(|error| Error::Http(format!("build REST client: {error}")))?;

        let adapter = Self {
            config,
            network_id: network_id.clone(),
            invoice_pubkey: XOnlyPubKey([0u8; 32]),
            client,
            span: cassis_core::network_span(&span, &network_id),
            incoming: Mutex::new(HashMap::new()),
            outgoing: Mutex::new(HashMap::new()),
        };
        let info: GetInfoResponse = adapter.get_json("v1/getinfo").await?;
        let pubkey_bytes = decode_hex_exact::<33>(&info.identity_pubkey).map_err(|error| {
            Error::InvalidParams(format!("invalid LND identity pubkey: {error}"))
        })?;
        let pubkey = secp256k1::PublicKey::from_slice(&pubkey_bytes).map_err(|error| {
            Error::InvalidParams(format!("invalid LND identity pubkey: {error}"))
        })?;
        let (xonly, _) = pubkey.x_only_public_key();
        let invoice_pubkey = XOnlyPubKey::from_bytes(xonly.serialize()).map_err(|error| {
            Error::InvalidParams(format!("invalid LND x-only identity: {error}"))
        })?;

        let adapter = Arc::new(Self {
            invoice_pubkey,
            ..adapter
        });
        adapter.span.in_scope(|| {
            debug!(
                target: "cassis_lightning",
                "LND adapter ready: rest_url={} identity={}",
                adapter.config.rest_url,
                invoice_pubkey.to_hex(),
            );
        });
        Ok(adapter)
    }

    fn endpoint(&self, path: &str) -> String {
        format!(
            "{}/{}",
            self.config.rest_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        )
    }

    async fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T, Error> {
        let response = self
            .client
            .get(self.endpoint(path))
            .send()
            .await
            .map_err(|error| Error::Http(error.to_string()))?;
        decode_response(response).await
    }

    async fn post_json<T, R>(&self, path: &str, body: &T) -> Result<R, Error>
    where
        T: Serialize + ?Sized,
        R: DeserializeOwned,
    {
        let response = self
            .client
            .post(self.endpoint(path))
            .json(body)
            .send()
            .await
            .map_err(|error| Error::Http(error.to_string()))?;
        decode_response(response).await
    }

    async fn post_empty<T: Serialize + ?Sized>(&self, path: &str, body: &T) -> Result<(), Error> {
        let response = self
            .client
            .post(self.endpoint(path))
            .json(body)
            .send()
            .await
            .map_err(|error| Error::Http(error.to_string()))?;
        ensure_success(response).await
    }

    async fn lookup_invoice(&self, payment_hash: Bytes32) -> Result<Option<InvoiceLookup>, Error> {
        let response = self
            .client
            .get(self.endpoint(&format!("v1/invoice/{payment_hash}")))
            .send()
            .await
            .map_err(|error| Error::Http(error.to_string()))?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        decode_response(response).await.map(Some)
    }

    async fn add_hold_invoice(
        &self,
        payment_hash: Bytes32,
        amount_msat: u64,
        deadline: u64,
    ) -> Result<String, Error> {
        let expiry = deadline.saturating_sub(unix_now()).max(60);
        let request = AddHoldInvoiceRequest {
            hash: BASE64.encode(payment_hash.0),
            value_msat: amount_msat.to_string(),
            memo: "cassis".to_string(),
            expiry: expiry.to_string(),
        };
        let response: AddHoldInvoiceResponse = self.post_json("v2/invoices/hodl", &request).await?;
        Ok(response.payment_request)
    }

    async fn ensure_incoming(
        &self,
        payment_hash: Bytes32,
        amount_msat: u64,
        deadline: u64,
    ) -> Result<String, Error> {
        if let Some(existing) = self.incoming.lock().await.get(&payment_hash).cloned() {
            if existing.amount_msat < amount_msat {
                return Err(Error::InvalidParams(format!(
                    "existing incoming invoice is only {} msat, need {amount_msat}",
                    existing.amount_msat
                )));
            }
            return Ok(existing.payment_request);
        }

        let payment_request = match self.lookup_invoice(payment_hash).await? {
            Some(invoice) => {
                if invoice.settled == Some(true)
                    || invoice
                        .state
                        .as_deref()
                        .is_some_and(|state| state.eq_ignore_ascii_case("CANCELED"))
                {
                    return Err(Error::InvalidParams("LND invoice is no longer open".into()));
                }
                let value = invoice
                    .value_msat
                    .as_ref()
                    .and_then(value_as_u64)
                    .unwrap_or(amount_msat);
                if value < amount_msat {
                    return Err(Error::InvalidParams(format!(
                        "LND invoice is only {value} msat, need {amount_msat}"
                    )));
                }
                invoice
                    .payment_request
                    .ok_or_else(|| Error::Api("LND invoice has no payment request".into()))?
            }
            None => {
                self.add_hold_invoice(payment_hash, amount_msat, deadline)
                    .await?
            }
        };

        self.incoming.lock().await.insert(
            payment_hash,
            PendingIncoming {
                amount_msat,
                deadline,
                payment_request: payment_request.clone(),
            },
        );
        Ok(payment_request)
    }

    fn parse_target(
        &self,
        descriptor: &HtlcDescriptor,
        payment_hash: Bytes32,
        amount_msat: u64,
    ) -> Result<String, Error> {
        let HtlcDescriptor::Lightning { payment_request } = descriptor else {
            return Err(Error::InvalidParams(
                "LND outgoing payment requires a Lightning invoice descriptor".into(),
            ));
        };
        let invoice = Bolt11Invoice::from_str(payment_request)
            .map_err(|error| Error::InvalidParams(format!("invalid BOLT11 invoice: {error}")))?;
        if invoice.payment_hash().as_ref() != payment_hash.0 {
            return Err(Error::InvalidParams(
                "Lightning invoice hash does not match the route payment hash".into(),
            ));
        }
        if let Some(invoice_amount) = invoice.amount_milli_satoshis() {
            if invoice_amount < amount_msat {
                return Err(Error::InvalidParams(format!(
                    "Lightning invoice is only {invoice_amount} msat, need {amount_msat}"
                )));
            }
        }
        Ok(payment_request.clone())
    }

    async fn start_payment(&self, payment_hash: Bytes32, pending: PendingOutgoing) {
        let request = SendPaymentRequest {
            payment_request: &pending.payment_request,
            fee_limit_msat: ((pending.amount_msat / 100).max(1_000)).to_string(),
            timeout_seconds: SEND_TIMEOUT_SECS,
            no_inflight_updates: true,
            cancelable: true,
        };
        let send = async {
            let response = self
                .client
                .post(self.endpoint("v2/router/send"))
                .json(&request)
                .send()
                .await
                .map_err(|error| Error::Http(error.to_string()))?;
            let body = ensure_success_body(response).await?;
            parse_payment_stream(&body, payment_hash)
        };

        let result = tokio::select! {
            result = send => result,
            _ = pending.cancel.notified() => Err(Error::Api("outgoing payment cancelled".into())),
        };
        let state = match result {
            Ok(preimage) => OutgoingState::Succeeded(preimage),
            Err(error) if error.to_string().contains("cancelled") => OutgoingState::Cancelled,
            Err(error) => OutgoingState::Failed(error.to_string()),
        };
        *pending.state.lock().await = state;
        pending.changed.notify_waiters();
    }

    async fn track_payment(&self, payment_hash: Bytes32, pending: PendingOutgoing) {
        let result = async {
            let response = self
                .client
                .get(self.endpoint(&format!("v2/router/track/{payment_hash}")))
                .send()
                .await
                .map_err(|error| Error::Http(error.to_string()))?;
            let body = ensure_success_body(response).await?;
            parse_payment_stream(&body, payment_hash)
        }
        .await;
        let state = match result {
            Ok(preimage) => OutgoingState::Succeeded(preimage),
            Err(error) => OutgoingState::Failed(error.to_string()),
        };
        *pending.state.lock().await = state;
        pending.changed.notify_waiters();
    }
}

#[async_trait]
impl NetworkRouterAdapter for LndAdapter {
    fn network_id(&self) -> NetworkId {
        self.network_id.clone()
    }

    fn invoice_pubkey(&self) -> XOnlyPubKey {
        self.invoice_pubkey
    }

    fn claim_pubkey(&self) -> XOnlyPubKey {
        self.invoice_pubkey
    }

    fn incoming_delta_secs(&self) -> u64 {
        DEFAULT_INCOMING_DELTA_SECS
    }

    async fn register_incoming_htlc(
        &self,
        payment_hash: Bytes32,
        min_amount_msat: u64,
        deadline: u64,
    ) -> Result<(), HtlcError> {
        if deadline <= unix_now() {
            return Err(HtlcError::InvalidParams("deadline in the past".into()));
        }
        self.ensure_incoming(payment_hash, min_amount_msat, deadline)
            .await
            .map_err(HtlcError::from)?;
        Ok(())
    }

    async fn htlc_target(&self, payment_hash: Bytes32) -> Result<HtlcTarget, HtlcError> {
        let payment_request = self
            .incoming
            .lock()
            .await
            .get(&payment_hash)
            .map(|pending| pending.payment_request.clone())
            .ok_or_else(|| Error::NoIncoming(payment_hash.to_string()))
            .map_err(HtlcError::from)?;
        Ok(HtlcTarget::LightningInvoice(payment_request))
    }

    async fn cancel_incoming_htlc(&self, payment_hash: Bytes32) -> Result<(), HtlcError> {
        let request = HashRequest {
            payment_hash: BASE64.encode(payment_hash.0),
        };
        self.post_empty("v2/invoices/cancel", &request)
            .await
            .map_err(HtlcError::from)?;
        self.incoming.lock().await.remove(&payment_hash);
        Ok(())
    }

    async fn create_outgoing_htlc(
        &self,
        payment_hash: Bytes32,
        amount_msat: u64,
        expiry: u64,
        htlc_target: &HtlcTarget,
    ) -> Result<OutgoingHtlc, HtlcError> {
        let payment_request = match htlc_target {
            HtlcTarget::LightningInvoice(invoice) => invoice.clone(),
            HtlcTarget::XOnlyPubKey(_) | HtlcTarget::PubKey(_) => {
                return Err(HtlcError::InvalidParams(
                    "lightning requires a hold invoice target".into(),
                ))
            }
        };
        if expiry <= unix_now() {
            return Err(HtlcError::InvalidParams(
                "outgoing expiry is in the past".into(),
            ));
        }
        self.parse_target(
            &HtlcDescriptor::Lightning {
                payment_request: payment_request.clone(),
            },
            payment_hash,
            amount_msat,
        )
        .map_err(HtlcError::from)?;
        let pending = PendingOutgoing {
            amount_msat,
            expiry,
            payment_request: payment_request.clone(),
            state: Arc::new(Mutex::new(OutgoingState::Pending)),
            changed: Arc::new(Notify::new()),
            cancel: Arc::new(Notify::new()),
        };
        self.outgoing
            .lock()
            .await
            .insert(payment_hash, pending.clone());
        let adapter = self.clone_for_task();
        tokio::spawn(async move { adapter.start_payment(payment_hash, pending).await });
        Ok(OutgoingHtlc {
            payment_hash,
            amount_msat,
            expiry,
            recipient: payment_request,
            network: self.network_id.clone(),
        })
    }

    async fn restore_outgoing_htlc(
        &self,
        payment: &OutgoingPayment,
        descriptor: Option<&HtlcDescriptor>,
    ) -> Result<(), HtlcError> {
        let payment_request = self
            .parse_target(
                descriptor.ok_or(HtlcError::Unimplemented)?,
                payment.payment_hash,
                payment.amount_msat,
            )
            .map_err(HtlcError::from)?;
        let pending = PendingOutgoing {
            amount_msat: payment.amount_msat,
            expiry: payment.expiry,
            payment_request,
            state: Arc::new(Mutex::new(OutgoingState::Pending)),
            changed: Arc::new(Notify::new()),
            cancel: Arc::new(Notify::new()),
        };
        let payment_hash = payment.payment_hash;
        self.outgoing
            .lock()
            .await
            .insert(payment_hash, pending.clone());
        let adapter = self.clone_for_task();
        tokio::spawn(async move { adapter.track_payment(payment_hash, pending).await });
        Ok(())
    }

    async fn claim_incoming(
        &self,
        payment_hash: Bytes32,
        preimage: Bytes32,
    ) -> Result<(), HtlcError> {
        let digest = Sha256::digest(preimage.0);
        if digest.as_slice() != payment_hash.0 {
            return Err(HtlcError::InvalidParams(
                "preimage does not match the payment hash".into(),
            ));
        }
        let request = PreimageRequest {
            preimage: BASE64.encode(preimage.0),
        };
        self.post_empty("v2/invoices/settle", &request)
            .await
            .map_err(HtlcError::from)?;
        self.incoming.lock().await.remove(&payment_hash);
        Ok(())
    }

    async fn refund_outgoing(&self, payment_hash: Bytes32) -> Result<(), HtlcError> {
        let pending = self
            .outgoing
            .lock()
            .await
            .get(&payment_hash)
            .cloned()
            .ok_or_else(|| Error::NoOutgoing(payment_hash.to_string()))
            .map_err(HtlcError::from)?;
        pending.cancel.notify_waiters();
        *pending.state.lock().await = OutgoingState::Cancelled;
        pending.changed.notify_waiters();
        Ok(())
    }

    async fn watch_preimage(
        &self,
        payment_hash: Bytes32,
        deadline: u64,
    ) -> Result<Bytes32, WatchError> {
        let pending = self
            .outgoing
            .lock()
            .await
            .get(&payment_hash)
            .cloned()
            .ok_or_else(|| Error::NoOutgoing(payment_hash.to_string()))
            .map_err(WatchError::from)?;
        loop {
            match &*pending.state.lock().await {
                OutgoingState::Pending => {}
                OutgoingState::Succeeded(preimage) => return Ok(*preimage),
                OutgoingState::Failed(error) => return Err(WatchError::Network(error.clone())),
                OutgoingState::Cancelled => {
                    return Err(WatchError::Network("outgoing payment cancelled".into()))
                }
            }
            if unix_now() >= deadline {
                return Err(WatchError::DeadlineExceeded);
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    async fn verify_incoming_htlc(
        &self,
        descriptor: &HtlcDescriptor,
        payment_hash: Bytes32,
    ) -> Result<(), HtlcError> {
        let payment_request = match descriptor {
            HtlcDescriptor::Lightning { payment_request } => payment_request,
            _ => {
                return Err(HtlcError::InvalidParams(
                    "expected a Lightning invoice descriptor".into(),
                ))
            }
        };
        let invoice = Bolt11Invoice::from_str(payment_request).map_err(|error| {
            HtlcError::InvalidParams(format!("invalid BOLT11 invoice: {error}"))
        })?;
        if invoice.payment_hash().as_ref() != payment_hash.0 {
            return Err(HtlcError::InvalidParams(
                "invoice hash does not match the route payment hash".into(),
            ));
        }
        Ok(())
    }

    async fn accept_incoming_htlc(
        &self,
        payment_hash: Bytes32,
        descriptor: &HtlcDescriptor,
        deadline: u64,
    ) -> Result<(), HtlcError> {
        self.verify_incoming_htlc(descriptor, payment_hash).await?;
        let payment_request = match descriptor {
            HtlcDescriptor::Lightning { payment_request } => payment_request.clone(),
            _ => unreachable!(),
        };
        let invoice = self
            .lookup_invoice(payment_hash)
            .await
            .map_err(HtlcError::from)?
            .ok_or_else(|| HtlcError::InvalidParams("LND hold invoice not found".into()))?;
        if invoice.settled == Some(true)
            || invoice
                .state
                .as_deref()
                .is_some_and(|state| state.eq_ignore_ascii_case("CANCELED"))
        {
            return Err(HtlcError::InvalidParams("LND invoice is not open".into()));
        }
        let amount_msat = invoice
            .value_msat
            .as_ref()
            .and_then(value_as_u64)
            .unwrap_or(0);
        self.incoming.lock().await.insert(
            payment_hash,
            PendingIncoming {
                amount_msat,
                deadline,
                payment_request,
            },
        );
        Ok(())
    }

    async fn outgoing_htlc_descriptor(
        &self,
        payment_hash: Bytes32,
    ) -> Result<HtlcDescriptor, HtlcError> {
        let payment_request = self
            .outgoing
            .lock()
            .await
            .get(&payment_hash)
            .map(|pending| pending.payment_request.clone())
            .ok_or_else(|| Error::NoOutgoing(payment_hash.to_string()))
            .map_err(HtlcError::from)?;
        Ok(HtlcDescriptor::Lightning { payment_request })
    }
}

impl LndAdapter {
    fn clone_for_task(&self) -> Arc<Self> {
        // The task only needs the shared HTTP client and endpoint helpers. A
        // lightweight Arc clone keeps the request alive without duplicating
        // any mutable payment maps.
        Arc::new(Self {
            config: self.config.clone(),
            network_id: self.network_id.clone(),
            invoice_pubkey: self.invoice_pubkey,
            client: self.client.clone(),
            span: self.span.clone(),
            incoming: Mutex::new(HashMap::new()),
            outgoing: Mutex::new(HashMap::new()),
        })
    }
}

async fn decode_response<T: DeserializeOwned>(response: reqwest::Response) -> Result<T, Error> {
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|error| Error::Http(error.to_string()))?;
    if !status.is_success() {
        return Err(Error::Api(format!("HTTP {status}: {body}")));
    }
    serde_json::from_str(&body)
        .map_err(|error| Error::Api(format!("decode response: {error}; body={body}")))
}

async fn ensure_success(response: reqwest::Response) -> Result<(), Error> {
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|error| Error::Http(error.to_string()))?;
    if status.is_success() {
        Ok(())
    } else {
        Err(Error::Api(format!("HTTP {status}: {body}")))
    }
}

async fn ensure_success_body(response: reqwest::Response) -> Result<String, Error> {
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|error| Error::Http(error.to_string()))?;
    if status.is_success() {
        Ok(body)
    } else {
        Err(Error::Api(format!("HTTP {status}: {body}")))
    }
}

fn parse_payment_stream(body: &str, expected_hash: Bytes32) -> Result<Bytes32, Error> {
    let mut last: Option<PaymentUpdate> = None;
    for item in serde_json::Deserializer::from_str(body).into_iter::<Value>() {
        let value = item.map_err(|error| Error::Api(format!("decode payment stream: {error}")))?;
        let update: PaymentUpdate = serde_json::from_value(value)
            .map_err(|error| Error::Api(format!("decode payment update: {error}")))?;
        let status = status_name(&update.status);
        if status == "SUCCEEDED" {
            let raw = update
                .payment_preimage
                .ok_or_else(|| Error::Api("successful LND payment has no preimage".into()))?;
            let preimage = decode_hex_or_base64_32(&raw)?;
            if Sha256::digest(preimage).as_slice() != expected_hash.0 {
                return Err(Error::Api(
                    "LND returned a preimage for the wrong payment hash".into(),
                ));
            }
            return Ok(Bytes32(preimage));
        }
        if status == "FAILED" {
            return Err(Error::Api(format!(
                "LND payment failed: {}",
                update
                    .failure_reason
                    .map(|reason| reason.to_string())
                    .unwrap_or_else(|| "unknown reason".into())
            )));
        }
        last = Some(update);
    }
    Err(Error::Api(format!(
        "LND payment stream ended without terminal success: {last:?}"
    )))
}

fn status_name(value: &Value) -> String {
    match value {
        Value::String(value) => value.to_ascii_uppercase(),
        Value::Number(value) => match value.as_u64() {
            Some(2) => "SUCCEEDED".into(),
            Some(3) => "FAILED".into(),
            Some(1) => "IN_FLIGHT".into(),
            Some(4) => "INITIATED".into(),
            _ => "UNKNOWN".into(),
        },
        _ => "UNKNOWN".into(),
    }
}

fn value_as_u64(value: &Value) -> Option<u64> {
    match value {
        Value::String(value) => value.parse().ok(),
        Value::Number(value) => value.as_u64(),
        _ => None,
    }
}

fn decode_hex_exact<const N: usize>(value: &str) -> Result<[u8; N], String> {
    let mut bytes = [0u8; N];
    lowercase_hex::decode_to_slice(value, &mut bytes).map_err(|error| error.to_string())?;
    Ok(bytes)
}

fn decode_hex_or_base64_32(value: &str) -> Result<[u8; 32], Error> {
    if let Ok(bytes) = decode_hex_exact::<32>(value) {
        return Ok(bytes);
    }
    let decoded = BASE64
        .decode(value)
        .map_err(|error| Error::Api(format!("decode preimage: {error}")))?;
    decoded
        .try_into()
        .map_err(|_| Error::Api("preimage is not 32 bytes".into()))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
