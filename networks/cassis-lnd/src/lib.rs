//! Lightning network through an external LND node's REST API.
//!
//! * **Receive**: the target is an LND *hold invoice* for the payment
//!   hash, with a final CLTV covering the agreed expiry; it is settled
//!   with the preimage when claiming.
//! * **Send**: LND pays the target invoice (the downstream hold
//!   invoice), with a CLTV limit keeping the HTLC within the expiry.
//!   Hash-only sends are refused: modern invoices need their payment
//!   secret.
//! * **Watch**: LND tracks the payment; success reveals the preimage,
//!   failure means the funds are back.

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use cassis_core::{
    unix_now, Bytes32, Htlc, HtlcDescriptor, InvoiceTarget, Network, NetworkError, NetworkId,
    OutgoingState, MSAT_PER_SAT,
};
use lightning_invoice::Bolt11Invoice;
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::StatusCode;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;
use tracing::{debug, info, warn, Span};

const SEND_TIMEOUT_SECS: i32 = 60;
/// Block interval used to turn expiries into CLTV deltas: 30s on
/// mutinynet, bitcoin's 10 minutes everywhere else.
fn secs_per_block(id: &NetworkId) -> u64 {
    match id.param() {
        Some("mutinynet") => 30,
        _ => 600,
    }
}
/// LND's minimum final CLTV delta.
const MIN_FINAL_CLTV: u64 = 18;
/// How long a check waits for LND's payment stream to say where the
/// payment is.
const TRACK_WAIT: Duration = Duration::from_secs(3);
/// How long a send waits for LND to take the payment or refuse it. A
/// slower LND is not a failure: the payment is watched by hash.
const SEND_START_WAIT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug, Serialize, Deserialize)]
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

fn api_error(error: impl std::fmt::Display) -> NetworkError {
    NetworkError::network(format!("LND: {error}"))
}

#[derive(Deserialize)]
struct GetInfoResponse {
    identity_pubkey: String,
}

#[derive(Deserialize)]
struct Payment {
    status: Value,
    payment_preimage: Option<String>,
}

#[derive(Deserialize)]
struct AddHoldInvoiceResponse {
    payment_request: String,
}

#[derive(Deserialize)]
struct InvoiceLookup {
    payment_request: Option<String>,
    state: Option<String>,
    value_msat: Option<Value>,
}

/// `GET /v1/balance/channels`; LND string-encodes sat amounts, but older
/// builds answer with a number, so both shapes are accepted.
#[derive(Deserialize)]
struct ChannelBalanceResponse {
    balance: Option<Value>,
}

/// `GET /v1/balance/blockchain`.
#[derive(Deserialize)]
struct WalletBalanceResponse {
    confirmed_balance: Option<Value>,
}

#[derive(Deserialize)]
struct NewAddressResponse {
    address: String,
}

#[derive(Serialize)]
struct AddInvoiceRequest {
    value_msat: String,
    memo: String,
}

#[derive(Deserialize)]
struct AddInvoiceResponse {
    payment_request: String,
}

#[derive(Serialize)]
struct PayInvoiceRequest<'a> {
    payment_request: &'a str,
}

#[derive(Deserialize)]
struct PayInvoiceResponse {
    #[serde(default)]
    payment_error: String,
}

#[derive(Serialize)]
struct SendCoinsRequest<'a> {
    addr: &'a str,
    amount: String,
    target_conf: i32,
}

#[derive(Deserialize)]
struct SendCoinsResponse {
    txid: String,
}

#[derive(Serialize)]
struct AddHoldInvoiceRequest {
    hash: String,
    value_msat: String,
    memo: String,
    expiry: String,
    cltv_expiry: String,
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
    cltv_limit: i32,
    no_inflight_updates: bool,
    cancelable: bool,
}

pub struct LndAdapter {
    id: NetworkId,
    config: LndConfig,
    client: reqwest::Client,
    span: Span,
}

impl LndAdapter {
    /// Connect to the LND node of `config` as network `lightning`.
    pub async fn open(id: NetworkId, config: LndConfig, span: &Span) -> Result<Self, String> {
        let mut builder = reqwest::Client::builder();
        if let Some(path) = &config.tls_cert_path {
            let pem = tokio::fs::read(path)
                .await
                .map_err(|e| format!("read TLS certificate {}: {e}", path.display()))?;
            let certificate = reqwest::Certificate::from_pem(&pem)
                .map_err(|e| format!("parse TLS certificate: {e}"))?;
            builder = builder.add_root_certificate(certificate);
        }
        let mut headers = HeaderMap::new();
        if let Some(path) = &config.macaroon_path {
            let macaroon = tokio::fs::read(path)
                .await
                .map_err(|e| format!("read macaroon {}: {e}", path.display()))?;
            let value = HeaderValue::from_str(&lowercase_hex::encode(macaroon))
                .map_err(|e| format!("invalid macaroon: {e}"))?;
            headers.insert("grpc-metadata-macaroon", value);
        }
        let client = builder
            .default_headers(headers)
            .build()
            .map_err(|e| format!("REST client: {e}"))?;
        let adapter = Self {
            span: cassis_core::network_span(span, &id),
            id,
            config,
            client,
        };
        let info: GetInfoResponse = adapter
            .get_json("v1/getinfo")
            .await
            .map_err(|e| e.to_string())?;
        debug!(
            parent: &adapter.span,
            "LND ready: {} identity={}",
            adapter.config.rest_url,
            info.identity_pubkey
        );
        Ok(adapter)
    }

    /// Outbound liquidity of the node's channels, in msat.
    pub async fn channel_balance_msat(&self) -> Result<u64, NetworkError> {
        let response: ChannelBalanceResponse = self.get_json("v1/balance/channels").await?;
        Ok(response
            .balance
            .as_ref()
            .and_then(value_as_u64)
            .unwrap_or(0)
            .saturating_mul(MSAT_PER_SAT))
    }

    /// Confirmed coins of the node's on-chain wallet, in msat.
    pub async fn onchain_balance_msat(&self) -> Result<u64, NetworkError> {
        let response: WalletBalanceResponse = self.get_json("v1/balance/blockchain").await?;
        Ok(response
            .confirmed_balance
            .as_ref()
            .and_then(value_as_u64)
            .unwrap_or(0)
            .saturating_mul(MSAT_PER_SAT))
    }

    /// A new on-chain address of the node's wallet.
    pub async fn new_address(&self) -> Result<String, NetworkError> {
        let response: NewAddressResponse =
            self.get_json("v1/newaddress?type=TAPROOT_PUBKEY").await?;
        Ok(response.address)
    }

    /// A plain invoice of `amount_msat` paying the node.
    pub async fn add_invoice(&self, amount_msat: u64) -> Result<String, NetworkError> {
        let request = AddInvoiceRequest {
            value_msat: amount_msat.to_string(),
            memo: "cassis".to_string(),
        };
        let response: AddInvoiceResponse = self.post_json("v1/invoices", &request).await?;
        Ok(response.payment_request)
    }

    /// Pay `invoice` from the node's channels, waiting for the outcome.
    pub async fn pay_invoice(&self, invoice: &str) -> Result<(), NetworkError> {
        let request = PayInvoiceRequest {
            payment_request: invoice.trim(),
        };
        let response: PayInvoiceResponse =
            self.post_json("v1/channels/transactions", &request).await?;
        if !response.payment_error.is_empty() {
            return Err(NetworkError::network(response.payment_error));
        }
        Ok(())
    }

    /// Send `amount_sat` on-chain to `address`. Returns the txid.
    pub async fn send_onchain(
        &self,
        address: &str,
        amount_sat: u64,
    ) -> Result<String, NetworkError> {
        let request = SendCoinsRequest {
            addr: address.trim(),
            amount: amount_sat.to_string(),
            target_conf: 6,
        };
        let response: SendCoinsResponse = self.post_json("v1/transactions", &request).await?;
        Ok(response.txid)
    }

    fn endpoint(&self, path: &str) -> String {
        format!(
            "{}/{}",
            self.config.rest_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        )
    }

    async fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T, NetworkError> {
        let response = self
            .client
            .get(self.endpoint(path))
            .send()
            .await
            .map_err(api_error)?;
        decode_response(response).await
    }

    async fn post_json<T, R>(&self, path: &str, body: &T) -> Result<R, NetworkError>
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
            .map_err(api_error)?;
        decode_response(response).await
    }

    async fn post_empty<T: Serialize + ?Sized>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<(), NetworkError> {
        let response = self
            .client
            .post(self.endpoint(path))
            .json(body)
            .send()
            .await
            .map_err(api_error)?;
        ensure_success(response).await
    }

    async fn lookup_invoice(
        &self,
        payment_hash: Bytes32,
    ) -> Result<Option<InvoiceLookup>, NetworkError> {
        let response = self
            .client
            .get(self.endpoint(&format!("v1/invoice/{payment_hash}")))
            .send()
            .await
            .map_err(api_error)?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        decode_response(response).await.map(Some)
    }

    /// Open hold invoice for `payment_hash`: the one LND already holds,
    /// or a new one.
    async fn hold_invoice(
        &self,
        payment_hash: Bytes32,
        amount_msat: u64,
        expiry: u64,
    ) -> Result<String, NetworkError> {
        if let Some(invoice) = self.lookup_invoice(payment_hash).await? {
            if invoice.state.as_deref() != Some("OPEN") {
                return Err(NetworkError::invalid(
                    "an invoice for this hash is no longer open",
                ));
            }
            if invoice.value_msat.as_ref().and_then(value_as_u64) != Some(amount_msat) {
                return Err(NetworkError::invalid(
                    "an invoice for this hash has another amount",
                ));
            }
            return invoice
                .payment_request
                .ok_or_else(|| NetworkError::network("LND invoice has no payment request"));
        }
        let seconds = expiry.saturating_sub(unix_now());
        let request = AddHoldInvoiceRequest {
            hash: BASE64.encode(payment_hash.0),
            value_msat: amount_msat.to_string(),
            memo: "cassis".to_string(),
            expiry: seconds.max(60).to_string(),
            // LND only accepts HTLCs that stay locked this many blocks.
            cltv_expiry: (seconds.div_ceil(secs_per_block(&self.id)) + 1)
                .max(MIN_FINAL_CLTV)
                .to_string(),
        };
        let response: AddHoldInvoiceResponse = self.post_json("v2/invoices/hodl", &request).await?;
        Ok(response.payment_request)
    }

    /// LND's view of the payment for `payment_hash`, as reported on its
    /// tracking stream within [`TRACK_WAIT`].
    async fn payment(&self, payment_hash: Bytes32) -> Result<Tracked, NetworkError> {
        let mut response = self
            .client
            .get(self.endpoint(&format!("v2/router/track/{payment_hash}")))
            .send()
            .await
            .map_err(api_error)?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(Tracked::Unknown);
        }
        let mut body = Vec::new();
        let mut tracked = Tracked::Silent;
        let _ = tokio::time::timeout(TRACK_WAIT, async {
            while let Ok(Some(chunk)) = response.chunk().await {
                body.extend_from_slice(&chunk);
                for item in serde_json::Deserializer::from_slice(&body).into_iter::<Value>() {
                    let Ok(mut value) = item else { break };
                    // grpc-gateway wraps stream messages in `result`.
                    if let Some(result) = value.get_mut("result") {
                        value = result.take();
                    }
                    if let Some(error) = value.get("error") {
                        if error.get("code").and_then(Value::as_u64) == Some(GRPC_NOT_FOUND) {
                            tracked = Tracked::Unknown;
                        } else {
                            warn!("LND payment stream: {error}");
                        }
                        continue;
                    }
                    if let Ok(payment) = serde_json::from_value::<Payment>(value) {
                        tracked = Tracked::Found(payment);
                    }
                }
                // The stream opens with where the payment is now, which
                // is all a check needs.
                if !matches!(tracked, Tracked::Silent) {
                    break;
                }
            }
        })
        .await;
        Ok(tracked)
    }
}

/// What LND's tracking stream says of a payment.
enum Tracked {
    /// LND has no such payment.
    Unknown,
    /// Nothing in time: LND may or may not have it.
    Silent,
    Found(Payment),
}

/// gRPC's `NOT_FOUND` status code.
const GRPC_NOT_FOUND: u64 = 5;

#[async_trait]
impl Network for LndAdapter {
    fn id(&self) -> NetworkId {
        self.id.clone()
    }

    async fn receive_target(
        &self,
        payment_hash: Bytes32,
        amount_msat: u64,
        expiry: u64,
    ) -> Result<InvoiceTarget, NetworkError> {
        self.hold_invoice(payment_hash, amount_msat, expiry)
            .await
            .map(|invoice| InvoiceTarget::Lightning {
                network: self.id.clone(),
                invoice,
            })
    }

    async fn cancel_receive(&self, payment_hash: Bytes32) -> Result<(), NetworkError> {
        match self.lookup_invoice(payment_hash).await? {
            // Canceling an accepted invoice fails its HTLCs back to the
            // payer right away, instead of at their expiry.
            Some(invoice) if matches!(invoice.state.as_deref(), Some("OPEN" | "ACCEPTED")) => {
                let request = HashRequest {
                    payment_hash: BASE64.encode(payment_hash.0),
                };
                self.post_empty("v2/invoices/cancel", &request).await
            }
            _ => Ok(()),
        }
    }

    async fn verify_incoming_htlc(&self, htlc: &Htlc) -> Result<(), NetworkError> {
        let HtlcDescriptor::Lightning { target: request } = &htlc.descriptor else {
            return Err(NetworkError::invalid("not a lightning HTLC"));
        };
        parse_invoice(request, htlc.payment_hash)?;
        let invoice = self
            .lookup_invoice(htlc.payment_hash)
            .await?
            .ok_or_else(|| NetworkError::invalid("no hold invoice for this hash"))?;
        if invoice.payment_request.as_deref() != Some(request.as_str()) {
            return Err(NetworkError::invalid("HTLC is not addressed to this node"));
        }
        // LND accepted the HTLC only if it locks the invoice amount and
        // stays locked for the invoice's final CLTV.
        if invoice.state.as_deref() != Some("ACCEPTED") {
            return Err(NetworkError::not_yet("hold invoice is not funded yet"));
        }
        if invoice
            .value_msat
            .as_ref()
            .and_then(value_as_u64)
            .unwrap_or(0)
            < htlc.amount_msat
        {
            return Err(NetworkError::invalid(
                "hold invoice is worth less than the HTLC",
            ));
        }
        Ok(())
    }

    async fn claim_incoming_htlc(
        &self,
        htlc: &Htlc,
        preimage: Bytes32,
    ) -> Result<(), NetworkError> {
        let request = PreimageRequest {
            preimage: BASE64.encode(preimage.0),
        };
        self.post_empty("v2/invoices/settle", &request).await?;
        info!(parent: &self.span, "settled {}", htlc.payment_hash.short());
        Ok(())
    }

    async fn create_outgoing_htlc(
        &self,
        payment_hash: Bytes32,
        amount_msat: u64,
        expiry: u64,
        target: &InvoiceTarget,
    ) -> Result<HtlcDescriptor, NetworkError> {
        let InvoiceTarget::Lightning {
            invoice: payment_request,
            ..
        } = target
        else {
            return Err(NetworkError::invalid("lightning HTLCs pay an invoice"));
        };
        let invoice = parse_invoice(payment_request, payment_hash)?;
        // Receivers in whole sats (bark) round the amount up.
        let invoice_msat = invoice.amount_milli_satoshis().unwrap_or(0);
        if invoice_msat < amount_msat || invoice_msat > amount_msat.next_multiple_of(MSAT_PER_SAT) {
            return Err(NetworkError::invalid(format!(
                "invoice amount {invoice_msat} msat is not the HTLC amount {amount_msat} msat"
            )));
        }
        let cltv_limit = expiry.saturating_sub(unix_now()) / secs_per_block(&self.id);
        let request = SendPaymentRequest {
            payment_request,
            fee_limit_msat: (amount_msat / 100).max(1_000).to_string(),
            timeout_seconds: SEND_TIMEOUT_SECS,
            cltv_limit: i32::try_from(cltv_limit).map_err(NetworkError::invalid)?,
            // The first update tells that LND took the payment.
            no_inflight_updates: false,
            cancelable: false,
        };
        // The payment lives on in LND independently of this request:
        // drive the stream in the background and watch it by hash, once
        // LND has taken the payment or refused it.
        let call = self
            .client
            .post(self.endpoint("v2/router/send"))
            .json(&request)
            .send();
        let (started, starting) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let mut response = match call.await {
                Ok(response) => response,
                Err(error) => {
                    let _ = started.send(Err(error.to_string()));
                    return;
                }
            };
            let status = response.status();
            if !status.is_success() {
                let body = response.text().await.unwrap_or_default();
                let _ = started.send(Err(format!("HTTP {status}: {body}")));
                return;
            }
            let refusal = match response.chunk().await {
                Ok(Some(chunk)) => serde_json::from_slice::<Value>(&chunk)
                    .ok()
                    .and_then(|update| update.get("error").map(Value::to_string)),
                Ok(None) => Some("LND closed the payment stream".to_string()),
                Err(error) => Some(error.to_string()),
            };
            let refused = refusal.is_some();
            let _ = started.send(refusal.map_or(Ok(()), Err));
            if !refused {
                while let Ok(Some(_)) = response.chunk().await {}
            }
        });
        match tokio::time::timeout(SEND_START_WAIT, starting).await {
            Ok(Ok(Ok(()))) | Err(_) => {}
            Ok(Ok(Err(refusal))) => return Err(api_error(refusal)),
            Ok(Err(_)) => return Err(api_error("the send was interrupted")),
        }
        info!(parent: &self.span, "paying {amount_msat} msat for {}", payment_hash.short());
        Ok(HtlcDescriptor::Lightning {
            target: payment_request.clone(),
        })
    }

    async fn check_outgoing_htlc(&self, htlc: &Htlc) -> Result<OutgoingState, NetworkError> {
        let Tracked::Found(payment) = self.payment(htlc.payment_hash).await? else {
            return Ok(OutgoingState::Pending);
        };
        match status_name(&payment.status).as_str() {
            "SUCCEEDED" => {
                let preimage = payment
                    .payment_preimage
                    .ok_or_else(|| NetworkError::network("succeeded payment has no preimage"))?;
                Ok(OutgoingState::Claimed(Bytes32(decode_hex_or_base64_32(
                    &preimage,
                )?)))
            }
            "FAILED" => Ok(OutgoingState::Refunded),
            _ => Ok(OutgoingState::Pending),
        }
    }

    /// The send is tracked by the invoice's payment hash alone.
    fn outgoing_descriptor(
        &self,
        _payment_hash: Bytes32,
        _amount_msat: u64,
        _expiry: u64,
        target: &InvoiceTarget,
    ) -> Option<HtlcDescriptor> {
        match target {
            InvoiceTarget::Lightning { invoice, .. } => Some(HtlcDescriptor::Lightning {
                target: invoice.clone(),
            }),
            _ => None,
        }
    }

    /// Lightning has no refund: a failed payment returns the funds by
    /// itself, an in-flight one can only wait. A payment LND does not
    /// know by now was never sent.
    async fn refund_outgoing_htlc(&self, htlc: &Htlc) -> Result<(), NetworkError> {
        if matches!(self.payment(htlc.payment_hash).await?, Tracked::Unknown) {
            return Ok(());
        }
        match self.check_outgoing_htlc(htlc).await? {
            OutgoingState::Refunded => Ok(()),
            _ => Err(NetworkError::network("payment is still in flight")),
        }
    }

    async fn can_send(&self, amount_msat: u64) -> Result<(), NetworkError> {
        let available = self.channel_balance_msat().await?;
        if available < amount_msat {
            return Err(NetworkError::invalid(format!(
                "need {amount_msat} msat of outbound liquidity, channels hold {available} msat"
            )));
        }
        Ok(())
    }

    /// Settling a hold invoice costs nothing.
    async fn can_receive(&self, _amount_msat: u64) -> Result<(), NetworkError> {
        Ok(())
    }
}

/// Parse a BOLT11 request and pin it to the payment hash.
fn parse_invoice(
    payment_request: &str,
    payment_hash: Bytes32,
) -> Result<Bolt11Invoice, NetworkError> {
    let invoice = Bolt11Invoice::from_str(payment_request).map_err(NetworkError::invalid)?;
    if invoice.payment_hash().as_ref() != payment_hash.0 {
        return Err(NetworkError::invalid("invoice is for another payment hash"));
    }
    Ok(invoice)
}

async fn decode_response<T: DeserializeOwned>(
    response: reqwest::Response,
) -> Result<T, NetworkError> {
    let status = response.status();
    let body = response.text().await.map_err(api_error)?;
    if !status.is_success() {
        return Err(api_error(format!("HTTP {status}: {body}")));
    }
    serde_json::from_str(&body).map_err(|e| api_error(format!("{e}; body={body}")))
}

async fn ensure_success(response: reqwest::Response) -> Result<(), NetworkError> {
    let status = response.status();
    let body = response.text().await.map_err(api_error)?;
    if status.is_success() {
        Ok(())
    } else {
        Err(api_error(format!("HTTP {status}: {body}")))
    }
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

fn decode_hex_or_base64_32(value: &str) -> Result<[u8; 32], NetworkError> {
    if let Ok(bytes) = decode_hex_exact::<32>(value) {
        return Ok(bytes);
    }
    let decoded = BASE64.decode(value).map_err(api_error)?;
    decoded
        .try_into()
        .map_err(|_| api_error("preimage is not 32 bytes"))
}
