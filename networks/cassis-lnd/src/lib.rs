//! LND-backed Lightning adapter.
//!
//! The adapter talks to LND's authenticated REST API. Incoming payments use
//! LND hold invoices: the route hash is registered before funding and the
//! invoice is settled only after the downstream adapter reveals the preimage.
//! Outgoing payments always use the downstream BOLT11 request carried by the
//! Cassis HTLC descriptor; raw hash-only sends are deliberately rejected
//! because modern LND invoices require their payment secret.
//!
//! Both sides key their state by [`OperationId`]: an operation is one
//! authenticated attempt, a payment hash is the intent it serves. The
//! payment hash therefore lives inside every entry, so a caller holding the
//! wrong handle can never fund, accept or claim another operation's
//! contract. A retry of the same operation is answered from the state
//! already on record; a second operation claiming a live payment hash is
//! refused.

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use cassis_core::{
    AcceptedIncoming, AdapterError, Bytes32, HtlcDescriptor, HtlcTarget, IncomingRequest,
    IncomingReservation, NetworkAdapter, NetworkId, OperationId, OutgoingPayment, OutgoingRequest,
    XOnlyPubKey,
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
use tracing::{debug, info, Span};

const DEFAULT_INCOMING_DELTA_SECS: u64 = 30;
const SEND_TIMEOUT_SECS: i32 = 60;
const MSAT_PER_SAT: u64 = 1000;

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
}

impl From<Error> for AdapterError {
    fn from(error: Error) -> Self {
        match error {
            Error::InvalidParams(message) => AdapterError::InvalidParams(message),
            other => AdapterError::Network(other.to_string()),
        }
    }
}

/// Receiver-side state for a reserved LND hold invoice, keyed by the
/// operation that reserved it in [`LndAdapter::incoming`].
#[derive(Clone, Debug)]
struct PendingIncoming {
    /// Route payment hash this reservation is for. Kept next to the
    /// operation id so a caller holding the wrong reservation can never
    /// accept or claim another operation's invoice.
    payment_hash: Bytes32,
    amount_msat: u64,
    /// Unix deadline after which the receiver stops waiting for the
    /// sender to fund the invoice.
    deadline: u64,
    /// The exact hold invoice LND registered for `payment_hash`. This is
    /// also the hop's `HtlcTarget`: the upstream party must pay this
    /// payment request, not one of its own, so the payment secret that
    /// makes the invoice holdable is preserved.
    payment_request: String,
    /// Amount LND confirmed the invoice is holding, set once
    /// [`NetworkAdapter::accept_incoming`] has verified the funding.
    /// `None` while the invoice is still unfunded.
    accepted_amount_msat: Option<u64>,
}

/// Sender-side state for an outgoing LND payment, keyed by the operation
/// that funded it in [`LndAdapter::outgoing`].
#[derive(Clone)]
struct PendingOutgoing {
    /// Route payment hash this payment is for, so an operation-keyed
    /// lookup can reject a mismatched [`OutgoingPayment`].
    payment_hash: Bytes32,
    amount_msat: u64,
    expiry: u64,
    /// The BOLT11 request LND was asked to pay. It is both the
    /// destination and the wire descriptor, so recovery never needs a
    /// second map lookup.
    payment_request: String,
    state: Arc<Mutex<OutgoingState>>,
    changed: Arc<Notify>,
    cancel: Arc<Notify>,
}

#[derive(Clone, Debug)]
enum OutgoingState {
    Pending,
    Succeeded(Bytes32),
    Failed(String),
    Cancelled,
}

pub struct LndAdapter {
    config: LndConfig,
    network_id: NetworkId,
    invoice_pubkey: XOnlyPubKey,
    client: reqwest::Client,
    span: Span,
    /// Hold invoices we are expecting payment for, keyed by the operation
    /// that reserved them. The payment hash lives inside the entry so a
    /// second operation cannot quietly take over a published invoice.
    incoming: Arc<Mutex<HashMap<OperationId, PendingIncoming>>>,
    /// Outgoing payments we have asked LND to make, keyed by the
    /// operation that funded them.
    outgoing: Arc<Mutex<HashMap<OperationId, PendingOutgoing>>>,
    /// Serializes external LND payment starts for one adapter.
    outgoing_creation_lock: Arc<Mutex<()>>,
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

/// `GET /v1/balance/channels`; LND string-encodes sat amounts, but older
/// builds answer with a number, so both shapes are accepted.
#[derive(Deserialize)]
struct ChannelBalanceResponse {
    balance: Option<Value>,
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
            incoming: Arc::new(Mutex::new(HashMap::new())),
            outgoing: Arc::new(Mutex::new(HashMap::new())),
            outgoing_creation_lock: Arc::new(Mutex::new(())),
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
                target: "cassis_lnd",
                "LND adapter ready: rest_url={} identity={}",
                adapter.config.rest_url,
                invoice_pubkey.to_hex(),
            );
        });
        Ok(adapter)
    }

    /// Handle for a spawned send/track task.
    ///
    /// The task only drives the shared HTTP client, but it also updates
    /// the payment state the watcher reads, so it gets the very same
    /// operation maps rather than a detached copy: a copy would strand
    /// every watcher on a state nothing ever moves.
    fn clone_for_task(&self) -> Arc<Self> {
        Arc::new(Self {
            config: self.config.clone(),
            network_id: self.network_id.clone(),
            invoice_pubkey: self.invoice_pubkey,
            client: self.client.clone(),
            span: self.span.clone(),
            incoming: self.incoming.clone(),
            outgoing: self.outgoing.clone(),
            outgoing_creation_lock: self.outgoing_creation_lock.clone(),
        })
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

    /// The BOLT11 request LND is holding for `payment_hash`: the invoice
    /// an earlier process already registered, or a freshly created hold
    /// invoice. Adopting the open one is what makes a retry after a
    /// restart safe — the hop has already published that payment request
    /// to its upstream peer.
    async fn ensure_incoming(
        &self,
        payment_hash: Bytes32,
        amount_msat: u64,
        deadline: u64,
    ) -> Result<String, Error> {
        Ok(match self.lookup_invoice(payment_hash).await? {
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
                match invoice.payment_request {
                    Some(request) => request,
                    None => {
                        return Err(Error::Api("LND invoice has no payment request".into()));
                    }
                }
            }
            None => {
                self.add_hold_invoice(payment_hash, amount_msat, deadline)
                    .await?
            }
        })
    }

    /// Amount LND is holding for a funded, still-open invoice.
    ///
    /// `OPEN` means nobody paid the hold invoice yet, which is a normal
    /// race between funding and the COMMIT frame rather than a failure,
    /// so it is reported as retryable.
    async fn accepted_incoming_amount(
        &self,
        payment_hash: Bytes32,
        floor_msat: u64,
    ) -> Result<u64, AdapterError> {
        let invoice = self.lookup_invoice(payment_hash).await?.ok_or_else(|| {
            AdapterError::NotFound(format!("LND hold invoice for {payment_hash} not found"))
        })?;
        let state = invoice.state.as_deref().unwrap_or("").to_ascii_uppercase();
        if invoice.settled == Some(true) || state == "CANCELED" {
            return Err(AdapterError::InvalidParams(
                "LND invoice is not open".into(),
            ));
        }
        if state != "ACCEPTED" {
            return Err(AdapterError::Retryable(
                "LND hold invoice is not funded/accepted yet".into(),
            ));
        }
        // LND does not always echo the amount; the reserved floor is the
        // amount we know is locked either way.
        let amount_msat = invoice
            .value_msat
            .as_ref()
            .and_then(value_as_u64)
            .unwrap_or(floor_msat);
        if amount_msat < floor_msat {
            return Err(AdapterError::InvalidParams(format!(
                "LND invoice amount {amount_msat} msat below reserved {floor_msat} msat"
            )));
        }
        Ok(amount_msat)
    }

    /// The handle for a parked incoming entry. Both the fresh and the
    /// retry path of [`NetworkAdapter::reserve_incoming`] build it here,
    /// so one operation can never be answered with two reservations.
    fn incoming_reservation(
        &self,
        operation_id: &OperationId,
        slot: &PendingIncoming,
    ) -> IncomingReservation {
        IncomingReservation {
            operation_id: operation_id.clone(),
            payment_hash: slot.payment_hash,
            network: self.network_id.clone(),
            amount_msat: slot.amount_msat,
            deadline: slot.deadline,
            target: HtlcTarget::LightningInvoice(slot.payment_request.clone()),
        }
    }

    /// Resolve the entry `reservation` names, rejecting a handle whose
    /// payment hash does not match the operation that owns it.
    async fn incoming_slot(
        &self,
        reservation: &IncomingReservation,
    ) -> Result<PendingIncoming, AdapterError> {
        let slot = self
            .incoming
            .lock()
            .await
            .get(&reservation.operation_id)
            .cloned()
            .ok_or_else(|| {
                AdapterError::NotFound(format!(
                    "no incoming LND reservation for operation {}",
                    reservation.operation_id
                ))
            })?;
        if slot.payment_hash != reservation.payment_hash {
            return Err(AdapterError::InvalidParams(
                "LND reservation operation id does not match this payment".into(),
            ));
        }
        Ok(slot)
    }

    /// Decide whether `request` may park an entry in
    /// [`LndAdapter::incoming`].
    ///
    /// `Ok(Some(reservation))` means this exact operation is already
    /// reserved and the caller must hand that handle back unchanged;
    /// `Ok(None)` means the caller may register it now. The incoming map
    /// is keyed by operation, so the payment-hash scan is what keeps two
    /// operations from competing for one published hold invoice.
    fn existing_reservation(
        &self,
        incoming: &HashMap<OperationId, PendingIncoming>,
        operation_id: &OperationId,
        payment_hash: Bytes32,
    ) -> Result<Option<IncomingReservation>, AdapterError> {
        if let Some(slot) = incoming.get(operation_id) {
            if slot.payment_hash != payment_hash {
                return Err(AdapterError::InvalidParams(
                    "LND operation id is already reserved for another payment hash".into(),
                ));
            }
            return Ok(Some(self.incoming_reservation(operation_id, slot)));
        }
        if incoming
            .values()
            .any(|slot| slot.payment_hash == payment_hash)
        {
            return Err(AdapterError::Retryable(
                "LND payment hash already has an active hold invoice".into(),
            ));
        }
        Ok(None)
    }

    /// The [`AcceptedIncoming`] already committed for `reservation`, or
    /// `None` while the invoice is still unfunded. Makes a repeated
    /// [`NetworkAdapter::accept_incoming`] idempotent: the amount
    /// verified the first time stays authoritative and the descriptor is
    /// rebuilt from the hold invoice on record, so a caller's journal
    /// never records a payload other than the one that was checked.
    async fn accepted_incoming(
        &self,
        reservation: &IncomingReservation,
    ) -> Result<Option<AcceptedIncoming>, AdapterError> {
        let slot = self.incoming_slot(reservation).await?;
        let Some(amount_msat) = slot.accepted_amount_msat else {
            return Ok(None);
        };
        Ok(Some(AcceptedIncoming {
            reservation: reservation.clone(),
            descriptor: HtlcDescriptor::Lightning {
                payment_request: slot.payment_request,
            },
            amount_msat,
        }))
    }

    /// The handle for an outgoing payment this adapter already funded.
    /// A retry of the same operation is answered from here so the sender
    /// never pays the same invoice twice.
    fn outgoing_payment(
        &self,
        operation_id: &OperationId,
        slot: &PendingOutgoing,
    ) -> OutgoingPayment {
        OutgoingPayment {
            operation_id: operation_id.clone(),
            payment_hash: slot.payment_hash,
            amount_msat: slot.amount_msat,
            destination: HtlcTarget::LightningInvoice(slot.payment_request.clone()),
            destination_network: self.network_id.clone(),
            expiry: slot.expiry,
            // The invoice LND was asked to pay rides along with the
            // handle, so `restore_outgoing` can rebuild the watcher from
            // the payment alone.
            descriptor: HtlcDescriptor::Lightning {
                payment_request: slot.payment_request.clone(),
            },
        }
    }

    /// Resolve the entry `payment` names, rejecting a handle whose
    /// payment hash does not match the operation that owns it.
    async fn outgoing_slot(
        &self,
        payment: &OutgoingPayment,
    ) -> Result<PendingOutgoing, AdapterError> {
        let slot = self
            .outgoing
            .lock()
            .await
            .get(&payment.operation_id)
            .cloned()
            .ok_or_else(|| {
                AdapterError::NotFound(format!(
                    "no outgoing LND payment for operation {}",
                    payment.operation_id
                ))
            })?;
        if slot.payment_hash != payment.payment_hash {
            return Err(AdapterError::InvalidParams(
                "outgoing operation id does not match this payment".into(),
            ));
        }
        Ok(slot)
    }

    /// Ask LND to pay `payment_request` and record the terminal state.
    /// Runs on a spawned task so the caller gets its handle back without
    /// waiting for a route.
    async fn start_payment(&self, pending: PendingOutgoing) {
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
            parse_payment_stream(&body, pending.payment_hash)
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

    /// Re-attach to a payment LND is already making, without sending it
    /// again: after a restart the payment record outlives the process, so
    /// the preimage is read back off LND's own stream.
    async fn track_payment(&self, pending: PendingOutgoing) {
        let result = async {
            let response = self
                .client
                .get(self.endpoint(&format!("v2/router/track/{}", pending.payment_hash)))
                .send()
                .await
                .map_err(|error| Error::Http(error.to_string()))?;
            let body = ensure_success_body(response).await?;
            parse_payment_stream(&body, pending.payment_hash)
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
impl NetworkAdapter for LndAdapter {
    fn network_id(&self) -> NetworkId {
        self.network_id.clone()
    }

    fn invoice_pubkey(&self) -> XOnlyPubKey {
        self.invoice_pubkey
    }

    /// LND holds the funds itself, so its node identity is both the
    /// invoice identity and the key the hold is settled from.
    fn claim_pubkey(&self) -> XOnlyPubKey {
        self.invoice_pubkey
    }

    /// Hold invoices are funded by the first hop within seconds, so 30 s
    /// is enough margin to claim before the outgoing expiry bites.
    fn incoming_delta_secs(&self) -> u64 {
        DEFAULT_INCOMING_DELTA_SECS
    }

    /// Register a hold invoice for `request.payment_hash` and publish it
    /// as the hop's `HtlcTarget`.
    ///
    /// LND's incoming target *is* the hold invoice, so this call is what
    /// makes the reservation usable: the upstream party pays the exact
    /// payment request LND registered, and the invoice stays held until
    /// [`NetworkAdapter::claim_incoming`] reveals the preimage.
    ///
    /// A retry of the same operation returns the reservation already on
    /// record (re-adopting the invoice LND still holds, if this is a
    /// replay after a restart). A *different* operation claiming a live
    /// payment hash is rejected: a payment hash identifies intent, and one
    /// intent must never be reservable — or claimable — twice.
    async fn reserve_incoming(
        &self,
        request: IncomingRequest,
    ) -> Result<IncomingReservation, AdapterError> {
        if request.deadline <= unix_now() {
            return Err(AdapterError::InvalidParams(
                "incoming deadline is in the past".into(),
            ));
        }
        {
            let incoming = self.incoming.lock().await;
            if let Some(reservation) =
                self.existing_reservation(&incoming, &request.operation_id, request.payment_hash)?
            {
                return Ok(reservation);
            }
        }
        // Registration is a round trip to LND, so it happens with the
        // map unlocked; the checks below run again afterwards to close
        // the window a concurrent reservation would have opened.
        let payment_request = self
            .ensure_incoming(request.payment_hash, request.amount_msat, request.deadline)
            .await?;
        let mut incoming = self.incoming.lock().await;
        if let Some(reservation) =
            self.existing_reservation(&incoming, &request.operation_id, request.payment_hash)?
        {
            return Ok(reservation);
        }
        incoming.insert(
            request.operation_id.clone(),
            PendingIncoming {
                payment_hash: request.payment_hash,
                amount_msat: request.amount_msat,
                deadline: request.deadline,
                payment_request,
                accepted_amount_msat: None,
            },
        );
        Ok(self.incoming_reservation(
            &request.operation_id,
            incoming
                .get(&request.operation_id)
                .expect("reservation just inserted"),
        ))
    }

    async fn restore_incoming_reservation(
        &self,
        reservation: &IncomingReservation,
    ) -> Result<(), AdapterError> {
        let HtlcTarget::LightningInvoice(payment_request) = &reservation.target else {
            return Err(AdapterError::InvalidParams(
                "LND reservation target must be a Lightning invoice".into(),
            ));
        };
        if reservation.network != self.network_id {
            return Err(AdapterError::InvalidParams(
                "LND reservation belongs to another network".into(),
            ));
        }
        let mut incoming = self.incoming.lock().await;
        if let Some(existing) = incoming.get(&reservation.operation_id) {
            return if existing.payment_hash == reservation.payment_hash
                && existing.amount_msat == reservation.amount_msat
                && existing.deadline == reservation.deadline
                && existing.payment_request == *payment_request
            {
                Ok(())
            } else {
                Err(AdapterError::InvalidParams(
                    "LND reservation operation is bound to different state".into(),
                ))
            };
        }
        if incoming
            .values()
            .any(|slot| slot.payment_hash == reservation.payment_hash)
        {
            return Err(AdapterError::Retryable(
                "LND payment hash already has an active reservation".into(),
            ));
        }
        incoming.insert(
            reservation.operation_id.clone(),
            PendingIncoming {
                payment_hash: reservation.payment_hash,
                amount_msat: reservation.amount_msat,
                deadline: reservation.deadline,
                payment_request: payment_request.clone(),
                accepted_amount_msat: None,
            },
        );
        Ok(())
    }

    /// Cancel the hold invoice backing an unfunded reservation. LND only
    /// drops an `OPEN` hold invoice; a funded one is released by
    /// [`NetworkAdapter::claim_incoming`] instead.
    ///
    /// An operation this adapter no longer holds — never reserved,
    /// already cancelled, or already claimed — is a no-op: none of those
    /// races can move money, and the hold invoice is gone either way.
    async fn cancel_incoming(&self, reservation: &IncomingReservation) -> Result<(), AdapterError> {
        // The entry stays parked until LND confirms the cancel, so a
        // retry that races this call still cancels instead of reporting
        // an invoice nobody holds.
        let payment_hash = {
            let incoming = self.incoming.lock().await;
            match incoming.get(&reservation.operation_id) {
                Some(slot) if slot.payment_hash == reservation.payment_hash => slot.payment_hash,
                Some(_) => {
                    return Err(AdapterError::InvalidParams(
                        "LND reservation operation id does not match this payment".into(),
                    ))
                }
                None => return Ok(()),
            }
        };
        let request = HashRequest {
            payment_hash: BASE64.encode(payment_hash.0),
        };
        self.post_empty("v2/invoices/cancel", &request).await?;
        self.incoming.lock().await.remove(&reservation.operation_id);
        Ok(())
    }

    /// Verify that the incoming HTLC the upstream hop committed is the
    /// hold invoice this operation reserved, and that LND is holding it
    /// for at least the reserved amount.
    ///
    /// The descriptor is compared verbatim against the reserved payment
    /// request: LND can only hold *its own* invoice against the route
    /// hash, so a re-encoded or self-made BOLT11 would settle a payment
    /// that was never locked. Hash and amount are re-checked as well, so
    /// a descriptor that merely looks like a Lightning invoice is still
    /// refused.
    async fn accept_incoming(
        &self,
        reservation: &IncomingReservation,
        descriptor: &HtlcDescriptor,
    ) -> Result<AcceptedIncoming, AdapterError> {
        // Re-accept of an operation we already committed: hand back the
        // payload we verified the first time. LND now reports the invoice
        // `SETTLED`, which would turn a harmless retry into a failure.
        if let Some(accepted) = self.accepted_incoming(reservation).await? {
            return Ok(accepted);
        }
        let slot = self.incoming_slot(reservation).await?;
        let payment_request = lightning_request(descriptor)?;
        parse_invoice(payment_request, reservation.payment_hash)?;
        if payment_request != slot.payment_request {
            return Err(AdapterError::InvalidParams(
                "Lightning descriptor is not the reserved LND hold invoice".into(),
            ));
        }
        let amount_msat = self
            .accepted_incoming_amount(reservation.payment_hash, slot.amount_msat)
            .await?;
        {
            let mut incoming = self.incoming.lock().await;
            let stored = incoming.get_mut(&reservation.operation_id).ok_or_else(|| {
                AdapterError::NotFound(format!(
                    "no incoming LND reservation for operation {}",
                    reservation.operation_id
                ))
            })?;
            if stored.payment_hash != reservation.payment_hash {
                return Err(AdapterError::InvalidParams(
                    "LND reservation operation id does not match this payment".into(),
                ));
            }
            stored.accepted_amount_msat = Some(amount_msat);
        }
        Ok(AcceptedIncoming {
            reservation: reservation.clone(),
            descriptor: descriptor.clone(),
            amount_msat,
        })
    }

    /// Rebuild the receiver-side state from a journal replay.
    ///
    /// Only local checks run here: LND was already consulted when the
    /// invoice was accepted, and a restart must not turn into a network
    /// round trip that can fail while funds sit locked and claimable. The
    /// descriptor is re-parsed against the route hash and must still
    /// cover the reservation.
    async fn restore_incoming(&self, accepted: &AcceptedIncoming) -> Result<(), AdapterError> {
        let reservation = &accepted.reservation;
        let payment_request = lightning_request(&accepted.descriptor)?;
        parse_invoice(payment_request, reservation.payment_hash)?;
        if accepted.amount_msat < reservation.amount_msat {
            return Err(AdapterError::InvalidParams(format!(
                "accepted LND amount {} msat below reserved {} msat",
                accepted.amount_msat, reservation.amount_msat
            )));
        }
        let mut incoming = self.incoming.lock().await;
        if let Some(slot) = incoming.get(&reservation.operation_id) {
            // Live state wins over the journal copy, but the operation
            // must not be pointed at a different payment.
            return if slot.payment_hash == reservation.payment_hash {
                Ok(())
            } else {
                Err(AdapterError::InvalidParams(
                    "incoming operation id is already reserved for another payment hash".into(),
                ))
            };
        }
        incoming.insert(
            reservation.operation_id.clone(),
            PendingIncoming {
                payment_hash: reservation.payment_hash,
                amount_msat: reservation.amount_msat,
                deadline: reservation.deadline,
                payment_request: payment_request.to_string(),
                accepted_amount_msat: Some(accepted.amount_msat),
            },
        );
        Ok(())
    }

    /// Wait until the sender has funded the hold invoice. LND flips the
    /// invoice to `ACCEPTED` once the HTLC is on its way, and a hop that
    /// cancels before funding shows up as `CANCELED`.
    async fn watch_incoming(
        &self,
        reservation: &IncomingReservation,
        deadline: u64,
    ) -> Result<(), AdapterError> {
        let slot = self.incoming_slot(reservation).await?;
        if slot.accepted_amount_msat.is_some() {
            return Ok(());
        }
        let payment_hash = slot.payment_hash;
        let limit = deadline.min(slot.deadline);
        loop {
            if unix_now() >= limit {
                return Err(AdapterError::DeadlineExceeded);
            }
            if let Some(invoice) = self.lookup_invoice(payment_hash).await? {
                let state = invoice.state.as_deref().unwrap_or("").to_ascii_uppercase();
                if invoice.settled == Some(true) || state == "ACCEPTED" || state == "SETTLED" {
                    return Ok(());
                }
                if state == "CANCELED" {
                    return Err(AdapterError::Network(
                        "LND invoice was canceled before funding".to_string(),
                    ));
                }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    /// Settle the hold invoice with `preimage`, releasing the funds LND
    /// has been holding. This is the point of no return for the payee:
    /// the preimage is published to every upstream hop, so it must hash
    /// to the invoice we actually hold and the operation must be the one
    /// that reserved it.
    async fn claim_incoming(
        &self,
        accepted: &AcceptedIncoming,
        preimage: Bytes32,
    ) -> Result<(), AdapterError> {
        let reservation = &accepted.reservation;
        let payment_hash = reservation.payment_hash;
        if !payment_hash.matches_preimage(&preimage) {
            return Err(AdapterError::InvalidParams(
                "preimage does not match the payment hash".into(),
            ));
        }
        // LND is the authority on which invoices it holds and what they
        // are worth, so a replayed handle that lost its local entry can
        // still settle; it must never settle another operation's hash.
        if let Some(slot) = self
            .incoming
            .lock()
            .await
            .get(&reservation.operation_id)
            .cloned()
        {
            if slot.payment_hash != payment_hash {
                return Err(AdapterError::InvalidParams(
                    "LND reservation operation id does not match this payment".into(),
                ));
            }
        }
        let request = PreimageRequest {
            preimage: BASE64.encode(preimage.0),
        };
        self.span.in_scope(|| {
            info!(
                target: "cassis_lnd",
                "revealing preimage to LND for {}",
                payment_hash.short(),
            );
        });
        self.post_empty("v2/invoices/settle", &request).await?;
        self.incoming.lock().await.remove(&reservation.operation_id);
        Ok(())
    }

    /// Claim straight from reservation state, for the native receive path
    /// where the caller only kept the reservation handle. A funded LND
    /// hold invoice is claimed by its payment request and the preimage,
    /// so this rebuilds the accepted handle and takes the normal route.
    async fn claim_reserved_incoming(
        &self,
        reservation: &IncomingReservation,
        preimage: Bytes32,
    ) -> Result<(), AdapterError> {
        let accepted = self.accepted_incoming(reservation).await?.ok_or_else(|| {
            AdapterError::Retryable(format!(
                "LND reservation {} is not funded yet",
                reservation.operation_id
            ))
        })?;
        self.claim_incoming(&accepted, preimage).await
    }

    /// Ask LND to pay the hop's BOLT11 invoice.
    ///
    /// A modern LND invoice carries its own payment secret, so a payment
    /// can only be made by handing LND the exact request the receiver
    /// published; hash-only sends are refused rather than silently
    /// producing an unpayable HTLC.
    async fn create_outgoing(
        &self,
        request: OutgoingRequest,
    ) -> Result<OutgoingPayment, AdapterError> {
        let _creation_guard = self.outgoing_creation_lock.lock().await;
        if request.amount_msat == 0 {
            return Err(AdapterError::InvalidParams("amount must be > 0".into()));
        }
        if request.expiry <= unix_now() {
            return Err(AdapterError::InvalidParams(
                "outgoing expiry is in the past".into(),
            ));
        }
        let payment_request = match &request.target {
            HtlcTarget::LightningInvoice(invoice) => invoice.clone(),
            HtlcTarget::XOnlyPubKey(_) | HtlcTarget::PubKey(_) | HtlcTarget::SparkAddress(_) => {
                return Err(AdapterError::InvalidParams(
                    "lightning requires a BOLT11 invoice target".into(),
                ))
            }
        };
        validate_outgoing_invoice(&payment_request, request.payment_hash, request.amount_msat)?;
        {
            let outgoing = self.outgoing.lock().await;
            // Retry of an attempt we already paid: hand back the very
            // same payment rather than paying the invoice a second time.
            if let Some(slot) = outgoing.get(&request.operation_id) {
                if slot.payment_hash != request.payment_hash
                    || slot.amount_msat != request.amount_msat
                    || slot.payment_request != payment_request
                {
                    return Err(AdapterError::InvalidParams(
                        "outgoing retry does not match the operation already in flight".into(),
                    ));
                }
                return Ok(self.outgoing_payment(&request.operation_id, slot));
            }
            if outgoing
                .values()
                .any(|slot| slot.payment_hash == request.payment_hash)
            {
                return Err(AdapterError::Retryable(
                    "LND payment hash already has a live outgoing payment".into(),
                ));
            }
        }
        let pending = PendingOutgoing {
            payment_hash: request.payment_hash,
            amount_msat: request.amount_msat,
            expiry: request.expiry,
            payment_request,
            state: Arc::new(Mutex::new(OutgoingState::Pending)),
            changed: Arc::new(Notify::new()),
            cancel: Arc::new(Notify::new()),
        };
        let payment = {
            let mut outgoing = self.outgoing.lock().await;
            outgoing.insert(request.operation_id.clone(), pending.clone());
            self.outgoing_payment(
                &request.operation_id,
                outgoing
                    .get(&request.operation_id)
                    .expect("outgoing payment just recorded"),
            )
        };
        let adapter = self.clone_for_task();
        tokio::spawn(async move { adapter.start_payment(pending).await });
        Ok(payment)
    }

    /// Wait for the receiver to reveal the preimage. The send task
    /// records the terminal state and wakes every watcher.
    async fn watch_outgoing(
        &self,
        payment: &OutgoingPayment,
        deadline: u64,
    ) -> Result<Bytes32, AdapterError> {
        let pending = self.outgoing_slot(payment).await?;
        loop {
            let state = pending.state.lock().await;
            match &*state {
                OutgoingState::Pending => {}
                OutgoingState::Succeeded(preimage) => return Ok(*preimage),
                OutgoingState::Failed(reason) => return Err(AdapterError::Network(reason.clone())),
                OutgoingState::Cancelled => {
                    return Err(AdapterError::Network("outgoing payment cancelled".into()))
                }
            }
            // Registered while the state lock is still held, so a send
            // task that settles right now cannot slip through unmissed.
            let settled = pending.changed.notified();
            drop(state);
            if unix_now() >= deadline {
                return Err(AdapterError::DeadlineExceeded);
            }
            // Wake on the terminal state, and poll regardless so a
            // watcher is never stranded by a missed notification.
            let _ = tokio::time::timeout(Duration::from_millis(250), settled).await;
        }
    }

    /// Give up on an outgoing payment. Lightning has no refund path for a
    /// payment the receiver already holds: the send is abandoned, LND's
    /// in-flight HTLC is dropped, and the watcher is released. A payment
    /// the receiver claims afterwards can only be resolved with the
    /// preimage, which is what [`NetworkAdapter::watch_outgoing`] is for.
    async fn refund_outgoing(&self, payment: &OutgoingPayment) -> Result<(), AdapterError> {
        let pending = self.outgoing_slot(payment).await?;
        {
            let mut state = pending.state.lock().await;
            // A payment that already reached a terminal state keeps it:
            // overwriting a success here would throw away a preimage the
            // upstream hops are still waiting to learn.
            if !matches!(&*state, OutgoingState::Pending) {
                return Ok(());
            }
            *state = OutgoingState::Cancelled;
        }
        pending.cancel.notify_waiters();
        pending.changed.notify_waiters();
        Ok(())
    }

    /// Re-arm the watcher for a payment LND may still be making.
    ///
    /// Everything needed is in `payment.descriptor`: the BOLT11 request
    /// LND was asked to pay, which is re-checked against the route hash
    /// and the destination before it is trusted. The payment is tracked,
    /// never re-sent, so a restart cannot pay an invoice twice.
    async fn restore_outgoing(&self, payment: &OutgoingPayment) -> Result<(), AdapterError> {
        if payment.destination_network != self.network_id {
            return Err(AdapterError::InvalidParams(format!(
                "outgoing payment targets {}, not {}",
                payment.destination_network, self.network_id
            )));
        }
        let HtlcDescriptor::Lightning { payment_request } = &payment.descriptor else {
            return Err(AdapterError::InvalidParams(
                "LND outgoing payment requires a Lightning invoice descriptor".into(),
            ));
        };
        // The destination is what the sender was told to pay; it must be
        // the very request the descriptor carries, or the payment on
        // record is not the one that was committed.
        match &payment.destination {
            HtlcTarget::LightningInvoice(request) if request == payment_request => {}
            _ => {
                return Err(AdapterError::InvalidParams(
                    "outgoing destination is not the descriptor's BOLT11 invoice".into(),
                ))
            }
        }
        validate_outgoing_invoice(payment_request, payment.payment_hash, payment.amount_msat)?;
        // Already tracking this attempt: keep the live watcher rather
        // than swapping in the journal copy and arming a second one.
        if let Some(slot) = self
            .outgoing
            .lock()
            .await
            .get(&payment.operation_id)
            .cloned()
        {
            return if slot.payment_hash == payment.payment_hash {
                Ok(())
            } else {
                Err(AdapterError::InvalidParams(
                    "outgoing operation id is already funding another payment hash".into(),
                ))
            };
        }
        let pending = PendingOutgoing {
            payment_hash: payment.payment_hash,
            amount_msat: payment.amount_msat,
            expiry: payment.expiry,
            payment_request: payment_request.clone(),
            state: Arc::new(Mutex::new(OutgoingState::Pending)),
            changed: Arc::new(Notify::new()),
            cancel: Arc::new(Notify::new()),
        };
        self.outgoing
            .lock()
            .await
            .insert(payment.operation_id.clone(), pending.clone());
        let adapter = self.clone_for_task();
        tokio::spawn(async move { adapter.track_payment(pending).await });
        Ok(())
    }

    /// PREPARE-time check: can we fund `amount_msat` right now? An LND
    /// node pays from its own channel balance, so the local (outbound)
    /// side of the channels has to cover the amount.
    async fn can_route(&self, amount_msat: u64) -> Result<(), AdapterError> {
        if amount_msat == 0 {
            return Err(AdapterError::InvalidParams("amount must be > 0".into()));
        }
        let response: ChannelBalanceResponse = self.get_json("v1/balance/channels").await?;
        let available_msat = response
            .balance
            .as_ref()
            .and_then(value_as_u64)
            .unwrap_or(0)
            .saturating_mul(MSAT_PER_SAT);
        if available_msat < amount_msat {
            return Err(AdapterError::InvalidParams(format!(
                "insufficient lightning outbound liquidity on {}: need {amount_msat} msat, \
                 LND channels hold {available_msat} msat",
                self.network_id
            )));
        }
        Ok(())
    }

    /// Claiming releases funds LND is already holding, so the adapter
    /// needs no balance of its own to settle a hold invoice.
    async fn can_claim(&self, _amount_msat: u64) -> Result<(), AdapterError> {
        Ok(())
    }
}

/// The BOLT11 request carried by a Lightning descriptor. Every LND
/// descriptor check starts here, so a descriptor of another kind is a
/// hard error rather than a silently ignored payload.
fn lightning_request(descriptor: &HtlcDescriptor) -> Result<&str, AdapterError> {
    let HtlcDescriptor::Lightning { payment_request } = descriptor else {
        return Err(AdapterError::InvalidParams(
            "LND HTLC requires a Lightning invoice descriptor".into(),
        ));
    };
    Ok(payment_request)
}

/// Parse a BOLT11 request and pin it to the route payment hash.
fn parse_invoice(
    payment_request: &str,
    payment_hash: Bytes32,
) -> Result<Bolt11Invoice, AdapterError> {
    let invoice = Bolt11Invoice::from_str(payment_request)
        .map_err(|error| AdapterError::InvalidParams(format!("invalid BOLT11 invoice: {error}")))?;
    if invoice.payment_hash().as_ref() != payment_hash.0 {
        return Err(AdapterError::InvalidParams(
            "Lightning invoice hash does not match the route payment hash".into(),
        ));
    }
    Ok(invoice)
}

/// Checks an outgoing invoice before LND is asked to pay it: it must be
/// the invoice for this payment hash, and worth at least the amount
/// being routed.
fn validate_outgoing_invoice(
    payment_request: &str,
    payment_hash: Bytes32,
    amount_msat: u64,
) -> Result<(), AdapterError> {
    let invoice = parse_invoice(payment_request, payment_hash)?;
    if let Some(invoice_amount) = invoice.amount_milli_satoshis() {
        if invoice_amount < amount_msat {
            return Err(AdapterError::InvalidParams(format!(
                "Lightning invoice is only {invoice_amount} msat, need {amount_msat}"
            )));
        }
    }
    Ok(())
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
