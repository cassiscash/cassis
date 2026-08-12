//! Spark network adapter (raw `spark-wallet` SDK).
//!
//! One per-node Spark wallet connected to the Spark operators via the
//! `spark-wallet` crate, acting as:
//!
//! * **Receiver** — a HODL invoice (BOLT11) created against a
//!   caller-supplied payment hash (`create_hodl_lightning_invoice`).
//!   The payer must pay it over lightning, and the invoice is only
//!   settled when [`NetworkAdapter::claim_incoming`] reveals the
//!   preimage via `claim_htlc`.
//! * **Sender** — a Spark HTLC transfer: `create_htlc` locks the
//!   amount to the recipient's Spark address carrying the route's
//!   payment hash and expiry; the receiver claims it by revealing the
//!   preimage, otherwise the transfer is automatically returned.
//!
//! Both sides honor an external `payment_hash`, which is what makes
//! Spark a first-class cassis network. Spark cannot act as an invoice
//! issuer for arbitrary hashes over the Spark network itself (the
//! HODL invoice is a lightning invoice), so the two roles above are the
//! only directions a cassis route can use.
//!
//! Amounts: Spark and Lightning denominate sats, cassis denominates
//! msat. Invoice and transfer amounts are rounded *up* to whole sats
//! (`ceil`), so amounts at sub-sat precision round against the room.
//!
//! Wallet state lives in memory and re-syncs from the operators; no
//! on-disk database is used.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bitcoin::hashes::Hash as _;
use cassis_core::{
    AcceptedIncoming, AdapterError, Bytes32, HtlcDescriptor, HtlcTarget, IncomingRequest,
    IncomingReservation, NetworkAdapter, NetworkId, OperationId, OutgoingPayment, OutgoingRequest,
    XOnlyPubKey,
};
use lightning_invoice::Bolt11Invoice;
use spark_wallet::{
    DefaultSigner, InvoiceDescription, ListTransfersRequest, Network, Preimage, SparkAddress,
    SparkSigner, SparkSignerAdapter, SparkWallet, SparkWalletConfig, TransferId, TransferStatus,
    TransferType,
};
use tokio::sync::Mutex;
use tracing::{debug, info, Span};

/// Per-hop delta the routing layer gets on Spark legs. The receiver
/// side is a Lightning HODL invoice whose claim is one `claim_htlc`
/// call; the sender side is a single Spark transfer. Generous, same
/// order as the other fast networks.
const INCOMING_DELTA_SECS: u64 = 60;

/// Poll interval for Spark transfer and HODL invoice state.
const POLL_INTERVAL: Duration = Duration::from_millis(1000);

/// Receiver-side state for one operation.
///
/// Incoming Spark reservations are Lightning HODL invoices. Keeping the
/// operation id as map key and payment hash in value prevents one
/// operation from accepting another operation's invoice.
#[derive(Clone)]
struct PendingIncoming {
    payment_hash: Bytes32,
    /// Protocol amount requested by the routing layer, in msat.
    amount_msat: u64,
    /// Unix seconds after which reservation/funding is no longer valid.
    deadline: u64,
    /// Exact BOLT11 payment request returned by the SSP.
    payment_request: String,
    /// SSP receive-request id. This is lost across a process restart,
    /// so restored state falls back to querying claimable HTLCs.
    invoice_id: Option<String>,
    /// Preimage supplied for a locally-created invoice, if any.
    preimage: Option<Bytes32>,
    /// Descriptor accepted by the protocol, if funding was executed.
    accepted: Option<AcceptedIncoming>,
    /// Set after `claim_htlc` succeeds. Keeping the state makes a retry
    /// idempotent and preserves the operation's audit trail.
    claimed: bool,
    /// Serializes claims for this operation across concurrent callers.
    claim_lock: Arc<Mutex<()>>,
}

/// Sender-side state for one funded Spark HTLC transfer.
#[derive(Clone, Debug)]
struct PendingOutgoing {
    payment_hash: Bytes32,
    amount_msat: u64,
    expiry: u64,
    destination: HtlcTarget,
    destination_network: NetworkId,
    address: String,
    transfer_id: String,
    descriptor: HtlcDescriptor,
    /// Preimage learned from the recipient, if settlement completed.
    preimage: Option<Bytes32>,
}

#[derive(Clone, Debug, Default)]
pub struct SparkConfig {
    /// Reserved for future use. The raw wallet needs no API key — it
    /// talks directly to the Spark operators and the SSP endpoints
    /// baked into [`SparkWalletConfig::default_config`].
    pub api_key: Option<String>,
}

pub struct SparkAdapter {
    network_id: NetworkId,
    wallet: SparkWallet,
    /// Node identity advertised via [`NetworkAdapter::invoice_pubkey`].
    /// Spark has no separate x-only claim identity; this invoice key is
    /// also the valid fallback claim identity for the adapter API.
    invoice_pubkey: XOnlyPubKey,
    incoming: Mutex<HashMap<OperationId, PendingIncoming>>,
    outgoing: Mutex<HashMap<OperationId, PendingOutgoing>>,
    span: Span,
}

impl std::fmt::Debug for SparkAdapter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SparkAdapter")
            .field("network_id", &self.network_id)
            .finish()
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid parameters: {0}")]
    InvalidParams(String),
    #[error("spark wallet error: {0}")]
    Wallet(String),
}

impl From<Error> for AdapterError {
    fn from(error: Error) -> Self {
        match error {
            Error::InvalidParams(message) => AdapterError::InvalidParams(message),
            other => AdapterError::Network(other.to_string()),
        }
    }
}

impl From<spark_wallet::SparkWalletError> for Error {
    fn from(error: spark_wallet::SparkWalletError) -> Self {
        Error::Wallet(error.to_string())
    }
}

impl From<spark_wallet::DefaultSignerError> for Error {
    fn from(error: spark_wallet::DefaultSignerError) -> Self {
        Error::Wallet(error.to_string())
    }
}

impl From<spark_wallet::ServiceError> for Error {
    fn from(error: spark_wallet::ServiceError) -> Self {
        Error::Wallet(error.to_string())
    }
}

/// Route msat count rounded up to whole sats.
fn msat_to_sats(amount_msat: u64) -> u64 {
    amount_msat.div_ceil(1000)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn preimage_bytes(preimage: Preimage) -> Result<Bytes32, Error> {
    let bytes: [u8; 32] = preimage
        .to_vec()
        .try_into()
        .map_err(|_| Error::InvalidParams("preimage is not 32 bytes".into()))?;
    Ok(Bytes32(bytes))
}

impl SparkAdapter {
    /// Connect the Spark adapter. `secret` seeds the wallet's BIP32
    /// master key (internal fallback account number, same derivation
    /// the default signer applies). Mainnet only — the adapter's
    /// network id must be `spark`.
    pub async fn new(
        network_id: NetworkId,
        _config: SparkConfig,
        secret: [u8; 32],
        invoice_pubkey: XOnlyPubKey,
        span: Span,
    ) -> Result<Arc<Self>, Error> {
        if network_id.0 != "spark" {
            return Err(Error::InvalidParams(format!(
                "spark adapter requires network id 'spark', got '{network_id}'"
            )));
        }
        let signer: Arc<dyn SparkSigner> = Arc::new(SparkSignerAdapter::new(Arc::new(
            DefaultSigner::new(&secret, Network::Mainnet).map_err(Error::from)?,
        )));
        let config = SparkWalletConfig::default_config(Network::Mainnet);
        let wallet = SparkWallet::connect(config, signer)
            .await
            .map_err(Error::from)?;
        let span = cassis_core::network_span(&span, &network_id);
        span.in_scope(|| {
            debug!(target: "cassis_spark", "spark adapter connected: network=Mainnet");
        });
        Ok(Arc::new(Self {
            network_id,
            wallet,
            invoice_pubkey,
            incoming: Mutex::new(HashMap::new()),
            outgoing: Mutex::new(HashMap::new()),
            span,
        }))
    }

    /// Claimable funds in the Spark wallet, in sats. Syncs first so
    /// the leaf set reflects settled transfers.
    pub async fn balance_sats(&self) -> Result<u64, Error> {
        self.wallet.sync().await.map_err(Error::from)?;
        self.wallet.get_balance().await.map_err(Error::from)
    }

    /// The wallet's own Spark address (what other Spark parties can
    /// send a Spark HTLC transfer to), in its `spark:addr` string form.
    pub async fn spark_address(&self) -> Result<String, Error> {
        let address = self
            .wallet
            .get_spark_address()
            .map_err(Error::from)?
            .to_address_string()
            .map_err(|error| Error::Wallet(error.to_string()))?;
        Ok(address)
    }

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

    fn validate_incoming_request(&self, request: &IncomingRequest) -> Result<(), AdapterError> {
        if request.amount_msat == 0 {
            return Err(AdapterError::InvalidParams(
                "incoming amount must be greater than zero".into(),
            ));
        }
        if request.deadline <= unix_now() {
            return Err(AdapterError::InvalidParams(
                "incoming deadline is in the past".into(),
            ));
        }
        if request
            .preimage
            .is_some_and(|preimage| !request.payment_hash.matches_preimage(&preimage))
        {
            return Err(AdapterError::InvalidParams(
                "incoming preimage does not match payment hash".into(),
            ));
        }
        Ok(())
    }

    fn validate_incoming_reservation(
        &self,
        reservation: &IncomingReservation,
    ) -> Result<(), AdapterError> {
        if reservation.network != self.network_id {
            return Err(AdapterError::InvalidParams(
                "incoming reservation is for another network".into(),
            ));
        }
        if reservation.amount_msat == 0 {
            return Err(AdapterError::InvalidParams(
                "incoming reservation amount must be greater than zero".into(),
            ));
        }
        if !matches!(&reservation.target, HtlcTarget::LightningInvoice(_)) {
            return Err(AdapterError::InvalidParams(
                "Spark incoming reservations require a Lightning invoice target".into(),
            ));
        }
        Ok(())
    }

    fn validate_incoming_state(
        &self,
        slot: &PendingIncoming,
        reservation: &IncomingReservation,
    ) -> Result<(), AdapterError> {
        self.validate_incoming_reservation(reservation)?;
        if slot.payment_hash != reservation.payment_hash
            || slot.amount_msat != reservation.amount_msat
            || slot.deadline != reservation.deadline
            || reservation.target != HtlcTarget::LightningInvoice(slot.payment_request.clone())
        {
            return Err(AdapterError::InvalidParams(
                "incoming reservation does not match operation state".into(),
            ));
        }
        Ok(())
    }

    fn expected_invoice_amount_msat(&self, amount_msat: u64) -> Result<u64, AdapterError> {
        msat_to_sats(amount_msat)
            .checked_mul(1000)
            .ok_or_else(|| AdapterError::InvalidParams("incoming amount overflows sats".into()))
    }

    /// Parse and validate a Lightning descriptor against the invoice
    /// reserved for this operation. The invoice string itself is part
    /// of the reservation: accepting a different invoice with the same
    /// hash would let an upstream peer substitute its own HTLC.
    fn verify_hodl_descriptor(
        &self,
        reservation: &IncomingReservation,
        descriptor: &HtlcDescriptor,
        expected_payment_request: Option<&str>,
    ) -> Result<(String, u64), AdapterError> {
        let HtlcDescriptor::Lightning { payment_request } = descriptor else {
            return Err(AdapterError::InvalidParams(
                "Spark incoming side requires a Lightning hold invoice".into(),
            ));
        };
        let invoice = Bolt11Invoice::from_str(payment_request).map_err(|error| {
            AdapterError::InvalidParams(format!("invalid Spark/Lightning invoice: {error}"))
        })?;
        if invoice.payment_hash().as_ref() != reservation.payment_hash.0 {
            return Err(AdapterError::InvalidParams(
                "Spark/Lightning invoice hash does not match payment hash".into(),
            ));
        }
        let amount_msat = invoice
            .amount_milli_satoshis()
            .ok_or_else(|| AdapterError::InvalidParams("Spark invoice has no amount".into()))?;
        let expected_amount_msat = self.expected_invoice_amount_msat(reservation.amount_msat)?;
        if amount_msat != expected_amount_msat {
            return Err(AdapterError::InvalidParams(format!(
                "Spark invoice amount {amount_msat} msat does not equal reserved {expected_amount_msat} msat"
            )));
        }
        if let Some(expected_payment_request) = expected_payment_request {
            if payment_request != expected_payment_request {
                return Err(AdapterError::InvalidParams(
                    "Spark/Lightning invoice is not the invoice reserved for this operation".into(),
                ));
            }
        }
        Ok((payment_request.clone(), amount_msat))
    }

    /// Query the operator-side state for a funded HODL invoice. New
    /// reservations have an SSP receive id; restored reservations do
    /// not, so the claimable-HTLC query is the durable fallback.
    async fn incoming_is_funded(
        &self,
        payment_hash: Bytes32,
        expected_amount_sats: u64,
        payment_request: &str,
        invoice_id: Option<&str>,
    ) -> Result<bool, Error> {
        if let Some(invoice_id) = invoice_id {
            if let Some(payment) = self
                .wallet
                .fetch_lightning_receive_payment(invoice_id)
                .await
                .map_err(Error::from)?
            {
                if payment.invoice != payment_request {
                    return Err(Error::InvalidParams(
                        "Spark SSP receive record has a different invoice".into(),
                    ));
                }
                if payment
                    .transfer_amount_sat
                    .is_some_and(|amount| amount != expected_amount_sats)
                {
                    return Err(Error::InvalidParams(
                        "Spark SSP receive record has a different amount".into(),
                    ));
                }
                if payment.transfer_id.is_some() {
                    return Ok(true);
                }
            }
        }

        let transfers = self
            .wallet
            .list_claimable_htlc_transfers(None)
            .await
            .map_err(Error::from)?;
        for transfer in transfers {
            let Some(request) = transfer.htlc_preimage_request else {
                continue;
            };
            if request.payment_hash.as_byte_array() != &payment_hash.0 {
                continue;
            }
            if transfer.total_value_sat != expected_amount_sats {
                return Err(Error::InvalidParams(
                    "Spark funded HTLC has a different amount".into(),
                ));
            }
            return Ok(true);
        }
        Ok(false)
    }

    fn validate_outgoing_request(
        &self,
        request: &OutgoingRequest,
    ) -> Result<(String, SparkAddress), AdapterError> {
        if request.amount_msat == 0 {
            return Err(AdapterError::InvalidParams(
                "outgoing amount must be greater than zero".into(),
            ));
        }
        if request.expiry <= unix_now() {
            return Err(AdapterError::InvalidParams(
                "outgoing expiry is in the past".into(),
            ));
        }
        if request.network != self.network_id {
            return Err(AdapterError::InvalidParams(
                "outgoing request is for another network".into(),
            ));
        }
        let HtlcTarget::SparkAddress(address) = &request.target else {
            return Err(AdapterError::InvalidParams(
                "Spark outgoing side requires a Spark address target".into(),
            ));
        };
        let receiver_address = SparkAddress::from_str(address).map_err(|error| {
            AdapterError::InvalidParams(format!("invalid Spark address: {error}"))
        })?;
        if receiver_address.is_invoice() {
            return Err(AdapterError::InvalidParams(
                "Spark outgoing side requires a plain Spark address, not an invoice".into(),
            ));
        }
        Ok((address.clone(), receiver_address))
    }

    fn outgoing_request_matches(state: &PendingOutgoing, request: &OutgoingRequest) -> bool {
        state.payment_hash == request.payment_hash
            && state.amount_msat == request.amount_msat
            && state.expiry == request.expiry
            && state.destination == request.target
            && state.destination_network == request.network
    }

    fn outgoing_payment_from_state(
        &self,
        operation_id: &OperationId,
        state: &PendingOutgoing,
    ) -> OutgoingPayment {
        OutgoingPayment {
            operation_id: operation_id.clone(),
            payment_hash: state.payment_hash,
            amount_msat: state.amount_msat,
            destination: state.destination.clone(),
            destination_network: state.destination_network.clone(),
            expiry: state.expiry,
            descriptor: state.descriptor.clone(),
        }
    }

    /// Validate and normalize the descriptor embedded in an outgoing
    /// payment. Recovery uses this descriptor, never a separate map
    /// lookup or an optional descriptor argument.
    fn validate_outgoing_payment(
        &self,
        payment: &OutgoingPayment,
    ) -> Result<(String, String), AdapterError> {
        if payment.amount_msat == 0 {
            return Err(AdapterError::InvalidParams(
                "outgoing payment amount must be greater than zero".into(),
            ));
        }
        if payment.destination_network != self.network_id {
            return Err(AdapterError::InvalidParams(
                "outgoing payment is for another network".into(),
            ));
        }
        let HtlcTarget::SparkAddress(address) = &payment.destination else {
            return Err(AdapterError::InvalidParams(
                "Spark outgoing payment requires a Spark address target".into(),
            ));
        };
        let HtlcDescriptor::Spark {
            address: descriptor_address,
            expiry_secs,
            transfer_id,
        } = &payment.descriptor
        else {
            return Err(AdapterError::InvalidParams(
                "Spark outgoing payment requires a Spark descriptor".into(),
            ));
        };
        if address != descriptor_address {
            return Err(AdapterError::InvalidParams(
                "Spark descriptor address does not match payment destination".into(),
            ));
        }
        if *expiry_secs == 0 {
            return Err(AdapterError::InvalidParams(
                "Spark descriptor has no remaining expiry".into(),
            ));
        }
        let transfer_id = transfer_id
            .as_deref()
            .filter(|id| !id.is_empty())
            .ok_or_else(|| {
                AdapterError::InvalidParams(
                    "Spark restore requires the HTLC transfer id in the descriptor".into(),
                )
            })?;
        transfer_id.parse::<TransferId>().map_err(|error| {
            AdapterError::InvalidParams(format!("invalid Spark transfer id: {error}"))
        })?;
        SparkAddress::from_str(descriptor_address).map_err(|error| {
            AdapterError::InvalidParams(format!("invalid Spark address: {error}"))
        })?;
        Ok((descriptor_address.clone(), transfer_id.to_string()))
    }

    fn outgoing_payment_matches(
        &self,
        state: &PendingOutgoing,
        payment: &OutgoingPayment,
    ) -> Result<(), AdapterError> {
        let (address, transfer_id) = self.validate_outgoing_payment(payment)?;
        if state.payment_hash != payment.payment_hash
            || state.amount_msat != payment.amount_msat
            || state.expiry != payment.expiry
            || state.destination != payment.destination
            || state.destination_network != payment.destination_network
            || state.address != address
            || state.transfer_id != transfer_id
            || state.descriptor != payment.descriptor
        {
            return Err(AdapterError::InvalidParams(
                "outgoing payment does not match operation state".into(),
            ));
        }
        Ok(())
    }

    /// Poll the funded HTLC transfer (by id) for the receiver's
    /// preimage reveal, verified against the route payment hash.
    async fn find_revealed_preimage_by_transfer(
        &self,
        transfer_id: &str,
        payment_hash: Bytes32,
    ) -> Result<Option<Bytes32>, Error> {
        let id = transfer_id
            .parse::<TransferId>()
            .map_err(|error| Error::InvalidParams(format!("invalid transfer id: {error}")))?;
        let transfers = self
            .wallet
            .list_transfers(ListTransfersRequest {
                transfer_ids: vec![id],
                paging: None,
            })
            .await
            .map_err(Error::from)?;
        for transfer in transfers.items {
            if transfer.transfer_type != TransferType::PreimageSwap {
                continue;
            }
            match transfer.status {
                TransferStatus::Returned | TransferStatus::Expired => return Ok(None),
                _ => {}
            }
            let Some(request) = transfer.htlc_preimage_request else {
                continue;
            };
            if request.payment_hash.as_byte_array() != &payment_hash.0 {
                continue;
            }
            if let Some(preimage) = request.preimage {
                let bytes = preimage_bytes(preimage)?;
                if payment_hash.matches_preimage(&bytes) {
                    return Ok(Some(bytes));
                }
            }
        }
        Ok(None)
    }
}

#[async_trait]
impl NetworkAdapter for SparkAdapter {
    fn network_id(&self) -> NetworkId {
        self.network_id.clone()
    }

    fn invoice_pubkey(&self) -> XOnlyPubKey {
        self.invoice_pubkey
    }

    /// Spark has no separate x-only claim key. The invoice identity is
    /// the node identity used for route announcements and is a valid
    /// fallback claim identity for the single-trait API.
    fn claim_pubkey(&self) -> XOnlyPubKey {
        self.invoice_pubkey
    }

    fn incoming_delta_secs(&self) -> u64 {
        INCOMING_DELTA_SECS
    }

    /// Reserve a Lightning HODL invoice for an incoming operation.
    /// Incoming Spark HTLCs cannot replace this invoice: Spark's
    /// Lightning hold path is the receiver-side role.
    async fn reserve_incoming(
        &self,
        request: IncomingRequest,
    ) -> Result<IncomingReservation, AdapterError> {
        self.validate_incoming_request(&request)?;

        // Keep the map guard through invoice creation. This makes
        // concurrent retries of one operation observe one reservation,
        // while a different operation with the same hash is rejected
        // before another invoice can be created.
        let mut incoming = self.incoming.lock().await;
        if let Some(existing) = incoming.get(&request.operation_id) {
            if existing.payment_hash != request.payment_hash
                || existing.amount_msat != request.amount_msat
                || existing.deadline != request.deadline
                || existing.preimage != request.preimage
            {
                return Err(AdapterError::InvalidParams(
                    "incoming operation id was reused with a different request".into(),
                ));
            }
            return Ok(self.incoming_reservation(&request.operation_id, existing));
        }
        if incoming
            .values()
            .any(|slot| slot.payment_hash == request.payment_hash)
        {
            return Err(AdapterError::Retryable(
                "Spark payment hash already has an active reservation".into(),
            ));
        }

        let now = unix_now();
        let expiry_secs = deadline_expiry_secs(request.deadline, now)?;
        let amount_sats = msat_to_sats(request.amount_msat);
        let payment = self
            .wallet
            .create_hodl_lightning_invoice(
                amount_sats,
                Some(InvoiceDescription::Memo("cassis htlc".to_string())),
                // HODL: the payer's Lightning HTLC is held until the
                // preimage is provided via `claim_htlc`.
                bitcoin::hashes::sha256::Hash::from_byte_array(request.payment_hash.0),
                None,
                Some(expiry_secs),
            )
            .await
            .map_err(Error::from)?;
        let slot = PendingIncoming {
            payment_hash: request.payment_hash,
            amount_msat: request.amount_msat,
            deadline: request.deadline,
            payment_request: payment.invoice.clone(),
            invoice_id: Some(payment.id),
            preimage: request.preimage,
            accepted: None,
            claimed: false,
            claim_lock: Arc::new(Mutex::new(())),
        };
        let reservation = self.incoming_reservation(&request.operation_id, &slot);
        incoming.insert(request.operation_id, slot);
        debug!(
            target: "cassis_spark",
            payment_hash = ?request.payment_hash,
            "registered HODL invoice"
        );
        Ok(reservation)
    }

    async fn restore_incoming_reservation(
        &self,
        reservation: &IncomingReservation,
    ) -> Result<(), AdapterError> {
        self.validate_incoming_reservation(reservation)?;
        let HtlcTarget::LightningInvoice(payment_request) = &reservation.target else {
            return Err(AdapterError::InvalidParams(
                "Spark reservation target must be a Lightning invoice".into(),
            ));
        };
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
                    "Spark reservation operation is bound to different state".into(),
                ))
            };
        }
        if incoming
            .values()
            .any(|slot| slot.payment_hash == reservation.payment_hash)
        {
            return Err(AdapterError::Retryable(
                "Spark payment hash already has an active reservation".into(),
            ));
        }
        incoming.insert(
            reservation.operation_id.clone(),
            PendingIncoming {
                payment_hash: reservation.payment_hash,
                amount_msat: reservation.amount_msat,
                deadline: reservation.deadline,
                payment_request: payment_request.clone(),
                invoice_id: None,
                preimage: None,
                accepted: None,
                claimed: false,
                claim_lock: Arc::new(Mutex::new(())),
            },
        );
        Ok(())
    }

    /// Cancel an unfunded reservation. Spark exposes no native invoice
    /// cancellation, so dropping the local record lets the invoice age
    /// out naturally. Missing state is an idempotent success.
    async fn cancel_incoming(&self, reservation: &IncomingReservation) -> Result<(), AdapterError> {
        self.validate_incoming_reservation(reservation)?;
        let mut incoming = self.incoming.lock().await;
        let Some(slot) = incoming.get(&reservation.operation_id) else {
            return Ok(());
        };
        self.validate_incoming_state(slot, reservation)?;
        if slot.accepted.is_some() || slot.claimed {
            return Err(AdapterError::InvalidParams(
                "cannot cancel an accepted or claimed incoming operation".into(),
            ));
        }
        incoming.remove(&reservation.operation_id);
        Ok(())
    }

    /// Verify and bind the exact reserved HODL invoice to its operation.
    /// The descriptor is the protocol proof that the upstream party
    /// paid the reservation's invoice, so hash, exact request, and
    /// rounded amount must all match.
    async fn accept_incoming(
        &self,
        reservation: &IncomingReservation,
        descriptor: &HtlcDescriptor,
    ) -> Result<AcceptedIncoming, AdapterError> {
        self.validate_incoming_reservation(reservation)?;
        let (payment_request, existing) = {
            let incoming = self.incoming.lock().await;
            let slot = incoming.get(&reservation.operation_id).ok_or_else(|| {
                AdapterError::NotFound(format!(
                    "no incoming Spark reservation for operation {}",
                    reservation.operation_id
                ))
            })?;
            self.validate_incoming_state(slot, reservation)?;
            (slot.payment_request.clone(), slot.accepted.clone())
        };

        if let Some(existing) = existing {
            if existing.reservation == *reservation && existing.descriptor == *descriptor {
                return Ok(existing);
            }
            return Err(AdapterError::InvalidParams(
                "incoming operation was accepted with a different reservation or descriptor".into(),
            ));
        }
        if reservation.deadline <= unix_now() {
            return Err(AdapterError::DeadlineExceeded);
        }

        let (payment_request, amount_msat) =
            self.verify_hodl_descriptor(reservation, descriptor, Some(&payment_request))?;
        let accepted = AcceptedIncoming {
            reservation: reservation.clone(),
            descriptor: HtlcDescriptor::Lightning {
                payment_request: payment_request.clone(),
            },
            amount_msat,
        };

        let mut incoming = self.incoming.lock().await;
        let slot = incoming.get_mut(&reservation.operation_id).ok_or_else(|| {
            AdapterError::NotFound("incoming Spark reservation disappeared".into())
        })?;
        self.validate_incoming_state(slot, reservation)?;
        if let Some(existing) = &slot.accepted {
            if existing == &accepted {
                return Ok(existing.clone());
            }
            return Err(AdapterError::InvalidParams(
                "incoming operation was accepted with a different descriptor".into(),
            ));
        }
        slot.accepted = Some(accepted.clone());
        Ok(accepted)
    }

    /// Restore an accepted HODL invoice after process restart. The
    /// invoice remains operator-side, so replay only validates the
    /// durable descriptor and rebuilds local operation state.
    async fn restore_incoming(&self, accepted: &AcceptedIncoming) -> Result<(), AdapterError> {
        self.validate_incoming_reservation(&accepted.reservation)?;
        let expected_payment_request = match &accepted.reservation.target {
            HtlcTarget::LightningInvoice(payment_request) => payment_request.as_str(),
            _ => {
                return Err(AdapterError::InvalidParams(
                    "Spark incoming reservation requires a Lightning invoice target".into(),
                ))
            }
        };
        let (payment_request, amount_msat) = self.verify_hodl_descriptor(
            &accepted.reservation,
            &accepted.descriptor,
            Some(expected_payment_request),
        )?;
        if accepted.amount_msat != amount_msat {
            return Err(AdapterError::InvalidParams(
                "restored incoming amount does not match its invoice".into(),
            ));
        }

        let mut incoming = self.incoming.lock().await;
        if let Some(slot) = incoming.get_mut(&accepted.reservation.operation_id) {
            self.validate_incoming_state(slot, &accepted.reservation)?;
            if let Some(existing) = &slot.accepted {
                if existing == accepted {
                    return Ok(());
                }
                return Err(AdapterError::InvalidParams(
                    "incoming operation was restored with different accepted state".into(),
                ));
            }
            slot.accepted = Some(accepted.clone());
            return Ok(());
        }
        if incoming
            .values()
            .any(|slot| slot.payment_hash == accepted.reservation.payment_hash)
        {
            return Err(AdapterError::Retryable(
                "Spark payment hash already has an active incoming operation".into(),
            ));
        }
        incoming.insert(
            accepted.reservation.operation_id.clone(),
            PendingIncoming {
                payment_hash: accepted.reservation.payment_hash,
                amount_msat: accepted.reservation.amount_msat,
                deadline: accepted.reservation.deadline,
                payment_request,
                invoice_id: None,
                preimage: None,
                accepted: Some(accepted.clone()),
                claimed: false,
                claim_lock: Arc::new(Mutex::new(())),
            },
        );
        Ok(())
    }

    /// Wait until the HODL invoice has an operator-side HTLC. A
    /// Lightning invoice is not a Spark transfer, so this path polls
    /// receive state and never treats a Spark address as funding.
    async fn watch_incoming(
        &self,
        reservation: &IncomingReservation,
        deadline: u64,
    ) -> Result<(), AdapterError> {
        self.validate_incoming_reservation(reservation)?;
        let deadline = deadline.min(reservation.deadline);
        loop {
            let (
                payment_hash,
                amount_sats,
                payment_request,
                invoice_id,
                accepted,
                claimed,
                state_deadline,
            ) = {
                let incoming = self.incoming.lock().await;
                let slot = incoming.get(&reservation.operation_id).ok_or_else(|| {
                    AdapterError::NotFound(format!(
                        "no incoming Spark reservation for operation {}",
                        reservation.operation_id
                    ))
                })?;
                self.validate_incoming_state(slot, reservation)?;
                (
                    slot.payment_hash,
                    msat_to_sats(slot.amount_msat),
                    slot.payment_request.clone(),
                    slot.invoice_id.clone(),
                    slot.accepted.is_some(),
                    slot.claimed,
                    slot.deadline,
                )
            };
            let deadline = deadline.min(state_deadline);
            if accepted || claimed {
                return Ok(());
            }
            if unix_now() >= deadline {
                return Err(AdapterError::DeadlineExceeded);
            }
            match self
                .incoming_is_funded(
                    payment_hash,
                    amount_sats,
                    &payment_request,
                    invoice_id.as_deref(),
                )
                .await
            {
                Ok(true) => return Ok(()),
                Ok(false) => {}
                Err(error @ Error::InvalidParams(_)) => return Err(error.into()),
                Err(error) => {
                    self.span.in_scope(|| {
                        debug!(
                            target: "cassis_spark",
                            ?payment_hash,
                            "incoming HODL poll failed: {error}"
                        );
                    });
                }
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }

    /// Claim the accepted HODL invoice with the route preimage. The
    /// claim lock plus retained claimed bit make repeated claims
    /// idempotent under concurrent COMMIT delivery.
    async fn claim_incoming(
        &self,
        accepted: &AcceptedIncoming,
        preimage: Bytes32,
    ) -> Result<(), AdapterError> {
        self.validate_incoming_reservation(&accepted.reservation)?;
        let expected_payment_request = match &accepted.reservation.target {
            HtlcTarget::LightningInvoice(payment_request) => payment_request.as_str(),
            _ => {
                return Err(AdapterError::InvalidParams(
                    "Spark incoming reservation requires a Lightning invoice target".into(),
                ))
            }
        };
        let (_, amount_msat) = self.verify_hodl_descriptor(
            &accepted.reservation,
            &accepted.descriptor,
            Some(expected_payment_request),
        )?;
        if accepted.amount_msat != amount_msat {
            return Err(AdapterError::InvalidParams(
                "accepted incoming amount does not match its invoice".into(),
            ));
        }
        if !accepted
            .reservation
            .payment_hash
            .matches_preimage(&preimage)
        {
            return Err(AdapterError::InvalidParams(
                "preimage does not match the payment hash".into(),
            ));
        }

        let claim_lock = {
            let incoming = self.incoming.lock().await;
            let slot = incoming
                .get(&accepted.reservation.operation_id)
                .ok_or_else(|| {
                    AdapterError::NotFound(format!(
                        "no incoming Spark reservation for operation {}",
                        accepted.reservation.operation_id
                    ))
                })?;
            self.validate_incoming_state(slot, &accepted.reservation)?;
            if let Some(existing) = &slot.accepted {
                if existing != accepted {
                    return Err(AdapterError::InvalidParams(
                        "accepted incoming state does not match operation state".into(),
                    ));
                }
            }
            slot.claim_lock.clone()
        };
        let _claim_guard = claim_lock.lock().await;

        {
            let mut incoming = self.incoming.lock().await;
            let slot = incoming
                .get_mut(&accepted.reservation.operation_id)
                .ok_or_else(|| AdapterError::NotFound("incoming Spark state disappeared".into()))?;
            self.validate_incoming_state(slot, &accepted.reservation)?;
            if let Some(existing) = &slot.accepted {
                if existing != accepted {
                    return Err(AdapterError::InvalidParams(
                        "accepted incoming state does not match operation state".into(),
                    ));
                }
            }
            if slot.claimed {
                return Ok(());
            }
            slot.accepted = Some(accepted.clone());
        }

        self.wallet
            .claim_htlc(
                &Preimage::from_hex(&lowercase_hex::encode(preimage.0)).map_err(Error::from)?,
            )
            .await
            .map_err(Error::from)?;
        if let Some(slot) = self
            .incoming
            .lock()
            .await
            .get_mut(&accepted.reservation.operation_id)
        {
            slot.claimed = true;
        }
        info!(
            target: "cassis_spark",
            payment_hash = ?accepted.reservation.payment_hash,
            "claimed incoming HTLC"
        );
        Ok(())
    }

    /// Claim a locally watched reservation after its HODL invoice has
    /// funded. The COMMIT path uses [`Self::claim_incoming`] directly;
    /// this convenience path exists for the native receive flow.
    async fn claim_reserved_incoming(
        &self,
        reservation: &IncomingReservation,
        preimage: Bytes32,
    ) -> Result<(), AdapterError> {
        self.validate_incoming_reservation(reservation)?;
        let accepted = {
            let mut incoming = self.incoming.lock().await;
            let slot = incoming.get_mut(&reservation.operation_id).ok_or_else(|| {
                AdapterError::NotFound(format!(
                    "no incoming Spark reservation for operation {}",
                    reservation.operation_id
                ))
            })?;
            self.validate_incoming_state(slot, reservation)?;
            if let Some(existing) = &slot.accepted {
                existing.clone()
            } else {
                let amount_msat = self.expected_invoice_amount_msat(slot.amount_msat)?;
                let accepted = AcceptedIncoming {
                    reservation: reservation.clone(),
                    descriptor: HtlcDescriptor::Lightning {
                        payment_request: slot.payment_request.clone(),
                    },
                    amount_msat,
                };
                slot.accepted = Some(accepted.clone());
                accepted
            }
        };
        self.claim_incoming(&accepted, preimage).await
    }

    /// Fund a Spark HTLC transfer to the recipient's Spark address.
    /// This is the sender-side role; it never creates a HODL invoice.
    async fn create_outgoing(
        &self,
        request: OutgoingRequest,
    ) -> Result<OutgoingPayment, AdapterError> {
        let (address, receiver_address) = self.validate_outgoing_request(&request)?;
        let mut outgoing = self.outgoing.lock().await;
        if let Some(existing) = outgoing.get(&request.operation_id) {
            if !Self::outgoing_request_matches(existing, &request) {
                return Err(AdapterError::InvalidParams(
                    "outgoing operation id was reused with a different request".into(),
                ));
            }
            return Ok(self.outgoing_payment_from_state(&request.operation_id, existing));
        }
        if outgoing
            .values()
            .any(|slot| slot.payment_hash == request.payment_hash)
        {
            return Err(AdapterError::Retryable(
                "Spark payment hash already has a live outgoing transfer".into(),
            ));
        }

        let now = unix_now();
        let expiry_secs = request.expiry.saturating_sub(now);
        if expiry_secs == 0 {
            return Err(AdapterError::InvalidParams(
                "outgoing expiry is in the past".into(),
            ));
        }
        let amount_sats = msat_to_sats(request.amount_msat);
        let transfer = self
            .wallet
            .create_htlc(
                amount_sats,
                &receiver_address,
                &bitcoin::hashes::sha256::Hash::from_byte_array(request.payment_hash.0),
                Duration::from_secs(expiry_secs),
                None,
            )
            .await
            .map_err(Error::from)?;
        let transfer_id = transfer.id.to_string();
        let log_transfer_id = transfer_id.clone();
        let descriptor = HtlcDescriptor::Spark {
            address: address.clone(),
            expiry_secs,
            transfer_id: Some(transfer_id.clone()),
        };
        let payment = OutgoingPayment {
            operation_id: request.operation_id.clone(),
            payment_hash: request.payment_hash,
            amount_msat: request.amount_msat,
            destination: request.target.clone(),
            destination_network: request.network.clone(),
            expiry: request.expiry,
            descriptor: descriptor.clone(),
        };
        outgoing.insert(
            request.operation_id.clone(),
            PendingOutgoing {
                payment_hash: request.payment_hash,
                amount_msat: request.amount_msat,
                expiry: request.expiry,
                destination: request.target,
                destination_network: request.network,
                address,
                transfer_id,
                descriptor,
                preimage: None,
            },
        );
        drop(outgoing);
        debug!(
            target: "cassis_spark",
            payment_hash = ?request.payment_hash,
            amount_sats,
            transfer_id = %log_transfer_id,
            "funded spark HTLC"
        );
        Ok(payment)
    }

    /// Wait for the recipient to reveal the preimage on the funded
    /// Spark transfer. The transfer id comes from the operation state
    /// and is also embedded in `payment.descriptor` for recovery.
    async fn watch_outgoing(
        &self,
        payment: &OutgoingPayment,
        deadline: u64,
    ) -> Result<Bytes32, AdapterError> {
        self.validate_outgoing_payment(payment)?;
        let (payment_hash, transfer_id, cached) = {
            let outgoing = self.outgoing.lock().await;
            let slot = outgoing.get(&payment.operation_id).ok_or_else(|| {
                AdapterError::NotFound(format!(
                    "no outgoing Spark payment for operation {}",
                    payment.operation_id
                ))
            })?;
            self.outgoing_payment_matches(slot, payment)?;
            (slot.payment_hash, slot.transfer_id.clone(), slot.preimage)
        };
        if let Some(preimage) = cached {
            return Ok(preimage);
        }
        let deadline = deadline.min(payment.expiry);
        loop {
            match self
                .find_revealed_preimage_by_transfer(&transfer_id, payment_hash)
                .await
            {
                Ok(Some(preimage)) => {
                    if let Some(slot) = self.outgoing.lock().await.get_mut(&payment.operation_id) {
                        slot.preimage = Some(preimage);
                    }
                    return Ok(preimage);
                }
                Ok(None) => {}
                Err(error @ Error::InvalidParams(_)) => return Err(error.into()),
                Err(error) => {
                    self.span.in_scope(|| {
                        debug!(
                            target: "cassis_spark",
                            ?payment_hash,
                            "transfer poll failed: {error}"
                        );
                    });
                }
            }
            if unix_now() >= deadline {
                return Err(AdapterError::DeadlineExceeded);
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }

    /// Stop watching a Spark transfer. The operators return unclaimed
    /// transfers automatically at expiry; no sender-side cancellation
    /// call is needed or exposed by `spark-wallet`.
    async fn refund_outgoing(&self, payment: &OutgoingPayment) -> Result<(), AdapterError> {
        self.validate_outgoing_payment(payment)?;
        let mut outgoing = self.outgoing.lock().await;
        let Some(slot) = outgoing.get(&payment.operation_id) else {
            return Ok(());
        };
        self.outgoing_payment_matches(slot, payment)?;
        outgoing.remove(&payment.operation_id);
        Ok(())
    }

    /// Restore outgoing state from the descriptor embedded in
    /// `payment.descriptor`. The transfer id and address are the durable
    /// Spark HTLC handles; no hash-keyed map reconstruction is used.
    async fn restore_outgoing(&self, payment: &OutgoingPayment) -> Result<(), AdapterError> {
        let (address, transfer_id) = self.validate_outgoing_payment(payment)?;
        let mut outgoing = self.outgoing.lock().await;
        if let Some(existing) = outgoing.get(&payment.operation_id) {
            self.outgoing_payment_matches(existing, payment)?;
            return Ok(());
        }
        if outgoing
            .values()
            .any(|slot| slot.payment_hash == payment.payment_hash)
        {
            return Err(AdapterError::Retryable(
                "Spark payment hash already belongs to another outgoing operation".into(),
            ));
        }
        outgoing.insert(
            payment.operation_id.clone(),
            PendingOutgoing {
                payment_hash: payment.payment_hash,
                amount_msat: payment.amount_msat,
                expiry: payment.expiry,
                destination: payment.destination.clone(),
                destination_network: payment.destination_network.clone(),
                address,
                transfer_id,
                descriptor: payment.descriptor.clone(),
                preimage: None,
            },
        );
        debug!(
            target: "cassis_spark",
            payment_hash = ?payment.payment_hash,
            "restored outgoing Spark HTLC"
        );
        Ok(())
    }

    /// PREPARE-time check: enough claimable sats to fund a Spark HTLC.
    async fn can_route(&self, amount_msat: u64) -> Result<(), AdapterError> {
        if amount_msat == 0 {
            return Err(AdapterError::InvalidParams(
                "route amount must be greater than zero".into(),
            ));
        }
        let balance = self.balance_sats().await?;
        let needed = msat_to_sats(amount_msat);
        if balance < needed {
            return Err(AdapterError::InvalidParams(format!(
                "insufficient spark balance: need {needed} sats, have {balance} sats"
            )));
        }
        Ok(())
    }

    /// Receiving a Spark-side HODL invoice requires revealing a
    /// preimage, not spending adapter-owned balance. Claim capacity is
    /// therefore not a balance check.
    async fn can_claim(&self, _amount_msat: u64) -> Result<(), AdapterError> {
        Ok(())
    }
}

fn deadline_expiry_secs(deadline: u64, now: u64) -> Result<u32, AdapterError> {
    let remaining = deadline.saturating_sub(now).max(60);
    u32::try_from(remaining).map_err(|_| {
        AdapterError::InvalidParams("incoming deadline exceeds Spark invoice limit".into())
    })
}
