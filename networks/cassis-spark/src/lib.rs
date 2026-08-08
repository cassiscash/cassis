//! Spark network adapter (raw `spark-wallet` SDK).
//!
//! One per-node Spark wallet connected to the Spark operators via the
//! `spark-wallet` crate, acting as:
//!
//! * **Receiver** — a HODL invoice (BOLT11) created against a
//!   caller-supplied payment hash (`create_hodl_lightning_invoice`).
//!   The payer must pay it over lightning, and the invoice is only
//!   settled when [`NetworkRouterAdapter::claim_incoming`] reveals the
//!   preimage via `claim_htlc`.
//! * **Sender** — a Spark HTLC transfer: `create_htlc` locks the
//!   amount to the recipient's Spark address carrying the route's
//!   payment hash and expiry; the receiver claims it by revealing the
//!   preimage, otherwise the transfer is automatically returned.
//!
//! Both sides honor an external `payment_hash`, which is what makes
//! spark a first-class cassis network. Spark cannot act as an invoice
//! issuer for arbitrary hashes over the Spark network itself (the
//! HODL invoice is a lightning invoice), so the two roles above are the
//! only directions a cassis route can use.
//!
//! Amounts: spark and lightning denominate sats, cassis denominates
//! msat. Invoice and transfer amounts are rounded *up* to whole sats
//! (`ceil`), so amounts at sub-sat precision round against the room.
//!
//! The wallet keeps its leaf/session/token state in memory和中 re-syncs
//! from the operators; no on-disk database is used.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bitcoin::hashes::Hash as _;
use cassis_core::{
    Bytes32, HtlcDescriptor, HtlcError, HtlcTarget, NetworkId, NetworkRouterAdapter, OutgoingHtlc,
    OutgoingPayment, WatchError, XOnlyPubKey,
};
use lightning_invoice::Bolt11Invoice;
use spark_wallet::{
    DefaultSigner, InvoiceDescription, ListTransfersRequest, Network, Preimage, SparkAddress,
    SparkSigner, SparkSignerAdapter, SparkWallet, SparkWalletConfig, TransferStatus, TransferType,
};
use std::str::FromStr;
use tokio::sync::Mutex;
use tracing::{debug, info, Span};

/// Per-hop delta the routing layer gets on spark legs. The receiver
/// side is a lightning HODL invoice whose claim is one `claim_htlc`
/// call; the sender side is a single Spark transfer. Generous, same
/// order as the other fast networks.
const INCOMING_DELTA_SECS: u64 = 60;

/// How long [`NetworkRouterAdapter::watch_preimage`] waits between
/// transfer polls.
const POLL_INTERVAL: Duration = Duration::from_millis(1000);

/// A HODL invoice registered at PREPARE time and open for funding.
#[derive(Clone)]
#[allow(dead_code)]
struct PendingIncoming {
    /// Unix seconds the routing layer gave us for this hop.
    deadline: u64,
    /// The BOLT11 HODL invoice string the payer must pay.
    payment_request: String,
}

/// A Spark HTLC transfer we funded, keyed by the route payment hash.
#[derive(Clone, Debug)]
struct PendingOutgoing {
    /// Unix seconds the transfer expires.
    expiry: u64,
    /// Spark transfer id of the funded HTLC, when the wallet assigned
    /// one (only absent on descriptors restored without one).
    transfer_id: Option<String>,
    /// Spark address the transfer is locked to.
    address: String,
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
    /// Node identity advertised via [`NetworkRouterAdapter::invoice_pubkey`].
    /// Spark itself has no x-only claim identity; this is the node's
    /// invoice key, passed in at construction like the other adapters.
    invoice_pubkey: XOnlyPubKey,
    incoming: Mutex<std::collections::HashMap<Bytes32, PendingIncoming>>,
    outgoing: Mutex<std::collections::HashMap<Bytes32, PendingOutgoing>>,
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

impl From<Error> for HtlcError {
    fn from(error: Error) -> Self {
        match error {
            Error::InvalidParams(message) => HtlcError::InvalidParams(message),
            other => HtlcError::Network(other.to_string()),
        }
    }
}

impl From<Error> for WatchError {
    fn from(error: Error) -> Self {
        WatchError::Network(error.to_string())
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
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl SparkAdapter {
    /// Connect the spark adapter. `secret` seeds the wallet's BIP32
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
            incoming: Mutex::new(Default::default()),
            outgoing: Mutex::new(Default::default()),
            span,
        }))
    }

    /// Claimable funds in the spark wallet, in sats. Syncs first so
    /// the leaf set reflects settled transfers.
    pub async fn balance_sats(&self) -> Result<u64, Error> {
        self.wallet.sync().await.map_err(Error::from)?;
        self.wallet.get_balance().await.map_err(Error::from)
    }

    /// The wallet's own Spark address (what other spark parties can
    /// send a Spark HTLC transfer to), in its `spark:addr` string form.
    pub async fn spark_address(&self) -> Result<String, Error> {
        let address = self
            .wallet
            .get_spark_address()
            .map_err(Error::from)?
            .to_address_string()
            .map_err(|e| Error::Wallet(e.to_string()))?;
        Ok(address)
    }

    /// Poll the funded HTLC transfer (by id) for the receiver's
    /// preimage reveal, verified against the route payment hash.
    async fn find_revealed_preimage_by_transfer(
        &self,
        transfer_id: &str,
        payment_hash: Bytes32,
    ) -> Result<Option<Bytes32>, Error> {
        let id = transfer_id
            .parse()
            .map_err(|e| Error::InvalidParams(format!("invalid transfer id: {e}")))?;
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

fn preimage_bytes(preimage: Preimage) -> Result<Bytes32, Error> {
    let vec = preimage.to_vec();
    let array: [u8; 32] = vec
        .try_into()
        .map_err(|_| Error::InvalidParams("preimage is not 32 bytes".into()))?;
    Ok(Bytes32(array))
}

#[async_trait]
impl NetworkRouterAdapter for SparkAdapter {
    fn network_id(&self) -> NetworkId {
        self.network_id.clone()
    }

    fn invoice_pubkey(&self) -> XOnlyPubKey {
        self.invoice_pubkey
    }

    fn incoming_delta_secs(&self) -> u64 {
        INCOMING_DELTA_SECS
    }

    /// Create a HODL invoice against the route payment hash. Spark
    /// does not expose a cancel, so a registration that is never
    /// funded simply expires with the invoice.
    async fn register_incoming_htlc(
        &self,
        payment_hash: Bytes32,
        min_amount_msat: u64,
        deadline: u64,
    ) -> Result<(), HtlcError> {
        if deadline <= unix_now() {
            return Err(HtlcError::InvalidParams("deadline in the past".into()));
        }
        let amount_sats = msat_to_sats(min_amount_msat);
        let expiry_secs = deadline.saturating_sub(unix_now()).max(60) as u32;
        let payment = self
            .wallet
            .create_hodl_lightning_invoice(
                amount_sats,
                Some(InvoiceDescription::Memo("cassis htlc".to_string())),
                // HODL: the payer's lightning HTLC is held until the
                // preimage is provided via `claim_htlc`.
                bitcoin::hashes::sha256::Hash::from_byte_array(payment_hash.0),
                None,
                Some(expiry_secs),
            )
            .await
            .map_err(Error::from)?;
        let payment_request = payment.invoice;
        self.incoming.lock().await.insert(
            payment_hash,
            PendingIncoming {
                deadline,
                payment_request: payment_request.clone(),
            },
        );
        debug!(target: "cassis_spark", ?payment_hash, "registered HODL invoice");
        Ok(())
    }

    /// The upstream side pays our incoming HODL invoice with lightning.
    async fn htlc_target(&self, payment_hash: Bytes32) -> Result<HtlcTarget, HtlcError> {
        let payment_request = self
            .incoming
            .lock()
            .await
            .get(&payment_hash)
            .map(|pending| pending.payment_request.clone())
            .ok_or_else(|| {
                HtlcError::InvalidParams(format!("no incoming HTLC for {payment_hash:?}"))
            })?;
        Ok(HtlcTarget::LightningInvoice(payment_request))
    }

    async fn cancel_incoming_htlc(&self, payment_hash: Bytes32) -> Result<(), HtlcError> {
        self.incoming.lock().await.remove(&payment_hash);
        Ok(())
    }

    /// Fund a Spark HTLC transfer to the recipient's Spark address
    /// carrying `payment_hash` and the route expiry. Leaves the
    /// transfer id in [`PendingOutgoing`] so `watch_preimage` can
    /// poll it.
    async fn create_outgoing_htlc(
        &self,
        payment_hash: Bytes32,
        amount_msat: u64,
        expiry: u64,
        htlc_target: &HtlcTarget,
    ) -> Result<OutgoingHtlc, HtlcError> {
        let address = match htlc_target {
            HtlcTarget::SparkAddress(address) => address.clone(),
            HtlcTarget::XOnlyPubKey(_)
            | HtlcTarget::PubKey(_)
            | HtlcTarget::LightningInvoice(_) => {
                return Err(HtlcError::InvalidParams(
                    "spark requires a spark-address target".into(),
                ))
            }
        };
        if expiry <= unix_now() {
            return Err(HtlcError::InvalidParams(
                "outgoing expiry is in the past".into(),
            ));
        }
        let receiver_address = SparkAddress::from_str(&address)
            .map_err(|e| HtlcError::InvalidParams(format!("invalid spark address: {e}")))?;
        let amount_sats = msat_to_sats(amount_msat);
        let transfer = self
            .wallet
            .create_htlc(
                amount_sats,
                &receiver_address,
                &bitcoin::hashes::sha256::Hash::from_byte_array(payment_hash.0),
                // The transfer is returned automatically once this
                // much time has passed.
                Duration::from_secs(expiry.saturating_sub(unix_now())),
                None,
            )
            .await
            .map_err(Error::from)?;
        self.outgoing.lock().await.insert(
            payment_hash,
            PendingOutgoing {
                expiry,
                transfer_id: Some(transfer.id.to_string()),
                address: address.clone(),
            },
        );
        debug!(
            target: "cassis_spark",
            ?payment_hash,
            amount_sats,
            transfer_id = %transfer.id,
            "funded spark HTLC"
        );
        Ok(OutgoingHtlc {
            payment_hash,
            amount_msat,
            expiry,
            recipient: address.clone(),
            network: self.network_id.clone(),
        })
    }

    /// Serialize the funded transfer for the next hop / payer.
    async fn outgoing_htlc_descriptor(
        &self,
        payment_hash: Bytes32,
    ) -> Result<HtlcDescriptor, HtlcError> {
        let slot = self
            .outgoing
            .lock()
            .await
            .get(&payment_hash)
            .cloned()
            .ok_or_else(|| {
                HtlcError::InvalidParams(format!("no outgoing HTLC for {payment_hash:?}"))
            })?;
        Ok(HtlcDescriptor::Spark {
            address: slot.address,
            expiry_secs: slot.expiry.saturating_sub(unix_now()),
            transfer_id: slot.transfer_id,
        })
    }

    async fn restore_outgoing_htlc(
        &self,
        payment: &OutgoingPayment,
        descriptor: Option<&HtlcDescriptor>,
    ) -> Result<(), HtlcError> {
        let HtlcDescriptor::Spark {
            address,
            transfer_id,
            ..
        } = descriptor.ok_or(HtlcError::Unimplemented)?
        else {
            return Err(HtlcError::InvalidParams(
                "spark restore requires a spark descriptor".into(),
            ));
        };
        let transfer_id = transfer_id
            .as_deref()
            .ok_or_else(|| {
                HtlcError::InvalidParams(
                    "spark restore requires the htlc transfer id in the descriptor".into(),
                )
            })?
            .to_string();
        self.outgoing.lock().await.insert(
            payment.payment_hash,
            PendingOutgoing {
                expiry: payment.expiry,
                transfer_id: Some(transfer_id),
                address: address.clone(),
            },
        );
        Ok(())
    }

    /// Reveal the preimage to settle the HODL invoice.
    async fn claim_incoming(
        &self,
        payment_hash: Bytes32,
        preimage: Bytes32,
    ) -> Result<(), HtlcError> {
        if !payment_hash.matches_preimage(&preimage) {
            return Err(HtlcError::InvalidParams(
                "preimage does not match the payment hash".into(),
            ));
        }
        self.incoming
            .lock()
            .await
            .get(&payment_hash)
            .ok_or_else(|| {
                HtlcError::InvalidParams(format!("no incoming HTLC for {payment_hash:?}"))
            })?;
        self.wallet
            .claim_htlc(
                &Preimage::from_hex(&lowercase_hex::encode(preimage.0)).map_err(Error::from)?,
            )
            .await
            .map_err(Error::from)?;
        self.incoming.lock().await.remove(&payment_hash);
        info!(target: "cassis_spark", ?payment_hash, "claimed incoming HTLC");
        Ok(())
    }

    /// Nothing to do: an unclaimed Spark HTLC is returned to us by the
    /// operators once its expiry passes.
    async fn refund_outgoing(&self, payment_hash: Bytes32) -> Result<(), HtlcError> {
        self.outgoing.lock().await.remove(&payment_hash);
        Ok(())
    }

    /// Poll the funded transfer for the receiver's preimage reveal.
    async fn watch_preimage(
        &self,
        payment_hash: Bytes32,
        deadline: u64,
    ) -> Result<Bytes32, WatchError> {
        let transfer_id = self
            .outgoing
            .lock()
            .await
            .get(&payment_hash)
            .and_then(|pending| pending.transfer_id.clone())
            .ok_or_else(|| WatchError::Network(format!("no outgoing HTLC for {payment_hash:?}")))?;
        loop {
            match self
                .find_revealed_preimage_by_transfer(&transfer_id, payment_hash)
                .await
            {
                Ok(Some(preimage)) => return Ok(preimage),
                Ok(None) => {}
                Err(error) => {
                    self.span.in_scope(|| {
                        debug!(target: "cassis_spark", ?payment_hash, "transfer poll failed: {error}")
                    });
                }
            }
            if unix_now() >= deadline {
                return Err(WatchError::DeadlineExceeded);
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }

    /// PREPARE-time check: enough claimable sats to fund the transfer.
    async fn can_route(&self, amount_msat: u64) -> Result<(), HtlcError> {
        let balance = self.balance_sats().await.map_err(HtlcError::from)?;
        let needed = msat_to_sats(amount_msat);
        if balance < needed {
            return Err(HtlcError::InvalidParams(format!(
                "insufficient spark balance: need {needed} sats, have {balance} sats"
            )));
        }
        Ok(())
    }

    /// DISPATCH-time verify: the incoming descriptor must be a
    /// lightning registration whose invoice hash is the route hash.
    async fn verify_incoming_htlc(
        &self,
        descriptor: &HtlcDescriptor,
        payment_hash: Bytes32,
    ) -> Result<(), HtlcError> {
        let HtlcDescriptor::Lightning { payment_request } = descriptor else {
            return Err(HtlcError::InvalidParams(
                "expected a lightning invoice descriptor".into(),
            ));
        };
        let invoice = Bolt11Invoice::from_str(payment_request)
            .map_err(|e| HtlcError::InvalidParams(format!("invalid BOLT11 invoice: {e}")))?;
        if invoice.payment_hash().as_ref() != payment_hash.0 {
            return Err(HtlcError::InvalidParams(
                "invoice hash does not match the route payment hash".into(),
            ));
        }
        Ok(())
    }
}
