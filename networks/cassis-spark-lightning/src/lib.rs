//! Lightning network through a [Spark](https://spark.money) wallet, run by
//! [Breez's SDK](https://github.com/breez/spark-sdk): Lightspark's service
//! provider (SSP) pays and receives Lightning payments for its users, who
//! hold their funds as Spark leaves.
//!
//! * **Receive**: the target is a hold invoice the SSP issues for the
//!   payment hash alone. Once the SSP holds the payment's HTLCs it locks
//!   the amount to the wallet in a Spark HTLC, which the wallet claims by
//!   revealing the preimage.
//! * **Send**: the SSP pays the target invoice from a Spark HTLC the
//!   wallet locks to it; it reveals the preimage when the payment
//!   succeeds, and the HTLC comes back if it fails.
//!
//! **Timing.** The Spark HTLC of a receive expires a few hours after the
//! SSP took the payment ([`HOLD_SECS`], measured on regtest), whatever
//! the invoice asks of the payer, so a receive is only offered for HTLCs
//! that expire within that, and verified against the HTLC's real expiry.
//! A send only pays invoices whose final CLTV delta fits in the time
//! until the HTLC's expiry, so the payee cannot hold it longer. Past
//! that, sends trust the SSP, as any Spark user does: its HTLC on a send
//! lasts about two weeks, but a cooperating SSP settles or returns it as
//! soon as the payment does.
//!
//! **Fees.** The SSP takes its fee on top of a send; receives come in
//! whole.

use async_trait::async_trait;
pub use breez_sdk_spark::PaymentStatus;
use breez_sdk_spark::{
    BreezSdk, ClaimHtlcPaymentRequest, ConnectRequest, FetchLightningSendStatusRequest,
    GetInfoRequest, ListPaymentsRequest, Network as SparkNetwork, Payment, PaymentDetails,
    PaymentDetailsFilter, PaymentRequest, PaymentType, PrepareSendPaymentRequest,
    ReceivePaymentMethod, ReceivePaymentRequest, Seed, SendPaymentOptions, SendPaymentRequest,
    SparkHtlcDetails, SparkHtlcStatus, SyncWalletRequest, connect, default_config,
};
use cassis_core::keys::Mnemonic;
use cassis_core::{
    Bytes32, Htlc, HtlcDescriptor, InvoiceTarget, MSAT_PER_SAT, Network, NetworkError, NetworkId,
    OutgoingState, unix_now,
};
use lightning_invoice::Bolt11Invoice;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;
use tracing::{Span, debug, info};

/// What a Spark wallet needs besides its keys.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SparkLightningConfig {
    /// Breez API key, which mainnet requires; see
    /// <https://breez.technology/request-api-key/>.
    pub api_key: Option<String>,
}

/// How long after the SSP takes a payment the Spark HTLC it locks to the
/// wallet is sure to last: it expired just under 4 hours later on
/// regtest, less half an hour of margin.
pub const HOLD_SECS: u64 = 3 * 3600 + 30 * 60;

/// How often a long-running node syncs the wallet beyond the SDK's own
/// background sync.
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(15 * 60);

/// How often a funding invoice is checked for its payment.
const FUNDING_POLL: Duration = Duration::from_secs(5);

/// Room for the SSP's fee on a send of the HTLC amount, which it only
/// quotes for a given invoice.
const SEND_FEE_PPM: u64 = 5_000;
const SEND_FEE_MIN_SATS: u64 = 10;

fn wallet_error(error: impl std::fmt::Display) -> NetworkError {
    NetworkError::network(format!("spark: {error}"))
}

pub struct SparkLightningAdapter {
    id: NetworkId,
    sdk: BreezSdk,
    /// The invoices handed out by [`Network::receive_target`], one file
    /// per payment hash.
    receives: PathBuf,
    /// Average seconds between blocks of bitcoin.
    block_secs: u64,
    span: Span,
}

impl SparkLightningAdapter {
    /// Open (or create) the Spark wallet of `id` in `datadir`, its keys
    /// derived from `mnemonic` the way Breez's SDK does. `id` is
    /// `lightning` (mainnet) or `lightning::regtest`, Lightspark's.
    pub async fn open(
        id: NetworkId,
        mnemonic: &Mnemonic,
        datadir: &Path,
        config: &SparkLightningConfig,
        span: &Span,
    ) -> Result<Self, String> {
        let network = match id.param() {
            None => SparkNetwork::Mainnet,
            Some("regtest") => SparkNetwork::Regtest,
            Some(other) => return Err(format!("spark does not run on '{other}'")),
        };
        if network == SparkNetwork::Mainnet && config.api_key.is_none() {
            return Err("spark on mainnet needs a Breez API key (api_key)".into());
        }
        let mut sdk_config = default_config(network);
        sdk_config.api_key = config.api_key.clone();
        // The wallet's state lives in `datadir` alone: no syncing it with
        // other devices through Breez's server.
        sdk_config.real_time_sync_server_url = None;
        let receives = datadir.join("receives");
        std::fs::create_dir_all(&receives)
            .map_err(|e| format!("create {}: {e}", receives.display()))?;
        let sdk = connect(ConnectRequest {
            config: sdk_config,
            seed: Seed::Mnemonic {
                mnemonic: mnemonic.to_string(),
                passphrase: None,
            },
            storage_dir: datadir.join("sdk").display().to_string(),
        })
        .await
        .map_err(|e| format!("open spark wallet: {e}"))?;
        let adapter = Self {
            span: cassis_core::network_span(span, &id),
            id,
            sdk,
            receives,
            block_secs: 600,
        };
        debug!(parent: &adapter.span, "spark wallet ready");
        Ok(adapter)
    }

    pub fn sdk(&self) -> &BreezSdk {
        &self.sdk
    }

    /// Sats that can be sent right now.
    pub async fn balance_sats(&self) -> Result<u64, NetworkError> {
        let info = self
            .sdk
            .get_info(GetInfoRequest {
                ensure_synced: Some(true),
            })
            .await
            .map_err(wallet_error)?;
        Ok(info.balance_sats)
    }

    /// The wallet's Spark address, and the bitcoin address deposits to it
    /// go to.
    pub async fn addresses(&self) -> Result<(String, String), NetworkError> {
        let mut addresses = Vec::with_capacity(2);
        for payment_method in [
            ReceivePaymentMethod::SparkAddress,
            ReceivePaymentMethod::BitcoinAddress { new_address: None },
        ] {
            let response = self
                .sdk
                .receive_payment(ReceivePaymentRequest { payment_method })
                .await
                .map_err(wallet_error)?;
            addresses.push(response.payment_request);
        }
        let bitcoin = addresses.pop().unwrap_or_default();
        Ok((addresses.pop().unwrap_or_default(), bitcoin))
    }

    /// Send `sats` to a Spark address, else on-chain to a bitcoin
    /// address. Returns the id of the payment.
    pub async fn send(&self, to: &str, sats: u64) -> Result<String, NetworkError> {
        let prepare_response = self
            .sdk
            .prepare_send_payment(PrepareSendPaymentRequest {
                payment_request: PaymentRequest::Input {
                    input: to.trim().to_string(),
                },
                amount: Some(sats.into()),
                token_identifier: None,
                conversion_options: None,
                fee_policy: None,
            })
            .await
            .map_err(|e| NetworkError::invalid(format!("not a Spark or bitcoin address: {e}")))?;
        let response = self
            .sdk
            .send_payment(SendPaymentRequest {
                prepare_response,
                options: None,
                idempotency_key: None,
            })
            .await
            .map_err(wallet_error)?;
        Ok(response.payment.id)
    }

    /// Pay `invoice`, waiting up to a minute for it to settle.
    pub async fn pay_invoice(&self, invoice: &str) -> Result<PaymentStatus, NetworkError> {
        let payment = self.pay(invoice.trim(), None, Some(60)).await?;
        if payment.status == PaymentStatus::Failed {
            return Err(NetworkError::network("the payment failed"));
        }
        Ok(payment.status)
    }

    /// A plain invoice of `sats` (with a preimage the SDK keeps) to fund
    /// the wallet over Lightning; the SSP settles it by itself.
    pub async fn funding_invoice(&self, sats: u64) -> Result<String, NetworkError> {
        let response = self
            .sdk
            .receive_payment(ReceivePaymentRequest {
                payment_method: ReceivePaymentMethod::Bolt11Invoice {
                    description: "cassis".to_string(),
                    amount_sats: Some(sats),
                    expiry_secs: None,
                    payment_hash: None,
                    receiver_identity_public_key: None,
                    preimage: None,
                },
            })
            .await
            .map_err(wallet_error)?;
        Ok(response.payment_request)
    }

    /// Wait until a funding invoice is paid to the wallet, or expires.
    pub async fn claim_funding(&self, invoice: &str) -> Result<(), NetworkError> {
        let parsed = Bolt11Invoice::from_str(invoice).map_err(NetworkError::invalid)?;
        let expires = unix_now() + parsed.duration_until_expiry().as_secs();
        loop {
            self.sync().await?;
            let payments = self.lightning_payments(PaymentType::Receive, None).await?;
            if payments.iter().any(|(payment, paid)| {
                paid == invoice && payment.status == PaymentStatus::Completed
            }) {
                return Ok(());
            }
            if unix_now() > expires {
                return Err(NetworkError::invalid("the invoice expired unpaid"));
            }
            tokio::time::sleep(FUNDING_POLL).await;
        }
    }

    async fn sync(&self) -> Result<(), NetworkError> {
        self.sdk
            .sync_wallet(SyncWalletRequest {})
            .await
            .map_err(wallet_error)?;
        Ok(())
    }

    /// The wallet's lightning payments of `kind`, with their invoices,
    /// whose Spark HTLC is in one of `htlc_status` (any if `None`).
    async fn lightning_payments(
        &self,
        kind: PaymentType,
        htlc_status: Option<Vec<SparkHtlcStatus>>,
    ) -> Result<Vec<(Payment, String)>, NetworkError> {
        let payments = self
            .sdk
            .list_payments(ListPaymentsRequest {
                type_filter: Some(vec![kind]),
                payment_details_filter: Some(vec![PaymentDetailsFilter::Lightning { htlc_status }]),
                ..Default::default()
            })
            .await
            .map_err(wallet_error)?
            .payments;
        Ok(payments
            .into_iter()
            .filter_map(|payment| match &payment.details {
                Some(PaymentDetails::Lightning { invoice, .. }) => {
                    let invoice = invoice.clone();
                    Some((payment, invoice))
                }
                _ => None,
            })
            .collect())
    }

    /// The Spark HTLC the SSP locked to the wallet for `payment_hash`, and
    /// its amount in sats, once it holds the payment.
    async fn received_htlc(
        &self,
        payment_hash: Bytes32,
        htlc_status: SparkHtlcStatus,
    ) -> Result<Option<(SparkHtlcDetails, u128)>, NetworkError> {
        self.sync().await?;
        let hash = payment_hash.to_string();
        Ok(self
            .lightning_payments(PaymentType::Receive, Some(vec![htlc_status]))
            .await?
            .into_iter()
            .find_map(|(payment, _)| match payment.details {
                Some(PaymentDetails::Lightning { htlc_details, .. })
                    if htlc_details.payment_hash == hash =>
                {
                    Some((htlc_details, payment.amount))
                }
                _ => None,
            }))
    }

    /// Pay `invoice` over Lightning (never by a direct Spark transfer, which
    /// would reveal no preimage), as the payment `idempotency_key` if set.
    async fn pay(
        &self,
        invoice: &str,
        idempotency_key: Option<String>,
        completion_timeout_secs: Option<u32>,
    ) -> Result<Payment, NetworkError> {
        let prepare_response = self
            .sdk
            .prepare_send_payment(PrepareSendPaymentRequest {
                payment_request: PaymentRequest::Input {
                    input: invoice.to_string(),
                },
                amount: None,
                token_identifier: None,
                conversion_options: None,
                fee_policy: None,
            })
            .await
            .map_err(|e| NetworkError::invalid(format!("cannot pay the invoice: {e}")))?;
        let response = self
            .sdk
            .send_payment(SendPaymentRequest {
                prepare_response,
                options: Some(SendPaymentOptions::Bolt11Invoice {
                    prefer_spark: false,
                    completion_timeout_secs,
                }),
                idempotency_key,
            })
            .await
            .map_err(wallet_error)?;
        Ok(response.payment)
    }

    fn receive_path(&self, payment_hash: Bytes32) -> PathBuf {
        self.receives.join(payment_hash.to_string())
    }

    /// The invoice [`Network::receive_target`] handed out for
    /// `payment_hash`, if any.
    fn stored_receive(&self, payment_hash: Bytes32) -> Result<Option<String>, NetworkError> {
        match std::fs::read_to_string(self.receive_path(payment_hash)) {
            Ok(invoice) => Ok(Some(invoice)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(NetworkError::network(format!("read receive: {e}"))),
        }
    }
}

#[async_trait]
impl Network for SparkLightningAdapter {
    fn id(&self) -> NetworkId {
        self.id.clone()
    }

    async fn receive_target(
        &self,
        payment_hash: Bytes32,
        amount_msat: u64,
        expiry: u64,
    ) -> Result<InvoiceTarget, NetworkError> {
        let sats = amount_msat.div_ceil(MSAT_PER_SAT);
        if let Some(invoice) = self.stored_receive(payment_hash)? {
            let parsed = parse_invoice(&invoice, payment_hash)?;
            if parsed.amount_milli_satoshis() != Some(sats * MSAT_PER_SAT) {
                return Err(NetworkError::invalid(
                    "an invoice for this hash has another amount",
                ));
            }
            return Ok(InvoiceTarget::Lightning {
                network: self.id.clone(),
                invoice,
            });
        }
        // The Spark HTLC lasts `HOLD_SECS` from when the SSP takes the
        // payment, which is not before now.
        let lifetime = expiry.saturating_sub(unix_now());
        if lifetime > HOLD_SECS {
            return Err(NetworkError::invalid(format!(
                "spark holds receives {HOLD_SECS}s, {expiry} is {lifetime}s away"
            )));
        }
        let response = self
            .sdk
            .receive_payment(ReceivePaymentRequest {
                payment_method: ReceivePaymentMethod::Bolt11Invoice {
                    description: "cassis".to_string(),
                    amount_sats: Some(sats),
                    expiry_secs: Some(lifetime.max(60) as u32),
                    payment_hash: Some(payment_hash.to_string()),
                    receiver_identity_public_key: None,
                    preimage: None,
                },
            })
            .await
            .map_err(wallet_error)?;
        let invoice = response.payment_request;
        parse_invoice(&invoice, payment_hash)?;
        std::fs::write(self.receive_path(payment_hash), &invoice)
            .map_err(|e| NetworkError::network(format!("store receive: {e}")))?;
        Ok(InvoiceTarget::Lightning {
            network: self.id.clone(),
            invoice,
        })
    }

    /// Spark has no way to cancel a hold invoice: an unpaid one expires,
    /// and a held payment goes back to the payer when its Spark HTLC does.
    async fn cancel_receive(&self, payment_hash: Bytes32) -> Result<(), NetworkError> {
        debug!(parent: &self.span, "not canceling {}: spark cannot", payment_hash.short());
        Ok(())
    }

    async fn verify_incoming_htlc(&self, htlc: &Htlc) -> Result<(), NetworkError> {
        let HtlcDescriptor::Lightning { target: request } = &htlc.descriptor else {
            return Err(NetworkError::invalid("not a lightning HTLC"));
        };
        let invoice = parse_invoice(request, htlc.payment_hash)?;
        if invoice.amount_milli_satoshis().unwrap_or(0) < htlc.amount_msat {
            return Err(NetworkError::invalid("invoice is worth less than the HTLC"));
        }
        if self.stored_receive(htlc.payment_hash)?.as_deref() != Some(request.as_str()) {
            return Err(NetworkError::invalid("HTLC is not addressed to this node"));
        }
        let Some((held, sats)) = self
            .received_htlc(htlc.payment_hash, SparkHtlcStatus::WaitingForPreimage)
            .await?
        else {
            return Err(NetworkError::not_yet("invoice is not paid yet"));
        };
        if sats.saturating_mul(MSAT_PER_SAT.into()) < u128::from(htlc.amount_msat) {
            return Err(NetworkError::invalid(format!(
                "the SSP holds {sats} sat, less than the HTLC"
            )));
        }
        if held.expiry_time < htlc.expiry {
            return Err(NetworkError::invalid(format!(
                "the SSP's HTLC expires at {}, before {}",
                held.expiry_time, htlc.expiry
            )));
        }
        Ok(())
    }

    async fn claim_incoming_htlc(
        &self,
        htlc: &Htlc,
        preimage: Bytes32,
    ) -> Result<(), NetworkError> {
        let claimed = self
            .sdk
            .claim_htlc_payment(ClaimHtlcPaymentRequest {
                preimage: preimage.to_string(),
            })
            .await;
        if let Err(error) = claimed {
            // A claim that went through before has nothing left to claim.
            if self
                .received_htlc(htlc.payment_hash, SparkHtlcStatus::PreimageShared)
                .await?
                .is_none()
            {
                return Err(wallet_error(error));
            }
        }
        info!(parent: &self.span, "claimed {}", htlc.payment_hash.short());
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
        // The payee can hold the payment for the invoice's final CLTV
        // delta: it must be over by `expiry`.
        let held_secs = invoice
            .min_final_cltv_expiry_delta()
            .saturating_mul(self.block_secs);
        if held_secs > expiry.saturating_sub(unix_now()) {
            return Err(NetworkError::invalid(format!(
                "the invoice can be held for {held_secs}s, past the HTLC's expiry"
            )));
        }
        // Receivers in whole sats round the amount up.
        let invoice_msat = invoice.amount_milli_satoshis().unwrap_or(0);
        if invoice_msat < amount_msat || invoice_msat > amount_msat.next_multiple_of(MSAT_PER_SAT) {
            return Err(NetworkError::invalid(format!(
                "invoice amount {invoice_msat} msat is not the HTLC amount {amount_msat} msat"
            )));
        }
        // A send already started for this hash is the payment under its
        // idempotency key, which the SDK returns rather than repeats.
        self.pay(payment_request, Some(idempotency_key(payment_hash)), None)
            .await?;
        info!(parent: &self.span, "paying {invoice_msat} msat for {}", payment_hash.short());
        Ok(HtlcDescriptor::Lightning {
            target: payment_request.clone(),
        })
    }

    /// The send is tracked by the invoice alone.
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

    /// Asks the Spark operators, not the wallet's history.
    async fn check_outgoing_htlc(&self, htlc: &Htlc) -> Result<OutgoingState, NetworkError> {
        let HtlcDescriptor::Lightning { target: invoice } = &htlc.descriptor else {
            return Err(NetworkError::invalid("not a lightning HTLC"));
        };
        let status = self
            .sdk
            .fetch_lightning_send_status(FetchLightningSendStatusRequest {
                invoice: invoice.clone(),
            })
            .await
            .map_err(wallet_error)?;
        match status.status {
            Some(PaymentStatus::Completed) => {
                let preimage = status
                    .preimage
                    .as_deref()
                    .ok_or_else(|| NetworkError::network("paid, but no preimage yet"))?;
                let preimage = Bytes32::from_str(preimage).map_err(NetworkError::network)?;
                if !htlc.payment_hash.matches_preimage(&preimage) {
                    return Err(NetworkError::network("the SSP gave a wrong preimage"));
                }
                Ok(OutgoingState::Claimed(preimage))
            }
            Some(PaymentStatus::Pending) => Ok(OutgoingState::Pending),
            // Every send was returned, or none was made.
            Some(PaymentStatus::Failed) | None => Ok(OutgoingState::Refunded),
        }
    }

    /// Lightning has no refund: a failed payment returns the funds by
    /// itself, an in-flight one can only wait.
    async fn refund_outgoing_htlc(&self, htlc: &Htlc) -> Result<(), NetworkError> {
        match self.check_outgoing_htlc(htlc).await? {
            OutgoingState::Refunded => Ok(()),
            _ => Err(NetworkError::network("payment is still in flight")),
        }
    }

    /// The SSP only quotes its fee for a given invoice: this leaves room
    /// for [`SEND_FEE_PPM`] of the amount.
    async fn can_send(&self, amount_msat: u64) -> Result<(), NetworkError> {
        let sats = amount_msat.div_ceil(MSAT_PER_SAT);
        let needed = sats + (sats * SEND_FEE_PPM / 1_000_000).max(SEND_FEE_MIN_SATS);
        let available = self.balance_sats().await?;
        if available < needed {
            return Err(NetworkError::invalid(format!(
                "need about {needed} sats with the SSP's fee, wallet has {available} sats"
            )));
        }
        Ok(())
    }

    /// The SSP takes any amount in, at no fee.
    async fn can_receive(&self, _amount_msat: u64) -> Result<(), NetworkError> {
        Ok(())
    }

    fn maintenance_interval(&self) -> Option<Duration> {
        Some(MAINTENANCE_INTERVAL)
    }

    /// Sync the wallet, which also claims confirmed deposits.
    async fn maintain(&self) -> Result<(), NetworkError> {
        self.sync().await
    }
}

/// Parse a BOLT11 request and pin it to the payment hash.
fn parse_invoice(
    payment_request: &str,
    payment_hash: Bytes32,
) -> Result<Bolt11Invoice, NetworkError> {
    let invoice = Bolt11Invoice::from_str(payment_request).map_err(NetworkError::invalid)?;
    if invoice.payment_hash().as_ref() as &[u8] != payment_hash.0 {
        return Err(NetworkError::invalid("invoice is for another payment hash"));
    }
    Ok(invoice)
}

/// The id of the send for `payment_hash`: a UUID (version 4, as the SDK
/// wants one) from the hash's first 16 bytes.
fn idempotency_key(payment_hash: Bytes32) -> String {
    let mut bytes: [u8; 16] = payment_hash.0[..16].try_into().expect("16 bytes");
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = lowercase_hex::encode(bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idempotency_keys_are_uuids() {
        let key = idempotency_key(Bytes32([0xff; 32]));
        assert_eq!(key, "ffffffff-ffff-4fff-bfff-ffffffffffff");
    }
}
