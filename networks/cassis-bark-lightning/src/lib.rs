//! Lightning network through a [bark](https://gitlab.com/ark-bitcoin/bark)
//! wallet: Ark VTXOs at a Second-style Ark server, which pays and
//! receives Lightning payments for its users.
//!
//! * **Receive**: the target is a hold invoice the server issues for the
//!   payment hash alone (a bark fork feature). Once the server holds the
//!   payment's HTLCs it grants the wallet HTLC-recv VTXOs, which the
//!   wallet swaps for spendable VTXOs by revealing the preimage when
//!   claiming.
//! * **Send**: the server pays the target invoice from HTLC-send VTXOs;
//!   it reveals the preimage when the payment succeeds, and the VTXOs come
//!   back if it fails.
//!
//! **Timing.** Every lightning HTLC sits in front of an Ark one, which
//! the wallet must be able to exit on-chain on its own. A receive's
//! invoice therefore asks for a CLTV delta covering the whole HTLC
//! expiry, and the time bark needs to exit is this network's incoming
//! delta: on mainnet defaults over 180 blocks, about 31 hours. Sends
//! trust the server, as any bark user does: it could hold a send's VTXOs
//! for its `htlc_send_expiry_delta` (256 blocks on signet) before
//! revealing the preimage or letting them be revoked, but a cooperating
//! server settles or revokes as soon as the payment does.
//!
//! **Fees.** The server takes a fee from every receive, so a claimed
//! payment nets less than the HTLC amount; routers should price it in.

use async_trait::async_trait;
use bark::actions::lightning::pay::LightningSendState;
use bark::actions::lightning::receive::{LightningReceiveState, Progress};
use bark::ark::bitcoin::{Amount, Network as BitcoinNetwork};
use bark::ark::lightning::{PaymentHash, Preimage};
use bark::lightning_invoice::Bolt11Invoice;
use bark::{Config, OpenWalletArgs, Wallet, WalletSeed};
use bitcoin_ext::BlockDelta;
use cassis_core::{
    unix_now, Bytes32, Htlc, HtlcDescriptor, HtlcTarget, Network, NetworkError, NetworkId,
    OutgoingState, MSAT_PER_SAT,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::path::Path;
use std::str::FromStr;
use tracing::{debug, info, Span};

/// Where a bark wallet finds its Ark server and the chain.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BarkConfig {
    /// The Ark server, e.g. `https://ark.second.tech`.
    pub server_url: String,
    /// An Esplora API for the server's chain, e.g.
    /// `https://mempool.space/api`.
    pub esplora_url: String,
}

impl BarkConfig {
    /// Second's public server and an Esplora for `network`'s chain, if
    /// it has them.
    pub fn default_for(network: &NetworkId) -> Option<Self> {
        let (server_url, esplora_url) = match network.param() {
            None => ("https://ark.second.tech", "https://mempool.second.tech/api"),
            Some("signet") => (
                "https://ark.signet.2nd.dev",
                "https://esplora.signet.2nd.dev",
            ),
            _ => return None,
        };
        Some(Self {
            server_url: server_url.into(),
            esplora_url: esplora_url.into(),
        })
    }
}

fn wallet_error(error: impl std::fmt::Display) -> NetworkError {
    NetworkError::network(format!("bark: {error:#}"))
}

pub struct BarkLightningAdapter {
    id: NetworkId,
    wallet: Wallet,
    /// Average seconds between blocks of the server's chain.
    block_secs: u64,
    /// The server's blocks between a lightning HTLC and the Ark HTLC
    /// behind it.
    htlc_expiry_delta: u64,
    /// Blocks an HTLC-send VTXO can stay locked.
    /// Smallest CLTV delta a receive may ask for.
    min_cltv_delta: u64,
    /// Largest CLTV delta the server grants a receive.
    max_cltv_delta: u64,
    span: Span,
}

impl BarkLightningAdapter {
    /// Open (or create) the bark wallet of `id` in `datadir`, its keys
    /// derived from `secret`. `id` is `lightning` (mainnet),
    /// `lightning::signet`, `lightning::mutinynet` or `lightning::regtest`.
    pub async fn open(
        id: NetworkId,
        secret: [u8; 32],
        datadir: &Path,
        config: &BarkConfig,
        span: &Span,
    ) -> Result<Self, String> {
        let (network, block_secs) = match id.param() {
            None => (BitcoinNetwork::Bitcoin, 600),
            Some("signet") => (BitcoinNetwork::Signet, 600),
            Some("mutinynet") => (BitcoinNetwork::Signet, 30),
            Some("regtest") => (BitcoinNetwork::Regtest, 600),
            Some(other) => return Err(format!("bark does not run on '{other}'")),
        };
        let seed: [u8; 64] = Sha512::new()
            .chain_update(b"cassis bark wallet")
            .chain_update(secret)
            .finalize()
            .into();
        let bark_config = Config {
            server_address: config.server_url.clone(),
            esplora_address: Some(config.esplora_url.clone()),
            ..Config::network_default(network)
        };
        let wallet = Wallet::open(
            network,
            WalletSeed::new_from_seed(network, &seed),
            bark_config,
            OpenWalletArgs {
                datadir: Some(datadir.to_path_buf()),
                ..Default::default()
            },
        )
        .await
        .map_err(|e| format!("open bark wallet: {e:#}"))?;
        let ark_info = wallet
            .require_ark_info()
            .await
            .map_err(|e| format!("Ark server {}: {e:#}", config.server_url))?;
        let min_cltv_delta = wallet
            .min_lightning_receive_cltv_delta()
            .await
            .map_err(|e| format!("Ark server: {e:#}"))?;
        let adapter = Self {
            span: cassis_core::network_span(span, &id),
            id,
            wallet,
            block_secs,
            htlc_expiry_delta: ark_info.htlc_expiry_delta.to_u16().into(),
            min_cltv_delta: min_cltv_delta.to_u16().into(),
            max_cltv_delta: ark_info.max_user_invoice_cltv_delta.to_u16().into(),
        };
        debug!(
            parent: &adapter.span,
            "bark wallet ready: server={} receive CLTV {}..{} blocks",
            config.server_url,
            adapter.min_cltv_delta,
            adapter.max_cltv_delta
        );
        Ok(adapter)
    }

    pub fn wallet(&self) -> &Wallet {
        &self.wallet
    }

    /// Sats that can be sent right now, after picking up payments sent to
    /// the wallet's Ark address.
    pub async fn spendable_sats(&self) -> Result<u64, NetworkError> {
        self.wallet.sync().await;
        let balance = self.wallet.balance().await.map_err(wallet_error)?;
        Ok(balance.spendable.to_sat())
    }

    /// A plain invoice of `sats` (with its own preimage) to fund the
    /// wallet over Lightning; the wallet claims it in the background.
    pub async fn funding_invoice(&self, sats: u64) -> Result<String, NetworkError> {
        let invoice = self
            .wallet
            .bolt11_invoice_builder()
            .amount(Amount::from_sat(sats))
            .description("cassis".to_string())
            .build()
            .await
            .map_err(wallet_error)?;
        Ok(invoice.to_string())
    }

    /// Drive the receive of a funding invoice until it is claimed.
    pub async fn claim_funding(&self, invoice: &str) -> Result<(), NetworkError> {
        let invoice = Bolt11Invoice::from_str(invoice).map_err(NetworkError::invalid)?;
        self.wallet
            .try_claim_lightning_receive(PaymentHash::from(&invoice), true)
            .await
            .map_err(wallet_error)?;
        Ok(())
    }
}

#[async_trait]
impl Network for BarkLightningAdapter {
    fn id(&self) -> NetworkId {
        self.id.clone()
    }

    /// The blocks a receive needs to exit its HTLC-recv VTXOs on-chain
    /// if the server stops cooperating, plus one of slack: the claim
    /// window closes that long before the incoming HTLC expires.
    fn incoming_delta_secs(&self) -> u64 {
        (self.min_cltv_delta + self.htlc_expiry_delta + 1) * self.block_secs
    }

    /// The longest CLTV the server grants a receive.
    fn max_incoming_lifetime_secs(&self) -> Option<u64> {
        Some((self.max_cltv_delta + self.htlc_expiry_delta) * self.block_secs)
    }

    async fn receive_target(
        &self,
        payment_hash: Bytes32,
        amount_msat: u64,
        expiry: u64,
    ) -> Result<HtlcTarget, NetworkError> {
        let hash = PaymentHash::from(payment_hash.0);
        let sats = amount_msat.div_ceil(MSAT_PER_SAT);
        if let Some(receive) = self
            .wallet
            .lightning_receive_checkpoint(hash)
            .await
            .map_err(wallet_error)?
        {
            if receive.invoice.amount_milli_satoshis() != Some(sats * MSAT_PER_SAT) {
                return Err(NetworkError::invalid(
                    "an invoice for this hash has another amount",
                ));
            }
            return Ok(HtlcTarget::LightningInvoice(receive.invoice.to_string()));
        }
        // The invoice's whole CLTV, the server's delta included, fits in
        // the time until `expiry`, within what the server accepts. Payers
        // lock at least `incoming_delta_secs`, which covers the minimum.
        let lifetime = expiry.saturating_sub(unix_now());
        let cltv_delta = (lifetime / self.block_secs)
            .saturating_sub(self.htlc_expiry_delta)
            .clamp(self.min_cltv_delta, self.max_cltv_delta);
        let invoice = self
            .wallet
            .bolt11_invoice_builder()
            .payment_hash(hash)
            .amount(Amount::from_sat(sats))
            .description("cassis".to_string())
            .cltv_delta(BlockDelta::new(cltv_delta as u16))
            .build()
            .await
            .map_err(wallet_error)?;
        Ok(HtlcTarget::LightningInvoice(invoice.to_string()))
    }

    /// Cancels the hold invoice while it is unpaid. Once the server holds
    /// the HTLCs it cannot be: without the preimage the receive is
    /// abandoned when its claim window closes.
    async fn cancel_receive(&self, payment_hash: Bytes32) -> Result<(), NetworkError> {
        let hash = PaymentHash::from(payment_hash.0);
        if let Err(error) = self.wallet.cancel_lightning_receive(hash).await {
            debug!(parent: &self.span, "not canceling {}: {error:#}", payment_hash.short());
        }
        Ok(())
    }

    async fn verify_incoming_htlc(&self, htlc: &Htlc) -> Result<(), NetworkError> {
        if htlc.descriptor != HtlcDescriptor::Lightning {
            return Err(NetworkError::invalid("not a lightning HTLC"));
        }
        let HtlcTarget::LightningInvoice(request) = &htlc.target else {
            return Err(NetworkError::invalid("lightning HTLCs pay an invoice"));
        };
        let invoice = parse_invoice(request, htlc.payment_hash)?;
        if invoice.amount_milli_satoshis().unwrap_or(0) < htlc.amount_msat {
            return Err(NetworkError::invalid("invoice is worth less than the HTLC"));
        }
        let hash = PaymentHash::from(htlc.payment_hash.0);
        // One step polls the server and, once it holds the HTLCs, takes
        // the HTLC-recv VTXOs it grants (checking their amount, hash and
        // timelocks).
        let state = self
            .wallet
            .try_claim_lightning_receive(hash, false)
            .await
            .map_err(wallet_error)?;
        let LightningReceiveState::InProgress(receive) = state else {
            return Err(NetworkError::invalid("this receive is already settled"));
        };
        if receive.invoice != invoice {
            return Err(NetworkError::invalid("HTLC is not addressed to this node"));
        }
        match receive.progress {
            Progress::AwaitingPayment => Err(NetworkError::not_yet("invoice is not paid yet")),
            Progress::HtlcsReady(_) => Ok(()),
            Progress::PreimageRevealed(_) | Progress::Delivering(_) => Err(NetworkError::invalid(
                "this receive is already being claimed",
            )),
        }
    }

    async fn claim_incoming_htlc(
        &self,
        htlc: &Htlc,
        preimage: Bytes32,
    ) -> Result<(), NetworkError> {
        let hash = PaymentHash::from(htlc.payment_hash.0);
        let state = self
            .wallet
            .provide_lightning_receive_preimage(hash, Preimage::from(preimage.0))
            .await
            .map_err(wallet_error)?;
        match state {
            LightningReceiveState::Settled(_) => {
                info!(parent: &self.span, "claimed {}", htlc.payment_hash.short());
                Ok(())
            }
            // The preimage is out; bark retries the claim.
            LightningReceiveState::InProgress(_) => {
                Err(NetworkError::network("claim is still in progress"))
            }
        }
    }

    async fn create_outgoing_htlc(
        &self,
        payment_hash: Bytes32,
        amount_msat: u64,
        _expiry: u64,
        target: &HtlcTarget,
    ) -> Result<HtlcDescriptor, NetworkError> {
        let HtlcTarget::LightningInvoice(payment_request) = target else {
            return Err(NetworkError::invalid("lightning HTLCs pay an invoice"));
        };
        let invoice = parse_invoice(payment_request, payment_hash)?;
        // Receivers in whole sats round the amount up.
        let invoice_msat = invoice.amount_milli_satoshis().unwrap_or(0);
        if invoice_msat < amount_msat || invoice_msat > amount_msat.next_multiple_of(MSAT_PER_SAT) {
            return Err(NetworkError::invalid(format!(
                "invoice amount {invoice_msat} msat is not the HTLC amount {amount_msat} msat"
            )));
        }
        // Resumes, rather than repeats, a send already started for this
        // hash.
        self.wallet
            .pay_lightning_invoice(invoice, None, false)
            .await
            .map_err(wallet_error)?;
        info!(parent: &self.span, "paying {invoice_msat} msat for {}", payment_hash.short());
        Ok(HtlcDescriptor::Lightning)
    }

    async fn check_outgoing_htlc(&self, htlc: &Htlc) -> Result<OutgoingState, NetworkError> {
        let hash = PaymentHash::from(htlc.payment_hash.0);
        match self
            .wallet
            .check_lightning_payment(hash, false)
            .await
            .map_err(wallet_error)?
        {
            LightningSendState::Paid(paid) => {
                Ok(OutgoingState::Claimed(Bytes32(paid.preimage.into())))
            }
            LightningSendState::InProgress(_) => Ok(OutgoingState::Pending),
            // A failed send is revoked and forgotten, its VTXOs back.
            LightningSendState::Unknown => Ok(OutgoingState::Refunded),
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

    async fn can_send(&self, amount_msat: u64) -> Result<(), NetworkError> {
        let amount = Amount::from_sat(amount_msat.div_ceil(MSAT_PER_SAT));
        let estimate = self
            .wallet
            .estimate_lightning_send_fee(amount)
            .await
            .map_err(wallet_error)?;
        let available = self.spendable_sats().await?;
        if available < estimate.gross_amount.to_sat() {
            return Err(NetworkError::invalid(format!(
                "need {} sats with the server's fee, wallet has {available} sats",
                estimate.gross_amount.to_sat()
            )));
        }
        Ok(())
    }

    /// The server's fee comes out of the payment itself.
    async fn can_receive(&self, amount_msat: u64) -> Result<(), NetworkError> {
        let amount = Amount::from_sat(amount_msat.div_ceil(MSAT_PER_SAT));
        self.wallet
            .estimate_lightning_receive_fee(amount)
            .await
            .map_err(|e| NetworkError::invalid(format!("bark cannot receive it: {e:#}")))?;
        Ok(())
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
