//! On-chain Bitcoin network adapter for cassis.
//!
//! HTLCs are P2TR outputs whose taproot tree has a *single script
//! leaf* in the Liquid contract shape (with an absolute *unix
//! timestamp* refund CLTV instead of a block height):
//!
//! ```text
//! OP_IF   OP_HASH160 <hash160(preimage)> OP_EQUALVERIFY
//!         <claim_pubkey> OP_CHECKSIG
//! OP_ELSE <refund_locktime> OP_CLTV OP_DROP <refund_pubkey>
//!         OP_CHECKSIG
//! OP_ENDIF
//! ```
//!
//! The taproot internal key is the BIP-341 Nothing-Up-My-Sleeve (NUMS)
//! point. It has no known discrete logarithm, so the HTLC key path is
//! intentionally unspendable; only the script leaf can spend the output.
//! All keys are x-only (BIP342 CHECKSIG), so network identities drop
//! straight into the script.
//!
//! * **Lockup** (outgoing HTLC): an on-chain transaction the sender
//!   pays for, sweeping its own P2TR UTXOs (key path); the HTLC
//!   output is the P2TR of the tweaked single-leaf tree above.
//! * **Claim** (incoming HTLC): witness
//!   `[sig, preimage, <true>, leaf_script, control_block]` — the
//!   explicit `OP_TRUE` selects the claim branch while the preimage
//!   stays on the stack for the hash check.
//! * **Refund**: once the unix locktime passes, witness
//!   `[sig, <empty>, leaf_script, control_block]` with the
//!   transaction locktime set.
//! * **Preimage observation** (for routing): when the counterparty
//!   claims our outgoing HTLC, its claim transaction embeds the
//!   preimage in the witness stack; we poll the chain for the spend
//!   and read it from there.
//!
//! Hash semantics: a cassis payment hash is SHA256(preimage), and the
//! script hashes with `OP_HASH160` = RIPEMD160(SHA256(x)), so the
//! script's preimage hash is RIPEMD160(payment_hash).
//!
//! BIP342 signatures: script-path CHECKSIGs sign with the *leaf*
//! pubkey tweaked alone (no branch commitment), independent of the
//! internal key — so `claim` signs with the receiver's key even
//! though the tree's internal key is the shared NUMS point.

use async_trait::async_trait;
use bitcoin::absolute;
use bitcoin::hashes::ripemd160;
use bitcoin::hashes::Hash;
use bitcoin::key::Keypair;
use bitcoin::key::Secp256k1;
use bitcoin::key::TapTweak;
use bitcoin::key::XOnlyPublicKey;
use bitcoin::opcodes::all::OP_CHECKSIG;
use bitcoin::opcodes::all::OP_CLTV;
use bitcoin::opcodes::all::OP_DROP;
use bitcoin::opcodes::all::OP_ELSE;
use bitcoin::opcodes::all::OP_ENDIF;
use bitcoin::opcodes::all::OP_EQUALVERIFY;
use bitcoin::opcodes::all::OP_HASH160;
use bitcoin::opcodes::all::OP_IF;
use bitcoin::script::Builder as ScriptBuilder;
use bitcoin::sighash::SighashCache;
use bitcoin::sighash::TapSighashType;
use bitcoin::taproot::LeafVersion;
use bitcoin::taproot::TapLeafHash;
use bitcoin::taproot::TaprootBuilder;
use bitcoin::transaction::Version;
use bitcoin::Address;
use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::Sequence;
use bitcoin::Transaction;
use bitcoin::TxIn;
use bitcoin::TxOut;
use bitcoin::Witness;
use cassis_core::split_spec;
use cassis_core::AcceptedIncoming;
use cassis_core::AdapterError;
use cassis_core::Bytes32;
use cassis_core::HtlcDescriptor;
use cassis_core::HtlcTarget;
use cassis_core::IncomingRequest;
use cassis_core::IncomingReservation;
use cassis_core::NetworkAdapter;
use cassis_core::NetworkId;
use cassis_core::OperationId;
use cassis_core::OutgoingPayment;
use cassis_core::OutgoingRequest;
use cassis_core::XOnlyPubKey;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::Span;
use tracing::{debug, info, warn};

const POLL_INTERVAL_SECS: u64 = 5;
const RPC_TIMEOUT_SECS: u64 = 30;
/// Millisatoshi per satoshi.
const MSAT_PER_SAT: u64 = 1000;
/// `nLockTime` values below this threshold are block heights; HTLCs
/// here always use unix timestamps.
const MIN_TIMESTAMP_LOCKTIME: u32 = 500_000_000;
/// Satoshis: below this an output is unrelayable.
const DUST_SATS: u64 = 330;
/// Default feerate (sat/vB) for lockup / claim / refund spends.
const DEFAULT_FEE_RATE_VB: u64 = 1;

/// Virtual-size surcharges from conservative witness estimates;
/// combined by [`vsize_for`].
const TX_OVERHEAD_VB: u64 = 11;
const P2TR_INPUT_VB: u64 = 58;
const HTLC_INPUT_VB: u64 = 68;
const P2TR_OUTPUT_VB: u64 = 43;
const HTLC_OUTPUT_VB: u64 = 43;

/// BIP-341's canonical Nothing-Up-My-Sleeve point, encoded as an
/// x-only public key. Its discrete logarithm is unknown, so using it as
/// the HTLC internal key makes key-path spending impossible.
const NUMS_INTERNAL_KEY: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

fn nums_internal_key() -> XOnlyPublicKey {
    XOnlyPublicKey::from_slice(&NUMS_INTERNAL_KEY)
        .expect("BIP-341 NUMS point is a valid x-only public key")
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid parameters: {0}")]
    InvalidParams(String),
    #[error("client error: {0}")]
    Client(String),
}

impl From<Error> for AdapterError {
    fn from(e: Error) -> AdapterError {
        match e {
            Error::InvalidParams(s) => AdapterError::InvalidParams(s),
            other => AdapterError::Network(other.to_string()),
        }
    }
}

pub struct BitcoinConfig {
    pub network_id: NetworkId,
    pub network: bitcoin::Network,
    pub esplora_url: String,
    /// Per-network signing key (derived from `cassis/network/<id>`).
    pub sk: [u8; 32],
    /// Feerate in sat/vB for every transaction this adapter broadcasts.
    pub fee_rate_vb: u64,
    pub span: Span,
}

pub const MAINNET_ESPLORA_URL: &str = "https://mempool.space/api";
pub const MUTINYNET_ESPLORA_URL: &str = "https://mutinynet.com/api";

/// Canonical config for `bitcoin` (mainnet) or `bitcoin::mutinynet`.
pub fn default_config(
    network_id: NetworkId,
    sk: [u8; 32],
    span: Span,
) -> Result<BitcoinConfig, String> {
    let kind = split_spec(&network_id.0).0.to_owned();
    if kind != "bitcoin" {
        return Err(format!(
            "cassis_bitcoin only handles the 'bitcoin' kind, got '{kind}'"
        ));
    }
    let param = split_spec(&network_id.0).1.map(str::to_owned);
    let mut cfg = BitcoinConfig {
        network_id,
        network: bitcoin::Network::Bitcoin,
        esplora_url: MAINNET_ESPLORA_URL.to_string(),
        sk,
        fee_rate_vb: DEFAULT_FEE_RATE_VB,
        span,
    };
    match param.as_deref() {
        None => Ok(cfg),
        Some("mutinynet") => {
            cfg.network = bitcoin::Network::Signet;
            cfg.esplora_url = MUTINYNET_ESPLORA_URL.to_string();
            Ok(cfg)
        }
        Some(other) => Err(format!(
            "network 'bitcoin' only accepts no parameter or 'mutinynet', got '{other}'"
        )),
    }
}

// ---------------------------------------------------------------------------
// Script helpers.
// ---------------------------------------------------------------------------

/// Build the HTLC taproot script leaf (see crate docs). Keys are
/// x-only: BIP342 CHECKSIG signs them directly. The hash check lives
/// inside the claim branch so the refund branch never executes any
/// hash-opcode consumption; the branch selector is an explicit
/// OP_TRUE / empty push, leaving the preimage free for OP_HASH160:
///
/// ```text
/// OP_IF OP_HASH160 <hash> OP_EQUALVERIFY <claim_pubkey> OP_CHECKSIG
/// OP_ELSE <locktime> OP_CLTV OP_DROP <refund_pubkey> OP_CHECKSIG
/// OP_ENDIF
/// ```
fn htlc_script(
    payment_hash160: &[u8; 20],
    claim_pubkey: &[u8; 32],
    refund_pubkey: &[u8; 32],
    refund_locktime: u32,
) -> ScriptBuf {
    ScriptBuilder::new()
        .push_opcode(OP_IF)
        .push_opcode(OP_HASH160)
        .push_slice(*payment_hash160)
        .push_opcode(OP_EQUALVERIFY)
        .push_slice(*claim_pubkey)
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_ELSE)
        .push_int(i64::from(refund_locktime))
        .push_opcode(OP_CLTV)
        .push_opcode(OP_DROP)
        .push_slice(*refund_pubkey)
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_ENDIF)
        .into_script()
}

/// Core x-only key -> bitcoin crate x-only key.
fn b_xonly(pk: &XOnlyPubKey) -> Result<XOnlyPublicKey, AdapterError> {
    XOnlyPublicKey::from_slice(pk.as_bytes())
        .map_err(|e| AdapterError::InvalidParams(format!("x-only key: {e}")))
}

fn lower_hex(bytes: &[u8]) -> String {
    use bitcoin::hex::DisplayHex as _;
    bytes.to_lower_hex_string()
}

// ---------------------------------------------------------------------------
// Adapter state.
// ---------------------------------------------------------------------------

/// A payment hash plus everything needed to rebuild the taproot
/// output and either spend path of it.
#[derive(Clone, Debug)]
struct HtlcOptions {
    payment_hash160: ripemd160::Hash,
    /// A txid-less descriptor can never be claim-verified, so the
    /// lockup outpoint rides along.
    lockup_txid: bitcoin::Txid,
    lockup_vout: u32,
    /// Receiver's claim leaf key.
    claim_pubkey: XOnlyPublicKey,
    /// Sender's refund leaf key.
    refund_pubkey: XOnlyPublicKey,
    refund_locktime: u32,
}

impl HtlcOptions {
    fn payment_hash160(payment_hash: &Bytes32) -> ripemd160::Hash {
        ripemd160::Hash::hash(payment_hash.as_ref())
    }

    fn witness_script(&self) -> ScriptBuf {
        htlc_script(
            &self.payment_hash160.to_byte_array(),
            &self.claim_pubkey.serialize(),
            &self.refund_pubkey.serialize(),
            self.refund_locktime,
        )
    }

    /// The P2TR output the HTLC locks into (tweaked output key of the
    /// single-leaf tree). Internal key is always fixed NUMS, never the
    /// wallet key.
    fn spend_info(
        &self,
        secp: &Secp256k1<bitcoin::secp256k1::VerifyOnly>,
    ) -> Result<bitcoin::taproot::TaprootSpendInfo, AdapterError> {
        TaprootBuilder::new()
            .add_leaf(0, self.witness_script())
            .map_err(|_| AdapterError::Network("taproot leaf insert failed".into()))?
            .finalize(secp, nums_internal_key())
            .map_err(|_| AdapterError::Network("taproot tree finalize failed".into()))
    }

    fn taproot_spk(&self, secp: &Secp256k1<bitcoin::secp256k1::VerifyOnly>) -> ScriptBuf {
        let info = self
            .spend_info(secp)
            .expect("single-leaf tree is always valid");
        ScriptBuf::new_p2tr_tweaked(info.output_key())
    }

    fn parse_descriptor(
        descriptor: &HtlcDescriptor,
        payment_hash: Bytes32,
        our_claim_pk: &XOnlyPublicKey,
    ) -> Result<Self, AdapterError> {
        let HtlcDescriptor::Bitcoin {
            lockup_txid,
            lockup_vout,
            payment_hash160,
            internal_key,
            refund_pubkey,
            refund_locktime,
        } = descriptor
        else {
            return Err(AdapterError::InvalidParams(
                "descriptor is not a bitcoin on-chain HTLC".into(),
            ));
        };
        let expected = ripemd160::Hash::hash(payment_hash.as_ref());
        let got = ripemd160::Hash::from_str(payment_hash160)
            .map_err(|e| AdapterError::InvalidParams(format!("bad payment_hash160: {e}")))?;
        if got != expected {
            return Err(AdapterError::InvalidParams(
                "descriptor hash160 does not match the route payment hash".into(),
            ));
        }
        if *refund_locktime < MIN_TIMESTAMP_LOCKTIME {
            return Err(AdapterError::InvalidParams(format!(
                "refund locktime {refund_locktime} is a block height; \
                 on-chain HTLCs use unix timestamps"
            )));
        }
        let lockup_txid = bitcoin::Txid::from_str(lockup_txid)
            .map_err(|e| AdapterError::InvalidParams(format!("bad lockup_txid: {e}")))?;
        if internal_key.as_bytes() != NUMS_INTERNAL_KEY.as_slice() {
            return Err(AdapterError::InvalidParams(
                "bitcoin HTLC internal key is not the BIP-341 NUMS point".into(),
            ));
        }
        Ok(Self {
            payment_hash160: expected,
            lockup_txid,
            lockup_vout: u32::from(*lockup_vout),
            claim_pubkey: *our_claim_pk,
            refund_pubkey: XOnlyPublicKey::from_slice(refund_pubkey.as_bytes())
                .map_err(|e| AdapterError::InvalidParams(format!("refund pubkey: {e}")))?,
            refund_locktime: *refund_locktime,
        })
    }

    fn descriptor(&self) -> Result<HtlcDescriptor, AdapterError> {
        Ok(HtlcDescriptor::Bitcoin {
            lockup_txid: self.lockup_txid.to_string(),
            lockup_vout: self.lockup_vout as u8,
            payment_hash160: lower_hex(&self.payment_hash160.to_byte_array()),
            internal_key: XOnlyPubKey::from_bytes(nums_internal_key().serialize())
                .map_err(|e| AdapterError::Network(format!("internal key: {e}")))?,
            refund_pubkey: XOnlyPubKey::from_bytes(self.refund_pubkey.serialize())
                .map_err(|e| AdapterError::Network(format!("refund pubkey: {e}")))?,
            refund_locktime: self.refund_locktime,
        })
    }
}

#[derive(Clone, Debug)]
struct PendingOutgoing {
    payment_hash: Bytes32,
    payment: OutgoingPayment,
    options: HtlcOptions,
}

#[derive(Clone, Debug)]
struct PendingIncoming {
    payment_hash: Bytes32,
    reservation: IncomingReservation,
    accepted: Option<AcceptedIncoming>,
    expected_sat: u64,
}

fn incoming_reservation_matches(
    pending: &PendingIncoming,
    reservation: &IncomingReservation,
) -> bool {
    pending.payment_hash == reservation.payment_hash && &pending.reservation == reservation
}

fn accepted_incoming_matches(left: &AcceptedIncoming, right: &AcceptedIncoming) -> bool {
    left.reservation == right.reservation
        && left.descriptor == right.descriptor
        && left.amount_msat == right.amount_msat
}

fn outgoing_request_matches(pending: &PendingOutgoing, request: &OutgoingRequest) -> bool {
    pending.payment_hash == request.payment_hash
        && pending.payment.operation_id == request.operation_id
        && pending.payment.amount_msat == request.amount_msat
        && pending.payment.destination == request.target
        && pending.payment.destination_network == request.network
        && pending.payment.expiry == request.expiry
}

fn outgoing_payment_matches(pending: &PendingOutgoing, payment: &OutgoingPayment) -> bool {
    pending.payment_hash == payment.payment_hash
        && pending.payment.operation_id == payment.operation_id
        && pending.payment.amount_msat == payment.amount_msat
        && pending.payment.destination == payment.destination
        && pending.payment.destination_network == payment.destination_network
        && pending.payment.expiry == payment.expiry
        && pending.payment.descriptor == payment.descriptor
}

pub struct BitcoinAdapter {
    network_id: NetworkId,
    #[allow(dead_code)] // reported via operator_summary-style info
    network: bitcoin::Network,
    #[allow(dead_code)] // printed at construction; useful in logs
    esplora_url: String,
    fee_rate_vb: u64,
    /// Owns the funding address (P2TR sweep cash, key path).
    wallet_sk: bitcoin::secp256k1::SecretKey,
    /// X-only half of `wallet_sk`: funding address key path, refund leaf
    /// key, and claim identity. HTLC internal keys are fixed NUMS, not
    /// this wallet key.
    key_xonly: XOnlyPublicKey,
    /// P2TR address wallet UTXOs are swept from and change returns to.
    funding_address: Address,
    client: Arc<esplora_client::AsyncClient>,
    span: Span,
    incoming: Mutex<HashMap<OperationId, PendingIncoming>>,
    outgoing: Mutex<HashMap<OperationId, PendingOutgoing>>,
}

impl BitcoinAdapter {
    pub async fn new(cfg: BitcoinConfig) -> Result<Self, Error> {
        let secp = Secp256k1::new();
        let wallet_sk = bitcoin::secp256k1::SecretKey::from_slice(&cfg.sk)
            .map_err(|e| Error::InvalidParams(format!("invalid per-network secret key: {e}")))?;
        let keypair = Keypair::from_secret_key(&secp, &wallet_sk);
        let (key_xonly, _parity) = keypair.x_only_public_key();
        let funding_address = Address::p2tr(&secp, key_xonly, None, cfg.network);
        let client = esplora_client::Builder::new(&cfg.esplora_url)
            .build_async()
            .map_err(|e| Error::Client(format!("esplora client: {e}")))?;

        cfg.span.in_scope(|| {
            info!(
                target: "cassis_bitcoin",
                "bitcoin adapter online on {} via {} funding={funding_address} claim={}",
                cfg.network_id, cfg.esplora_url, key_xonly
            );
        });

        Ok(Self {
            network_id: cfg.network_id,
            network: cfg.network,
            esplora_url: cfg.esplora_url,
            fee_rate_vb: cfg.fee_rate_vb,
            wallet_sk,
            key_xonly,
            funding_address,
            client: Arc::new(client),
            span: cfg.span,
            incoming: Mutex::new(HashMap::new()),
            outgoing: Mutex::new(HashMap::new()),
        })
    }

    fn unix_now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Validate reservation binding and every descriptor-controlled script
    /// property. NUMS assertion remains inside descriptor parsing.
    fn validate_incoming_descriptor(
        &self,
        reservation: &IncomingReservation,
        descriptor: &HtlcDescriptor,
    ) -> Result<HtlcOptions, AdapterError> {
        if reservation.network != self.network_id {
            return Err(AdapterError::InvalidParams(format!(
                "reservation targets {}, not {}",
                reservation.network, self.network_id
            )));
        }
        if reservation.target != HtlcTarget::XOnlyPubKey(self.claim_pubkey()) {
            return Err(AdapterError::InvalidParams(
                "incoming reservation has wrong Bitcoin claim target".into(),
            ));
        }
        let options = HtlcOptions::parse_descriptor(
            descriptor,
            reservation.payment_hash,
            &b_xonly(&self.claim_pubkey())?,
        )?;
        if options.claim_pubkey != self.key_xonly {
            return Err(AdapterError::InvalidParams(format!(
                "incoming HTLC is locked to {}, which this node cannot claim; \
                 upstream hop locked to the wrong claim key",
                options.claim_pubkey
            )));
        }
        if u64::from(options.refund_locktime) < reservation.deadline {
            return Err(AdapterError::InvalidParams(format!(
                "refund locktime {} precedes the claim deadline {}; the \
                 sender could race our claim",
                options.refund_locktime, reservation.deadline
            )));
        }
        Ok(options)
    }

    /// Confirm exact lockup outpoint is unspent and covers reservation.
    async fn observe_incoming_amount(
        &self,
        options: &HtlcOptions,
        expected_sat: u64,
    ) -> Result<u64, AdapterError> {
        let spk = options.taproot_spk(&Secp256k1::verification_only());
        let utxos = self.scan_unspent(&spk).await?;
        let value = utxos
            .iter()
            .find(|(outpoint, _)| {
                outpoint.txid == options.lockup_txid && outpoint.vout == options.lockup_vout
            })
            .map(|(_, value)| *value)
            .ok_or_else(|| {
                AdapterError::Network(format!(
                    "HTLC outpoint {}:{} is not unspent at its P2TR address",
                    options.lockup_txid, options.lockup_vout
                ))
            })?;
        if value.to_sat() < expected_sat {
            return Err(AdapterError::InvalidParams(format!(
                "Bitcoin HTLC amount {} sat below reserved {expected_sat} sat",
                value.to_sat()
            )));
        }
        value.to_sat().checked_mul(MSAT_PER_SAT).ok_or_else(|| {
            AdapterError::Network("observed Bitcoin amount overflows u64 millisatoshis".into())
        })
    }

    /// Parse complete outgoing recovery state using destination claim key.
    /// The fixed NUMS internal key is asserted by descriptor parsing.
    fn validate_outgoing_payment(
        &self,
        payment: &OutgoingPayment,
    ) -> Result<(HtlcOptions, XOnlyPubKey), AdapterError> {
        if payment.destination_network != self.network_id {
            return Err(AdapterError::InvalidParams(format!(
                "outgoing payment targets {}, not {}",
                payment.destination_network, self.network_id
            )));
        }
        let recipient = match &payment.destination {
            HtlcTarget::XOnlyPubKey(key) => *key,
            HtlcTarget::PubKey(_) | HtlcTarget::LightningInvoice(_) => {
                return Err(AdapterError::InvalidParams(
                    "Bitcoin requires an x-only destination".into(),
                ))
            }
        };
        let options = HtlcOptions::parse_descriptor(
            &payment.descriptor,
            payment.payment_hash,
            &b_xonly(&recipient)?,
        )?;
        if options.refund_pubkey != self.key_xonly {
            return Err(AdapterError::InvalidParams(
                "Bitcoin descriptor refund key is not this adapter".into(),
            ));
        }
        let expiry = u32::try_from(payment.expiry)
            .map_err(|_| AdapterError::InvalidParams("outgoing expiry overflows u32".into()))?;
        if options.refund_locktime != expiry {
            return Err(AdapterError::InvalidParams(
                "Bitcoin descriptor refund locktime does not match outgoing expiry".into(),
            ));
        }
        Ok((options, recipient))
    }

    /// The address test coins must be sent to so the wallet has
    /// spendable cash (also where change and claims return to).
    pub fn deposit_address(&self) -> String {
        self.funding_address.to_string()
    }

    /// Spendable wallet cash, in msat (sats * 1000).
    pub async fn balance_msat(&self) -> Result<u64, AdapterError> {
        let funding_spk = self.funding_address.script_pubkey();
        self.scan_unspent(&funding_spk).await.map(|utxos| {
            utxos
                .iter()
                .map(|(_, v)| v.to_sat())
                .sum::<u64>()
                .saturating_mul(MSAT_PER_SAT)
        })
    }

    /// Send `amount_msat` to `address` from the wallet's P2TR cash,
    /// change back to the funding address. Mirrors the lockup sweep
    /// but with a single P2TR recipient instead of an HTLC output.
    pub async fn transfer_to_address(
        &self,
        address: &str,
        amount_msat: u64,
    ) -> Result<bitcoin::Txid, AdapterError> {
        if !amount_msat.is_multiple_of(MSAT_PER_SAT) {
            return Err(AdapterError::InvalidParams(format!(
                "amount {amount_msat} msat is not a whole number of satoshis"
            )));
        }
        let amount_sat = amount_msat / MSAT_PER_SAT;
        if amount_sat < DUST_SATS {
            return Err(AdapterError::InvalidParams(format!(
                "amount {amount_sat} sats is below the dust limit of {DUST_SATS} sats"
            )));
        }
        let destination = Address::from_str(address)
            .map_err(|e| AdapterError::InvalidParams(format!("bad destination address: {e}")))?
            .require_network(self.network)
            .map_err(|e| {
                AdapterError::InvalidParams(format!("wrong network for destination: {e}"))
            })?;

        let funding_spk = self.funding_address.script_pubkey();
        let mut utxos = self.scan_unspent(&funding_spk).await?;
        utxos.sort_by_key(|(_, v)| std::cmp::Reverse(*v));
        let mut selected: Vec<(OutPoint, Amount)> = Vec::new();
        let mut gathered = 0u64;
        let mut fee = self.fee_for(Self::vsize_for(0, 0, 1, 0)).to_sat();
        let mut change_used = false;
        for utxo in &utxos {
            gathered += utxo.1.to_sat();
            selected.push(*utxo);
            change_used = gathered > amount_sat;
            if change_used {
                fee = self
                    .fee_for(Self::vsize_for(selected.len() as u64, 0, 2, 0))
                    .to_sat();
            } else {
                fee = self
                    .fee_for(Self::vsize_for(selected.len() as u64, 0, 1, 0))
                    .to_sat();
            }
            if gathered >= amount_sat + fee && (!change_used || gathered - amount_sat >= DUST_SATS)
            {
                break;
            }
        }
        if gathered < amount_sat + fee {
            return Err(AdapterError::Network(format!(
                "insufficient balance: sending {} sats needs {} sats with fee, wallet holds {gathered}",
                amount_sat,
                amount_sat + fee
            )));
        }
        let change = gathered.saturating_sub(amount_sat + fee);
        let mut outputs = vec![TxOut {
            value: Amount::from_sat(amount_sat),
            script_pubkey: destination.script_pubkey(),
        }];
        if change_used && change >= DUST_SATS {
            outputs.push(TxOut {
                value: Amount::from_sat(change),
                script_pubkey: funding_spk.clone(),
            });
        }

        let mut tx = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: selected
                .iter()
                .map(|(op, _)| TxIn {
                    previous_output: *op,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                })
                .collect(),
            output: outputs,
        };
        // P2TR key-path sweep: Schnorr signatures over the taproot
        // key-spend sighash of each funding input.
        let secp = Secp256k1::new();
        let wallet_pair = Keypair::from_secret_key(&secp, &self.wallet_sk);
        let tweaked_pair = wallet_pair.tap_tweak(&secp, None);
        let prevouts: Vec<TxOut> = selected
            .iter()
            .map(|(_, value)| TxOut {
                value: *value,
                script_pubkey: funding_spk.clone(),
            })
            .collect();
        let mut cache = SighashCache::new(&tx);
        let mut sigs = Vec::with_capacity(selected.len());
        for (idx, _) in selected.iter().enumerate() {
            let sh = cache
                .taproot_key_spend_signature_hash(
                    idx,
                    &bitcoin::sighash::Prevouts::All(&prevouts),
                    TapSighashType::Default,
                )
                .map_err(|e| AdapterError::Network(format!("taproot sighash: {e}")))?;
            let msg = bitcoin::secp256k1::Message::from_digest(*sh.as_ref());
            sigs.push(
                secp.sign_schnorr_no_aux_rand(&msg, tweaked_pair.as_keypair())
                    .serialize(),
            );
        }
        for (idx, sig) in sigs.into_iter().enumerate() {
            tx.input[idx].witness = Witness::from_slice(&[sig]);
        }
        self.broadcast(&tx, "wallet transfer").await
    }

    /// All unspent `(outpoint, value)` at `script`.
    async fn scan_unspent(
        &self,
        script: &ScriptBuf,
    ) -> Result<Vec<(OutPoint, Amount)>, AdapterError> {
        let txs = tokio::time::timeout(
            Duration::from_secs(RPC_TIMEOUT_SECS),
            self.client.scripthash_txs(script, None),
        )
        .await
        .map_err(|_| AdapterError::Network("scripthash_txs timed out".into()))?
        .map_err(|e| AdapterError::Network(format!("scripthash_txs: {e}")))?;
        let spent: std::collections::HashSet<OutPoint> = txs
            .iter()
            .flat_map(|tx| {
                tx.vin.iter().filter_map(|vin| {
                    vin.prevout.as_ref().map(|_| OutPoint {
                        txid: vin.txid,
                        vout: vin.vout,
                    })
                })
            })
            .collect();
        Ok(txs
            .iter()
            .flat_map(|tx| {
                tx.vout
                    .iter()
                    .enumerate()
                    .filter(|(_, out)| out.scriptpubkey == *script)
                    .map(move |(i, out)| {
                        (
                            OutPoint {
                                txid: tx.txid,
                                vout: i as u32,
                            },
                            Amount::from_sat(out.value),
                        )
                    })
            })
            .filter(|(outpoint, _)| !spent.contains(outpoint))
            .collect())
    }

    async fn tip_time(&self) -> Result<u64, AdapterError> {
        let height = tokio::time::timeout(
            Duration::from_secs(RPC_TIMEOUT_SECS),
            self.client.get_height(),
        )
        .await
        .map_err(|_| AdapterError::Network("get_height timed out".into()))?
        .map_err(|e| AdapterError::Network(format!("get_height: {e}")))?;
        let hash = self
            .client
            .get_block_hash(height)
            .await
            .map_err(|e| AdapterError::Network(format!("get_block_hash: {e}")))?;
        let block = self
            .client
            .get_block_by_hash(&hash)
            .await
            .map_err(|e| AdapterError::Network(format!("get_block_by_hash: {e}")))?
            .ok_or_else(|| {
                AdapterError::Network(format!("tip block {height} missing from explorer"))
            })?;
        Ok(u64::from(block.header.time))
    }

    async fn broadcast(&self, tx: &Transaction, what: &str) -> Result<bitcoin::Txid, AdapterError> {
        tokio::time::timeout(
            Duration::from_secs(RPC_TIMEOUT_SECS),
            self.client.broadcast(tx),
        )
        .await
        .map_err(|_| AdapterError::Network("broadcast timed out".into()))?
        .map_err(|e| AdapterError::Network(format!("broadcast failed: {e}")))?;
        let txid = tx.compute_txid();
        self.span.in_scope(|| {
            debug!(target: "cassis_bitcoin", "{what}: txid={txid}");
        });
        Ok(txid)
    }

    fn fee_for(&self, vsize: u64) -> Amount {
        Amount::from_sat(self.fee_rate_vb.saturating_mul(vsize))
    }

    /// vsize upper bound: `n_in` P2TR key-path + `htlc_in` HTLC
    /// inputs, `n_out` P2TR + `htlc_out` HTLC outputs.
    fn vsize_for(n_in: u64, htlc_in: u64, n_out: u64, htlc_out: u64) -> u64 {
        TX_OVERHEAD_VB
            + n_in * P2TR_INPUT_VB
            + htlc_in * HTLC_INPUT_VB
            + n_out * P2TR_OUTPUT_VB
            + htlc_out * HTLC_OUTPUT_VB
    }
}

// ---------------------------------------------------------------------------
// HTLC mechanics: lockup, claim, refund, prefix observation.
// ---------------------------------------------------------------------------

impl BitcoinAdapter {
    /// Sweep wallet UTXOs to pay the HTLC output, change back to the
    /// funding address. Returns the resulting outpoint slot.
    async fn lock_htlc(
        &self,
        request: &OutgoingRequest,
        options: HtlcOptions,
        amount_sat: u64,
        recipient_xonly: XOnlyPubKey,
    ) -> Result<PendingOutgoing, AdapterError> {
        let funding_spk = self.funding_address.script_pubkey();
        let refund_locktime = options.refund_locktime;
        let payment_hash = request.payment_hash;
        let mut utxos = self.scan_unspent(&funding_spk).await?;
        utxos.sort_by_key(|(_, v)| std::cmp::Reverse(*v));
        let mut selected: Vec<(OutPoint, Amount)> = Vec::new();
        let mut gathered = 0u64;
        let mut change_expected = false;
        let mut fee = self.fee_for(Self::vsize_for(0, 0, 1, 1)).to_sat();
        for utxo in &utxos {
            if gathered >= amount_sat + fee + DUST_SATS {
                break;
            }
            gathered += utxo.1.to_sat();
            selected.push(*utxo);
            fee = self
                .fee_for(Self::vsize_for(selected.len() as u64, 0, 2, 1))
                .to_sat();
            change_expected = gathered >= amount_sat + fee + DUST_SATS;
        }
        if gathered < amount_sat + fee {
            return Err(AdapterError::InvalidParams(format!(
                "insufficient bitcoin balance on {}: HTLC needs {} sats (with fee), \
                 wallet holds {gathered} sats",
                self.network_id,
                amount_sat + fee,
            )));
        }
        let change = gathered - (amount_sat + fee);

        let mut outputs = vec![TxOut {
            value: Amount::from_sat(amount_sat),
            script_pubkey: options.taproot_spk(&Secp256k1::verification_only()),
        }];
        if change_expected && change >= DUST_SATS {
            outputs.push(TxOut {
                value: Amount::from_sat(change),
                script_pubkey: funding_spk.clone(),
            });
        }

        let mut tx = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: selected
                .iter()
                .map(|(op, _)| TxIn {
                    previous_output: *op,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                })
                .collect(),
            output: outputs,
        };
        // P2TR key-path sweep: Schnorr signatures over the taproot
        // key-spend sighash of each funding input. Funding address key
        // is tweaked with no merkle root, matching `tap_tweak(None)`.
        let secp = Secp256k1::new();
        let wallet_pair = Keypair::from_secret_key(&secp, &self.wallet_sk);
        let tweaked_pair = wallet_pair.tap_tweak(&secp, None);

        let mut sigs = Vec::with_capacity(tx.input.len());
        let prevouts: Vec<TxOut> = selected
            .iter()
            .map(|(_, value)| TxOut {
                value: *value,
                script_pubkey: funding_spk.clone(),
            })
            .collect();
        {
            let mut cache = SighashCache::new(&tx);
            for (idx, _) in selected.iter().enumerate() {
                let sh = cache
                    .taproot_key_spend_signature_hash(
                        idx,
                        &bitcoin::sighash::Prevouts::All(&prevouts),
                        TapSighashType::Default,
                    )
                    .map_err(|e| AdapterError::Network(format!("taproot sighash: {e}")))?;
                let msg = bitcoin::secp256k1::Message::from_digest(*sh.as_ref());
                sigs.push(
                    secp.sign_schnorr_no_aux_rand(&msg, tweaked_pair.as_keypair())
                        .serialize()
                        .to_vec(),
                );
            }
        }
        for (idx, sig) in sigs.into_iter().enumerate() {
            tx.input[idx].witness = Witness::from_slice(&[sig]);
        }
        let txid = self.broadcast(&tx, "htlc lockup").await?;

        self.span.in_scope(|| {
            debug!(target: "cassis_bitcoin",
                "htlc locked {}: {amount_sat} sats (expiry {refund_locktime})",
                payment_hash.short()
            );
        });
        let mut stored_options = options;
        stored_options.lockup_txid = txid;
        stored_options.lockup_vout = 0;
        let descriptor = stored_options.descriptor()?;
        let payment = OutgoingPayment {
            operation_id: request.operation_id.clone(),
            payment_hash,
            amount_msat: request.amount_msat,
            destination: HtlcTarget::XOnlyPubKey(recipient_xonly),
            destination_network: request.network.clone(),
            expiry: request.expiry,
            descriptor,
        };
        Ok(PendingOutgoing {
            payment_hash,
            payment,
            options: stored_options,
        })
    }

    /// Claim (preimage path) or refund (CLTV path) of an HTLC input.
    async fn spend_htlc(
        &self,
        options: &HtlcOptions,
        preimage: Option<Bytes32>,
        destination: Address,
    ) -> Result<bitcoin::Txid, AdapterError> {
        if let Some(preimage) = preimage {
            let computed = ripemd160::Hash::hash(
                bitcoin::hashes::sha256::Hash::hash(preimage.as_ref()).as_ref(),
            );
            if computed != options.payment_hash160 {
                return Err(AdapterError::InvalidParams(
                    "preimage does not match the HTLC payment hash".into(),
                ));
            }
        }
        let witness_script = options.witness_script();
        let verify_secp = Secp256k1::verification_only();
        let spk = options.taproot_spk(&verify_secp);
        let utxos = self.scan_unspent(&spk).await?;
        let (outpoint, value) = utxos
            .iter()
            .find(|(o, _)| o.txid == options.lockup_txid && o.vout == options.lockup_vout)
            .copied()
            .ok_or_else(|| {
                AdapterError::Network(format!(
                    "HTLC outpoint {}:{} not found unspent at its script address",
                    options.lockup_txid, options.lockup_vout
                ))
            })?;

        if preimage.is_none() {
            let tip_time = self.tip_time().await?;
            if u64::from(options.refund_locktime) > tip_time {
                return Err(AdapterError::Retryable(format!(
                    "timelock not reached: tip_time={tip_time} refund_locktime={}",
                    options.refund_locktime
                )));
            }
        }

        let fee = self.fee_for(Self::vsize_for(0, 1, 1, 0));
        if value <= fee + Amount::from_sat(DUST_SATS) {
            return Err(AdapterError::Network(format!(
                "HTLC value {} sats cannot cover a {} sat claim fee plus dust",
                value.to_sat(),
                fee.to_sat()
            )));
        }
        let out_value = value - fee;
        let is_claim = preimage.is_some();
        let mut tx = Transaction {
            version: Version::TWO,
            // Refund spends gate on the CLTV; claims spend immediately.
            lock_time: if is_claim {
                absolute::LockTime::ZERO
            } else {
                absolute::LockTime::from_consensus(options.refund_locktime)
            },
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                // Non-final so the transaction locktime applies.
                sequence: Sequence::from_consensus(0xFFFFFFFE),
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: out_value,
                script_pubkey: destination.script_pubkey(),
            }],
        };
        let tree_info = options
            .spend_info(&verify_secp)
            .map_err(|e| AdapterError::Network(e.to_string()))?;
        // BIP342 semantics: script-path signatures are made with the
        // leaf pubkey tweaked on its own (no branch commitment); the
        // tweaking is keypair-local, a signing ctx suffices. The claim
        // branch embeds our claim x-only key (checked on accept) so its
        // secret is always ours; refunds sign with the refund leaf key.
        let signing_secp = Secp256k1::new();
        let claim_pair = Keypair::from_secret_key(&signing_secp, &self.wallet_sk);
        let wallet_pair = Keypair::from_secret_key(&signing_secp, &self.wallet_sk);
        let control_block = tree_info
            .control_block(&(witness_script.clone(), LeafVersion::TapScript))
            .ok_or_else(|| AdapterError::Network("control block missing for spend leaf".into()))?;
        let leaf_hash = TapLeafHash::from_script(&witness_script, LeafVersion::TapScript);
        let prevouts = [TxOut {
            value,
            script_pubkey: spk,
        }];
        let sighash = {
            let mut cache = SighashCache::new(&tx);
            cache
                .taproot_script_spend_signature_hash(
                    0,
                    &bitcoin::sighash::Prevouts::All(&prevouts),
                    leaf_hash,
                    TapSighashType::Default,
                )
                .map_err(|e| AdapterError::Network(format!("taproot sighash: {e}")))?
        };
        // BIP342: a script-path CHECKSIG signs with the leaf key
        // tweaked on its own (no branch commitment).
        let signing_pair = if is_claim { claim_pair } else { wallet_pair };
        let tweaked = signing_pair.tap_tweak(&signing_secp, None);
        let msg = bitcoin::secp256k1::Message::from_digest(*sighash.as_ref());
        let sig = signing_secp
            .sign_schnorr_no_aux_rand(&msg, tweaked.as_keypair())
            .serialize()
            .to_vec();
        // Witness items land on the stack in order: the signature sits
        // at the bottom (CHECKSIG pops it after the branch supplies
        // the pubkey), the preimage above it (OP_HASH160 pops it
        // inside the claim branch), and the OP_TRUE / empty branch
        // selector on top for OP_IF.
        let mut witness_items: Vec<Vec<u8>> = vec![sig];
        witness_items.extend(match preimage {
            Some(p) => vec![p.0.to_vec(), vec![1u8]],
            None => vec![Vec::new()],
        });
        witness_items.push(witness_script.to_bytes());
        witness_items.push(control_block.serialize());
        tx.input[0].witness = Witness::from_slice(&witness_items);
        self.broadcast(
            &tx,
            if is_claim {
                "htlc claim"
            } else {
                "htlc refund"
            },
        )
        .await
    }

    /// Spend tx where a witness item is the preimage → a claim of our
    /// outgoing HTLC.
    async fn scan_spend_preimage(
        &self,
        options: &HtlcOptions,
    ) -> Result<Option<(Bytes32, bitcoin::Txid)>, AdapterError> {
        let spk = options.taproot_spk(&Secp256k1::verification_only());
        let txs = tokio::time::timeout(
            Duration::from_secs(RPC_TIMEOUT_SECS),
            self.client.scripthash_txs(&spk, None),
        )
        .await
        .map_err(|_| AdapterError::Network("scripthash_txs timed out".into()))?
        .map_err(|e| AdapterError::Network(format!("scripthash_txs: {e}")))?;
        for spend_tx in &txs {
            for vin in &spend_tx.vin {
                let Some(prevout) = &vin.prevout else {
                    continue;
                };
                if prevout.scriptpubkey != spk {
                    continue;
                }
                if vin.txid != options.lockup_txid || vin.vout != options.lockup_vout {
                    continue;
                }
                let Some(spend) = self.get_tx(spend_tx.txid).await? else {
                    continue;
                };
                if let Some(preimage) = Self::preimage_from_spend(&spend, options) {
                    return Ok(Some((preimage, spend_tx.txid)));
                }
            }
        }
        Ok(None)
    }

    /// Parse the claim preimage out of a spend input, verifying it
    /// opens this HTLC's payment hash.
    fn preimage_from_spend(spend: &Transaction, options: &HtlcOptions) -> Option<Bytes32> {
        spend.input.iter().find_map(|txin| {
            let bytes: &[u8] = txin.witness.nth(1)?;
            if bytes.len() != 32 {
                return None;
            }
            let preimage = Bytes32(bytes.try_into().ok()?);
            let computed = ripemd160::Hash::hash(
                bitcoin::hashes::sha256::Hash::hash(preimage.as_ref()).as_ref(),
            );
            (computed == options.payment_hash160).then_some(preimage)
        })
    }

    async fn get_tx(&self, txid: bitcoin::Txid) -> Result<Option<Transaction>, AdapterError> {
        tokio::time::timeout(
            Duration::from_secs(RPC_TIMEOUT_SECS),
            self.client.get_tx(&txid),
        )
        .await
        .map_err(|_| AdapterError::Network("get_tx timed out".into()))?
        .map_err(|e| AdapterError::Network(format!("get_tx: {e}")))
    }
}

// ---------------------------------------------------------------------------
// Router adapter trait.
// ---------------------------------------------------------------------------

#[async_trait]
impl NetworkAdapter for BitcoinAdapter {
    fn network_id(&self) -> NetworkId {
        self.network_id.clone()
    }

    /// Claim identity: x-only half of per-network key. Taproot claim leaf
    /// embeds this key directly, so counterparties lock to it unchanged.
    fn claim_pubkey(&self) -> XOnlyPubKey {
        XOnlyPubKey::from_bytes(self.key_xonly.serialize()).expect("32 bytes is a valid x-only key")
    }

    /// On-chain money lands block-granular. Give router 300 s between
    /// locking and claim.
    fn incoming_delta_secs(&self) -> u64 {
        300
    }

    async fn reserve_incoming(
        &self,
        request: IncomingRequest,
    ) -> Result<IncomingReservation, AdapterError> {
        if let Some(preimage) = request.preimage {
            if !request.payment_hash.matches_preimage(&preimage) {
                return Err(AdapterError::InvalidParams(
                    "incoming preimage does not match payment hash".into(),
                ));
            }
        }

        let mut incoming = self.incoming.lock().await;
        if let Some(existing) = incoming.get(&request.operation_id) {
            if existing.payment_hash != request.payment_hash
                || existing.reservation.amount_msat != request.amount_msat
                || existing.reservation.deadline != request.deadline
            {
                return Err(AdapterError::InvalidParams(
                    "operation ID is already bound to different incoming state".into(),
                ));
            }
            return Ok(existing.reservation.clone());
        }
        if incoming
            .values()
            .any(|pending| pending.payment_hash == request.payment_hash)
        {
            return Err(AdapterError::Retryable(
                "Bitcoin payment hash already has an active operation".into(),
            ));
        }
        if request.deadline <= Self::unix_now() {
            return Err(AdapterError::InvalidParams("deadline in the past".into()));
        }
        let expected_sat = request.amount_msat.div_ceil(MSAT_PER_SAT).max(1);
        let reservation = IncomingReservation {
            operation_id: request.operation_id,
            payment_hash: request.payment_hash,
            network: self.network_id.clone(),
            amount_msat: request.amount_msat,
            deadline: request.deadline,
            target: HtlcTarget::XOnlyPubKey(self.claim_pubkey()),
        };
        incoming.insert(
            reservation.operation_id.clone(),
            PendingIncoming {
                payment_hash: reservation.payment_hash,
                reservation: reservation.clone(),
                accepted: None,
                expected_sat,
            },
        );
        Ok(reservation)
    }

    async fn cancel_incoming(&self, reservation: &IncomingReservation) -> Result<(), AdapterError> {
        let mut incoming = self.incoming.lock().await;
        let Some(pending) = incoming.get(&reservation.operation_id) else {
            // Cancellation retry after success is a no-op.
            return Ok(());
        };
        if !incoming_reservation_matches(pending, reservation) {
            return Err(AdapterError::InvalidParams(
                "incoming reservation does not match stored operation state".into(),
            ));
        }
        if pending.accepted.is_some() {
            return Err(AdapterError::InvalidParams(
                "cannot cancel an accepted incoming HTLC".into(),
            ));
        }
        incoming.remove(&reservation.operation_id);
        Ok(())
    }

    async fn accept_incoming(
        &self,
        reservation: &IncomingReservation,
        descriptor: &HtlcDescriptor,
    ) -> Result<AcceptedIncoming, AdapterError> {
        let expected_sat = {
            let incoming = self.incoming.lock().await;
            let pending = incoming.get(&reservation.operation_id).ok_or_else(|| {
                AdapterError::NotFound(format!(
                    "no incoming reservation for operation {}",
                    reservation.operation_id
                ))
            })?;
            if !incoming_reservation_matches(pending, reservation) {
                return Err(AdapterError::InvalidParams(
                    "incoming reservation does not match stored operation state".into(),
                ));
            }
            if let Some(accepted) = &pending.accepted {
                if &accepted.reservation == reservation && accepted.descriptor == *descriptor {
                    return Ok(accepted.clone());
                }
                return Err(AdapterError::InvalidParams(
                    "incoming operation is already accepted with different state".into(),
                ));
            }
            pending.expected_sat
        };

        let options = self.validate_incoming_descriptor(reservation, descriptor)?;
        let amount_msat = self.observe_incoming_amount(&options, expected_sat).await?;
        if amount_msat < reservation.amount_msat {
            return Err(AdapterError::InvalidParams(format!(
                "Bitcoin HTLC amount {amount_msat} msat below reserved {} msat",
                reservation.amount_msat
            )));
        }
        let accepted = AcceptedIncoming {
            reservation: reservation.clone(),
            descriptor: descriptor.clone(),
            amount_msat,
        };

        let mut incoming = self.incoming.lock().await;
        let pending = incoming.get_mut(&reservation.operation_id).ok_or_else(|| {
            AdapterError::NotFound(format!(
                "incoming operation {} disappeared during acceptance",
                reservation.operation_id
            ))
        })?;
        if !incoming_reservation_matches(pending, reservation) {
            return Err(AdapterError::InvalidParams(
                "incoming reservation changed during acceptance".into(),
            ));
        }
        if let Some(existing) = &pending.accepted {
            if accepted_incoming_matches(existing, &accepted) {
                return Ok(existing.clone());
            }
            return Err(AdapterError::InvalidParams(
                "incoming operation is already accepted with different state".into(),
            ));
        }
        pending.accepted = Some(accepted.clone());
        Ok(accepted)
    }

    async fn restore_incoming(&self, accepted: &AcceptedIncoming) -> Result<(), AdapterError> {
        {
            let incoming = self.incoming.lock().await;
            if let Some(existing) = incoming.get(&accepted.reservation.operation_id) {
                if !incoming_reservation_matches(existing, &accepted.reservation) {
                    return Err(AdapterError::InvalidParams(
                        "operation ID is already bound to different incoming state".into(),
                    ));
                }
                if let Some(stored) = &existing.accepted {
                    if accepted_incoming_matches(stored, accepted) {
                        return Ok(());
                    }
                    return Err(AdapterError::InvalidParams(
                        "operation ID is already bound to different accepted state".into(),
                    ));
                }
            }
        }
        let options =
            self.validate_incoming_descriptor(&accepted.reservation, &accepted.descriptor)?;
        let expected_sat = accepted
            .reservation
            .amount_msat
            .div_ceil(MSAT_PER_SAT)
            .max(1);
        let expected_msat = expected_sat.checked_mul(MSAT_PER_SAT).ok_or_else(|| {
            AdapterError::InvalidParams("reserved Bitcoin amount overflows u64".into())
        })?;
        if accepted.amount_msat < accepted.reservation.amount_msat
            || accepted.amount_msat < expected_msat
        {
            return Err(AdapterError::InvalidParams(
                "accepted incoming amount is below reservation amount".into(),
            ));
        }
        let observed_msat = self.observe_incoming_amount(&options, expected_sat).await?;
        if observed_msat != accepted.amount_msat {
            return Err(AdapterError::InvalidParams(format!(
                "restored incoming amount {observed_msat} msat does not match accepted {} msat",
                accepted.amount_msat
            )));
        }

        let mut incoming = self.incoming.lock().await;
        if let Some(existing) = incoming.get(&accepted.reservation.operation_id) {
            if !incoming_reservation_matches(existing, &accepted.reservation) {
                return Err(AdapterError::InvalidParams(
                    "operation ID is already bound to different incoming state".into(),
                ));
            }
            if let Some(stored) = &existing.accepted {
                if accepted_incoming_matches(stored, accepted) {
                    return Ok(());
                }
                return Err(AdapterError::InvalidParams(
                    "operation ID is already bound to different accepted state".into(),
                ));
            }
        } else if incoming
            .values()
            .any(|pending| pending.payment_hash == accepted.reservation.payment_hash)
        {
            return Err(AdapterError::Retryable(
                "Bitcoin payment hash already has an active operation".into(),
            ));
        }
        incoming.insert(
            accepted.reservation.operation_id.clone(),
            PendingIncoming {
                payment_hash: accepted.reservation.payment_hash,
                reservation: accepted.reservation.clone(),
                accepted: Some(accepted.clone()),
                expected_sat,
            },
        );
        Ok(())
    }

    async fn watch_incoming(
        &self,
        reservation: &IncomingReservation,
        deadline: u64,
    ) -> Result<(), AdapterError> {
        let effective_deadline = deadline.min(reservation.deadline);
        loop {
            {
                let incoming = self.incoming.lock().await;
                let pending = incoming.get(&reservation.operation_id).ok_or_else(|| {
                    AdapterError::NotFound(format!(
                        "no incoming reservation for operation {}",
                        reservation.operation_id
                    ))
                })?;
                if !incoming_reservation_matches(pending, reservation) {
                    return Err(AdapterError::InvalidParams(
                        "incoming reservation does not match stored operation state".into(),
                    ));
                }
                if pending.accepted.is_some() {
                    return Ok(());
                }
            }
            if Self::unix_now() >= effective_deadline {
                return Err(AdapterError::DeadlineExceeded);
            }
            tokio::time::sleep(Duration::from_secs(POLL_INTERVAL_SECS)).await;
        }
    }

    async fn claim_incoming(
        &self,
        accepted: &AcceptedIncoming,
        preimage: Bytes32,
    ) -> Result<(), AdapterError> {
        let options =
            self.validate_incoming_descriptor(&accepted.reservation, &accepted.descriptor)?;
        let expected_sat = accepted
            .reservation
            .amount_msat
            .div_ceil(MSAT_PER_SAT)
            .max(1);
        let expected_msat = expected_sat.checked_mul(MSAT_PER_SAT).ok_or_else(|| {
            AdapterError::InvalidParams("reserved Bitcoin amount overflows u64".into())
        })?;
        if accepted.amount_msat < expected_msat {
            return Err(AdapterError::InvalidParams(
                "accepted incoming amount is below reservation amount".into(),
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
        {
            let incoming = self.incoming.lock().await;
            let Some(pending) = incoming.get(&accepted.reservation.operation_id) else {
                // Successful claim already removed state. Same-handle retry
                // is complete.
                return Ok(());
            };
            let stored = pending.accepted.as_ref().ok_or_else(|| {
                AdapterError::InvalidParams(format!(
                    "incoming operation {} is not accepted",
                    accepted.reservation.operation_id
                ))
            })?;
            if !incoming_reservation_matches(pending, &accepted.reservation)
                || !accepted_incoming_matches(stored, accepted)
            {
                return Err(AdapterError::InvalidParams(
                    "accepted incoming state does not match reservation".into(),
                ));
            }
        }
        let txid = self
            .spend_htlc(&options, Some(preimage), self.funding_address.clone())
            .await?;
        self.span.in_scope(|| {
            info!(target: "cassis_bitcoin",
                "incoming htlc claimed {}: tx={txid}",
                accepted.reservation.payment_hash.short());
        });
        self.incoming
            .lock()
            .await
            .remove(&accepted.reservation.operation_id);
        Ok(())
    }

    async fn claim_reserved_incoming(
        &self,
        reservation: &IncomingReservation,
        preimage: Bytes32,
    ) -> Result<(), AdapterError> {
        let accepted = {
            let incoming = self.incoming.lock().await;
            let slot = incoming.get(&reservation.operation_id).ok_or_else(|| {
                AdapterError::NotFound(format!(
                    "no incoming Bitcoin reservation for operation {}",
                    reservation.operation_id
                ))
            })?;
            slot.accepted.clone().ok_or(AdapterError::Unimplemented)
        }?;
        self.claim_incoming(&accepted, preimage).await
    }

    async fn create_outgoing(
        &self,
        request: OutgoingRequest,
    ) -> Result<OutgoingPayment, AdapterError> {
        // Keep lock through external funding. Concurrent retries for one
        // operation must not broadcast two HTLCs.
        let mut outgoing = self.outgoing.lock().await;
        if let Some(existing) = outgoing.get(&request.operation_id) {
            if outgoing_request_matches(existing, &request) {
                return Ok(existing.payment.clone());
            }
            return Err(AdapterError::InvalidParams(
                "operation ID is already bound to different outgoing state".into(),
            ));
        }
        if outgoing
            .values()
            .any(|pending| pending.payment_hash == request.payment_hash)
        {
            return Err(AdapterError::Retryable(
                "Bitcoin payment hash already has an active operation".into(),
            ));
        }
        if request.network != self.network_id {
            return Err(AdapterError::InvalidParams(format!(
                "outgoing payment targets {}, not {}",
                request.network, self.network_id
            )));
        }
        let recipient_xonly = match &request.target {
            HtlcTarget::XOnlyPubKey(key) => *key,
            HtlcTarget::PubKey(_) | HtlcTarget::LightningInvoice(_) => {
                return Err(AdapterError::InvalidParams(
                    "bitcoin requires a pubkey target".into(),
                ))
            }
        };
        if !request.amount_msat.is_multiple_of(MSAT_PER_SAT) {
            return Err(AdapterError::InvalidParams(format!(
                "amount {} msat is not a whole number of satoshis",
                request.amount_msat
            )));
        }
        let amount_sat = request.amount_msat / MSAT_PER_SAT;
        if amount_sat < DUST_SATS {
            return Err(AdapterError::InvalidParams(format!(
                "amount {amount_sat} sats is below the dust limit of {DUST_SATS} sats"
            )));
        }
        if request.expiry < u64::from(MIN_TIMESTAMP_LOCKTIME) {
            return Err(AdapterError::InvalidParams(format!(
                "expiry {} looks like a block height; on-chain HTLCs use \
                 unix timestamps (>= {MIN_TIMESTAMP_LOCKTIME})",
                request.expiry
            )));
        }
        if request.expiry <= Self::unix_now() {
            return Err(AdapterError::InvalidParams(format!(
                "expiry {} is in the past",
                request.expiry
            )));
        }
        let refund_locktime = u32::try_from(request.expiry).map_err(|error| {
            AdapterError::InvalidParams(format!("expiry overflows u32: {error}"))
        })?;
        let options = HtlcOptions {
            payment_hash160: HtlcOptions::payment_hash160(&request.payment_hash),
            // Placeholder never crosses wire. Broadcast path replaces it
            // with real lockup outpoint before descriptor creation.
            lockup_txid: bitcoin::Txid::from_slice(&[0u8; 32]).expect("all-zero txid"),
            lockup_vout: 0,
            claim_pubkey: b_xonly(&recipient_xonly)?,
            refund_pubkey: self.key_xonly,
            refund_locktime,
        };
        let pending = self
            .lock_htlc(&request, options, amount_sat, recipient_xonly)
            .await?;
        let payment = pending.payment.clone();
        outgoing.insert(payment.operation_id.clone(), pending);
        Ok(payment)
    }

    async fn watch_outgoing(
        &self,
        payment: &OutgoingPayment,
        deadline: u64,
    ) -> Result<Bytes32, AdapterError> {
        let options = {
            let outgoing = self.outgoing.lock().await;
            let pending = outgoing.get(&payment.operation_id).ok_or_else(|| {
                AdapterError::NotFound(format!("no outgoing operation {}", payment.operation_id))
            })?;
            if !outgoing_payment_matches(pending, payment) {
                return Err(AdapterError::InvalidParams(
                    "outgoing payment does not match stored operation state".into(),
                ));
            }
            pending.options.clone()
        };
        loop {
            if Self::unix_now() >= deadline {
                return Err(AdapterError::DeadlineExceeded);
            }
            match self.scan_spend_preimage(&options).await {
                Ok(Some((preimage, spend_txid))) => {
                    if !payment.payment_hash.matches_preimage(&preimage) {
                        return Err(AdapterError::Network(
                            "observed preimage does not match outgoing payment hash".into(),
                        ));
                    }
                    self.span.in_scope(|| {
                        info!(target: "cassis_bitcoin",
                            "preimage observed for {}: spend={spend_txid}",
                            payment.payment_hash.short());
                    });
                    return Ok(preimage);
                }
                Ok(None) => {}
                Err(error) => {
                    self.span.in_scope(|| {
                        warn!(target: "cassis_bitcoin", "outgoing settlement poll failed: {error}");
                    });
                }
            }
            tokio::time::sleep(Duration::from_secs(POLL_INTERVAL_SECS)).await;
        }
    }

    async fn refund_outgoing(&self, payment: &OutgoingPayment) -> Result<(), AdapterError> {
        self.validate_outgoing_payment(payment)?;
        let options = {
            let outgoing = self.outgoing.lock().await;
            let Some(pending) = outgoing.get(&payment.operation_id) else {
                // Successful refund already removed state. Same-handle retry
                // is complete.
                return Ok(());
            };
            if !outgoing_payment_matches(pending, payment) {
                return Err(AdapterError::InvalidParams(
                    "outgoing payment does not match stored operation state".into(),
                ));
            }
            pending.options.clone()
        };
        let txid = self
            .spend_htlc(&options, None, self.funding_address.clone())
            .await?;
        self.span.in_scope(|| {
            info!(target: "cassis_bitcoin",
                "outgoing htlc refunded {}: tx={txid}",
                payment.payment_hash.short());
        });
        self.outgoing.lock().await.remove(&payment.operation_id);
        Ok(())
    }

    async fn restore_outgoing(&self, payment: &OutgoingPayment) -> Result<(), AdapterError> {
        let mut outgoing = self.outgoing.lock().await;
        if let Some(existing) = outgoing.get(&payment.operation_id) {
            if outgoing_payment_matches(existing, payment) {
                return Ok(());
            }
            return Err(AdapterError::InvalidParams(
                "operation ID is already bound to different outgoing state".into(),
            ));
        }
        if outgoing
            .values()
            .any(|pending| pending.payment_hash == payment.payment_hash)
        {
            return Err(AdapterError::Retryable(
                "Bitcoin payment hash already has an active operation".into(),
            ));
        }
        let (options, _recipient) = self.validate_outgoing_payment(payment)?;
        let spk = options.taproot_spk(&Secp256k1::verification_only());
        let utxos = self.scan_unspent(&spk).await?;
        let value = utxos
            .iter()
            .find(|(outpoint, _)| {
                outpoint.txid == options.lockup_txid && outpoint.vout == options.lockup_vout
            })
            .map(|(_, value)| *value)
            .ok_or_else(|| {
                AdapterError::Network(format!(
                    "Bitcoin HTLC outpoint {}:{} is not unspent during recovery",
                    options.lockup_txid, options.lockup_vout
                ))
            })?;
        let value_msat = value.to_sat().checked_mul(MSAT_PER_SAT).ok_or_else(|| {
            AdapterError::Network("recovered Bitcoin amount overflows u64".into())
        })?;
        if value_msat < payment.amount_msat {
            return Err(AdapterError::InvalidParams(
                "Bitcoin recovered HTLC amount is below payment amount".into(),
            ));
        }
        outgoing.insert(
            payment.operation_id.clone(),
            PendingOutgoing {
                payment_hash: payment.payment_hash,
                payment: payment.clone(),
                options,
            },
        );
        Ok(())
    }

    async fn restore_incoming_reservation(
        &self,
        reservation: &IncomingReservation,
    ) -> Result<(), AdapterError> {
        let restored = self
            .reserve_incoming(IncomingRequest {
                operation_id: reservation.operation_id.clone(),
                payment_hash: reservation.payment_hash,
                amount_msat: reservation.amount_msat,
                deadline: reservation.deadline,
                preimage: None,
            })
            .await?;
        if restored == *reservation {
            Ok(())
        } else {
            Err(AdapterError::InvalidParams(
                "restored Bitcoin reservation differs from persisted state".into(),
            ))
        }
    }

    async fn can_route(&self, amount_msat: u64) -> Result<(), AdapterError> {
        let funding_spk = self.funding_address.script_pubkey();
        let utxos = self.scan_unspent(&funding_spk).await?;
        let available = utxos.iter().fold(0u64, |total, (_, value)| {
            total.saturating_add(value.to_sat())
        });
        if available.saturating_mul(MSAT_PER_SAT) < amount_msat {
            return Err(AdapterError::InvalidParams(format!(
                "insufficient bitcoin balance on {}: need {amount_msat} msat, \
                 wallet holds {available} sats",
                self.network_id
            )));
        }
        Ok(())
    }

    /// Claim output comes entirely from incoming HTLC, including fee money;
    /// no separate wallet balance is required.
    async fn can_claim(&self, _amount_msat: u64) -> Result<(), AdapterError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_kinds() {
        let sk = [1u8; 32];

        let cfg = default_config(NetworkId("bitcoin".to_string()), sk, Span::none()).unwrap();
        assert_eq!(cfg.network, bitcoin::Network::Bitcoin);
        assert_eq!(cfg.esplora_url, MAINNET_ESPLORA_URL);

        let cfg = default_config(
            NetworkId("bitcoin::mutinynet".to_string()),
            sk,
            Span::none(),
        )
        .unwrap();
        assert_eq!(cfg.network, bitcoin::Network::Signet);
        assert_eq!(cfg.esplora_url, MUTINYNET_ESPLORA_URL);

        let mut other = default_config(NetworkId("bitcoin::foo".to_string()), sk, Span::none())
            .err()
            .unwrap()
            .to_string();
        other.make_ascii_lowercase();
        assert!(other.starts_with("network 'bitcoin' only accepts"));
    }

    #[test]
    fn htlc_script_is_taproot_leaf() {
        let hash = [7u8; 20];
        let secp = Secp256k1::signing_only();
        let xonly_of = |seed: u8| -> [u8; 32] {
            bitcoin::key::Keypair::from_secret_key(
                &secp,
                &bitcoin::secp256k1::SecretKey::from_slice(&[seed; 32]).unwrap(),
            )
            .x_only_public_key()
            .0
            .serialize()
        };
        let claim = xonly_of(2);
        let refund = xonly_of(3);
        let script = htlc_script(&hash, &claim, &refund, 700_000_000);
        let bytes = script.as_bytes();
        // OP_IF opener, then OP_HASH160 + hash right after it,
        // closed by OP_EQUALVERIFY (0x88) so the claim branch leaves
        // the signature on the stack for CHECKSIG.
        assert_eq!(bytes[0], 0x63_u8);
        assert_eq!(bytes[1], 0xA9_u8);
        assert_eq!(&bytes[3..23], &hash);
        assert_eq!(bytes[23], 0x88_u8);
        // Refund tail: OP_ELSE already seen; final opcodes are
        // OP_CHECKSIG + OP_ENDIF.
        assert_eq!(bytes[bytes.len() - 2..], [0xACu8, 0x68u8]);

        // The single-leaf taproot tree over the script produces a
        // valid P2TR bech32 address.
        let options = HtlcOptions {
            payment_hash160: ripemd160::Hash::from_byte_array(hash),
            lockup_txid: "0000000000000000000000000000000000000000000000000000000000000000"
                .parse()
                .unwrap(),
            lockup_vout: 0,
            claim_pubkey: bitcoin::XOnlyPublicKey::from_slice(&claim).unwrap(),
            refund_pubkey: bitcoin::XOnlyPublicKey::from_slice(&refund).unwrap(),
            refund_locktime: 700_000_000,
        };
        let secp = Secp256k1::verification_only();
        let info = options.spend_info(&secp).unwrap();
        assert_eq!(info.internal_key().serialize(), NUMS_INTERNAL_KEY);
        let spk = ScriptBuf::new_p2tr_tweaked(info.output_key());
        let address = Address::from_script(&spk, bitcoin::Network::Bitcoin).unwrap();
        assert!(address.to_string().starts_with("bc1"));

        // A control block exists for the leaf (claim/refund spin on
        // their existence at spend time).
        let control_block = info
            .control_block(&(options.witness_script(), LeafVersion::TapScript))
            .expect("single-leaf tree has a control block");
        assert_eq!(control_block.internal_key.serialize(), NUMS_INTERNAL_KEY);
    }

    #[test]
    fn descriptor_accepts_nums_and_rejects_other_internal_keys() {
        let secp = Secp256k1::signing_only();
        let xonly_of = |seed: u8| -> [u8; 32] {
            bitcoin::key::Keypair::from_secret_key(
                &secp,
                &bitcoin::secp256k1::SecretKey::from_slice(&[seed; 32]).unwrap(),
            )
            .x_only_public_key()
            .0
            .serialize()
        };
        let payment_hash = Bytes32([7u8; 32]);
        let descriptor = HtlcDescriptor::Bitcoin {
            lockup_txid: "0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            lockup_vout: 0,
            payment_hash160: lower_hex(
                &HtlcOptions::payment_hash160(&payment_hash).to_byte_array(),
            ),
            internal_key: XOnlyPubKey::from_bytes(NUMS_INTERNAL_KEY).unwrap(),
            refund_pubkey: XOnlyPubKey::from_bytes(xonly_of(3)).unwrap(),
            refund_locktime: 700_000_000,
        };
        let our_claim_pk = bitcoin::XOnlyPublicKey::from_slice(&xonly_of(2)).unwrap();
        HtlcOptions::parse_descriptor(&descriptor, payment_hash, &our_claim_pk)
            .expect("canonical NUMS descriptor must parse");

        let mut bad_descriptor = descriptor;
        let HtlcDescriptor::Bitcoin { internal_key, .. } = &mut bad_descriptor else {
            unreachable!()
        };
        *internal_key = XOnlyPubKey::from_bytes(xonly_of(9)).unwrap();
        let err = HtlcOptions::parse_descriptor(&bad_descriptor, payment_hash, &our_claim_pk)
            .expect_err("non-NUMS internal keys must be rejected");
        assert!(err.to_string().contains("NUMS"));
    }

    #[test]
    fn tap_spend_is_deterministic_schnorr() {
        // A script-path signature verifies against the leaf key
        // tweaked on its own (BIP342), exercising the same path the
        // adapter uses for claims and refunds.
        let secp = Secp256k1::new();
        let pair = bitcoin::key::Keypair::from_secret_key(
            &secp,
            &bitcoin::secp256k1::SecretKey::from_slice(&[5u8; 32]).unwrap(),
        );
        let tweaked = pair.tap_tweak(&secp, None);
        let msg = bitcoin::secp256k1::Message::from_digest([6u8; 32]);
        let sig = secp.sign_schnorr_no_aux_rand(&msg, tweaked.as_keypair());
        let pubkey: bitcoin::XOnlyPublicKey = tweaked.public_parts().0.into();
        secp.verify_schnorr(&sig, &msg, &pubkey).unwrap();
    }
}
