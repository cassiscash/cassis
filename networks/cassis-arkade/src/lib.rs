//! Arkade network adapter for cassis.
//!
//! Implements [`NetworkRouterAdapter`] on top of an Arkade operator
//! (arkd) using the Arkade Rust SDK. HTLCs are Arkade
//! VHTLCs (`ark_core::vhtlc::VhtlcScript`, a taproot tree with six
//! spending paths):
//!
//! * **Lockup** (outgoing HTLC): a plain offchain send of VTXOs to
//!   the VHTLC address. Instant, offchain.
//! * **Claim** (incoming HTLC): the receiver reveals the preimage in
//!   the witness and signs; the operator co-signs the collaborative
//!   claim path during submitTx/finalizeTx.
//! * **Refund**: once the chain tip's block time passes the absolute
//!   `refund_locktime` timestamp, the sender spends via the "refund
//!   without receiver" path, again co-signed by the operator.
//! * **Preimage observation** (for routing): when the counterparty
//!   claims our outgoing VHTLC, the preimage is embedded in the spend
//!   transaction's PSBT under the `condition` unknown field; we poll
//!   the indexer for the spent outpoint and decode it.
//!
//! Hash semantics: a cassis payment hash is SHA256(preimage), and the
//! VHTLC script hashes with `OP_HASH160` = RIPEMD160(SHA256(x)), so
//! the script's preimage hash is RIPEMD160(payment_hash).

pub mod esplora;

use ark_bdk_wallet::Wallet as BdkWallet;
use ark_client::BoltzReferralId;
use ark_client::Client;
use ark_client::InMemorySwapStorage;
use ark_client::OfflineClient;
use ark_client::OfflineClientConfig;
use ark_core::send::build_offchain_transactions;
use ark_core::send::sign_ark_transaction;
use ark_core::send::sign_checkpoint_transaction;
use ark_core::send::OffchainTransactions;
use ark_core::send::SendReceiver;
use ark_core::send::VtxoInput;
use ark_core::server::VirtualTxOutPoint;
use ark_core::vhtlc::VhtlcOptions;
use ark_core::vhtlc::VhtlcScript;
use ark_core::ArkAddress;
use ark_core::Asset;
use ark_core::VTXO_CONDITION_KEY;
use async_trait::async_trait;
use bitcoin::absolute;
use bitcoin::consensus::Decodable;
use bitcoin::hashes::ripemd160;
use bitcoin::hashes::sha256;
use bitcoin::hashes::Hash;
use bitcoin::key::Keypair;
use bitcoin::key::Secp256k1;
use bitcoin::psbt;
use bitcoin::relative;
use bitcoin::secp256k1::schnorr;
use bitcoin::secp256k1::Message;
use bitcoin::taproot::LeafVersion;
use bitcoin::Sequence;
use bitcoin::VarInt;
use bitcoin::XOnlyPublicKey;
use cassis_core::{
    Bytes32, HtlcDescriptor, HtlcError, HtlcTarget, NetworkId, NetworkRouterAdapter, OutgoingHtlc,
    OutgoingPayment, WatchError, XOnlyPubKey,
};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::Once;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{debug, info, warn, Span};

/// Public mainnet operator. Serves gRPC + REST on 443.
pub const MAINNET_SERVER_URL: &str = "https://arkade.computer";
/// Public mutinynet operator ("testnet" for cassis purposes).
pub const TESTNET_SERVER_URL: &str = "https://mutinynet.arkade.sh";
const MAINNET_ESPLORA_URL: &str = "https://mempool.space/api";
const TESTNET_ESPLORA_URL: &str = "https://mutinynet.com/api";

// The operator re-validates every tapscript leaf of a VHTLC whenever
// a spend of it is registered, and unless it is itself configured
// with a block-based batch expiry -- the public Arkade operators are
// seconds-based -- it rejects block-based timelocks outright
// ("INVALID_VTXO_SCRIPT ... block type not allowed"). Every timelock
// below is therefore expressed in seconds: the CSV delays as BIP68
// seconds-type sequences, the refund CLTV as a unix timestamp.

/// CSV delay (seconds) for the unilateral claim path of HTLCs locked
/// by us: how long the downstream hop must wait to claim without
/// operator cooperation after unilaterally exiting. Small enough
/// that it is not a burden, large enough to be a meaningful escape
/// hatch.
const UNILATERAL_CLAIM_DELAY_SECS: u32 = 12 * 60 * 60;
/// How much later (seconds) the sender-alone unilateral refund path
/// opens compared to the receiver's unilateral claim path. The
/// receiver needs a strict head start: with the operator gone, a
/// refund path opening at or before the claim path would let the
/// sender race the receiver for funds the preimage already entitles
/// the receiver to.
const UNILATERAL_REFUND_GAP_SECS: u32 = 12 * 60 * 60;
/// `nLockTime` values below this threshold are block heights, values
/// at or above it unix timestamps (Bitcoin consensus rule; the
/// operator applies the same cutoff to the refund CLTV).
const MIN_TIMESTAMP_LOCKTIME: u32 = 500_000_000;

const POLL_INTERVAL_SECS: u64 = 5;
const RPC_TIMEOUT_SECS: u64 = 30;
/// Millisatoshi per satoshi.
const MSAT_PER_SAT: u64 = 1000;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid parameters: {0}")]
    InvalidParams(String),
    #[error("client error: {0}")]
    Client(String),
}

impl From<Error> for HtlcError {
    fn from(e: Error) -> HtlcError {
        match e {
            Error::InvalidParams(s) => HtlcError::InvalidParams(s),
            other => HtlcError::Network(other.to_string()),
        }
    }
}

impl From<Error> for WatchError {
    fn from(e: Error) -> WatchError {
        WatchError::Network(e.to_string())
    }
}

/// Convenience conversion into the routing layer's network error.
fn htlc(e: impl std::fmt::Display) -> HtlcError {
    HtlcError::Network(e.to_string())
}

#[derive(Clone, Debug)]
pub struct ArkadeConfig {
    pub network_id: NetworkId,
    /// gRPC endpoint of the operator (e.g. `https://mutinynet.arkade.sh`).
    pub server_url: String,
    pub esplora_url: String,
    /// 32-byte secret key derived from `cassis/network/<network_id>`.
    /// The adapter claims incoming VHTLCs with its x-only pubkey.
    pub sk: [u8; 32],
    pub invoice_pubkey: XOnlyPubKey,
    pub span: Span,
}

/// Canonical config for `arkade` (mainnet) or `arkade::testnet`
/// (mutinynet). Callers may override any field before constructing.
pub fn default_config(
    network_id: NetworkId,
    sk: [u8; 32],
    invoice_pubkey: XOnlyPubKey,
    span: Span,
) -> ArkadeConfig {
    match network_id.0.as_str() {
        "arkade::testnet" => ArkadeConfig {
            network_id,
            server_url: TESTNET_SERVER_URL.to_string(),
            esplora_url: TESTNET_ESPLORA_URL.to_string(),
            sk,
            invoice_pubkey,
            span: span.clone(),
        },
        _ => ArkadeConfig {
            network_id,
            server_url: MAINNET_SERVER_URL.to_string(),
            esplora_url: MAINNET_ESPLORA_URL.to_string(),
            sk,
            invoice_pubkey,
            span,
        },
    }
}

fn bitcoin_network(network_id: &NetworkId) -> bitcoin::Network {
    match network_id.0.as_str() {
        // Mutinynet is signet-based (tb1.. addresses).
        "arkade::testnet" => bitcoin::Network::Signet,
        _ => bitcoin::Network::Bitcoin,
    }
}

/// RIPEMD160 of the route's 32-byte payment hash: the 20-byte value
/// burned into the VHTLC script. Equals HASH160(preimage), since the
/// payment hash is SHA256(preimage).
fn vhtlc_payment_hash160(payment_hash: &Bytes32) -> ripemd160::Hash {
    ripemd160::Hash::hash(payment_hash.as_ref())
}

/// A CSV delay measured the way the operator compares exit delays
/// when validating a VTXO script: seconds-type sequences count their
/// real seconds (512-second granularity), height-type ones a nominal
/// one second per block.
fn exit_delay_secs(delay: Sequence) -> u32 {
    match delay.to_relative_lock_time() {
        Some(relative::LockTime::Time(time)) => u32::from(time.value()) * 512,
        Some(relative::LockTime::Blocks(height)) => u32::from(height.value()),
        None => 0,
    }
}

fn msat_to_sat_amount(amount_msat: u64) -> Result<bitcoin::Amount, HtlcError> {
    if amount_msat % MSAT_PER_SAT != 0 {
        return Err(HtlcError::InvalidParams(format!(
            "amount {amount_msat} msat is not a whole number of satoshis; \
             arkade amounts must be multiples of {MSAT_PER_SAT} msat"
        )));
    }
    Ok(bitcoin::Amount::from_sat(amount_msat / MSAT_PER_SAT))
}

type ArkClient = Client<esplora::EsploraBlockchain, BdkWallet, InMemorySwapStorage>;

struct PendingIncoming {
    /// Set only once a descriptor has been accepted via DISPATCH or a
    /// COMMIT. A bare `register_incoming_htlc` reservation (invoice
    /// creation) does not know the script yet, because the upstream
    /// hop picks sender/server/delays freely.
    options: Option<VhtlcOptions>,
    expected_sat: bitcoin::Amount,
    /// Kept for parity with the reserved-slot bookkeeping model of the
    /// other adapters (the PREPARE deadline); not polled directly.
    #[allow(dead_code)]
    deadline: u64,
}

struct PendingOutgoing {
    options: VhtlcOptions,
    /// Recorded so diagnostics can render who the lock targeted.
    #[allow(dead_code)]
    recipient: XOnlyPubKey,
}

/// A pair built from one unspent VTXO at a VHTLC address.
struct UnspentVtxo {
    outpoint: bitcoin::OutPoint,
    amount: bitcoin::Amount,
    assets: Vec<Asset>,
}

pub struct ArkadeAdapter {
    network_id: NetworkId,
    invoice_pubkey: XOnlyPubKey,
    span: Span,
    /// The operator rejects scripts whose smallest exit (CSV) delay is
    /// shorter than its advertised unilateral exit delay, measured via
    /// [`exit_delay_secs`]; our delays are floored at this.
    exit_delay_floor_secs: u32,
    keypair: Keypair,
    claim_xonly: XOnlyPublicKey,
    claim_pubkey: XOnlyPubKey,
    /// Operator signer key reported by GetInfo. Descriptor transfers
    /// only round-trip inside one operator, so accept-time checks
    /// compare against this.
    server_pk_xonly: XOnlyPublicKey,
    dust: bitcoin::Amount,
    client: Arc<ArkClient>,
    chain: Arc<esplora::EsploraBlockchain>,
    incoming: Mutex<HashMap<Bytes32, PendingIncoming>>,
    outgoing: Mutex<HashMap<Bytes32, PendingOutgoing>>,
}

impl std::fmt::Debug for ArkadeAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArkadeAdapter")
            .field("network_id", &self.network_id)
            .field("claim_pubkey", &self.claim_pubkey.to_hex())
            .finish_non_exhaustive()
    }
}

impl ArkadeAdapter {
    pub async fn new(config: ArkadeConfig) -> Result<Arc<Self>, Error> {
        install_rustls_crypto_provider();

        let secp = Secp256k1::new();
        let secret = bitcoin::secp256k1::SecretKey::from_slice(&config.sk)
            .map_err(|e| Error::InvalidParams(format!("invalid secret key: {e}")))?;
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let claim_xonly = keypair.x_only_public_key().0;
        let claim_pubkey = XOnlyPubKey::from_bytes(claim_xonly.serialize())
            .map_err(|e| Error::InvalidParams(format!("invalid claim pubkey: {e}")))?;

        let chain =
            Arc::new(esplora::EsploraBlockchain::new(&config.esplora_url).map_err(Error::Client)?);
        let wallet = Arc::new(
            BdkWallet::new(
                keypair,
                bitcoin_network(&config.network_id),
                &config.esplora_url,
            )
            .map_err(|e| Error::Client(format!("bdk wallet init: {e}")))?,
        );
        let client_config = OfflineClientConfig {
            ark_server_url: config.server_url.clone(),
            boltz_url: String::new(),
            boltz_referral_id: BoltzReferralId::Disabled,
            ..Default::default()
        };
        let client = Arc::new(
            OfflineClient::with_keypair(
                client_config,
                keypair,
                chain.clone(),
                wallet,
                Arc::new(InMemorySwapStorage::new()),
            )
            .connect()
            .await
            .map_err(|e| Error::Client(format!("operator connect ({config:?}): {e}")))?,
        );

        let info = client
            .server_info()
            .await
            .map_err(|e| Error::Client(format!("get_info: {e}")))?;
        let server_pk_xonly = XOnlyPublicKey::from(info.signer_pk);
        let exit_delay_floor_secs = exit_delay_secs(info.unilateral_exit_delay);

        let span = cassis_core::network_span(&config.span, &config.network_id);
        span.in_scope(|| {
            debug!(
                target: "cassis_arkade",
                "adapter ready: operator={} signer={} claim={} dust={} sats exit_floor={}s",
                config.server_url,
                server_pk_xonly,
                claim_xonly,
                info.dust.to_sat(),
                exit_delay_floor_secs,
            );
        });

        Ok(Arc::new(Self {
            network_id: config.network_id.clone(),
            invoice_pubkey: config.invoice_pubkey,
            span,
            exit_delay_floor_secs,
            keypair,
            claim_xonly,
            claim_pubkey,
            server_pk_xonly,
            dust: info.dust,
            client,
            chain,
            incoming: Mutex::new(HashMap::new()),
            outgoing: Mutex::new(HashMap::new()),
        }))
    }

    fn unix_now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Decode an [`HtlcDescriptor::Arkade`] back into VHTLC options.
    fn parse_vhtlc_options(descriptor: &HtlcDescriptor) -> Result<VhtlcOptions, HtlcError> {
        let HtlcDescriptor::Arkade {
            sender,
            receiver,
            server,
            payment_hash160,
            refund_locktime,
            unilateral_claim_delay,
            unilateral_refund_delay,
            unilateral_refund_without_receiver_delay,
        } = descriptor
        else {
            return Err(HtlcError::InvalidParams(format!(
                "unsupported htlc descriptor for arkade network: {descriptor:?}"
            )));
        };
        let parse_xonly = |key: &XOnlyPubKey| -> Result<XOnlyPublicKey, HtlcError> {
            XOnlyPublicKey::from_slice(key.as_bytes())
                .map_err(|e| HtlcError::InvalidParams(format!("invalid x-only pubkey: {e}")))
        };
        let parse_hash = |hex: &String| -> Result<ripemd160::Hash, HtlcError> {
            let bytes = lowercase_hex_decode(hex).ok_or_else(|| {
                HtlcError::InvalidParams(format!("invalid payment hash160 '{hex}'"))
            })?;
            let arr: [u8; 20] = match bytes.try_into() {
                Ok(arr) => arr,
                Err(moved) => {
                    return Err(HtlcError::InvalidParams(format!(
                        "payment hash160 must be 20 bytes, got {}",
                        moved.len()
                    )));
                }
            };
            Ok(ripemd160::Hash::from_byte_array(arr))
        };
        // The descriptor carries consensus sequence numbers, so they
        // round-trip bit-for-bit (seconds-type sequences set bit 22 and
        // would be mangled by any blocks-vs-seconds heuristic).
        let parse_sequence = |u: u32| -> Result<Sequence, HtlcError> {
            let sequence = Sequence::from_consensus(u);
            if !sequence.is_relative_lock_time() {
                return Err(HtlcError::InvalidParams(format!(
                    "invalid CSV delay: {u} is not a relative locktime"
                )));
            }
            Ok(sequence)
        };

        Ok(VhtlcOptions {
            sender: parse_xonly(sender)?,
            receiver: parse_xonly(receiver)?,
            server: parse_xonly(server)?,
            preimage_hash: parse_hash(payment_hash160)?,
            refund_locktime: *refund_locktime,
            unilateral_claim_delay: parse_sequence(*unilateral_claim_delay)?,
            unilateral_refund_delay: parse_sequence(*unilateral_refund_delay)?,
            unilateral_refund_without_receiver_delay: parse_sequence(
                *unilateral_refund_without_receiver_delay,
            )?,
        })
    }

    fn descriptor_from_options(options: &VhtlcOptions) -> HtlcDescriptor {
        HtlcDescriptor::Arkade {
            sender: XOnlyPubKey::from_bytes(options.sender.serialize())
                .expect("Arkade sender key is valid"),
            receiver: XOnlyPubKey::from_bytes(options.receiver.serialize())
                .expect("Arkade receiver key is valid"),
            server: XOnlyPubKey::from_bytes(options.server.serialize())
                .expect("Arkade server key is valid"),
            payment_hash160: lowercase_hex_encode(options.preimage_hash.as_byte_array()),
            refund_locktime: options.refund_locktime,
            unilateral_claim_delay: options.unilateral_claim_delay.to_consensus_u32(),
            unilateral_refund_delay: options.unilateral_refund_delay.to_consensus_u32(),
            unilateral_refund_without_receiver_delay: options
                .unilateral_refund_without_receiver_delay
                .to_consensus_u32(),
        }
    }

    fn build_options_for_outgoing(
        &self,
        payment_hash: &Bytes32,
        recipient: &XOnlyPubKey,
        expiry: u64,
    ) -> Result<VhtlcOptions, HtlcError> {
        let now = Self::unix_now();
        if expiry <= now {
            return Err(HtlcError::InvalidParams("expiry in the past".into()));
        }
        let recipient_xonly = XOnlyPublicKey::from_str(recipient.to_hex().as_str())
            .map_err(|e| HtlcError::InvalidParams(format!("invalid recipient pubkey: {e}")))?;
        // The refund CLTV takes the route expiry directly: cassis
        // expiries are unix seconds, and the operator checks timestamp
        // locktimes against the chain tip's block time.
        let refund_locktime = u32::try_from(expiry).map_err(|_| {
            HtlcError::InvalidParams(format!("expiry {expiry} overflows nLockTime"))
        })?;
        if refund_locktime < MIN_TIMESTAMP_LOCKTIME {
            return Err(HtlcError::InvalidParams(format!(
                "expiry {expiry} is not an absolute unix timestamp"
            )));
        }

        let unilateral_claim_delay = self.exit_delay(UNILATERAL_CLAIM_DELAY_SECS)?;
        // The sender-alone exit opens a strict gap after the
        // receiver's claim exit (see [`UNILATERAL_REFUND_GAP_SECS`]),
        // measured from the claim delay's actual (floored, 512s-
        // granular) value so the ordering survives any operator floor.
        let unilateral_refund_without_receiver_delay = Sequence::from_seconds_ceil(
            exit_delay_secs(unilateral_claim_delay).saturating_add(UNILATERAL_REFUND_GAP_SECS),
        )
        .map_err(|e| HtlcError::InvalidParams(format!("CSV delay out of range: {e}")))?;

        Ok(VhtlcOptions {
            sender: self.claim_xonly,
            receiver: recipient_xonly,
            server: self.server_pk_xonly,
            // `payment_hash160` is HASH160(preimage), represented by
            // the RIPEMD160 of cassis' SHA256 payment hash.
            preimage_hash: vhtlc_payment_hash160(payment_hash),
            refund_locktime,
            unilateral_claim_delay,
            // The joint sender+receiver refund needs the receiver's
            // signature, so it is safe at the earliest delay the
            // operator accepts; only the sender-alone path must wait
            // out the receiver's head start.
            unilateral_refund_delay: unilateral_claim_delay,
            unilateral_refund_without_receiver_delay,
        })
    }

    /// A seconds-type CSV sequence of at least `secs`, floored at the
    /// operator's minimum exit delay.
    fn exit_delay(&self, secs: u32) -> Result<Sequence, HtlcError> {
        Sequence::from_seconds_ceil(secs.max(self.exit_delay_floor_secs))
            .map_err(|e| HtlcError::InvalidParams(format!("CSV delay out of range: {e}")))
    }

    fn script_for(&self, options: &VhtlcOptions) -> Result<VhtlcScript, HtlcError> {
        VhtlcScript::new(options.clone(), bitcoin_network(&self.network_id)).map_err(htlc)
    }

    /// Timestamp of the chain tip block: what the operator holds
    /// timestamp CLTVs against (not the wall clock).
    async fn tip_time(&self) -> Result<u64, Error> {
        self.chain
            .tip_time()
            .await
            .map_err(|e| Error::Client(format!("esplora tip_time: {e}")))
    }

    /// All VTXO outpoints (spent or not) at the given VHTLC address.
    async fn outpoints_at_address(
        &self,
        vhtlc: &VhtlcScript,
    ) -> Result<Vec<VirtualTxOutPoint>, Error> {
        self.client
            .get_virtual_tx_outpoints(std::iter::once(vhtlc.address()))
            .await
            .map_err(|e| Error::Client(format!("get_virtual_tx_outpoints: {e}")))
    }

    /// The single unspent VTXO at the VHTLC address.
    async fn unspent_vtxo_at(&self, options: &VhtlcOptions) -> Result<UnspentVtxo, HtlcError> {
        let vhtlc = self.script_for(options)?;
        let mut unspent: Vec<UnspentVtxo> = self
            .outpoints_at_address(&vhtlc)
            .await
            .map_err(htlc)?
            .into_iter()
            .filter(|o| !o.is_spent && !o.is_swept && o.amount > bitcoin::Amount::ZERO)
            .map(|o| UnspentVtxo {
                outpoint: o.outpoint,
                amount: o.amount,
                assets: o.assets,
            })
            .collect();
        match unspent.len() {
            1 => Ok(unspent.remove(0)),
            0 => Err(HtlcError::Network(
                "no unspent VTXO found at the VHTLC address".into(),
            )),
            n => Err(HtlcError::Network(format!(
                "expected one VTXO at the VHTLC address, found {n}"
            ))),
        }
    }

    async fn our_offchain_address(&self) -> Result<ArkAddress, HtlcError> {
        self.client
            .get_offchain_address()
            .await
            .map(|(addr, _)| addr)
            .map_err(|e| HtlcError::Network(format!("get_offchain_address: {e}")))
    }

    /// Sign closure helper: schnorr-sign an offchain sighash with the
    /// adapter's per-network keypair. When a preimage is given it is
    /// embedded under the `condition` unknown PSBT field (see below).
    fn signer_with(
        &self,
        preimage: Option<&[u8; 32]>,
    ) -> impl Fn(
        &mut psbt::Input,
        Message,
    ) -> Result<Vec<(schnorr::Signature, XOnlyPublicKey)>, ark_core::Error>
           + Clone {
        let keypair = self.keypair;
        let preimage = preimage.copied();
        move |input: &mut psbt::Input,
              msg: Message|
              -> Result<Vec<(schnorr::Signature, XOnlyPublicKey)>, ark_core::Error> {
            if let Some(preimage_bytes) = preimage {
                // Embed the preimage under the `condition` unknown PSBT
                // field: `[witness element count][varint len][preimage]`.
                // Matches the SDK's own encoding (see boltz claims); the
                // finalizer turns this into the first witness element so
                // `OP_HASH160 <hash> EQUALVERIFY` pops it. The length is
                // always 32 (< 253), so a single-byte varint is exact.
                debug_assert_eq!(preimage_bytes.len(), 32);
                let mut condition = vec![1u8, preimage_bytes.len() as u8];
                condition.extend_from_slice(&preimage_bytes);
                input.unknown.insert(
                    psbt::raw::Key {
                        type_value: 222,
                        key: VTXO_CONDITION_KEY.to_vec(),
                    },
                    condition,
                );
            }

            let sig = Secp256k1::new().sign_schnorr_no_aux_rand(&msg, &keypair);
            Ok(vec![(sig, keypair.x_only_public_key().0)])
        }
    }

    /// Build + sign + submit + finalize a single-input VHTLC spend
    /// over `spend_script`. Shared by claim and refund flows. The
    /// signer closure is applied to both the Arkade transaction input and
    /// the first checkpoint PSBT (mirroring the SDK's swap flows).
    async fn submit_vhtlc_spend(
        &self,
        input: VtxoInput,
        outputs: &[SendReceiver],
        change_address: &ArkAddress,
        sign_fn: impl Fn(
                &mut psbt::Input,
                Message,
            ) -> Result<Vec<(schnorr::Signature, XOnlyPublicKey)>, ark_core::Error>
            + Clone,
    ) -> Result<bitcoin::Txid, HtlcError> {
        let server_info = self
            .client
            .server_info()
            .await
            .map_err(|e| HtlcError::Network(format!("server_info: {e}")))?;

        let OffchainTransactions {
            mut ark_tx,
            checkpoint_txs,
        } = build_offchain_transactions(
            outputs,
            change_address,
            std::slice::from_ref(&input),
            &server_info,
        )
        .map_err(htlc)?;

        sign_ark_transaction(sign_fn.clone(), &mut ark_tx, 0).map_err(htlc)?;
        let ark_txid = ark_tx.unsigned_tx.compute_txid();

        let res = tokio::time::timeout(
            Duration::from_secs(RPC_TIMEOUT_SECS),
            self.client
                .network_client()
                .submit_offchain_transaction_request(ark_tx, checkpoint_txs),
        )
        .await
        .map_err(|_| HtlcError::Network("submit_offchain_transaction_request timed out".into()))?
        .map_err(htlc)?;

        let mut checkpoint_psbt = res
            .signed_checkpoint_txs
            .first()
            .cloned()
            .ok_or_else(|| HtlcError::Network("no checkpoint PSBTs returned".into()))?;
        sign_checkpoint_transaction(sign_fn.clone(), &mut checkpoint_psbt).map_err(htlc)?;

        tokio::time::timeout(
            Duration::from_secs(RPC_TIMEOUT_SECS),
            self.client
                .network_client()
                .finalize_offchain_transaction(ark_txid, vec![checkpoint_psbt]),
        )
        .await
        .map_err(|_| HtlcError::Network("finalize_offchain_transaction timed out".into()))?
        .map_err(htlc)?;

        Ok(ark_txid)
    }

    /// Collaborative claim: spends the incoming VHTLC back into our
    /// own offchain script using the reveal-preimage leaf.
    async fn claim_locked_htlc(
        &self,
        payment_hash: Bytes32,
        preimage: Bytes32,
    ) -> Result<(), HtlcError> {
        let slot = {
            let incoming = self.incoming.lock().await;
            match incoming.get(&payment_hash) {
                Some(slot) => slot.options.clone(),
                None => None,
            }
        };
        let Some(options) = slot else {
            return Err(HtlcError::InvalidParams(format!(
                "no incoming HTLC registered for {payment_hash:?}"
            )));
        };

        // Revealed preimage must satisfy both the script hash and the
        // route hash; anything else means an inconsistent upstream.
        let sha = sha256::Hash::hash(preimage.as_ref());
        let computed_payment_hash = Bytes32(sha.to_byte_array());
        if computed_payment_hash != payment_hash
            || ripemd160::Hash::hash(computed_payment_hash.as_ref()) != options.preimage_hash
        {
            return Err(HtlcError::InvalidParams(
                "preimage does not hash to the HTLC's payment hash".into(),
            ));
        }

        let vhtlc = self.script_for(&options)?;
        let vtxo = self.unspent_vtxo_at(&options).await?;

        self.span.in_scope(|| {
            info!(
                target: "cassis_arkade",
                "claiming htlc {} amount={} sats on {}",
                payment_hash.short(),
                vtxo.amount.to_sat(),
                self.network_id,
            );
        });

        let our_address = self.our_offchain_address().await?;
        let claim_script = vhtlc.claim_script();
        let control_block = vhtlc
            .taproot_spend_info()
            .control_block(&(claim_script.clone(), LeafVersion::TapScript))
            .ok_or_else(|| HtlcError::Network("control block missing for claim leaf".into()))?;
        let script_pubkey = vhtlc.script_pubkey();
        // `tapscripts` consumes the script: collect it last.
        let tapscripts = vhtlc.tapscripts();
        let input = VtxoInput::new(
            claim_script,
            None,
            control_block,
            tapscripts,
            script_pubkey,
            vtxo.amount,
            vtxo.outpoint,
            vtxo.assets,
        );
        let outputs = vec![SendReceiver::bitcoin(our_address.clone(), vtxo.amount)];

        let txid = self
            .submit_vhtlc_spend(
                input,
                &outputs,
                &our_address,
                self.signer_with(Some(&preimage.0)),
            )
            .await?;

        self.span.in_scope(|| {
            info!(target: "cassis_arkade", "htlc claimed for {}: tx={txid}", payment_hash.short());
        });
        self.incoming.lock().await.remove(&payment_hash);
        Ok(())
    }

    async fn virtual_tx_psbt(&self, txid: bitcoin::Txid) -> Result<Option<psbt::Psbt>, String> {
        let res = tokio::time::timeout(
            Duration::from_secs(RPC_TIMEOUT_SECS),
            self.client
                .network_client()
                .get_virtual_txs(vec![txid.to_string()], None),
        )
        .await
        .map_err(|_| "get_virtual_txs timed out".to_string())?
        .map_err(|e| format!("get_virtual_txs: {e}"))?;
        Ok(res.txs.into_iter().next())
    }

    /// Decode the `condition` unknown field on any PSBT input into a
    /// revealed preimage, mirroring the SDK's own extraction used by
    /// submarine swap bookkeeping.
    fn extract_preimage_from_psbt(claim_psbt: &psbt::Psbt) -> Result<Option<[u8; 32]>, String> {
        let condition_key = psbt::raw::Key {
            type_value: 222,
            key: VTXO_CONDITION_KEY.to_vec(),
        };
        for input in &claim_psbt.inputs {
            let Some(condition_data) = input.unknown.get(&condition_key) else {
                continue;
            };
            if condition_data.is_empty() || condition_data[0] == 0 {
                continue;
            }
            let mut cursor = std::io::Cursor::new(&condition_data[1..]);
            let VarInt(length) = VarInt::consensus_decode(&mut cursor)
                .map_err(|e| format!("failed to decode varint length: {e}"))?;
            let offset = cursor.position() as usize;
            let remaining = condition_data
                .get(1 + offset..)
                .ok_or_else(|| format!("condition data shorter than varint suggests ({offset})"))?;
            let length_usize = length as usize;
            if remaining.len() < length_usize {
                return Err(format!(
                    "condition data too short: expected {length_usize}, got {}",
                    remaining.len()
                ));
            }
            let bytes = &remaining[..length_usize];
            if bytes.len() != 32 {
                return Err(format!("preimage has unexpected length {}", bytes.len()));
            }
            let mut preimage = [0u8; 32];
            preimage.copy_from_slice(bytes);
            return Ok(Some(preimage));
        }
        Ok(None)
    }

    // -----------------------------------------------------------------
    // Wallet-facing helpers used by the CLI and Playground (funds mgmt).
    // -----------------------------------------------------------------

    /// Current offchain balance (confirmed + pre-confirmed spendable
    /// VTXOs) in msat.
    pub async fn balance_msat(&self) -> Result<u64, HtlcError> {
        let balance = self
            .client
            .offchain_balance()
            .await
            .map_err(|e| HtlcError::Network(format!("offchain_balance: {e}")))?;
        let total_sats = balance
            .confirmed()
            .to_sat()
            .saturating_add(balance.pre_confirmed().to_sat());
        Ok(total_sats.saturating_mul(MSAT_PER_SAT))
    }

    /// Include confirmed boarding outputs in the next batch swap.
    /// Returns the commitment transaction ID, or `None` when no
    /// boarding output or recoverable VTXO is ready to settle.
    pub async fn onboard(&self) -> Result<Option<bitcoin::Txid>, HtlcError> {
        // OsRng (not `thread_rng`) so the returned future stays Send
        // and can be awaited from spawned tasks.
        let mut rng = rand::rngs::OsRng;
        self.client
            .settle(&mut rng)
            .await
            .map_err(|e| HtlcError::Network(format!("onboard: {e}")))
    }

    /// Addresses for manual funding, returned as
    /// `(boarding, onchain, arkade)` strings. VTXOs sent to the
    /// boarding address settle into spendable offchain coins after
    /// they confirm and the node joins a batch swap.
    pub async fn deposit_addresses(&self) -> Result<(String, String, String), HtlcError> {
        let ark_address = self.our_offchain_address().await?;
        let boarding = self
            .client
            .get_boarding_address()
            .await
            .map_err(|e| HtlcError::Network(format!("get_boarding_address: {e}")))?;
        let onchain = self
            .client
            .get_onchain_address()
            .map_err(|e| HtlcError::Network(format!("get_onchain_address: {e}")))?;
        Ok((
            boarding.to_string(),
            onchain.to_string(),
            ark_address.encode(),
        ))
    }

    /// Send VTXOs to another Arkade address (`tark1...` / `ark1...`).
    pub async fn transfer_to_ark_address(
        &self,
        address: &str,
        amount_msat: u64,
    ) -> Result<bitcoin::Txid, HtlcError> {
        let to = ArkAddress::decode(address.trim()).map_err(|e| {
            HtlcError::InvalidParams(format!("invalid arkade address '{address}': {e}"))
        })?;
        let amount = msat_to_sat_amount(amount_msat)?;
        self.client
            .send(vec![SendReceiver::bitcoin(to, amount)])
            .await
            .map_err(|e| HtlcError::Network(format!("send: {e}")))
    }

    /// Operator summary line for CLI `info`.
    pub fn operator_summary(&self) -> String {
        format!(
            "{} signer={}",
            match self.network_id.0.as_str() {
                "arkade::testnet" => TESTNET_SERVER_URL,
                _ => MAINNET_SERVER_URL,
            },
            self.server_pk_xonly
        )
    }
}

#[async_trait]
impl NetworkRouterAdapter for ArkadeAdapter {
    fn invoice_pubkey(&self) -> XOnlyPubKey {
        self.invoice_pubkey
    }

    /// Claims happen with the dedicated per-network key, not the
    /// invoice key, so counterparties must lock HTLCs to this x-only
    /// identity.
    fn claim_pubkey(&self) -> XOnlyPubKey {
        self.claim_pubkey
    }

    fn network_id(&self) -> NetworkId {
        self.network_id.clone()
    }

    /// Lockups land instantly in the virtual mempool; we still poll
    /// the indexer rather than streaming, so keep a modest budget.
    fn incoming_delta_secs(&self) -> u64 {
        60
    }

    async fn register_incoming_htlc(
        &self,
        payment_hash: Bytes32,
        min_amount_msat: u64,
        deadline: u64,
    ) -> Result<(), HtlcError> {
        if deadline <= Self::unix_now() {
            return Err(HtlcError::InvalidParams("deadline in the past".into()));
        }
        let expected_sat =
            msat_to_sat_amount(min_amount_msat).map_err(|e| HtlcError::Network(e.to_string()))?;
        self.incoming
            .lock()
            .await
            .entry(payment_hash)
            .or_insert(PendingIncoming {
                options: None,
                expected_sat,
                deadline,
            });
        Ok(())
    }

    async fn create_outgoing_htlc(
        &self,
        payment_hash: Bytes32,
        amount_msat: u64,
        expiry: u64,
        htlc_target: &HtlcTarget,
    ) -> Result<OutgoingHtlc, HtlcError> {
        let recipient = match htlc_target {
            HtlcTarget::XOnlyPubKey(pubkey) => *pubkey,
            HtlcTarget::PubKey(_) | HtlcTarget::LightningInvoice(_) => {
                return Err(HtlcError::InvalidParams(
                    "arkade requires a pubkey target".into(),
                ))
            }
        };
        let amount = msat_to_sat_amount(amount_msat)?;
        if amount < self.dust {
            return Err(HtlcError::InvalidParams(format!(
                "amount {} sats is below the operator's dust limit of {} sats",
                amount.to_sat(),
                self.dust.to_sat()
            )));
        }
        let options = self.build_options_for_outgoing(&payment_hash, &recipient, expiry)?;
        let destination = self.script_for(&options)?.address();

        self.span.in_scope(|| {
            info!(
                target: "cassis_arkade",
                "locking htlc {}: {} sats -> {} (expiry {})",
                payment_hash.short(),
                amount.to_sat(),
                destination.encode(),
                expiry,
            );
        });

        let txid = self
            .client
            .send(vec![SendReceiver::bitcoin(destination, amount)])
            .await
            .map_err(|e| HtlcError::Network(format!("lock send failed: {e}")))?;

        self.span.in_scope(|| {
            debug!(target: "cassis_arkade", "htlc locked {}: txid={txid}", payment_hash.short());
        });

        self.outgoing
            .lock()
            .await
            .insert(payment_hash, PendingOutgoing { options, recipient });

        Ok(OutgoingHtlc {
            payment_hash,
            amount_msat,
            expiry,
            recipient: recipient.to_hex(),
            network: self.network_id.clone(),
        })
    }

    async fn restore_outgoing_htlc(
        &self,
        payment: &OutgoingPayment,
        descriptor: Option<&HtlcDescriptor>,
    ) -> Result<(), HtlcError> {
        let options = Self::parse_vhtlc_options(descriptor.ok_or(HtlcError::Unimplemented)?)?;
        let recipient = match &payment.destination {
            HtlcTarget::XOnlyPubKey(pubkey) => *pubkey,
            HtlcTarget::PubKey(_) | HtlcTarget::LightningInvoice(_) => {
                return Err(HtlcError::InvalidParams(
                    "arkade requires a pubkey destination".into(),
                ))
            }
        };
        if options.preimage_hash != vhtlc_payment_hash160(&payment.payment_hash) {
            return Err(HtlcError::InvalidParams(
                "Arkade descriptor hash does not match outgoing payment".into(),
            ));
        }
        self.outgoing
            .lock()
            .await
            .insert(payment.payment_hash, PendingOutgoing { options, recipient });
        Ok(())
    }

    async fn claim_incoming(
        &self,
        payment_hash: Bytes32,
        preimage: Bytes32,
    ) -> Result<(), HtlcError> {
        self.claim_locked_htlc(payment_hash, preimage).await
    }

    async fn refund_outgoing(&self, payment_hash: Bytes32) -> Result<(), HtlcError> {
        let options = {
            let outgoing = self.outgoing.lock().await;
            outgoing.get(&payment_hash).map(|slot| slot.options.clone())
        };
        let Some(options) = options else {
            return Err(HtlcError::InvalidParams(format!(
                "no outgoing HTLC for {payment_hash:?}"
            )));
        };
        let vhtlc = self.script_for(&options)?;

        // Refunds use the CLTV-gated "without receiver" leaf; until the
        // locktime passes only a cooperative (receiver-signed) refund
        // could move the funds, which the routing protocol never asks
        // us for. The operator checks the timestamp CLTV against the
        // chain tip's block time, so gate on that too and let the
        // router retry until a late-enough block lands.
        let tip_time = self.tip_time().await.map_err(htlc)?;
        if u64::from(options.refund_locktime) > tip_time {
            return Err(HtlcError::InvalidParams(format!(
                "timelock not reached: tip_time={tip_time} refund_locktime={}",
                options.refund_locktime
            )));
        }

        let vtxo = self.unspent_vtxo_at(&options).await?;
        let our_address = self.our_offchain_address().await?;

        let refund_script = vhtlc.refund_without_receiver_script();
        let control_block = vhtlc
            .taproot_spend_info()
            .control_block(&(refund_script.clone(), LeafVersion::TapScript))
            .ok_or_else(|| HtlcError::Network("control block missing for refund leaf".into()))?;
        let script_pubkey = vhtlc.script_pubkey();
        // `tapscripts` consumes the script: collect it last.
        let tapscripts = vhtlc.tapscripts();
        let input = VtxoInput::new(
            refund_script,
            Some(absolute::LockTime::from_consensus(options.refund_locktime)),
            control_block,
            tapscripts,
            script_pubkey,
            vtxo.amount,
            vtxo.outpoint,
            vtxo.assets,
        );
        let outputs = vec![SendReceiver::bitcoin(our_address.clone(), vtxo.amount)];

        let txid = self
            .submit_vhtlc_spend(input, &outputs, &our_address, self.signer_with(None))
            .await?;

        self.span.in_scope(|| {
            info!(target: "cassis_arkade", "htlc refunded {}: tx={txid}", payment_hash.short());
        });
        self.outgoing.lock().await.remove(&payment_hash);
        Ok(())
    }

    async fn watch_preimage(
        &self,
        payment_hash: Bytes32,
        deadline: u64,
    ) -> Result<Bytes32, WatchError> {
        let options = {
            let outgoing = self.outgoing.lock().await;
            outgoing.get(&payment_hash).map(|slot| slot.options.clone())
        };
        let Some(options) = options else {
            return Err(WatchError::Network(format!(
                "no outgoing HTLC for {payment_hash:?}"
            )));
        };
        let vhtlc = self
            .script_for(&options)
            .map_err(|e| WatchError::Network(e.to_string()))?;

        loop {
            if Self::unix_now() >= deadline {
                return Err(WatchError::DeadlineExceeded);
            }

            // Poll until the counterparty's claim shows up as a spent
            // outpoint carrying its Arkade transaction id.
            let spent_txid = match self.outpoints_at_address(&vhtlc).await {
                Ok(outpoints) => {
                    outpoints
                        .iter()
                        .find_map(|o| if o.is_spent { o.ark_txid } else { None })
                }
                Err(e) => {
                    self.span.in_scope(|| {
                        warn!(target: "cassis_arkade", "watch_preimage poll failed: {e}");
                    });
                    None
                }
            };

            if let Some(txid) = spent_txid {
                let fetched_psbt = self.virtual_tx_psbt(txid).await.map_err(Error::Client)?;
                let extracted = fetched_psbt.as_ref().map(Self::extract_preimage_from_psbt);
                match extracted {
                    Some(Ok(Some(preimage))) => {
                        let computed =
                            ripemd160::Hash::hash(sha256::Hash::hash(&preimage).as_byte_array());
                        if computed != options.preimage_hash {
                            return Err(WatchError::Network(format!(
                                "revealed preimage hashes to {computed}, expected {}",
                                options.preimage_hash
                            )));
                        }
                        self.span.in_scope(|| {
                            info!(
                                target: "cassis_arkade",
                                "preimage observed on {} for {}: preimage={}",
                                self.network_id,
                                payment_hash.short(),
                                lowercase_hex_encode(&preimage),
                            );
                        });
                        return Ok(Bytes32(preimage));
                    }
                    Some(Err(msg)) => {
                        self.span.in_scope(|| {
                            warn!(target: "cassis_arkade", "preimage extraction from {txid}: {msg}");
                        });
                    }
                    _ => {}
                }
            }

            tokio::time::sleep(Duration::from_secs(POLL_INTERVAL_SECS)).await;
        }
    }

    async fn verify_incoming_htlc(
        &self,
        descriptor: &HtlcDescriptor,
        payment_hash: Bytes32,
    ) -> Result<(), HtlcError> {
        let options = Self::parse_vhtlc_options(descriptor)?;

        // Descriptor hash must commit to this very route hash.
        if options.preimage_hash != vhtlc_payment_hash160(&payment_hash) {
            return Err(HtlcError::InvalidParams(
                "descriptor hash160 does not match the payment hash".into(),
            ));
        }
        if options.server != self.server_pk_xonly {
            return Err(HtlcError::InvalidParams(format!(
                "descriptor targets operator {}, but this node connects to {}; \
                 descriptors only work within a single operator",
                options.server, self.server_pk_xonly
            )));
        }

        // The operator re-validates every leaf of the VHTLC script each
        // time a spend of it is registered, so leaves it would reject
        // make the VTXO unclaimable for us. Check the timelock shapes
        // up front and fail the DISPATCH before anything is locked
        // downstream.
        if options.refund_locktime < MIN_TIMESTAMP_LOCKTIME {
            return Err(HtlcError::InvalidParams(format!(
                "refund locktime {} is a block height; the operator only \
                 accepts unix-timestamp refund CLTVs",
                options.refund_locktime
            )));
        }
        for (name, delay) in [
            ("unilateral claim", options.unilateral_claim_delay),
            ("unilateral refund", options.unilateral_refund_delay),
            (
                "unilateral refund without receiver",
                options.unilateral_refund_without_receiver_delay,
            ),
        ] {
            if !delay.is_time_locked() {
                return Err(HtlcError::InvalidParams(format!(
                    "{name} delay {delay} is block-based; the operator only \
                     accepts seconds-type CSV delays"
                )));
            }
            if exit_delay_secs(delay) < self.exit_delay_floor_secs {
                return Err(HtlcError::InvalidParams(format!(
                    "{name} delay {delay} is below the operator's minimum \
                     exit delay of {} seconds",
                    self.exit_delay_floor_secs
                )));
            }
        }
        // As receiver we need a strict head start on the operator-less
        // exit paths: if the sender's lone refund opened at or before
        // our claim, a dead operator would leave us racing the sender
        // for funds the preimage already entitles us to.
        if exit_delay_secs(options.unilateral_refund_without_receiver_delay)
            <= exit_delay_secs(options.unilateral_claim_delay)
        {
            return Err(HtlcError::InvalidParams(format!(
                "unilateral refund delay {} must open after the unilateral \
                 claim delay {}",
                options.unilateral_refund_without_receiver_delay, options.unilateral_claim_delay
            )));
        }

        let vhtlc = self.script_for(&options)?;
        let has_coins = self
            .outpoints_at_address(&vhtlc)
            .await
            .map_err(htlc)?
            .iter()
            .any(|o| !o.is_spent && !o.is_swept && o.amount > bitcoin::Amount::ZERO);
        if !has_coins {
            return Err(HtlcError::Network(
                "no VTXO present at the VHTLC address".into(),
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
        let options = Self::parse_vhtlc_options(descriptor)?;
        if options.receiver != self.claim_xonly {
            return Err(HtlcError::InvalidParams(format!(
                "incoming HTLC is locked to {}, which this node cannot claim; \
                 expected {} (upstream hop locked to the wrong identity)",
                options.receiver, self.claim_xonly
            )));
        }

        // The upstream lock must not become refundable while our claim
        // window is still open, or the sender could race our claim.
        if u64::from(options.refund_locktime) < deadline {
            return Err(HtlcError::InvalidParams(format!(
                "refund locktime {} precedes the claim deadline {deadline}",
                options.refund_locktime
            )));
        }

        // Preserve the amount reserved at PREPARE time, then check the
        // locked total actually covers it.
        let expected_sat = {
            let mut incoming = self.incoming.lock().await;
            match incoming.get_mut(&payment_hash) {
                Some(existing) => existing.expected_sat,
                None => {
                    incoming.insert(
                        payment_hash,
                        PendingIncoming {
                            options: None,
                            expected_sat: bitcoin::Amount::ZERO,
                            deadline,
                        },
                    );
                    bitcoin::Amount::ZERO
                }
            }
        };
        if expected_sat > bitcoin::Amount::ZERO {
            let vhtlc = self.script_for(&options)?;
            let total_sats = self
                .outpoints_at_address(&vhtlc)
                .await
                .map_err(htlc)?
                .iter()
                .filter(|o| !o.is_spent && !o.is_swept)
                .fold(0u64, |acc, o| acc.saturating_add(o.amount.to_sat()));
            let total = bitcoin::Amount::from_sat(total_sats);
            if total < expected_sat {
                return Err(HtlcError::Network(format!(
                    "locked amount {} sats is below the reserved {} sats",
                    total.to_sat(),
                    expected_sat.to_sat()
                )));
            }
        }

        self.span.in_scope(|| {
            debug!(
                target: "cassis_arkade",
                "accepted incoming htlc {} deadline={deadline}",
                payment_hash.short(),
            );
        });
        self.incoming
            .lock()
            .await
            .entry(payment_hash)
            .and_modify(|slot| slot.options = Some(options.clone()))
            .or_insert(PendingIncoming {
                options: Some(options),
                expected_sat: bitcoin::Amount::ZERO,
                deadline,
            });
        Ok(())
    }

    async fn outgoing_htlc_descriptor(
        &self,
        payment_hash: Bytes32,
    ) -> Result<HtlcDescriptor, HtlcError> {
        let options = {
            let outgoing = self.outgoing.lock().await;
            outgoing.get(&payment_hash).map(|slot| slot.options.clone())
        };
        options
            .ok_or_else(|| {
                HtlcError::InvalidParams(format!("no outgoing HTLC for {payment_hash:?}"))
            })
            .map(|options| Self::descriptor_from_options(&options))
    }

    /// Offchain balance check: spendable VTXOs must cover the routed
    /// amount. Checked on the hop's outgoing side at PREPARE time.
    async fn can_route(&self, amount_msat: u64) -> Result<(), HtlcError> {
        let needed = msat_to_sat_amount(amount_msat)?;
        let available = self.balance_msat().await?;
        if needed.to_sat().saturating_mul(MSAT_PER_SAT) > available {
            return Err(HtlcError::InvalidParams(format!(
                "insufficient arkade balance on {}: need {available} msat, \
                 requested {} msat",
                self.network_id, amount_msat
            )));
        }
        Ok(())
    }

    // Claims are co-signed offchain by the operator and cost nothing
    // of ours beyond the value flowing in, mirroring cashu's
    // signed-message model: the trait default (`Ok`) is correct here,
    // no explicit `can_claim` override needed.
}

// ---------------------------------------------------------------------------
// Helpers below keep module-private concerns out of the trait impl.
// ---------------------------------------------------------------------------

/// tonic gRPC needs a TLS root set installed exactly once per process.
fn install_rustls_crypto_provider() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn lowercase_hex_encode(bytes: &[u8]) -> String {
    use bitcoin::hex::DisplayHex as _;
    bytes.to_lower_hex_string()
}

fn lowercase_hex_decode(hex: &str) -> Option<Vec<u8>> {
    use bitcoin::hex::FromHex as _;
    Vec::<u8>::from_hex(hex).ok()
}
