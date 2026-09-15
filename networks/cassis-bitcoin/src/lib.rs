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
//! The taproot internal key is the sender's per-network key (x-only):
//! it controls an *unpruned key path* that can serve collaborative
//! settlement later (a joint key-path spend only needs both parties,
//! no leaves), while the recovery paths live in the script leaf. All
//! keys are x-only (BIP342 CHECKSIG), so network identities drop
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
//! though the tree's internal key is the sender's.

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
use cassis_core::Bytes32;
use cassis_core::HtlcDescriptor;
use cassis_core::HtlcError;
use cassis_core::HtlcTarget;
use cassis_core::NetworkId;
use cassis_core::NetworkRouterAdapter;
use cassis_core::OutgoingHtlc;
use cassis_core::WatchError;
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

pub struct BitcoinConfig {
    pub network_id: NetworkId,
    pub network: bitcoin::Network,
    pub esplora_url: String,
    /// Per-network signing key (derived from `cassis/network/<id>`).
    pub sk: [u8; 32],
    pub invoice_pubkey: XOnlyPubKey,
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
    invoice_pubkey: XOnlyPubKey,
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
        invoice_pubkey,
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
fn b_xonly(pk: &XOnlyPubKey) -> Result<XOnlyPublicKey, HtlcError> {
    XOnlyPublicKey::from_slice(pk.as_bytes())
        .map_err(|e| HtlcError::InvalidParams(format!("x-only key: {e}")))
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
    /// Sender's internal taproot key: key-path signer (future
    /// collaborative settlement) and the tree's untweaked key.
    internal_key: XOnlyPublicKey,
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
    /// single-leaf tree).
    fn spend_info(
        &self,
        secp: &Secp256k1<bitcoin::secp256k1::VerifyOnly>,
    ) -> Result<bitcoin::taproot::TaprootSpendInfo, HtlcError> {
        TaprootBuilder::new()
            .add_leaf(0, self.witness_script())
            .map_err(|_| HtlcError::Network("taproot leaf insert failed".into()))?
            .finalize(secp, self.internal_key)
            .map_err(|_| HtlcError::Network("taproot tree finalize failed".into()))
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
    ) -> Result<Self, HtlcError> {
        let HtlcDescriptor::Bitcoin {
            lockup_txid,
            lockup_vout,
            payment_hash160,
            internal_key,
            refund_pubkey,
            refund_locktime,
        } = descriptor
        else {
            return Err(HtlcError::InvalidParams(
                "descriptor is not a bitcoin on-chain HTLC".into(),
            ));
        };
        let expected = ripemd160::Hash::hash(payment_hash.as_ref());
        let got = ripemd160::Hash::from_str(payment_hash160)
            .map_err(|e| HtlcError::InvalidParams(format!("bad payment_hash160: {e}")))?;
        if got != expected {
            return Err(HtlcError::InvalidParams(
                "descriptor hash160 does not match the route payment hash".into(),
            ));
        }
        if *refund_locktime < MIN_TIMESTAMP_LOCKTIME {
            return Err(HtlcError::InvalidParams(format!(
                "refund locktime {refund_locktime} is a block height; \
                 on-chain HTLCs use unix timestamps"
            )));
        }
        let lockup_txid = bitcoin::Txid::from_str(lockup_txid)
            .map_err(|e| HtlcError::InvalidParams(format!("bad lockup_txid: {e}")))?;
        Ok(Self {
            payment_hash160: expected,
            lockup_txid,
            lockup_vout: u32::from(*lockup_vout),
            internal_key: XOnlyPublicKey::from_slice(internal_key.as_bytes())
                .map_err(|e| HtlcError::InvalidParams(format!("internal key: {e}")))?,
            claim_pubkey: *our_claim_pk,
            refund_pubkey: XOnlyPublicKey::from_slice(refund_pubkey.as_bytes())
                .map_err(|e| HtlcError::InvalidParams(format!("refund pubkey: {e}")))?,
            refund_locktime: *refund_locktime,
        })
    }
}

#[derive(Clone, Debug)]
struct PendingOutgoing {
    options: HtlcOptions,
    lockup_txid: bitcoin::Txid,
    lockup_vout: u32,
    #[allow(dead_code)] // introspection/debugging on the running node
    value_sat: u64,
    #[allow(dead_code)] // OutgoingHtlc recall value; kept alongside value_sat
    amount_msat: u64,
    #[allow(dead_code)] // introspection/debugging on the running node
    recipient_xonly: XOnlyPubKey,
}

#[derive(Clone, Debug)]
struct PendingIncoming {
    options: Option<HtlcOptions>,
    #[allow(dead_code)] // guard for future claim-window checks
    deadline: u64,
    expected_sat: u64,
}

pub struct BitcoinAdapter {
    network_id: NetworkId,
    #[allow(dead_code)] // reported via operator_summary-style info
    network: bitcoin::Network,
    #[allow(dead_code)] // printed at construction; useful in logs
    esplora_url: String,
    fee_rate_vb: u64,
    /// Owns the funding address (P2TR sweep cash, key path) and the
    /// taproot internal key of the HTLC trees it locks out.
    wallet_sk: bitcoin::secp256k1::SecretKey,
    /// X-only half of `wallet_sk`: taproot wallet key (funding address
    /// key path), internal key of outgoing HTLC trees, refund leaf
    /// key, and claim identity.
    key_xonly: XOnlyPublicKey,
    invoice_pubkey: XOnlyPubKey,
    /// P2TR address wallet UTXOs are swept from and change returns to.
    funding_address: Address,
    client: Arc<esplora_client::AsyncClient>,
    span: Span,
    incoming: Mutex<HashMap<Bytes32, PendingIncoming>>,
    outgoing: Mutex<HashMap<Bytes32, PendingOutgoing>>,
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
            invoice_pubkey: cfg.invoice_pubkey,
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

    /// The address test coins must be sent to so the wallet has
    /// spendable cash (also where change and claims return to).
    pub fn deposit_address(&self) -> String {
        self.funding_address.to_string()
    }

    /// Spendable wallet cash, in msat (sats * 1000).
    pub async fn balance_msat(&self) -> Result<u64, HtlcError> {
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
    ) -> Result<bitcoin::Txid, HtlcError> {
        if amount_msat % MSAT_PER_SAT != 0 {
            return Err(HtlcError::InvalidParams(format!(
                "amount {amount_msat} msat is not a whole number of satoshis"
            )));
        }
        let amount_sat = amount_msat / MSAT_PER_SAT;
        if amount_sat < DUST_SATS {
            return Err(HtlcError::InvalidParams(format!(
                "amount {amount_sat} sats is below the dust limit of {DUST_SATS} sats"
            )));
        }
        let destination = Address::from_str(address)
            .map_err(|e| HtlcError::InvalidParams(format!("bad destination address: {e}")))?
            .require_network(self.network)
            .map_err(|e| HtlcError::InvalidParams(format!("wrong network for destination: {e}")))?;

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
            return Err(HtlcError::Network(format!(
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
                .map_err(|e| HtlcError::Network(format!("taproot sighash: {e}")))?;
            let msg = bitcoin::secp256k1::Message::from_digest(*sh.as_ref());
            sigs.push(
                secp.sign_schnorr_no_aux_rand(&msg, &tweaked_pair.as_keypair())
                    .serialize(),
            );
        }
        for (idx, sig) in sigs.into_iter().enumerate() {
            tx.input[idx].witness = Witness::from_slice(&[sig]);
        }
        self.broadcast(&tx, "wallet transfer").await
    }

    /// All unspent `(outpoint, value)` at `script`.
    async fn scan_unspent(&self, script: &ScriptBuf) -> Result<Vec<(OutPoint, Amount)>, HtlcError> {
        let txs = tokio::time::timeout(
            Duration::from_secs(RPC_TIMEOUT_SECS),
            self.client.scripthash_txs(script, None),
        )
        .await
        .map_err(|_| HtlcError::Network("scripthash_txs timed out".into()))?
        .map_err(|e| HtlcError::Network(format!("scripthash_txs: {e}")))?;
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

    async fn tip_time(&self) -> Result<u64, HtlcError> {
        let height = tokio::time::timeout(
            Duration::from_secs(RPC_TIMEOUT_SECS),
            self.client.get_height(),
        )
        .await
        .map_err(|_| HtlcError::Network("get_height timed out".into()))?
        .map_err(|e| HtlcError::Network(format!("get_height: {e}")))?;
        let hash = self
            .client
            .get_block_hash(height)
            .await
            .map_err(|e| HtlcError::Network(format!("get_block_hash: {e}")))?;
        let block = self
            .client
            .get_block_by_hash(&hash)
            .await
            .map_err(|e| HtlcError::Network(format!("get_block_by_hash: {e}")))?
            .ok_or_else(|| {
                HtlcError::Network(format!("tip block {height} missing from explorer"))
            })?;
        Ok(u64::from(block.header.time))
    }

    async fn broadcast(&self, tx: &Transaction, what: &str) -> Result<bitcoin::Txid, HtlcError> {
        tokio::time::timeout(
            Duration::from_secs(RPC_TIMEOUT_SECS),
            self.client.broadcast(tx),
        )
        .await
        .map_err(|_| HtlcError::Network("broadcast timed out".into()))?
        .map_err(|e| HtlcError::Network(format!("broadcast failed: {e}")))?;
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
        payment_hash: Bytes32,
        options: HtlcOptions,
        amount_sat: u64,
        recipient_xonly: XOnlyPubKey,
        amount_msat: u64,
    ) -> Result<OutgoingHtlc, HtlcError> {
        let funding_spk = self.funding_address.script_pubkey();
        let refund_locktime = options.refund_locktime;
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
            return Err(HtlcError::InvalidParams(format!(
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
                    .map_err(|e| HtlcError::Network(format!("taproot sighash: {e}")))?;
                let msg = bitcoin::secp256k1::Message::from_digest(*sh.as_ref());
                sigs.push(
                    secp.sign_schnorr_no_aux_rand(&msg, &tweaked_pair.as_keypair())
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
        self.outgoing.lock().await.insert(
            payment_hash,
            PendingOutgoing {
                options: {
                    let mut stored = options.clone();
                    stored.lockup_txid = txid;
                    stored.lockup_vout = 0;
                    stored
                },
                lockup_txid: txid,
                lockup_vout: 0,
                value_sat: amount_sat,
                amount_msat,
                recipient_xonly,
            },
        );
        Ok(OutgoingHtlc {
            payment_hash,
            amount_msat,
            expiry: u64::from(refund_locktime),
            recipient: recipient_xonly.to_hex(),
            network: self.network_id.clone(),
        })
    }

    /// Claim (preimage path) or refund (CLTV path) of an HTLC input.
    async fn spend_htlc(
        &self,
        options: &HtlcOptions,
        preimage: Option<Bytes32>,
        destination: Address,
    ) -> Result<bitcoin::Txid, HtlcError> {
        let witness_script = options.witness_script();
        let verify_secp = Secp256k1::verification_only();
        let spk = options.taproot_spk(&verify_secp);
        let utxos = self.scan_unspent(&spk).await?;
        let (outpoint, value) = utxos
            .iter()
            .find(|(o, _)| o.txid == options.lockup_txid && o.vout == options.lockup_vout)
            .copied()
            .ok_or_else(|| {
                HtlcError::Network(format!(
                    "HTLC outpoint {}:{} not found unspent at its script address",
                    options.lockup_txid, options.lockup_vout
                ))
            })?;

        if preimage.is_none() {
            let tip_time = self.tip_time().await?;
            if u64::from(options.refund_locktime) > tip_time {
                return Err(HtlcError::InvalidParams(format!(
                    "timelock not reached: tip_time={tip_time} refund_locktime={}",
                    options.refund_locktime
                )));
            }
        }

        let fee = self.fee_for(Self::vsize_for(0, 1, 1, 0));
        if value <= fee + Amount::from_sat(DUST_SATS) {
            return Err(HtlcError::Network(format!(
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
            .map_err(|e| HtlcError::Network(e.to_string()))?;
        // BIP342 semantics: script-path signatures are made with the
        // leaf pubkey tweaked on its own (no branch commitment); the
        // tweaking is keypair-local, a signing ctx suffices. The claim
        // branch embeds our claim x-only key (checked on accept) so its
        // secret is always ours; refunds sign with the internal key.
        let signing_secp = Secp256k1::new();
        let claim_pair = Keypair::from_secret_key(&signing_secp, &self.wallet_sk);
        let wallet_pair = Keypair::from_secret_key(&signing_secp, &self.wallet_sk);
        let control_block = tree_info
            .control_block(&(witness_script.clone(), LeafVersion::TapScript))
            .ok_or_else(|| HtlcError::Network("control block missing for spend leaf".into()))?;
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
                .map_err(|e| HtlcError::Network(format!("taproot sighash: {e}")))?
        };
        // BIP342: a script-path CHECKSIG signs with the leaf key
        // tweaked on its own (no branch commitment).
        let signing_pair = if is_claim {
            claim_pair
        } else {
            wallet_pair.clone()
        };
        let tweaked = signing_pair.tap_tweak(&signing_secp, None);
        let msg = bitcoin::secp256k1::Message::from_digest(*sighash.as_ref());
        let sig = signing_secp
            .sign_schnorr_no_aux_rand(&msg, &tweaked.as_keypair())
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
    ) -> Result<Option<(Bytes32, bitcoin::Txid)>, HtlcError> {
        let spk = options.taproot_spk(&Secp256k1::verification_only());
        let txs = tokio::time::timeout(
            Duration::from_secs(RPC_TIMEOUT_SECS),
            self.client.scripthash_txs(&spk, None),
        )
        .await
        .map_err(|_| HtlcError::Network("scripthash_txs timed out".into()))?
        .map_err(|e| HtlcError::Network(format!("scripthash_txs: {e}")))?;
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

    async fn get_tx(&self, txid: bitcoin::Txid) -> Result<Option<Transaction>, HtlcError> {
        tokio::time::timeout(
            Duration::from_secs(RPC_TIMEOUT_SECS),
            self.client.get_tx(&txid),
        )
        .await
        .map_err(|_| HtlcError::Network("get_tx timed out".into()))?
        .map_err(|e| HtlcError::Network(format!("get_tx: {e}")))
    }
}

// ---------------------------------------------------------------------------
// Router adapter trait.
// ---------------------------------------------------------------------------

#[async_trait]
impl NetworkRouterAdapter for BitcoinAdapter {
    fn invoice_pubkey(&self) -> XOnlyPubKey {
        self.invoice_pubkey
    }

    /// Claim identity: the x-only half of the per-network key; the
    /// taproot claim leaf embeds this key directly (BIP342 x-only
    /// pubkeys), so counterparties lock to it unchanged.
    fn claim_pubkey(&self) -> XOnlyPubKey {
        XOnlyPubKey::from_bytes(self.key_xonly.serialize()).expect("32 bytes is a valid x-only key")
    }

    fn network_id(&self) -> NetworkId {
        self.network_id.clone()
    }

    /// On-chain money lands block-granular: give the router 300 s of
    /// slack between locking and claim.
    fn incoming_delta_secs(&self) -> u64 {
        300
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
        self.incoming
            .lock()
            .await
            .entry(payment_hash)
            .or_insert(PendingIncoming {
                options: None,
                deadline,
                expected_sat: min_amount_msat / MSAT_PER_SAT,
            });
        Ok(())
    }

    async fn can_route(&self, amount_msat: u64) -> Result<(), HtlcError> {
        let funding_spk = self.funding_address.script_pubkey();
        let utxos = self.scan_unspent(&funding_spk).await?;
        let available = utxos.iter().map(|(_, v)| v.to_sat()).sum::<u64>();
        if available * MSAT_PER_SAT < amount_msat {
            return Err(HtlcError::InvalidParams(format!(
                "insufficient bitcoin balance on {}: need {amount_msat} msat, \
                 wallet holds {available} sats",
                self.network_id
            )));
        }
        Ok(())
    }

    async fn create_outgoing_htlc(
        &self,
        payment_hash: Bytes32,
        amount_msat: u64,
        expiry: u64,
        htlc_target: &HtlcTarget,
    ) -> Result<OutgoingHtlc, HtlcError> {
        let recipient_xonly = match htlc_target {
            HtlcTarget::XOnlyPubKey(pk) => *pk,
            HtlcTarget::PubKey(_) | HtlcTarget::LightningInvoice(_) => {
                return Err(HtlcError::InvalidParams(
                    "bitcoin requires a pubkey target".into(),
                ))
            }
        };
        if amount_msat % MSAT_PER_SAT != 0 {
            return Err(HtlcError::InvalidParams(format!(
                "amount {amount_msat} msat is not a whole number of satoshis"
            )));
        }
        let amount_sat = amount_msat / MSAT_PER_SAT;
        if amount_sat < DUST_SATS {
            return Err(HtlcError::InvalidParams(format!(
                "amount {amount_sat} sats is below the dust limit of {DUST_SATS} sats"
            )));
        }
        if expiry < u64::from(MIN_TIMESTAMP_LOCKTIME) {
            return Err(HtlcError::InvalidParams(format!(
                "expiry {expiry} looks like a block height; on-chain HTLCs use \
                 unix timestamps (>= {MIN_TIMESTAMP_LOCKTIME})"
            )));
        }
        if expiry <= Self::unix_now() {
            return Err(HtlcError::InvalidParams(format!(
                "expiry {expiry} is in the past"
            )));
        }
        let refund_locktime = u32::try_from(expiry)
            .map_err(|e| HtlcError::InvalidParams(format!("expiry overflows u32: {e}")))?;
        // The lockup outpoint is stamped in by lock_htlc after the
        // broadcast; the placeholder never crosses the wire.
        let options = HtlcOptions {
            payment_hash160: HtlcOptions::payment_hash160(&payment_hash),
            lockup_txid: bitcoin::Txid::from_slice(&[0u8; 32]).expect("all-zero txid"),
            lockup_vout: 0,
            internal_key: self.key_xonly,
            claim_pubkey: b_xonly(&recipient_xonly)?,
            refund_pubkey: self.key_xonly,
            refund_locktime,
        };
        self.lock_htlc(
            payment_hash,
            options,
            amount_sat,
            recipient_xonly,
            amount_msat,
        )
        .await
    }

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
                HtlcError::InvalidParams(format!("no outgoing bitcoin HTLC for {payment_hash:?}"))
            })?;
        Ok(HtlcDescriptor::Bitcoin {
            lockup_txid: slot.lockup_txid.to_string(),
            lockup_vout: slot.lockup_vout as u8,
            payment_hash160: lower_hex(&slot.options.payment_hash160.to_byte_array()),
            internal_key: XOnlyPubKey::from_bytes(slot.options.internal_key.serialize())
                .map_err(|e| HtlcError::Network(format!("internal key: {e}")))?,
            refund_pubkey: XOnlyPubKey::from_bytes(slot.options.refund_pubkey.serialize())
                .map_err(|e| HtlcError::Network(format!("refund pubkey: {e}")))?,
            refund_locktime: slot.options.refund_locktime,
        })
    }

    async fn verify_incoming_htlc(
        &self,
        descriptor: &HtlcDescriptor,
        payment_hash: Bytes32,
    ) -> Result<(), HtlcError> {
        let options = HtlcOptions::parse_descriptor(
            descriptor,
            payment_hash,
            &b_xonly(&self.claim_pubkey())?,
        )?;
        let spk = options.taproot_spk(&Secp256k1::verification_only());
        let utxos = self.scan_unspent(&spk).await?;
        let found = utxos.iter().any(|(outpoint, _)| {
            outpoint.txid == options.lockup_txid && outpoint.vout == options.lockup_vout
        });
        if !found {
            return Err(HtlcError::Network(format!(
                "HTLC outpoint {}:{} unspent at its P2WSH address; upstream lock not \
                 (yet) on chain",
                options.lockup_txid, options.lockup_vout
            )));
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
        let options = HtlcOptions::parse_descriptor(
            descriptor,
            payment_hash,
            &b_xonly(&self.claim_pubkey())?,
        )?;
        if options.claim_pubkey != self.key_xonly {
            return Err(HtlcError::InvalidParams(format!(
                "incoming HTLC is locked to {}, which this node cannot claim; \
                 upstream hop locked to the wrong claim key",
                options.claim_pubkey
            )));
        }
        if u64::from(options.refund_locktime) < deadline {
            return Err(HtlcError::InvalidParams(format!(
                "refund locktime {} precedes the claim deadline {deadline}; the \
                 sender could race our claim",
                options.refund_locktime
            )));
        }
        let mut incoming = self.incoming.lock().await;
        let expected_sat = incoming
            .get(&payment_hash)
            .map(|slot| slot.expected_sat)
            .unwrap_or(0);
        incoming.insert(
            payment_hash,
            PendingIncoming {
                options: Some(options),
                deadline,
                expected_sat,
            },
        );
        Ok(())
    }

    async fn claim_incoming(
        &self,
        payment_hash: Bytes32,
        preimage: Bytes32,
    ) -> Result<(), HtlcError> {
        let options = self
            .incoming
            .lock()
            .await
            .get(&payment_hash)
            .filter(|slot| slot.options.is_some())
            .map(|slot| slot.options.as_ref().expect("checked is_some").clone())
            .ok_or_else(|| {
                HtlcError::InvalidParams(format!("no accepted incoming HTLC for {payment_hash:?}"))
            })?;
        let txid = self
            .spend_htlc(&options, Some(preimage), self.funding_address.clone())
            .await?;
        self.span.in_scope(|| {
            info!(target: "cassis_bitcoin", "incoming htlc claimed {}: tx={txid}",
                payment_hash.short());
        });
        self.incoming.lock().await.remove(&payment_hash);
        Ok(())
    }

    async fn refund_outgoing(&self, payment_hash: Bytes32) -> Result<(), HtlcError> {
        let options = self
            .outgoing
            .lock()
            .await
            .get(&payment_hash)
            .map(|slot| slot.options.clone())
            .ok_or_else(|| {
                HtlcError::InvalidParams(format!("no outgoing HTLC for {payment_hash:?}"))
            })?;
        let txid = self
            .spend_htlc(&options, None, self.funding_address.clone())
            .await?;
        self.span.in_scope(|| {
            info!(target: "cassis_bitcoin", "outgoing htlc refunded {}: tx={txid}",
                payment_hash.short());
        });
        self.outgoing.lock().await.remove(&payment_hash);
        Ok(())
    }

    async fn watch_preimage(
        &self,
        payment_hash: Bytes32,
        deadline: u64,
    ) -> Result<Bytes32, WatchError> {
        let options = self
            .outgoing
            .lock()
            .await
            .get(&payment_hash)
            .map(|slot| slot.options.clone())
            .ok_or_else(|| WatchError::Network(format!("no outgoing HTLC for {payment_hash:?}")))?;
        loop {
            if Self::unix_now() >= deadline {
                return Err(WatchError::DeadlineExceeded);
            }
            match self.scan_spend_preimage(&options).await {
                Ok(Some((preimage, spend_txid))) => {
                    self.span.in_scope(|| {
                        info!(target: "cassis_bitcoin",
                            "preimage observed for {}: spend={spend_txid}",
                            payment_hash.short());
                    });
                    return Ok(preimage);
                }
                Ok(None) => {}
                Err(e) => {
                    self.span.in_scope(|| {
                        warn!(target: "cassis_bitcoin", "watch_preimage poll failed: {e}");
                    });
                }
            }
            tokio::time::sleep(Duration::from_secs(POLL_INTERVAL_SECS)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_kinds() {
        let sk = [1u8; 32];
        let pk = XOnlyPubKey::from_bytes([2u8; 32]).unwrap();

        let cfg = default_config(NetworkId("bitcoin".to_string()), sk, pk, Span::none()).unwrap();
        assert_eq!(cfg.network, bitcoin::Network::Bitcoin);
        assert_eq!(cfg.esplora_url, MAINNET_ESPLORA_URL);

        let cfg = default_config(
            NetworkId("bitcoin::mutinynet".to_string()),
            sk,
            pk,
            Span::none(),
        )
        .unwrap();
        assert_eq!(cfg.network, bitcoin::Network::Signet);
        assert_eq!(cfg.esplora_url, MUTINYNET_ESPLORA_URL);

        let mut other = default_config(NetworkId("bitcoin::foo".to_string()), sk, pk, Span::none())
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
            internal_key: bitcoin::XOnlyPublicKey::from_slice(&xonly_of(9)).unwrap(),
            claim_pubkey: bitcoin::XOnlyPublicKey::from_slice(&claim).unwrap(),
            refund_pubkey: bitcoin::XOnlyPublicKey::from_slice(&refund).unwrap(),
            refund_locktime: 700_000_000,
        };
        let secp = Secp256k1::verification_only();
        let info = options.spend_info(&secp).unwrap();
        let spk = ScriptBuf::new_p2tr_tweaked(info.output_key());
        let address = Address::from_script(&spk, bitcoin::Network::Bitcoin).unwrap();
        assert!(address.to_string().starts_with("bc1"));

        // A control block exists for the leaf (claim/refund spin on
        // their existence at spend time).
        assert!(info
            .control_block(&(options.witness_script(), LeafVersion::TapScript))
            .is_some());
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
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &tweaked.as_keypair());
        let pubkey: bitcoin::XOnlyPublicKey = tweaked.public_parts().0.into();
        secp.verify_schnorr(&sig, &msg, &pubkey).unwrap();
    }
}
