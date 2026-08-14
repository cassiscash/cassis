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
//! BIP342 signatures: a script-path `OP_CHECKSIG` verifies against the
//! key pushed in the leaf, untweaked, so claims and refunds sign with
//! the plain wallet key (only key-path spends of the funding address
//! use the tweaked key).
//!
//! Lockups are accepted unconfirmed on mutinynet, and only with one
//! confirmation on mainnet, where unconfirmed transactions can be
//! replaced.

use async_trait::async_trait;
use bitcoin::absolute;
use bitcoin::hashes::ripemd160;
use bitcoin::hashes::Hash;
use bitcoin::key::Keypair;
use bitcoin::key::Secp256k1;
use bitcoin::key::TapTweak;
use bitcoin::key::XOnlyPublicKey;
use bitcoin::opcodes::all::{
    OP_CHECKSIG, OP_CLTV, OP_DROP, OP_ELSE, OP_ENDIF, OP_EQUALVERIFY, OP_HASH160, OP_IF,
};
use bitcoin::script::Builder as ScriptBuilder;
use bitcoin::sighash::{SighashCache, TapSighashType};
use bitcoin::taproot::{LeafVersion, TapLeafHash, TaprootBuilder};
use bitcoin::transaction::Version;
use bitcoin::{Address, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use cassis_core::{
    sats_for_msat, Bytes32, Htlc, HtlcDescriptor, HtlcTarget, Network, NetworkError, NetworkId,
    OutgoingState, XOnlyPubKey, MSAT_PER_SAT,
};
use std::str::FromStr;
use std::time::Duration;
use tracing::{debug, info, Span};

pub const MAINNET_ESPLORA_URL: &str = "https://mempool.space/api";
pub const MUTINYNET_ESPLORA_URL: &str = "https://mutinynet.com/api";

const RPC_TIMEOUT_SECS: u64 = 30;
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
fn b_xonly(pk: &XOnlyPubKey) -> Result<XOnlyPublicKey, NetworkError> {
    XOnlyPublicKey::from_slice(pk.as_bytes())
        .map_err(|e| NetworkError::Invalid(format!("x-only key: {e}")))
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
    ) -> Result<bitcoin::taproot::TaprootSpendInfo, NetworkError> {
        TaprootBuilder::new()
            .add_leaf(0, self.witness_script())
            .map_err(|_| NetworkError::Network("taproot leaf insert failed".into()))?
            .finalize(secp, nums_internal_key())
            .map_err(|_| NetworkError::Network("taproot tree finalize failed".into()))
    }

    fn taproot_spk(&self, secp: &Secp256k1<bitcoin::secp256k1::VerifyOnly>) -> ScriptBuf {
        let info = self
            .spend_info(secp)
            .expect("single-leaf tree is always valid");
        ScriptBuf::new_p2tr_tweaked(info.output_key())
    }

    /// The HTLC of `htlc`: claim key from the target, refund terms and
    /// lockup from the descriptor.
    fn of(htlc: &Htlc) -> Result<Self, NetworkError> {
        let HtlcDescriptor::Bitcoin {
            lockup_txid,
            lockup_vout,
            refund_pubkey,
            refund_locktime,
        } = &htlc.descriptor
        else {
            return Err(NetworkError::invalid("not a bitcoin HTLC"));
        };
        let HtlcTarget::XOnlyPubKey(claim) = &htlc.target else {
            return Err(NetworkError::invalid(
                "bitcoin HTLCs are locked to an x-only key",
            ));
        };
        if *refund_locktime < MIN_TIMESTAMP_LOCKTIME {
            return Err(NetworkError::invalid(
                "refund locktime must be a unix timestamp",
            ));
        }
        Ok(Self {
            payment_hash160: Self::payment_hash160(&htlc.payment_hash),
            lockup_txid: bitcoin::Txid::from_str(lockup_txid).map_err(NetworkError::invalid)?,
            lockup_vout: *lockup_vout,
            claim_pubkey: b_xonly(claim)?,
            refund_pubkey: b_xonly(refund_pubkey)?,
            refund_locktime: *refund_locktime,
        })
    }

    fn descriptor(&self) -> HtlcDescriptor {
        HtlcDescriptor::Bitcoin {
            lockup_txid: self.lockup_txid.to_string(),
            lockup_vout: self.lockup_vout,
            refund_pubkey: XOnlyPubKey::from_bytes(self.refund_pubkey.serialize())
                .expect("valid x-only key"),
            refund_locktime: self.refund_locktime,
        }
    }
}

pub struct BitcoinAdapter {
    id: NetworkId,
    network: bitcoin::Network,
    /// Owns the funding address (key path) and signs claims and refunds
    /// (script path).
    wallet_sk: bitcoin::secp256k1::SecretKey,
    /// Untweaked x-only half of `wallet_sk`: the claim and refund key in
    /// HTLC leaves, and the funding address' internal key.
    key_xonly: XOnlyPublicKey,
    /// P2TR address wallet UTXOs live at, and change and claims return to.
    funding_address: Address,
    client: esplora_client::AsyncClient,
    span: Span,
}

impl BitcoinAdapter {
    /// Open the wallet for `bitcoin` or `bitcoin::mutinynet`. All state
    /// is on-chain, so no data directory is needed.
    pub fn open(id: NetworkId, secret: [u8; 32], span: &Span) -> Result<Self, String> {
        let (network, esplora_url) = match id.param() {
            None => (bitcoin::Network::Bitcoin, MAINNET_ESPLORA_URL),
            Some("mutinynet") => (bitcoin::Network::Signet, MUTINYNET_ESPLORA_URL),
            Some(other) => return Err(format!("unknown bitcoin network '{other}'")),
        };
        let secp = Secp256k1::new();
        let wallet_sk = bitcoin::secp256k1::SecretKey::from_slice(&secret)
            .map_err(|e| format!("invalid bitcoin key: {e}"))?;
        let key_xonly = Keypair::from_secret_key(&secp, &wallet_sk)
            .x_only_public_key()
            .0;
        let funding_address = Address::p2tr(&secp, key_xonly, None, network);
        let client = esplora_client::Builder::new(esplora_url)
            .build_async()
            .map_err(|e| format!("esplora client: {e}"))?;
        let span = cassis_core::network_span(span, &id);
        debug!(parent: &span, "bitcoin wallet ready: funding={funding_address} via {esplora_url}");
        Ok(Self {
            id,
            network,
            wallet_sk,
            key_xonly,
            funding_address,
            client,
            span,
        })
    }

    fn claim_target(&self) -> HtlcTarget {
        HtlcTarget::XOnlyPubKey(
            XOnlyPubKey::from_bytes(self.key_xonly.serialize()).expect("valid x-only key"),
        )
    }

    /// Value of the HTLC output if it is still unspent, and whether it
    /// is confirmed.
    async fn unspent_lockup(&self, options: &HtlcOptions) -> Result<(Amount, bool), NetworkError> {
        let outpoint = OutPoint::new(options.lockup_txid, options.lockup_vout);
        let spk = options.taproot_spk(&Secp256k1::verification_only());
        let value = self
            .scan_unspent(&spk)
            .await?
            .into_iter()
            .find(|(candidate, _)| *candidate == outpoint)
            .map(|(_, value)| value)
            .ok_or_else(|| NetworkError::invalid("HTLC output is missing or spent"))?;
        let status = self
            .client
            .get_tx_status(&options.lockup_txid)
            .await
            .map_err(|e| NetworkError::network(format!("tx status: {e}")))?;
        Ok((value, status.confirmed))
    }

    /// The address test coins must be sent to so the wallet has
    /// spendable cash (also where change and claims return to).
    pub fn deposit_address(&self) -> String {
        self.funding_address.to_string()
    }

    /// Spendable wallet cash, in msat (sats * 1000).
    pub async fn balance_msat(&self) -> Result<u64, NetworkError> {
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
    ) -> Result<bitcoin::Txid, NetworkError> {
        if !amount_msat.is_multiple_of(MSAT_PER_SAT) {
            return Err(NetworkError::Invalid(format!(
                "amount {amount_msat} msat is not a whole number of satoshis"
            )));
        }
        let amount_sat = amount_msat / MSAT_PER_SAT;
        if amount_sat < DUST_SATS {
            return Err(NetworkError::Invalid(format!(
                "amount {amount_sat} sats is below the dust limit of {DUST_SATS} sats"
            )));
        }
        let destination = Address::from_str(address)
            .map_err(|e| NetworkError::Invalid(format!("bad destination address: {e}")))?
            .require_network(self.network)
            .map_err(|e| NetworkError::Invalid(format!("wrong network for destination: {e}")))?;

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
            return Err(NetworkError::Network(format!(
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
                .map_err(|e| NetworkError::Network(format!("taproot sighash: {e}")))?;
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
    ) -> Result<Vec<(OutPoint, Amount)>, NetworkError> {
        let txs = tokio::time::timeout(
            Duration::from_secs(RPC_TIMEOUT_SECS),
            self.client.scripthash_txs(script, None),
        )
        .await
        .map_err(|_| NetworkError::Network("scripthash_txs timed out".into()))?
        .map_err(|e| NetworkError::Network(format!("scripthash_txs: {e}")))?;
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

    async fn tip_time(&self) -> Result<u64, NetworkError> {
        let height = tokio::time::timeout(
            Duration::from_secs(RPC_TIMEOUT_SECS),
            self.client.get_height(),
        )
        .await
        .map_err(|_| NetworkError::Network("get_height timed out".into()))?
        .map_err(|e| NetworkError::Network(format!("get_height: {e}")))?;
        let hash = self
            .client
            .get_block_hash(height)
            .await
            .map_err(|e| NetworkError::Network(format!("get_block_hash: {e}")))?;
        let block = self
            .client
            .get_block_by_hash(&hash)
            .await
            .map_err(|e| NetworkError::Network(format!("get_block_by_hash: {e}")))?
            .ok_or_else(|| {
                NetworkError::Network(format!("tip block {height} missing from explorer"))
            })?;
        Ok(u64::from(block.header.time))
    }

    async fn broadcast(&self, tx: &Transaction, what: &str) -> Result<bitcoin::Txid, NetworkError> {
        tokio::time::timeout(
            Duration::from_secs(RPC_TIMEOUT_SECS),
            self.client.broadcast(tx),
        )
        .await
        .map_err(|_| NetworkError::Network("broadcast timed out".into()))?
        .map_err(|e| NetworkError::Network(format!("broadcast failed: {e}")))?;
        let txid = tx.compute_txid();
        self.span.in_scope(|| {
            debug!(target: "cassis_bitcoin", "{what}: txid={txid}");
        });
        Ok(txid)
    }

    fn fee_for(&self, vsize: u64) -> Amount {
        Amount::from_sat(DEFAULT_FEE_RATE_VB.saturating_mul(vsize))
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
impl BitcoinAdapter {
    /// Sweep wallet UTXOs to pay the HTLC output (output 0), change
    /// back to the funding address. Returns the lockup txid.
    async fn lock_htlc(
        &self,
        payment_hash: Bytes32,
        options: &HtlcOptions,
        amount_sat: u64,
    ) -> Result<bitcoin::Txid, NetworkError> {
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
            return Err(NetworkError::Invalid(format!(
                "insufficient bitcoin balance on {}: HTLC needs {} sats (with fee), \
                 wallet holds {gathered} sats",
                self.id,
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
                    .map_err(|e| NetworkError::Network(format!("taproot sighash: {e}")))?;
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
        Ok(txid)
    }

    /// Claim (preimage path) or refund (CLTV path) of an HTLC input.
    async fn spend_htlc(
        &self,
        options: &HtlcOptions,
        preimage: Option<Bytes32>,
        destination: Address,
    ) -> Result<bitcoin::Txid, NetworkError> {
        if let Some(preimage) = preimage {
            let computed = ripemd160::Hash::hash(
                bitcoin::hashes::sha256::Hash::hash(preimage.as_ref()).as_ref(),
            );
            if computed != options.payment_hash160 {
                return Err(NetworkError::Invalid(
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
                NetworkError::Network(format!(
                    "HTLC outpoint {}:{} not found unspent at its script address",
                    options.lockup_txid, options.lockup_vout
                ))
            })?;

        if preimage.is_none() {
            let tip_time = self.tip_time().await?;
            if u64::from(options.refund_locktime) > tip_time {
                return Err(NetworkError::Network(format!(
                    "timelock not reached: tip_time={tip_time} refund_locktime={}",
                    options.refund_locktime
                )));
            }
        }

        let fee = self.fee_for(Self::vsize_for(0, 1, 1, 0));
        if value <= fee + Amount::from_sat(DUST_SATS) {
            return Err(NetworkError::Network(format!(
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
            .map_err(|e| NetworkError::Network(e.to_string()))?;
        // Both leaf keys (claim for incoming, refund for outgoing HTLCs)
        // are our untweaked wallet key, and a script-path CHECKSIG
        // verifies against that key as written in the leaf.
        let signing_secp = Secp256k1::new();
        let signing_pair = Keypair::from_secret_key(&signing_secp, &self.wallet_sk);
        let control_block = tree_info
            .control_block(&(witness_script.clone(), LeafVersion::TapScript))
            .ok_or_else(|| NetworkError::Network("control block missing for spend leaf".into()))?;
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
                .map_err(|e| NetworkError::Network(format!("taproot sighash: {e}")))?
        };
        let msg = bitcoin::secp256k1::Message::from_digest(*sighash.as_ref());
        let sig = signing_secp
            .sign_schnorr_no_aux_rand(&msg, &signing_pair)
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

    /// The transaction spending the HTLC output, if any.
    async fn scan_spend(&self, options: &HtlcOptions) -> Result<Option<Transaction>, NetworkError> {
        let spk = options.taproot_spk(&Secp256k1::verification_only());
        let txs = tokio::time::timeout(
            Duration::from_secs(RPC_TIMEOUT_SECS),
            self.client.scripthash_txs(&spk, None),
        )
        .await
        .map_err(|_| NetworkError::network("scripthash_txs timed out"))?
        .map_err(|e| NetworkError::network(format!("scripthash_txs: {e}")))?;
        let Some(spend) = txs.iter().find(|tx| {
            tx.vin
                .iter()
                .any(|vin| vin.txid == options.lockup_txid && vin.vout == options.lockup_vout)
        }) else {
            return Ok(None);
        };
        self.get_tx(spend.txid).await
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

    async fn get_tx(&self, txid: bitcoin::Txid) -> Result<Option<Transaction>, NetworkError> {
        tokio::time::timeout(
            Duration::from_secs(RPC_TIMEOUT_SECS),
            self.client.get_tx(&txid),
        )
        .await
        .map_err(|_| NetworkError::Network("get_tx timed out".into()))?
        .map_err(|e| NetworkError::Network(format!("get_tx: {e}")))
    }
}

#[async_trait]
impl Network for BitcoinAdapter {
    fn id(&self) -> NetworkId {
        self.id.clone()
    }

    /// Claims are on-chain transactions.
    fn incoming_delta_secs(&self) -> u64 {
        300
    }

    async fn receive_target(
        &self,
        _payment_hash: Bytes32,
        _amount_msat: u64,
        _expiry: u64,
    ) -> Result<HtlcTarget, NetworkError> {
        Ok(self.claim_target())
    }

    async fn cancel_receive(&self, _payment_hash: Bytes32) -> Result<(), NetworkError> {
        Ok(())
    }

    async fn verify_incoming_htlc(&self, htlc: &Htlc) -> Result<(), NetworkError> {
        let options = HtlcOptions::of(htlc)?;
        if htlc.target != self.claim_target() {
            return Err(NetworkError::invalid("HTLC is not addressed to this node"));
        }
        // The output script is rebuilt from the payment hash and our
        // key, so an unspent output paying it is bound to both.
        let (value, confirmed) = self.unspent_lockup(&options).await?;
        if value.to_sat() < sats_for_msat(htlc.amount_msat) {
            return Err(NetworkError::invalid("lockup is worth less than the HTLC"));
        }
        if u64::from(options.refund_locktime) < htlc.expiry {
            return Err(NetworkError::invalid("refund opens before the expiry"));
        }
        if self.network == bitcoin::Network::Bitcoin && !confirmed {
            return Err(NetworkError::network(
                "lockup is unconfirmed; mainnet HTLCs need a confirmation",
            ));
        }
        Ok(())
    }

    async fn claim_incoming_htlc(
        &self,
        htlc: &Htlc,
        preimage: Bytes32,
    ) -> Result<(), NetworkError> {
        let options = HtlcOptions::of(htlc)?;
        let txid = self
            .spend_htlc(&options, Some(preimage), self.funding_address.clone())
            .await?;
        info!(parent: &self.span, "claimed {}: tx {txid}", htlc.payment_hash.short());
        Ok(())
    }

    async fn create_outgoing_htlc(
        &self,
        payment_hash: Bytes32,
        amount_msat: u64,
        expiry: u64,
        target: &HtlcTarget,
    ) -> Result<HtlcDescriptor, NetworkError> {
        let HtlcTarget::XOnlyPubKey(claim) = target else {
            return Err(NetworkError::invalid(
                "bitcoin HTLCs are locked to an x-only key",
            ));
        };
        let amount_sat = sats_for_msat(amount_msat);
        if amount_sat < DUST_SATS {
            return Err(NetworkError::invalid(format!(
                "{amount_sat} sats is below the dust limit"
            )));
        }
        let mut options = HtlcOptions {
            payment_hash160: HtlcOptions::payment_hash160(&payment_hash),
            lockup_txid: bitcoin::Txid::all_zeros(),
            lockup_vout: 0,
            claim_pubkey: b_xonly(claim)?,
            refund_pubkey: self.key_xonly,
            refund_locktime: u32::try_from(expiry).map_err(NetworkError::invalid)?,
        };
        options.lockup_txid = self.lock_htlc(payment_hash, &options, amount_sat).await?;
        Ok(options.descriptor())
    }

    async fn check_outgoing_htlc(&self, htlc: &Htlc) -> Result<OutgoingState, NetworkError> {
        let options = HtlcOptions::of(htlc)?;
        match self.scan_spend(&options).await? {
            None => Ok(OutgoingState::Pending),
            Some(spend) => Ok(Self::preimage_from_spend(&spend, &options)
                .map(OutgoingState::Claimed)
                .unwrap_or(OutgoingState::Refunded)),
        }
    }

    async fn refund_outgoing_htlc(&self, htlc: &Htlc) -> Result<(), NetworkError> {
        let options = HtlcOptions::of(htlc)?;
        let txid = self
            .spend_htlc(&options, None, self.funding_address.clone())
            .await?;
        info!(parent: &self.span, "refunded {}: tx {txid}", htlc.payment_hash.short());
        Ok(())
    }

    async fn can_send(&self, amount_msat: u64) -> Result<(), NetworkError> {
        let available = self.balance_msat().await?;
        if available < amount_msat {
            return Err(NetworkError::invalid(format!(
                "need {amount_msat} msat plus fees, wallet has {available} msat"
            )));
        }
        Ok(())
    }

    /// Claim fees come out of the HTLC.
    async fn can_receive(&self, _amount_msat: u64) -> Result<(), NetworkError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn htlc_round_trips_through_its_descriptor() {
        let secp = Secp256k1::signing_only();
        let xonly_of = |seed: u8| {
            Keypair::from_secret_key(
                &secp,
                &bitcoin::secp256k1::SecretKey::from_slice(&[seed; 32]).unwrap(),
            )
            .x_only_public_key()
            .0
        };
        let payment_hash = Bytes32([7u8; 32]);
        let options = HtlcOptions {
            payment_hash160: HtlcOptions::payment_hash160(&payment_hash),
            lockup_txid: bitcoin::Txid::all_zeros(),
            lockup_vout: 1,
            claim_pubkey: xonly_of(2),
            refund_pubkey: xonly_of(3),
            refund_locktime: 700_000_000,
        };
        let htlc = Htlc {
            payment_hash,
            amount_msat: 1_000_000,
            expiry: 700_000_000,
            target: HtlcTarget::XOnlyPubKey(
                XOnlyPubKey::from_bytes(xonly_of(2).serialize()).unwrap(),
            ),
            descriptor: options.descriptor(),
        };
        let parsed = HtlcOptions::of(&htlc).unwrap();
        assert_eq!(parsed.witness_script(), options.witness_script());
        assert_eq!(parsed.lockup_vout, 1);
    }

    #[test]
    fn script_path_signature_verifies_against_the_leaf_key() {
        // Tapscript CHECKSIG checks the key as written in the leaf, so
        // the untweaked keypair must produce the signature.
        let secp = Secp256k1::new();
        let pair = Keypair::from_secret_key(
            &secp,
            &bitcoin::secp256k1::SecretKey::from_slice(&[5u8; 32]).unwrap(),
        );
        let msg = bitcoin::secp256k1::Message::from_digest([6u8; 32]);
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &pair);
        secp.verify_schnorr(&sig, &msg, &pair.x_only_public_key().0)
            .unwrap();
    }
}
