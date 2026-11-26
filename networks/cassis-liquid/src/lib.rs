//! Liquid network adapter.
//!
//! HTLCs are plain P2WSH outputs on Liquid whose single witness script
//! has two spending paths (boltz-style, hash check inside the claim
//! branch):
//!
//! ```text
//! OP_IF   OP_HASH160 <RIPEMD160(payment_hash)> OP_EQUALVERIFY
//!         <claim_pubkey> OP_CHECKSIG
//! OP_ELSE <refund_locktime> OP_CLTV OP_DROP <refund_pubkey>
//!         OP_CHECKSIG
//! OP_ENDIF
//! ```
//!
//! * **Claim**: witness `[sig, preimage, <true>, script]`.
//! * **Refund**: witness `[sig, <empty>, script]` once the absolute
//!   block height `refund_locktime` is reached.
//!
//! The lockup output is unblinded, so amounts are visible without
//! blinding keys. Claim and refund fees come out of the HTLC value; the
//! LWK wallet only pays for lockups.
//!
//! The claim key is a dedicated child key (`m/1037'/0`), and the target
//! is its full public key.
//!
//! 0-conf: lockups are broadcast non-RBF. The sender returns once
//! Blockstream's 0-conf service sees 4/5 of the functionaries holding
//! the transaction, and the receiver re-checks that before accepting.
//! The service only observes mainnet; on testnet both sides skip it.

mod zeroconf;

/// The `elements` crate (re-exported by LWK) whose script, key and
/// transaction types the HTLC items below use.
pub use lwk_wollet::elements;

use async_trait::async_trait;
use cassis_core::keys::Mnemonic;
use cassis_core::{
    Bytes32, Htlc, HtlcDescriptor, InvoiceTarget, MSAT_PER_SAT, Network, NetworkError, NetworkId,
    OutgoingState, PubKey, sats_for_msat, unix_now,
};
use lwk_common::Signer as LwkSigner;
use lwk_signer::SwSigner;
use lwk_wollet::clients::EsploraClientBuilder;
use lwk_wollet::clients::asyncr::EsploraClient;
use lwk_wollet::elements::bitcoin::PublicKey as BtcPublicKey;
use lwk_wollet::elements::bitcoin::bip32::{DerivationPath, Fingerprint};
use lwk_wollet::elements::bitcoin::hashes::Hash;
use lwk_wollet::elements::bitcoin::hashes::ripemd160;
use lwk_wollet::elements::bitcoin::hashes::sha256;
use lwk_wollet::elements::bitcoin::hex::FromHex as _;
use lwk_wollet::elements::bitcoin::secp256k1;
use lwk_wollet::elements::confidential::{
    Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor,
};
use lwk_wollet::elements::encode::Decodable as _;
use lwk_wollet::elements::opcodes::all::{
    OP_CHECKSIG, OP_CLTV, OP_DROP, OP_ELSE, OP_ENDIF, OP_EQUALVERIFY, OP_HASH160, OP_IF,
};
use lwk_wollet::elements::pset::PartiallySignedTransaction;
use lwk_wollet::elements::script::{Builder as ElScriptBuilder, Script as ElScript};
use lwk_wollet::elements::{
    Address, AddressParams, LockTime, OutPoint, Sequence, Transaction, TxInWitness, TxOut,
    TxOutSecrets, Txid,
};
use lwk_wollet::{Network as LwkNetwork, Wollet, WolletBuilder, WolletDescriptor};
use std::fs::File;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{Span, debug, info, warn};

/// Blockstream esplora for Liquid mainnet.
pub const MAINNET_ESPLORA_URL: &str = "https://blockstream.info/liquid/api";
pub const MAINNET_WATERFALLS_URL: &str = "https://waterfalls.liquidwebwallet.org/liquid/api";
/// Public Liquid testnet Esplora endpoint.
pub const TESTNET_ESPLORA_URL: &str = "https://liquid.network/liquidtestnet/api";
pub const TESTNET_WATERFALLS_URL: &str = "https://waterfalls.liquidwebwallet.org/liquidtestnet/api";

/// Liquid blocks land about every minute.
pub const BLOCK_TIME_SECS: u64 = 60;
/// Fee rate in sats/kilo-vbyte for lockups, claims and refunds
/// (0.1 sat/vbyte — Liquid is cheap).
const FEE_RATE_SATS_KVB: f32 = 100.0;
/// Non-final nSequence so the tx's nLockTime (CLTV) is enforced.
/// Also the BIP-125 boundary: any input sequence *below* this value
/// signals replace-by-fee, which the 0-conf trust model forbids.
pub const NON_FINAL_SEQUENCE: u32 = 0xFFFF_FFFE;
/// Propagation pause replacing the 0-conf coverage wait on testnet,
/// which the 0-conf service does not observe.
const TESTNET_PROPAGATION_WAIT_SECS: u64 = 5;
/// Weight of a claim before its HTLC input's witness, as lwk prices
/// it with the ELIP-200 discount (proofs and commitments count as
/// explicit): 4-byte version, flag, one-byte counts, the 41-byte input
/// shell, a 122-byte confidential P2WPKH wallet output, the 44-byte
/// fee output and 4-byte locktime, times 4; the 8 bytes of empty input
/// and output witnesses; less the value (24) and nonce (32) commitment
/// bytes the discount drops, times 4.
const CLAIM_TX_WEIGHT: usize = 218 * 4 + 8 - (24 + 32) * 4;
/// Dust threshold of the explicit P2WSH lockup output under Elements'
/// `DUST_RELAY_TX_FEE` of 0.1 sat/vbyte (ELIP-201): (78-byte output +
/// 67-byte spend) at 0.1 sat/vbyte, rounded up as `GetDustThreshold`
/// does.
const LOCKUP_DUST_SATS: u64 = (78_u64 + 67).div_ceil(10);

/// Derivation path of the HTLC claim key (see crate docs).
const CLAIM_KEY_PATH: &str = "m/1037'/0";

/// LWK errors (wallet, tx builder, signer, esplora) are network errors.
fn error_from_lwk(e: impl std::fmt::Display) -> NetworkError {
    NetworkError::network(format!("lwk: {e}"))
}

/// RIPEMD160 of the route's 32-byte payment hash: the 20-byte value
/// burned into the claim script. Equals HASH160(preimage), since the
/// payment hash is SHA256(preimage) and `OP_HASH160` checks
/// RIPEMD160(SHA256(x)).
pub fn payment_hash160(payment_hash: &Bytes32) -> [u8; 20] {
    *ripemd160::Hash::hash(payment_hash.as_ref()).as_byte_array()
}

/// Build the HTLC witness script (see the crate docs): an explicit
/// OP_TRUE / empty selector picks preimage revelation + receiver
/// signature on the IF branch or CLTV-gated sender recovery on the
/// ELSE branch; the hash check sits inside the claim branch, leaving
/// the preimage on the stack for OP_HASH160.
pub fn htlc_script(
    payment_hash160: &[u8; 20],
    claim_pubkey: &BtcPublicKey,
    refund_pubkey: &BtcPublicKey,
    refund_locktime: u32,
) -> ElScript {
    ElScriptBuilder::new()
        .push_opcode(OP_IF)
        .push_opcode(OP_HASH160)
        .push_slice(payment_hash160)
        .push_opcode(OP_EQUALVERIFY)
        .push_key(claim_pubkey)
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_ELSE)
        .push_int(i64::from(refund_locktime))
        .push_opcode(OP_CLTV)
        .push_opcode(OP_DROP)
        .push_key(refund_pubkey)
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_ENDIF)
        .into_script()
}

/// The block height an HTLC's refund opens at: the height of the
/// chain `tip` plus the blocks `expiry` (a unix timestamp, the route's
/// expiry) is away.
pub fn refund_locktime(tip_height: u64, expiry: u64) -> Result<u32, NetworkError> {
    let blocks = expiry.saturating_sub(unix_now()).div_ceil(BLOCK_TIME_SECS);
    u32::try_from(tip_height + blocks).map_err(NetworkError::invalid)
}

/// The earliest refund height a receiver accepts for an HTLC expiring
/// at `expiry`, given the chain `tip_height`. A lock made with
/// [`refund_locktime`] is never below it.
pub fn min_refund_locktime(tip_height: u64, expiry: u64) -> u64 {
    tip_height + expiry.saturating_sub(unix_now()) / BLOCK_TIME_SECS
}

/// One HTLC's witness script and the parameters it was built from.
/// Never crosses the wire as-is: the descriptor pins the lockup
/// outpoint and carries only the refund parameters (see
/// [`HtlcSpec::to_descriptor`]); the receiver rebuilds the same spec
/// with its own claim key.
///
/// A wallet that funds or claims HTLCs without a [`LiquidAdapter`]
/// builds this from an [`HtlcRequest`](cassis_core::HtlcRequest) or an
/// [`Htlc`], so that its lockups are the outputs cassis receivers and
/// routers expect.
#[derive(Clone, Debug)]
pub struct HtlcSpec {
    /// The route's 32-byte payment hash, SHA256(preimage). The
    /// script burns its RIPEMD160 (see [`payment_hash160`]).
    pub payment_hash: Bytes32,
    pub refund_pubkey: BtcPublicKey,
    pub refund_locktime: u32,
    pub witness_script: ElScript,
    /// `P2WSH(witness_script)` — the lockup output's script pubkey.
    pub lockup_script_pubkey: ElScript,
}

impl HtlcSpec {
    pub fn build(
        payment_hash: &Bytes32,
        claim_pubkey: BtcPublicKey,
        refund_pubkey: BtcPublicKey,
        refund_locktime: u32,
    ) -> Self {
        let witness_script = htlc_script(
            &payment_hash160(payment_hash),
            &claim_pubkey,
            &refund_pubkey,
            refund_locktime,
        );
        let lockup_script_pubkey = witness_script.to_v0_p2wsh();
        Self {
            payment_hash: *payment_hash,
            refund_pubkey,
            refund_locktime,
            witness_script,
            lockup_script_pubkey,
        }
    }

    /// The spec and lockup outpoint of `htlc`, whose claim key and
    /// refund terms are the descriptor's.
    pub fn of(htlc: &Htlc) -> Result<(Self, OutPoint), NetworkError> {
        let HtlcDescriptor::Liquid {
            lockup_txid,
            lockup_vout,
            refund_pubkey,
            refund_locktime,
            target: claim,
        } = &htlc.descriptor
        else {
            return Err(NetworkError::invalid("not a liquid HTLC"));
        };
        let txid = Txid::from_str(&lockup_txid.to_string()).map_err(NetworkError::invalid)?;
        let spec = Self::build(
            &htlc.payment_hash,
            btc_pubkey(claim)?,
            btc_pubkey(refund_pubkey)?,
            *refund_locktime,
        );
        Ok((spec, OutPoint::new(txid, *lockup_vout)))
    }

    /// The address a lockup pays (unblinded): pay at least the HTLC's
    /// amount of L-BTC to it, from a non-RBF transaction.
    pub fn lockup_address(&self, params: &'static AddressParams) -> Result<Address, NetworkError> {
        Address::from_script(&self.lockup_script_pubkey, None, params)
            .ok_or_else(|| NetworkError::Invalid("cannot derive lockup address".into()))
    }

    /// Build the wire descriptor: the pinned lockup outpoint, the
    /// refund parameters and the `target` claim key the spec was built
    /// with.
    pub fn to_descriptor(&self, lockup: OutPoint, target: PubKey) -> HtlcDescriptor {
        HtlcDescriptor::Liquid {
            lockup_txid: lockup
                .txid
                .to_string()
                .parse()
                .expect("a txid is 32 bytes of hex"),
            lockup_vout: lockup.vout,
            refund_pubkey: PubKey::from_bytes(
                self.refund_pubkey
                    .to_bytes()
                    .try_into()
                    .expect("compressed refund key is 33 bytes"),
            )
            .expect("wallet refund key is valid"),
            refund_locktime: self.refund_locktime,
            target,
        }
    }

    /// The witness of the lockup input given the DER `signature` (with
    /// its sighash byte) of the claim key, or of the refund key when
    /// there is no `preimage`: `[sig, preimage?, true-or-empty, script]`.
    pub fn spend_witness(&self, signature: Vec<u8>, preimage: Option<&[u8; 32]>) -> Vec<Vec<u8>> {
        // Witness items are pushed in order. The selector (OP_TRUE or
        // empty vector) must sit on top of the stack for the leading
        // OP_IF; on claims the preimage goes right below it, free for
        // the branch's OP_HASH160.
        let mut witness = vec![signature];
        if let Some(preimage) = preimage {
            witness.push(preimage.to_vec());
        }
        witness.push(if preimage.is_some() {
            vec![1u8]
        } else {
            Vec::new()
        });
        witness.push(self.witness_script.to_bytes());
        witness
    }

    /// Weight a spend of the lockup adds, for fee estimation.
    pub fn max_weight_to_satisfy(&self, with_preimage: bool) -> usize {
        let script_len = self.witness_script.len();
        let mut witness_len = 1; // item count
        // On claims: the 32-byte preimage (hashed by
        // the claim branch) plus a 1-byte OP_TRUE
        // selector; on refunds an empty push only.
        witness_len += if with_preimage { 1 + 32 + 1 } else { 1 };
        witness_len += 1 + 73; // der sig + sighash byte
        witness_len += varint_len(script_len) + script_len;
        witness_len * 4 + 64 // conservative overhead for the input shell
    }

    /// The preimage revealed by the claim witness of `tx`, which spends
    /// `outpoint`. Spend witness layout:
    /// `[sig, preimage?, selector, script]` — the preimage sits at
    /// index 1 on claims, where the claim branch's OP_HASH160 pops
    /// it; refunds carry an empty push there.
    pub fn preimage_from_spend(
        &self,
        tx: &Transaction,
        outpoint: OutPoint,
    ) -> Result<[u8; 32], String> {
        let vin_index = tx
            .input
            .iter()
            .position(|i| i.previous_output == outpoint)
            .ok_or("spending tx does not spend the lockup outpoint")?;
        let stack = &tx.input[vin_index].witness.script_witness;
        let preimage_bytes = stack.get(1).ok_or("spend witness has no preimage item")?;
        let preimage: [u8; 32] = preimage_bytes
            .as_slice()
            .try_into()
            .map_err(|_| format!("preimage has unexpected length {}", preimage_bytes.len()))?;
        let sha = sha256::Hash::hash(&preimage);
        if Bytes32(sha.to_byte_array()) != self.payment_hash {
            return Err("witness preimage does not hash to the HTLC's payment hash".into());
        }
        Ok(preimage)
    }
}

/// Wait until the lockup `txid` is covered by Blockstream's 0-conf
/// service (mainnet only: nothing observes testnet), which is what a
/// funder does before returning, since the receiver checks it.
pub async fn wait_for_zeroconf_coverage(span: &Span, txid: &str) -> Result<(), String> {
    zeroconf::wait_for_coverage(span, txid).await
}

/// Whether the 0-conf service covers the unconfirmed lockup `txid`,
/// as a receiver checks it on mainnet. The error says what is missing.
pub async fn check_zeroconf_coverage(http: &reqwest::Client, txid: &str) -> Result<(), String> {
    zeroconf::check_coverage(http, txid).await
}

pub struct LiquidAdapter {
    id: NetworkId,
    span: Span,
    signer: SwSigner,
    fingerprint: Fingerprint,
    /// Derivation path of the claim key.
    claim_path: DerivationPath,
    /// Full 33-byte claim pubkey.
    claim_pk_full: BtcPublicKey,
    wollet: Mutex<Wollet>,
    /// Held while a lockup picks wallet coins and spends them, so that
    /// two never pick the same ones.
    funding: Mutex<()>,
    esplora: Mutex<EsploraClient>,
    waterfalls: Mutex<EsploraClient>,
    http: reqwest::Client,
    esplora_url: String,
    network: LwkNetwork,
    /// Exclusive lock on the wallet directory while the adapter is open.
    _lock: File,
}

impl LiquidAdapter {
    /// Open the wallet for `liquid` or `liquid::testnet`, keeping LWK
    /// state under `data_dir` (locked while open).
    pub async fn open(
        id: NetworkId,
        mnemonic: &Mnemonic,
        data_dir: &Path,
        span: &Span,
    ) -> Result<Self, String> {
        let (network, esplora_url, waterfalls_url) = match id.param() {
            None => (
                LwkNetwork::Liquid,
                MAINNET_ESPLORA_URL,
                MAINNET_WATERFALLS_URL,
            ),
            Some("testnet") => (
                LwkNetwork::TestnetLiquid,
                TESTNET_ESPLORA_URL,
                TESTNET_WATERFALLS_URL,
            ),
            Some(other) => return Err(format!("unknown liquid network '{other}'")),
        };
        let secp = secp256k1::Secp256k1::new();
        let signer = SwSigner::new(&mnemonic.to_string(), network.is_mainnet())
            .map_err(|e| format!("invalid mnemonic: {e}"))?;
        let fingerprint = signer.fingerprint();

        let claim_path =
            DerivationPath::from_str(CLAIM_KEY_PATH).map_err(|e| format!("claim key path: {e}"))?;
        let claim_pk_full = BtcPublicKey::new(
            signer
                .derive_xprv(&claim_path)
                .map_err(|e| format!("claim key: {e}"))?
                .private_key
                .public_key(&secp),
        );

        // SLIP-0077 master blinding key of the seed, and the BIP84
        // account of the chain (SLIP-44 coin type 1776 on Liquid), with
        // its origin.
        let mbk_hex = signer
            .slip77_master_blinding_key()
            .map_err(|e| format!("slip77 key: {e}"))?
            .to_string();
        let coin_type = if network.is_mainnet() { 1776 } else { 1 };
        let account_path = DerivationPath::from_str(&format!("m/84'/{coin_type}'/0'"))
            .map_err(|e| format!("wallet account path: {e}"))?;
        let account_xpub = signer
            .derive_xpub(&account_path)
            .map_err(|e| format!("wallet account xpub: {e}"))?;
        let descriptor: WolletDescriptor = format!(
            "ct(slip77({mbk_hex}),elwpkh([{fingerprint}/84'/{coin_type}'/0']{account_xpub}/<0;1>/*))"
        )
        .parse()
        .map_err(|e| format!("wallet descriptor: {e}"))?;

        std::fs::create_dir_all(data_dir).map_err(|e| format!("create {data_dir:?}: {e}"))?;
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(data_dir.join(".lock"))
            .map_err(|e| format!("open liquid wallet lock: {e}"))?;
        fs2::FileExt::try_lock_exclusive(&lock).map_err(|e| {
            format!(
                "liquid wallet at {} is open in another process: {e}",
                data_dir.display()
            )
        })?;
        let store = lwk_wollet::FileStore::new(data_dir.to_path_buf())
            .map_err(|e| format!("liquid wallet store: {e}"))?;
        let wollet = WolletBuilder::new(network, descriptor)
            .utxo_only(true)
            .with_stores(std::sync::Arc::new(store))
            .map_err(|e| format!("liquid wallet store: {e}"))?
            .build()
            .map_err(|e| format!("liquid wallet: {e}"))?;
        #[allow(deprecated)]
        let waterfalls = EsploraClientBuilder::new(waterfalls_url, network)
            .waterfalls(true)
            .utxo_only(true)
            .build()
            .map_err(|e| format!("waterfalls client: {e}"))?;
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| format!("http client: {e}"))?;
        let span = cassis_core::network_span(span, &id);
        debug!(parent: &span, "liquid wallet ready: esplora={esplora_url} claim={claim_pk_full}");
        Ok(Self {
            id,
            span,
            signer,
            fingerprint,
            claim_path,
            claim_pk_full,
            wollet: Mutex::new(wollet),
            funding: Mutex::new(()),
            esplora: Mutex::new(EsploraClient::new(network, esplora_url)),
            waterfalls: Mutex::new(waterfalls),
            http,
            esplora_url: esplora_url.to_string(),
            network,
            _lock: lock,
        })
    }

    fn claim_target(&self) -> InvoiceTarget {
        InvoiceTarget::Liquid {
            network: self.id.clone(),
            target: PubKey::from_bytes(self.claim_pk_full.to_bytes().try_into().expect("33 bytes"))
                .expect("valid claim key"),
        }
    }

    /// The lockup output at `outpoint`, which must pay explicit L-BTC to
    /// `spec` from a non-RBF transaction. Returns its value in sats.
    async fn lockup_value(&self, spec: &HtlcSpec, outpoint: OutPoint) -> Result<u64, NetworkError> {
        let tx = self
            .esplora
            .lock()
            .await
            .get_transaction(outpoint.txid)
            .await
            .map_err(error_from_lwk)?;
        ensure_non_rbf(&tx)?;
        let output = tx
            .output
            .get(outpoint.vout as usize)
            .ok_or_else(|| NetworkError::invalid("lockup transaction has no such output"))?;
        if output.script_pubkey != spec.lockup_script_pubkey {
            return Err(NetworkError::invalid(
                "lockup output does not pay this HTLC (wrong key, hash or refund terms)",
            ));
        }
        if output.asset != Asset::Explicit(*self.network.policy_asset()) {
            return Err(NetworkError::invalid("lockup output is not explicit L-BTC"));
        }
        let Value::Explicit(value_sat) = output.value else {
            return Err(NetworkError::invalid("lockup value is not explicit"));
        };
        Ok(value_sat)
    }

    /// Wait until the lockup is safe to rely on unconfirmed. Errors are
    /// only logged: the lockup is broadcast either way and the receiver
    /// checks coverage itself.
    async fn wait_lockup_propagation(&self, txid: Txid) {
        if !self.network.is_mainnet() {
            tokio::time::sleep(Duration::from_secs(TESTNET_PROPAGATION_WAIT_SECS)).await;
        } else if let Err(error) = zeroconf::wait_for_coverage(&self.span, &txid.to_string()).await
        {
            warn!(parent: &self.span, "lockup {txid} lacks 0-conf coverage: {error}");
        }
    }

    async fn sync_wallet(&self) -> Result<(), NetworkError> {
        let mut waterfalls = self.waterfalls.lock().await;
        let wollet = self.wollet.lock().await;
        let update = waterfalls
            .full_scan(&wollet)
            .await
            .map_err(error_from_lwk)?;
        drop(waterfalls);
        drop(wollet);
        if let Some(update) = update {
            self.wollet
                .lock()
                .await
                .apply_update(update)
                .map_err(error_from_lwk)?;
        }
        Ok(())
    }

    async fn lbtc_balance_sat(&self) -> Result<u64, NetworkError> {
        self.sync_wallet().await?;
        let wollet = self.wollet.lock().await;
        let balance = wollet.balance().map_err(error_from_lwk)?;
        Ok(balance.get(&wollet.policy_asset()).copied().unwrap_or(0))
    }

    async fn next_wallet_address(&self) -> Result<Address, NetworkError> {
        let wollet = self.wollet.lock().await;
        let result = wollet.address(None).map_err(error_from_lwk)?;
        Ok(result.address().clone())
    }

    /// Current Liquid block height via the esplora tip endpoint.
    async fn tip_height(&self) -> Result<u64, NetworkError> {
        let url = format!("{}/blocks/tip/height", self.esplora_url);
        let text = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(error_from_lwk)?
            .error_for_status()
            .map_err(error_from_lwk)?
            .text()
            .await
            .map_err(error_from_lwk)?;
        text.trim()
            .parse()
            .map_err(|e| NetworkError::Network(format!("tip height parse '{text}': {e}")))
    }

    /// Whether `txid` is already included in a block, via the esplora
    /// tx-status endpoint.
    async fn tx_confirmed(&self, txid: &Txid) -> Result<bool, NetworkError> {
        #[derive(serde::Deserialize)]
        struct Status {
            confirmed: bool,
        }
        let url = format!("{}/tx/{}/status", self.esplora_url, txid);
        let status: Status = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(error_from_lwk)?
            .error_for_status()
            .map_err(error_from_lwk)?
            .json()
            .await
            .map_err(|e| NetworkError::Network(format!("tx {txid} status parse: {e}")))?;
        Ok(status.confirmed)
    }

    /// Sign `pset` with the software signer and return the extracted
    /// transaction with every input's witness built by hand: the HTLC
    /// input gets `[sig, preimage?, true-or-empty, script]` (the
    /// selector picks the script branch), plain p2wpkh wallet inputs
    /// get `[sig, pubkey]`.
    ///
    /// Manual witness assembly (instead of `Wollet::finalize`) is
    /// required for the claim path: the preimage is not representable
    /// as a PSBT field, so no generic finalizer can produce it.
    async fn sign_and_extract(
        &self,
        mut pset: PartiallySignedTransaction,
        htlc_input: Option<(OutPoint, Option<[u8; 32]>, &HtlcSpec)>,
    ) -> Result<Transaction, NetworkError> {
        let added = self
            .signer
            .sign(&mut pset)
            .map_err(|e| error_from_lwk(format!("pset sign: {e}")))?;
        if added == 0 {
            return Err(NetworkError::Network(
                "signer produced no signatures; PSBT key sources missing".into(),
            ));
        }
        let mut tx = pset.extract_tx().map_err(error_from_lwk)?;
        for (idx, input) in tx.input.iter_mut().enumerate() {
            if input.is_pegin || !input.witness.script_witness.is_empty() {
                continue;
            }
            let psbt_input = pset
                .inputs()
                .get(idx)
                .ok_or_else(|| NetworkError::Network("pset input missing".into()))?;
            let is_htlc_input = htlc_input
                .as_ref()
                .map(|(o, _, _)| *o == input.previous_output)
                .unwrap_or(false);
            let witness: Vec<Vec<u8>> = if is_htlc_input {
                let sig = psbt_input
                    .partial_sigs
                    .get(&self.claim_pk_full)
                    .ok_or_else(|| {
                        NetworkError::Network("claim signature missing after sign".into())
                    })?;
                let (_, preimage, spec) = htlc_input.as_ref().expect("matched above");
                spec.spend_witness(sig.clone(), preimage.as_ref())
            } else if !psbt_input.partial_sigs.is_empty() {
                // P2WPKH wallet input: [sig, pubkey].
                let (pk, sig) = psbt_input
                    .partial_sigs
                    .iter()
                    .next()
                    .ok_or_else(|| NetworkError::Network("wallet sig missing".into()))?;
                vec![sig.clone(), pk.to_bytes()]
            } else {
                continue;
            };
            input.witness = TxInWitness::empty();
            input.witness.script_witness = witness;
        }
        Ok(tx)
    }

    async fn broadcast(&self, tx: &Transaction) -> Result<Txid, NetworkError> {
        let txid = self
            .esplora
            .lock()
            .await
            .broadcast(tx)
            .await
            .map_err(error_from_lwk)?;
        // Feed our own spend back into wallet state: the next build
        // must not re-select these inputs. Esplora's scripthash scan
        // sees mempool txs, so an immediate resync registers the spend
        // as unconfirmed; without it the wallet happily spends the
        // same UTXO again and the node rejects the second broadcast
        // with `txn-mempool-conflict`. Best-effort: a failed resync
        // only delays UTXO awareness until the next sync.
        if let Err(error) = self.sync_wallet().await {
            self.span.in_scope(|| {
                warn!(target: "cassis_liquid", "post-broadcast resync failed: {error}");
            });
        }
        Ok(txid)
    }

    /// Fee-funded claim (`preimage` set) or refund (`cltv` set) of
    /// `outpoint` (value `value_sat`), draining everything to our
    /// wallet.
    async fn spend_htlc_input(
        &self,
        spec: &HtlcSpec,
        outpoint: OutPoint,
        value_sat: u64,
        preimage: Option<[u8; 32]>,
        cltv: Option<u32>,
    ) -> Result<Txid, NetworkError> {
        let our_address = self.next_wallet_address().await?;
        let txout = TxOut {
            asset: Asset::Explicit(*self.network.policy_asset()),
            value: Value::Explicit(value_sat),
            nonce: Nonce::Null,
            script_pubkey: spec.lockup_script_pubkey.clone(),
            witness: Default::default(),
        };
        let external = lwk_wollet::ExternalUtxo {
            outpoint,
            txout,
            tx: None,
            unblinded: TxOutSecrets::new(
                *self.network.policy_asset(),
                AssetBlindingFactor::zero(),
                value_sat,
                ValueBlindingFactor::zero(),
            ),
            max_weight_to_satisfy: spec.max_weight_to_satisfy(preimage.is_some()),
        };
        let mut pset = {
            let wollet = self.wollet.lock().await;
            wollet
                .tx_builder()
                .add_external_utxos(vec![external])
                .map_err(error_from_lwk)?
                .drain_lbtc_to(&our_address)
                .map_err(error_from_lwk)?
                .fee_rate(Some(FEE_RATE_SATS_KVB))
                .finish()
                .map_err(error_from_lwk)?
        };

        // Point the signer at the HTLC input: witness script + key
        // source on the input it controls.
        let idx = pset
            .inputs()
            .iter()
            .position(|i| {
                i.witness_utxo
                    .as_ref()
                    .map(|o| o.script_pubkey == spec.lockup_script_pubkey)
                    .unwrap_or(false)
            })
            .ok_or_else(|| NetworkError::Network("HTLC input missing from pset".into()))?;
        {
            let input = &mut pset.inputs_mut()[idx];
            input.witness_script = Some(spec.witness_script.clone());
            input.bip32_derivation.insert(
                self.claim_pk_full,
                (self.fingerprint, self.claim_path.clone()),
            );
            if let Some(height) = cltv {
                input.sequence = Some(Sequence::from_consensus(NON_FINAL_SEQUENCE));
                pset.global.tx_data.fallback_locktime = Some(LockTime::from_consensus(height));
            }
        }

        let tx = self
            .sign_and_extract(pset, Some((outpoint, preimage, spec)))
            .await?;
        self.broadcast(&tx).await
    }

    /// Directly send L-BTC to a confidential address (CLI `send`).
    pub async fn transfer_to_address(
        &self,
        address: &str,
        amount_msat: u64,
    ) -> Result<Txid, NetworkError> {
        let to = Address::from_str(address.trim())
            .map_err(|e| NetworkError::Invalid(format!("invalid liquid address: {e}")))?;
        let sats = sats_for_msat(amount_msat);
        self.sync_wallet().await?;
        let mut pset = {
            let wollet = self.wollet.lock().await;
            wollet
                .tx_builder()
                .add_lbtc_recipient(&to, sats)
                .map_err(error_from_lwk)?
                .fee_rate(Some(FEE_RATE_SATS_KVB))
                .finish()
                .map_err(error_from_lwk)?
        };
        let added = self
            .signer
            .sign(&mut pset)
            .map_err(|e| error_from_lwk(format!("pset sign: {e}")))?;
        if added == 0 {
            return Err(NetworkError::Network(
                "signer produced no signatures".into(),
            ));
        }
        let tx = self
            .wollet
            .lock()
            .await
            .finalize(&mut pset)
            .map_err(error_from_lwk)?;
        self.broadcast(&tx).await
    }

    /// Current offchain (L-BTC wallet) balance in msat.
    pub async fn balance_msat(&self) -> Result<u64, NetworkError> {
        let sats = self.lbtc_balance_sat().await?;
        Ok(sats.saturating_mul(MSAT_PER_SAT))
    }

    /// Confidential L-BTC address for deposits.
    pub async fn deposit_address(&self) -> Result<String, NetworkError> {
        Ok(self.next_wallet_address().await?.to_string())
    }

    /// Esplora URL for diagnostics.
    pub fn esplora_url(&self) -> &str {
        &self.esplora_url
    }
}

/// BIP-125: a transaction signals replaceability iff any input's
/// nSequence is below [`NON_FINAL_SEQUENCE`]. The 0-conf trust model
/// only holds for non-RBF transactions (Elements nodes keep the
/// first-seen spend of an input), so both ends refuse replaceable
/// lockups.
pub fn ensure_non_rbf(tx: &Transaction) -> Result<(), NetworkError> {
    if tx
        .input
        .iter()
        .any(|input| input.sequence.to_consensus_u32() < NON_FINAL_SEQUENCE)
    {
        return Err(NetworkError::Network(
            "HTLC lockup transaction signals replace-by-fee".into(),
        ));
    }
    Ok(())
}

/// The bitcoin key of a full cassis public key, parity included.
pub fn btc_pubkey(pubkey: &PubKey) -> Result<BtcPublicKey, NetworkError> {
    let inner = secp256k1::PublicKey::from_slice(pubkey.as_bytes())
        .map_err(|e| NetworkError::Invalid(format!("invalid compressed pubkey: {e}")))?;
    Ok(BtcPublicKey::new(inner))
}

/// The smallest HTLC worth locking: a claim's fee, as lwk computes it
/// at [`FEE_RATE_SATS_KVB`], plus [`LOCKUP_DUST_SATS`]. Any compressed
/// `key` sizes the witness script like the real ones.
fn min_lock_sats(key: &BtcPublicKey) -> u64 {
    // The longest witness script: the largest refund locktime push.
    let spec = HtlcSpec::build(&Bytes32([0; 32]), *key, *key, u32::MAX);
    let weight = CLAIM_TX_WEIGHT + spec.max_weight_to_satisfy(true);
    let claim_fee = (weight.div_ceil(4) as f32 * FEE_RATE_SATS_KVB / 1000.0).ceil() as u64;
    claim_fee + LOCKUP_DUST_SATS
}

fn varint_len(n: usize) -> usize {
    match n {
        0..=0xFC => 1,
        0xFD..=0xFFFF => 3,
        0x1_0000..=0xFFFF_FFFF => 5,
        _ => 9,
    }
}

impl LiquidAdapter {
    /// Find the transaction spending `outpoint` by scanning the
    /// address history, returning its raw bytes decoded.
    async fn find_spending_tx(
        &self,
        address: &Address,
        outpoint: OutPoint,
    ) -> Result<Option<Transaction>, String> {
        #[derive(serde::Deserialize)]
        struct Vin {
            #[serde(default)]
            txid: Option<String>,
            #[serde(default)]
            vout: Option<u32>,
        }
        #[derive(serde::Deserialize)]
        struct TxEntry {
            txid: String,
            #[serde(default)]
            vin: Vec<Vin>,
        }
        let url = format!("{}/address/{}/txs", self.esplora_url, address);
        let text = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("address txs: {e}"))?
            .error_for_status()
            .map_err(|e| format!("address txs: {e}"))?
            .text()
            .await
            .map_err(|e| format!("address txs: {e}"))?;
        let txs: Vec<TxEntry> =
            serde_json::from_str(&text).map_err(|e| format!("address txs parse: {e}"))?;
        for tx in txs {
            let spends = tx.vin.iter().any(|vin| {
                vin.txid.as_deref() == Some(&outpoint.txid.to_string())
                    && vin.vout == Some(outpoint.vout)
            });
            if !spends {
                continue;
            }
            let raw_url = format!("{}/tx/{}/hex", self.esplora_url, tx.txid);
            let hex = self
                .http
                .get(&raw_url)
                .send()
                .await
                .map_err(|e| format!("tx hex: {e}"))?
                .error_for_status()
                .map_err(|e| format!("tx hex: {e}"))?
                .text()
                .await
                .map_err(|e| format!("tx hex: {e}"))?;
            let bytes =
                Vec::<u8>::from_hex(hex.trim()).map_err(|e| format!("tx hex decode: {e}"))?;
            let decoded = Transaction::consensus_decode(&mut std::io::Cursor::new(&bytes))
                .map_err(|e| format!("tx decode: {e}"))?;
            return Ok(Some(decoded));
        }
        Ok(None)
    }
}

#[async_trait]
impl Network for LiquidAdapter {
    fn id(&self) -> NetworkId {
        self.id.clone()
    }

    async fn receive_target(
        &self,
        _payment_hash: Bytes32,
        _amount_msat: u64,
        _expiry: u64,
    ) -> Result<InvoiceTarget, NetworkError> {
        Ok(self.claim_target())
    }

    async fn cancel_receive(&self, _payment_hash: Bytes32) -> Result<(), NetworkError> {
        Ok(())
    }

    async fn verify_incoming_htlc(&self, htlc: &Htlc) -> Result<(), NetworkError> {
        if !htlc.descriptor.pays(&self.claim_target()) {
            return Err(NetworkError::invalid("HTLC is not addressed to this node"));
        }
        self.verify_htlc(htlc).await
    }

    async fn verify_htlc(&self, htlc: &Htlc) -> Result<(), NetworkError> {
        let (spec, outpoint) = HtlcSpec::of(htlc)?;
        // The script was rebuilt from the payment hash, so a lockup
        // paying it is bound to that hash.
        let value_sat = self.lockup_value(&spec, outpoint).await?;
        if value_sat < sats_for_msat(htlc.amount_msat) {
            return Err(NetworkError::invalid("lockup is worth less than the HTLC"));
        }
        let tip = self.tip_height().await?;
        if u64::from(spec.refund_locktime) < min_refund_locktime(tip, htlc.expiry) {
            return Err(NetworkError::invalid("refund opens before the expiry"));
        }
        if self.network.is_mainnet() && !self.tx_confirmed(&outpoint.txid).await? {
            zeroconf::check_coverage(&self.http, &outpoint.txid.to_string())
                .await
                .map_err(NetworkError::NotYet)?;
        }
        let address = spec.lockup_address(self.network.address_params())?;
        if self
            .find_spending_tx(&address, outpoint)
            .await
            .map_err(NetworkError::Network)?
            .is_some()
        {
            return Err(NetworkError::invalid("lockup is already spent"));
        }
        Ok(())
    }

    async fn claim_incoming_htlc(
        &self,
        htlc: &Htlc,
        preimage: Bytes32,
    ) -> Result<(), NetworkError> {
        let (spec, outpoint) = HtlcSpec::of(htlc)?;
        let value_sat = self.lockup_value(&spec, outpoint).await?;
        // TODO: a broadcast claim counts as settled, but nothing checks
        // that it confirms before the sender can refund. Watch it until
        // it does, broadcasting it again if it was dropped.
        let txid = self
            .spend_htlc_input(&spec, outpoint, value_sat, Some(preimage.0), None)
            .await?;
        info!(parent: &self.span, "claimed {}: tx {txid}", htlc.payment_hash.short());
        Ok(())
    }

    async fn create_outgoing_htlc(
        &self,
        payment_hash: Bytes32,
        amount_msat: u64,
        expiry: u64,
        target: &InvoiceTarget,
    ) -> Result<HtlcDescriptor, NetworkError> {
        let InvoiceTarget::Liquid { target: claim, .. } = target else {
            return Err(NetworkError::invalid(
                "liquid HTLCs are locked to a full key",
            ));
        };
        self.check_htlc_amount(amount_msat)?;
        let sats = sats_for_msat(amount_msat);
        let tip = self.tip_height().await?;
        let refund_locktime = refund_locktime(tip, expiry)?;
        let spec = HtlcSpec::build(
            &payment_hash,
            btc_pubkey(claim)?,
            self.claim_pk_full,
            refund_locktime,
        );
        let lockup_address = spec.lockup_address(self.network.address_params())?;
        let funding = self.funding.lock().await;
        self.sync_wallet().await?;
        let mut pset = {
            let wollet = self.wollet.lock().await;
            wollet
                .tx_builder()
                .add_explicit_recipient(&lockup_address, sats, *self.network.policy_asset())
                .map_err(error_from_lwk)?
                .fee_rate(Some(FEE_RATE_SATS_KVB))
                .finish()
                .map_err(error_from_lwk)?
        };
        for input in pset.inputs_mut() {
            if input
                .sequence
                .is_some_and(|sequence| sequence.to_consensus_u32() < NON_FINAL_SEQUENCE)
            {
                input.sequence = Some(Sequence::from_consensus(NON_FINAL_SEQUENCE));
            }
        }
        if self.signer.sign(&mut pset).map_err(error_from_lwk)? == 0 {
            return Err(NetworkError::network("signer produced no signatures"));
        }
        let tx = self
            .wollet
            .lock()
            .await
            .finalize(&mut pset)
            .map_err(error_from_lwk)?;
        ensure_non_rbf(&tx)?;
        let vout =
            tx.output
                .iter()
                .position(|output| output.script_pubkey == spec.lockup_script_pubkey)
                .ok_or_else(|| NetworkError::network("lockup output missing"))? as u32;
        let txid = self.broadcast(&tx).await?;
        drop(funding);
        info!(
            parent: &self.span,
            "locked {sats} sats for {} until block {refund_locktime}: tx {txid}",
            payment_hash.short()
        );
        self.wait_lockup_propagation(txid).await;
        Ok(spec.to_descriptor(OutPoint::new(txid, vout), *claim))
    }

    async fn check_outgoing_htlc(&self, htlc: &Htlc) -> Result<OutgoingState, NetworkError> {
        let (spec, outpoint) = HtlcSpec::of(htlc)?;
        let address = spec.lockup_address(self.network.address_params())?;
        match self
            .find_spending_tx(&address, outpoint)
            .await
            .map_err(NetworkError::Network)?
        {
            None => Ok(OutgoingState::Pending),
            Some(spend) => Ok(spec
                .preimage_from_spend(&spend, outpoint)
                .map(|preimage| OutgoingState::Claimed(Bytes32(preimage)))
                .unwrap_or(OutgoingState::Refunded)),
        }
    }

    async fn refund_outgoing_htlc(&self, htlc: &Htlc) -> Result<(), NetworkError> {
        let (spec, outpoint) = HtlcSpec::of(htlc)?;
        let tip = self.tip_height().await?;
        if tip < u64::from(spec.refund_locktime) {
            return Err(NetworkError::network(format!(
                "refund opens at block {}, tip is {tip}",
                spec.refund_locktime
            )));
        }
        let value_sat = self.lockup_value(&spec, outpoint).await?;
        let txid = self
            .spend_htlc_input(&spec, outpoint, value_sat, None, Some(spec.refund_locktime))
            .await?;
        info!(parent: &self.span, "refunded {}: tx {txid}", htlc.payment_hash.short());
        Ok(())
    }

    /// The claim fee comes out of the HTLC, which must still leave the
    /// receiver more than dust.
    fn min_htlc_msat(&self) -> u64 {
        min_lock_sats(&self.claim_pk_full) * MSAT_PER_SAT
    }

    /// The wallet can build the lockup, fee included.
    async fn can_send(&self, amount_msat: u64) -> Result<(), NetworkError> {
        let needed = sats_for_msat(amount_msat);
        let available = self.lbtc_balance_sat().await?;
        // The lockup is an explicit output; a confidential address would
        // be rejected by `add_explicit_recipient`.
        let address = self.next_wallet_address().await?.to_unconfidential();
        let wollet = self.wollet.lock().await;
        wollet
            .tx_builder()
            .add_explicit_recipient(&address, needed, *self.network.policy_asset())
            .and_then(|builder| builder.fee_rate(Some(FEE_RATE_SATS_KVB)).finish())
            .map_err(|e| {
                NetworkError::invalid(format!(
                    "cannot lock {needed} sats with fees, wallet has {available}: {e}"
                ))
            })?;
        Ok(())
    }

    /// Claim fees come out of the HTLC, which [`Self::min_htlc_msat`]
    /// keeps worth claiming.
    async fn can_receive(&self, _amount_msat: u64) -> Result<(), NetworkError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lwk_wollet::elements::bitcoin::hex::DisplayHex as _;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn test_pubkey(fill: u8) -> BtcPublicKey {
        let secp = secp256k1::Secp256k1::new();
        let secret = secp256k1::SecretKey::from_slice(&[fill; 32]).unwrap();
        BtcPublicKey::new(secret.public_key(&secp))
    }

    #[tokio::test]
    async fn claim_key_is_deterministic() {
        let open = |dir: &str| {
            let dir =
                std::env::temp_dir().join(format!("cassis-liquid-{dir}-{}", std::process::id()));
            async move {
                LiquidAdapter::open(
                    NetworkId("liquid::testnet".into()),
                    &Mnemonic::parse(TEST_MNEMONIC).unwrap(),
                    &dir,
                    &Span::none(),
                )
                .await
                .unwrap()
            }
        };
        let first = open("a").await;
        let second = open("b").await;
        assert_eq!(first.claim_target(), second.claim_target());
    }

    #[test]
    fn min_lock_covers_the_claim_fee_and_dust() {
        // A 394 vbyte claim at 0.1 sat/vbyte, plus 15 sats of dust
        // (145 bytes at 0.1 sat/vbyte, rounded up).
        assert_eq!(min_lock_sats(&test_pubkey(0xaa)), 40 + 15);
    }

    #[test]
    fn htlc_script_commits_to_hash_keys_and_locktime() {
        let payment_hash = Bytes32([42u8; 32]);
        let claimer = test_pubkey(0xaa);
        let refunder = test_pubkey(0xbb);
        let spec = HtlcSpec::build(&payment_hash, claimer, refunder, 1234);
        let script_hex = spec.witness_script.as_bytes().to_lower_hex_string();
        assert!(script_hex.contains(&payment_hash160(&payment_hash).to_lower_hex_string()));
        assert!(script_hex.contains(&claimer.to_bytes().to_lower_hex_string()));
        assert!(script_hex.contains(&refunder.to_bytes().to_lower_hex_string()));
        assert_eq!(spec.lockup_script_pubkey.len(), 34);
    }

    #[test]
    fn descriptor_rebuilds_the_same_spec() {
        let payment_hash = Bytes32([42u8; 32]);
        let claim = test_pubkey(0xaa);
        let spec = HtlcSpec::build(&payment_hash, claim, test_pubkey(0xbb), 1234);
        let txid = Txid::from_str(&"1f".repeat(32)).unwrap();
        let htlc = Htlc {
            payment_hash,
            amount_msat: 1_000_000,
            expiry: 0,
            descriptor: spec.to_descriptor(
                OutPoint::new(txid, 3),
                PubKey::from_bytes(claim.to_bytes().try_into().unwrap()).unwrap(),
            ),
        };
        let (rebuilt, outpoint) = HtlcSpec::of(&htlc).unwrap();
        assert_eq!(rebuilt.lockup_script_pubkey, spec.lockup_script_pubkey);
        assert_eq!(outpoint, OutPoint::new(txid, 3));
    }
}
