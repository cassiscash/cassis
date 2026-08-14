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
//! The claim key is a dedicated even-Y child key (`m/1037'/i`), so the
//! target `02 || x` is always the real key.
//!
//! 0-conf: lockups are broadcast non-RBF. The sender returns once
//! Blockstream's 0-conf service sees 4/5 of the functionaries holding
//! the transaction, and the receiver re-checks that before accepting.
//! The service only observes mainnet; on testnet both sides skip it.

mod zeroconf;

use async_trait::async_trait;
use cassis_core::{
    sats_for_msat, unix_now, Bytes32, Htlc, HtlcDescriptor, HtlcTarget, Network, NetworkError,
    NetworkId, OutgoingState, PubKey, MSAT_PER_SAT,
};
use hmac::Mac;
use lwk_common::Signer as LwkSigner;
use lwk_signer::SwSigner;
use lwk_wollet::clients::asyncr::EsploraClient;
use lwk_wollet::clients::EsploraClientBuilder;
use lwk_wollet::elements::bitcoin::bip32::{DerivationPath, Fingerprint, Xpriv};
use lwk_wollet::elements::bitcoin::hashes::ripemd160;
use lwk_wollet::elements::bitcoin::hashes::sha256;
use lwk_wollet::elements::bitcoin::hashes::Hash;
use lwk_wollet::elements::bitcoin::hex::DisplayHex as _;
use lwk_wollet::elements::bitcoin::hex::FromHex as _;
use lwk_wollet::elements::bitcoin::secp256k1;
use lwk_wollet::elements::bitcoin::PublicKey as BtcPublicKey;
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
use sha2::Sha512;
use std::fs::File;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{debug, info, warn, Span};

/// Blockstream esplora for Liquid mainnet.
pub const MAINNET_ESPLORA_URL: &str = "https://blockstream.info/liquid/api";
pub const MAINNET_WATERFALLS_URL: &str = "https://waterfalls.liquidwebwallet.org/liquid/api";
/// Public Liquid testnet Esplora endpoint.
pub const TESTNET_ESPLORA_URL: &str = "https://liquid.network/liquidtestnet/api";
pub const TESTNET_WATERFALLS_URL: &str = "https://waterfalls.liquidwebwallet.org/liquidtestnet/api";

/// Liquid blocks land about every minute.
const BLOCK_TIME_SECS: u64 = 60;
/// Fee rate in sats/kilo-vbyte for lockups, claims and refunds
/// (0.2 sat/vbyte — Liquid is cheap).
const FEE_RATE_SATS_KVB: f32 = 200.0;
/// Non-final nSequence so the tx's nLockTime (CLTV) is enforced.
/// Also the BIP-125 boundary: any input sequence *below* this value
/// signals replace-by-fee, which the 0-conf trust model forbids.
const NON_FINAL_SEQUENCE: u32 = 0xFFFF_FFFE;
/// Propagation pause replacing the 0-conf coverage wait on testnet,
/// which the 0-conf service does not observe.
const TESTNET_PROPAGATION_WAIT_SECS: u64 = 5;
/// Minimum lockable amount in sats: fees are carved out of the HTLC
/// value itself, so tiny locks would be eaten by fees.
const MIN_LOCK_SATS: u64 = 1_000;

/// Hardened prefix of the HTLC claim-key derivation path. Paths are
/// `m/1037'/{i}` with increasing `i` until the child pubkey has an
/// even Y coordinate (see crate docs).
const CLAIM_KEY_PATH_PREFIX: &str = "m/1037'";
/// SLIP-0077 domain-separation label for the master blinding key.
const SLIP77_LABEL: &[u8] = b"SLIP-0077";

/// LWK errors (wallet, tx builder, signer, esplora) are network errors.
fn error_from_lwk(e: impl std::fmt::Display) -> NetworkError {
    NetworkError::network(format!("lwk: {e}"))
}

/// RIPEMD160 of the route's 32-byte payment hash: the 20-byte value
/// burned into the claim script. Equals HASH160(preimage), since the
/// payment hash is SHA256(preimage) and `OP_HASH160` checks
/// RIPEMD160(SHA256(x)).
fn payment_hash160(payment_hash: &Bytes32) -> [u8; 20] {
    *ripemd160::Hash::hash(payment_hash.as_ref()).as_byte_array()
}

/// Build the HTLC witness script (see the crate docs): an explicit
/// OP_TRUE / empty selector picks preimage revelation + receiver
/// signature on the IF branch or CLTV-gated sender recovery on the
/// ELSE branch; the hash check sits inside the claim branch, leaving
/// the preimage on the stack for OP_HASH160.
fn htlc_script(
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

/// One HTLC's witness script and the parameters it was built from.
/// Never crosses the wire as-is: the descriptor pins the lockup
/// outpoint and carries only the refund parameters (see
/// [`HtlcSpec::to_descriptor`]); the receiver rebuilds the same spec
/// with its own claim key.
#[derive(Clone, Debug)]
struct HtlcSpec {
    /// The route's 32-byte payment hash, SHA256(preimage). The
    /// script burns its RIPEMD160 (see [`payment_hash160`]).
    payment_hash: Bytes32,
    refund_pubkey: BtcPublicKey,
    refund_locktime: u32,
    witness_script: ElScript,
    /// `P2WSH(witness_script)` — the lockup output's script pubkey.
    lockup_script_pubkey: ElScript,
}

impl HtlcSpec {
    fn build(
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

    fn lockup_address(&self, params: &'static AddressParams) -> Result<Address, NetworkError> {
        Address::from_script(&self.lockup_script_pubkey, None, params)
            .ok_or_else(|| NetworkError::Invalid("cannot derive lockup address".into()))
    }

    /// Build the wire descriptor: the pinned lockup outpoint plus the
    /// refund parameters the receiver cannot derive itself (the claim
    /// side it rebuilds from its own claim key and the payment hash).
    fn to_descriptor(&self, lockup: OutPoint) -> HtlcDescriptor {
        HtlcDescriptor::Liquid {
            lockup_txid: lockup.txid.to_string(),
            lockup_vout: lockup.vout,
            refund_pubkey: PubKey::from_bytes(
                self.refund_pubkey
                    .to_bytes()
                    .try_into()
                    .expect("compressed refund key is 33 bytes"),
            )
            .expect("wallet refund key is valid"),
            refund_locktime: self.refund_locktime,
        }
    }
}

pub struct LiquidAdapter {
    id: NetworkId,
    span: Span,
    signer: SwSigner,
    fingerprint: Fingerprint,
    /// Derivation path of the claim key (even-Y child).
    claim_path: DerivationPath,
    /// Full 33-byte claim pubkey (always `02 || X`).
    claim_pk_full: BtcPublicKey,
    wollet: Mutex<Wollet>,
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
        secret: [u8; 32],
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
        let bip32_network = if network.is_mainnet() {
            lwk_wollet::elements::bitcoin::Network::Bitcoin
        } else {
            lwk_wollet::elements::bitcoin::Network::Testnet
        };
        let xprv = Xpriv::new_master(bip32_network, &secret)
            .map_err(|e| format!("invalid secret key: {e}"))?;
        let signer = SwSigner::from_xprv(xprv);
        let fingerprint = signer.fingerprint();

        // Claim key: first even-Y child under m/1037'.
        let (claim_pk_full, claim_path) = (0u32..=64)
            .find_map(|i| {
                let path =
                    DerivationPath::from_str(&format!("{CLAIM_KEY_PATH_PREFIX}/{i}")).ok()?;
                let child = xprv.derive_priv(&secp, &path).ok()?;
                let pk = child.private_key.public_key(&secp);
                (pk.serialize()[0] == 0x02).then(|| (BtcPublicKey::new(pk), path))
            })
            .ok_or("no even-Y claim key found under m/1037' within 64 tries")?;

        // SLIP-0077 master blinding key derived from the secret, with
        // the account-level xpub and origin.
        let mut mac = <hmac::Hmac<Sha512> as hmac::Mac>::new_from_slice(SLIP77_LABEL)
            .expect("hmac key length is always valid");
        mac.update(&secret);
        let mbk_hex = mac.finalize().into_bytes()[..32].to_lower_hex_string();
        let account_path = DerivationPath::from_str("m/84'/1'/0'")
            .map_err(|e| format!("wallet account path: {e}"))?;
        let account_xpub = signer
            .derive_xpub(&account_path)
            .map_err(|e| format!("wallet account xpub: {e}"))?;
        let descriptor: WolletDescriptor = format!(
            "ct(slip77({mbk_hex}),elwpkh([{fingerprint}/84'/1'/0']{account_xpub}/<0;1>/*))"
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
            esplora: Mutex::new(EsploraClient::new(network, esplora_url)),
            waterfalls: Mutex::new(waterfalls),
            http,
            esplora_url: esplora_url.to_string(),
            network,
            _lock: lock,
        })
    }

    fn claim_target(&self) -> HtlcTarget {
        HtlcTarget::PubKey(
            PubKey::from_bytes(self.claim_pk_full.to_bytes().try_into().expect("33 bytes"))
                .expect("valid claim key"),
        )
    }

    /// Lockup outpoint and the HTLC script of `htlc`, whose claim key
    /// is the target's and whose refund terms are the descriptor's.
    fn htlc_spec(htlc: &Htlc) -> Result<(HtlcSpec, OutPoint), NetworkError> {
        let HtlcDescriptor::Liquid {
            lockup_txid,
            lockup_vout,
            refund_pubkey,
            refund_locktime,
        } = &htlc.descriptor
        else {
            return Err(NetworkError::invalid("not a liquid HTLC"));
        };
        let HtlcTarget::PubKey(claim) = &htlc.target else {
            return Err(NetworkError::invalid(
                "liquid HTLCs are locked to a full key",
            ));
        };
        let txid = Txid::from_str(lockup_txid).map_err(NetworkError::invalid)?;
        let spec = HtlcSpec::build(
            &htlc.payment_hash,
            even_y_pubkey(claim)?,
            even_y_pubkey(refund_pubkey)?,
            *refund_locktime,
        );
        Ok((spec, OutPoint::new(txid, *lockup_vout)))
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

    fn max_weight_to_satisfy(script: &ElScript, with_preimage: bool) -> usize {
        let script_len = script.len();
        let mut witness_len = 1; // item count
                                 // On claims: the 32-byte preimage (hashed by
                                 // the claim branch) plus a 1-byte OP_TRUE
                                 // selector; on refunds an empty push only.
        witness_len += if with_preimage { 1 + 32 + 1 } else { 1 };
        witness_len += 1 + 73; // der sig + sighash byte
        witness_len += varint_len(script_len) + script_len;
        witness_len * 4 + 64 // conservative overhead for the input shell
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
        htlc_input: Option<(OutPoint, Option<[u8; 32]>, &ElScript)>,
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
                let (_, preimage, script) = htlc_input.as_ref().expect("matched above");
                // Witness items are pushed in order. The selector
                // (OP_TRUE or empty vector) must sit on top of the
                // stack for the leading OP_IF; on claims the preimage
                // goes right below it, free for the branch's
                // OP_HASH160.
                let selector = if preimage.is_some() {
                    vec![1u8]
                } else {
                    Vec::new()
                };
                let mut witness = vec![sig.clone()];
                if let Some(p) = preimage {
                    witness.push(p.to_vec());
                }
                witness.push(selector);
                witness.push(script.to_bytes());
                witness
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
            max_weight_to_satisfy: Self::max_weight_to_satisfy(
                &spec.witness_script,
                preimage.is_some(),
            ),
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
            .sign_and_extract(pset, Some((outpoint, preimage, &spec.witness_script)))
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
fn ensure_non_rbf(tx: &Transaction) -> Result<(), NetworkError> {
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

fn even_y_pubkey(pubkey: &PubKey) -> Result<BtcPublicKey, NetworkError> {
    let inner = secp256k1::PublicKey::from_slice(pubkey.as_bytes())
        .map_err(|e| NetworkError::Invalid(format!("invalid compressed pubkey: {e}")))?;
    Ok(BtcPublicKey::new(inner))
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

    /// Pull the preimage from the claim witness of the tx spending
    /// `outpoint`. Spend witness layout:
    /// `[sig, preimage?, selector, script]` — the preimage sits at
    /// index 1 on claims, where the claim branch's OP_HASH160 pops
    /// it; refunds carry an empty push there.
    fn extract_preimage(
        tx: &Transaction,
        outpoint: OutPoint,
        spec: &HtlcSpec,
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
        if Bytes32(sha.to_byte_array()) != spec.payment_hash {
            return Err("witness preimage does not hash to the HTLC's payment hash".into());
        }
        Ok(preimage)
    }
}

#[async_trait]
impl Network for LiquidAdapter {
    fn id(&self) -> NetworkId {
        self.id.clone()
    }

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
        let (spec, outpoint) = Self::htlc_spec(htlc)?;
        if htlc.target != self.claim_target() {
            return Err(NetworkError::invalid("HTLC is not addressed to this node"));
        }
        // The script was rebuilt from the payment hash, so a lockup
        // paying it is bound to that hash.
        let value_sat = self.lockup_value(&spec, outpoint).await?;
        if value_sat < sats_for_msat(htlc.amount_msat) {
            return Err(NetworkError::invalid("lockup is worth less than the HTLC"));
        }
        let tip = self.tip_height().await?;
        let blocks = htlc.expiry.saturating_sub(unix_now()) / BLOCK_TIME_SECS;
        if u64::from(spec.refund_locktime) < tip + blocks {
            return Err(NetworkError::invalid("refund opens before the expiry"));
        }
        if self.network.is_mainnet() && !self.tx_confirmed(&outpoint.txid).await? {
            zeroconf::check_coverage(&self.http, &outpoint.txid.to_string())
                .await
                .map_err(NetworkError::Network)?;
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
        let (spec, outpoint) = Self::htlc_spec(htlc)?;
        let value_sat = self.lockup_value(&spec, outpoint).await?;
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
        target: &HtlcTarget,
    ) -> Result<HtlcDescriptor, NetworkError> {
        let HtlcTarget::PubKey(claim) = target else {
            return Err(NetworkError::invalid(
                "liquid HTLCs are locked to a full key",
            ));
        };
        let sats = sats_for_msat(amount_msat);
        if sats < MIN_LOCK_SATS {
            return Err(NetworkError::invalid(format!(
                "liquid HTLCs lock at least {MIN_LOCK_SATS} sats"
            )));
        }
        let tip = self.tip_height().await?;
        let blocks = expiry.saturating_sub(unix_now()).div_ceil(BLOCK_TIME_SECS);
        let refund_locktime = u32::try_from(tip + blocks).map_err(NetworkError::invalid)?;
        let spec = HtlcSpec::build(
            &payment_hash,
            even_y_pubkey(claim)?,
            self.claim_pk_full,
            refund_locktime,
        );
        let lockup_address = spec.lockup_address(self.network.address_params())?;
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
        info!(
            parent: &self.span,
            "locked {sats} sats for {} until block {refund_locktime}: tx {txid}",
            payment_hash.short()
        );
        self.wait_lockup_propagation(txid).await;
        Ok(spec.to_descriptor(OutPoint::new(txid, vout)))
    }

    async fn check_outgoing_htlc(&self, htlc: &Htlc) -> Result<OutgoingState, NetworkError> {
        let (spec, outpoint) = Self::htlc_spec(htlc)?;
        let address = spec.lockup_address(self.network.address_params())?;
        match self
            .find_spending_tx(&address, outpoint)
            .await
            .map_err(NetworkError::Network)?
        {
            None => Ok(OutgoingState::Pending),
            Some(spend) => Ok(Self::extract_preimage(&spend, outpoint, &spec)
                .map(|preimage| OutgoingState::Claimed(Bytes32(preimage)))
                .unwrap_or(OutgoingState::Refunded)),
        }
    }

    async fn refund_outgoing_htlc(&self, htlc: &Htlc) -> Result<(), NetworkError> {
        let (spec, outpoint) = Self::htlc_spec(htlc)?;
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

    async fn can_send(&self, amount_msat: u64) -> Result<(), NetworkError> {
        let needed = sats_for_msat(amount_msat);
        let available = self.lbtc_balance_sat().await?;
        if needed > available {
            return Err(NetworkError::invalid(format!(
                "need {needed} sats, wallet has {available}"
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

    fn test_pubkey(fill: u8) -> BtcPublicKey {
        let secp = secp256k1::Secp256k1::new();
        let secret = secp256k1::SecretKey::from_slice(&[fill; 32]).unwrap();
        BtcPublicKey::new(secret.public_key(&secp))
    }

    #[tokio::test]
    async fn claim_key_is_even_and_deterministic() {
        let open = |dir: &str| {
            let dir =
                std::env::temp_dir().join(format!("cassis-liquid-{dir}-{}", std::process::id()));
            async move {
                LiquidAdapter::open(
                    NetworkId("liquid::testnet".into()),
                    [7u8; 32],
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
        assert_eq!(first.claim_pk_full.to_bytes()[0], 0x02);
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
            target: HtlcTarget::PubKey(
                PubKey::from_bytes(claim.to_bytes().try_into().unwrap()).unwrap(),
            ),
            descriptor: spec.to_descriptor(OutPoint::new(txid, 3)),
        };
        let (rebuilt, outpoint) = LiquidAdapter::htlc_spec(&htlc).unwrap();
        assert_eq!(rebuilt.lockup_script_pubkey, spec.lockup_script_pubkey);
        assert_eq!(outpoint, OutPoint::new(txid, 3));
    }
}
