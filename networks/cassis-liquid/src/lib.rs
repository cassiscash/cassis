//! Liquid network adapter for cassis.
//!
//! Implements [`NetworkRouterAdapter`] on Liquid (Elements) using the
//! Liquid Wallet Kit (LWK): a watch-only wallet over a CT descriptor
//! derived from the node's per-network key, a software PSET signer,
//! and an esplora backend for sync and broadcast.
//!
//! HTLCs are plain P2WSH outputs whose single witness script has two
//! spending paths (boltz-style):
//!
//! ```text
//! OP_HASH160 <RIPEMD160(payment_hash)> OP_EQUAL
//! OP_IF <claim_pubkey>
//! OP_ELSE <refund_locktime> OP_CLTV OP_DROP <refund_pubkey>
//! OP_ENDIF
//! OP_CHECKSIG
//! ```
//!
//! * **Claim** (receiver): witness `[sig, preimage, script]` — the
//!   revealed preimage selects the IF branch and the receiver signs
//!   with its per-network claim key. The lockup output is *unblinded*
//!   (explicit), so no blinding keys ever cross the protocol.
//! * **Refund** (sender): witness `[sig, <empty>, script]` — the
//!   empty push fails the hash check, selecting the CLTV branch;
//!   recoverable after an absolute block height derived from the
//!   route expiry.
//!
//! Claim and refund are built as single-input spends whose fee comes
//! out of the HTLC value itself (LWK `drain_lbtc_to`), so neither
//! needs wallet funds — the wallet only pays fees for lockups.
//!
//! Hash semantics match the arkade adapter: a cassis payment hash is
//! SHA256(preimage), the script burns `OP_HASH160` =
//! RIPEMD160(SHA256(x)), so the 20 bytes in the script are
//! RIPEMD160(payment_hash). The claim side of the script is derived
//! from the payment hash and the receiver's claim key, so the wire
//! descriptor carries only the lockup outpoint plus the refund pubkey
//! and locktime — the receiver rebuilds the script itself, which
//! simultaneously verifies the hash binding and its own identity.
//!
//! Claim-key parity: cassis identities are x-only (32 bytes), but
//! `OP_CHECKSIG` on Liquid needs the full 33-byte compressed pubkey.
//! The adapter derives a dedicated claim key at a hardened path,
//! scanning paths until the child pubkey has an even Y coordinate, so
//! `02 || x-only(claim key)` is always the real pubkey and
//! counterparties locking to the x-only identity are safe.
//!
//! 0-conf: lockups are broadcast non-RBF, and the sender only reports
//! an outgoing HTLC as deployed once Blockstream's 0-conf observation
//! service (see the `zeroconf` module) shows at least 4/5 of the functionaries
//! have the tx in their mempool. The descriptor sent in DISPATCH pins
//! the lockup txid and output, so the receiver re-checks the same
//! service with one REST call and verifies the pinned output via
//! esplora before accepting. The service only observes mainnet, so on
//! `liquid::testnet` both checks are skipped and the sender instead
//! pauses briefly for mempool propagation.

mod zeroconf;

use async_trait::async_trait;
use cassis_core::{
    Bytes32, HtlcDescriptor, HtlcError, NetworkId, NetworkRouterAdapter, OutgoingHtlc, PubKey,
    WatchError,
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
    OP_CHECKSIG, OP_CLTV, OP_DROP, OP_ELSE, OP_ENDIF, OP_EQUAL, OP_HASH160, OP_IF,
};
use lwk_wollet::elements::pset::PartiallySignedTransaction;
use lwk_wollet::elements::script::{Builder as ElScriptBuilder, Script as ElScript};
use lwk_wollet::elements::{
    Address, AddressParams, LockTime, OutPoint, Sequence, Transaction, TxInWitness, TxOut,
    TxOutSecrets, Txid,
};
use lwk_wollet::{Network, Wollet, WolletBuilder, WolletDescriptor};
use sha2::Sha512;
use std::collections::HashMap;
use std::fs::File;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
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
/// Headroom added on top of the expiry-derived refund locktime.
const REFUND_LOCKTIME_SLACK_BLOCKS: u64 = 6;
/// Fee rate in sats/kilo-vbyte for lockups, claims and refunds
/// (0.2 sat/vbyte — Liquid is cheap).
const FEE_RATE_SATS_KVB: f32 = 200.0;
/// Non-final nSequence so the tx's nLockTime (CLTV) is enforced.
/// Also the BIP-125 boundary: any input sequence *below* this value
/// signals replace-by-fee, which the 0-conf trust model forbids.
const NON_FINAL_SEQUENCE: u32 = 0xFFFF_FFFE;
const POLL_INTERVAL_SECS: u64 = 5;
/// Propagation pause replacing the 0-conf coverage wait on testnet,
/// which the 0-conf service does not observe.
const TESTNET_PROPAGATION_WAIT_SECS: u64 = 5;
/// Millisatoshi per satoshi.
const MSAT_PER_SAT: u64 = 1000;
/// Minimum lockable amount in sats: fees are carved out of the HTLC
/// value itself, so tiny locks would be eaten by fees.
const MIN_LOCK_SATS: u64 = 1_000;

/// Hardened prefix of the HTLC claim-key derivation path. Paths are
/// `m/1037'/{i}` with increasing `i` until the child pubkey has an
/// even Y coordinate (see crate docs).
const CLAIM_KEY_PATH_PREFIX: &str = "m/1037'";
/// SLIP-0077 domain-separation label for the master blinding key.
const SLIP77_LABEL: &[u8] = b"SLIP-0077";
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

/// Convert an LWK error (wallet, tx builder, signer or esplora
/// client) into the routing layer's network error. The `lwk: ` prefix
/// keeps the failing subsystem identifiable in router logs.
fn error_from_lwk(e: impl std::fmt::Display) -> HtlcError {
    HtlcError::Network(format!("lwk: {e}"))
}

#[derive(Clone, Debug)]
pub struct LiquidConfig {
    pub network_id: NetworkId,
    pub esplora_url: String,
    pub waterfalls_url: String,
    /// Directory used for LWK wallet state. `None` keeps wallet state
    /// in memory, useful for tests.
    pub persist_dir: Option<PathBuf>,
    /// 32-byte secret key derived from `cassis/network/<network_id>`.
    pub sk: [u8; 32],
    pub invoice_pubkey: PubKey,
    pub span: Span,
}

/// Canonical config for `liquid` (mainnet) or `liquid::testnet`.
/// Callers may override any field before constructing.
pub fn default_config(
    network_id: NetworkId,
    sk: [u8; 32],
    invoice_pubkey: PubKey,
    span: Span,
) -> LiquidConfig {
    match network_id.0.as_str() {
        "liquid::testnet" => LiquidConfig {
            network_id,
            esplora_url: TESTNET_ESPLORA_URL.to_string(),
            waterfalls_url: TESTNET_WATERFALLS_URL.to_string(),
            persist_dir: None,
            sk,
            invoice_pubkey,
            span: span.clone(),
        },
        _ => LiquidConfig {
            network_id,
            esplora_url: MAINNET_ESPLORA_URL.to_string(),
            waterfalls_url: MAINNET_WATERFALLS_URL.to_string(),
            persist_dir: None,
            sk,
            invoice_pubkey,
            span,
        },
    }
}

fn lwk_network(network_id: &NetworkId) -> Network {
    match network_id.0.as_str() {
        "liquid::testnet" => Network::TestnetLiquid,
        _ => Network::Liquid,
    }
}

/// RIPEMD160 of the route's 32-byte payment hash: the 20-byte value
/// burned into the claim script. Equals HASH160(preimage), since the
/// payment hash is SHA256(preimage) and `OP_HASH160` checks
/// RIPEMD160(SHA256(x)).
fn payment_hash160(payment_hash: &Bytes32) -> [u8; 20] {
    *ripemd160::Hash::hash(payment_hash.as_ref()).as_byte_array()
}

fn msat_to_sat(amount_msat: u64) -> Result<u64, HtlcError> {
    if amount_msat % MSAT_PER_SAT != 0 {
        return Err(HtlcError::InvalidParams(format!(
            "amount {amount_msat} msat is not a whole number of satoshis; \
             liquid amounts must be multiples of {MSAT_PER_SAT} msat"
        )));
    }
    Ok(amount_msat / MSAT_PER_SAT)
}

/// Build the HTLC witness script (see the crate docs): preimage
/// revelation + receiver signature on the IF branch, CLTV-gated
/// sender recovery on the ELSE branch.
fn htlc_script(
    payment_hash160: &[u8; 20],
    claim_pubkey: &BtcPublicKey,
    refund_pubkey: &BtcPublicKey,
    refund_locktime: u32,
) -> ElScript {
    ElScriptBuilder::new()
        .push_opcode(OP_HASH160)
        .push_slice(payment_hash160)
        .push_opcode(OP_EQUAL)
        .push_opcode(OP_IF)
        .push_key(claim_pubkey)
        .push_opcode(OP_ELSE)
        .push_int(i64::from(refund_locktime))
        .push_opcode(OP_CLTV)
        .push_opcode(OP_DROP)
        .push_key(refund_pubkey)
        .push_opcode(OP_ENDIF)
        .push_opcode(OP_CHECKSIG)
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

    fn lockup_address(&self, params: &'static AddressParams) -> Result<Address, HtlcError> {
        Address::from_script(&self.lockup_script_pubkey, None, params)
            .ok_or_else(|| HtlcError::InvalidParams("cannot derive lockup address".into()))
    }

    /// Build the wire descriptor: the pinned lockup outpoint plus the
    /// refund parameters the receiver cannot derive itself (the claim
    /// side it rebuilds from its own claim key and the payment hash).
    fn to_descriptor(&self, lockup: OutPoint) -> Result<HtlcDescriptor, HtlcError> {
        Ok(HtlcDescriptor::Liquid {
            lockup_txid: lockup.txid.to_string(),
            lockup_vout: lockup.vout.try_into().map_err(|_| {
                HtlcError::InvalidParams(format!(
                    "lockup output index {} does not fit the descriptor's u8",
                    lockup.vout
                ))
            })?,
            refund_pubkey: self.refund_pubkey.to_bytes().to_lower_hex_string(),
            refund_locktime: self.refund_locktime,
        })
    }
}

struct PendingIncoming {
    /// Pinned lockup output, populated once the dispatched HTLC
    /// passes 0-conf + on-chain verification; `None` while the slot
    /// is only reserved by PREPARE.
    accepted: Option<AcceptedHtlc>,
    expected_sat: u64,
    /// Kept for parity with the reserved-slot bookkeeping model of the
    /// other adapters (the PREPARE deadline); not polled directly.
    #[allow(dead_code)]
    deadline: u64,
}

/// Incoming HTLC that passed `verified_incoming`: claims spend this
/// exact outpoint with this exact witness script instead of
/// re-scanning the lockup address.
#[derive(Clone)]
struct AcceptedHtlc {
    spec: HtlcSpec,
    outpoint: OutPoint,
    value_sat: u64,
}

struct PendingOutgoing {
    spec: HtlcSpec,
    /// Output of the lockup tx carrying the HTLC.
    outpoint: OutPoint,
    value_sat: u64,
}

pub struct LiquidAdapter {
    network_id: NetworkId,
    invoice_pubkey: PubKey,
    span: Span,
    signer: SwSigner,
    fingerprint: Fingerprint,
    /// Derivation path of the claim key (even-Y child).
    claim_path: DerivationPath,
    /// Full 33-byte claim pubkey (always `02 || X`).
    claim_pk_full: BtcPublicKey,
    /// x-only half of `claim_pk_full`, the identity counterparties
    /// lock to.
    claim_xonly: PubKey,
    wollet: Arc<Mutex<Wollet>>,
    esplora: Arc<Mutex<EsploraClient>>,
    waterfalls: Arc<Mutex<EsploraClient>>,
    http: reqwest::Client,
    esplora_url: String,
    network: Network,
    /// Exclusive lock for `persist_dir`; held while adapter is open.
    _persist_lock: Option<File>,
    incoming: Mutex<HashMap<Bytes32, PendingIncoming>>,
    outgoing: Mutex<HashMap<Bytes32, PendingOutgoing>>,
}

impl std::fmt::Debug for LiquidAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LiquidAdapter")
            .field("network_id", &self.network_id)
            .field("claim_pubkey", &self.claim_xonly.to_hex())
            .field("esplora", &self.esplora_url)
            .finish()
    }
}

impl LiquidAdapter {
    pub async fn new(config: LiquidConfig) -> Result<Arc<Self>, Error> {
        let secp = secp256k1::Secp256k1::new();
        let network = lwk_network(&config.network_id);
        let bip32_network = if network.is_mainnet() {
            lwk_wollet::elements::bitcoin::Network::Bitcoin
        } else {
            lwk_wollet::elements::bitcoin::Network::Testnet
        };
        let xprv = Xpriv::new_master(bip32_network, &config.sk)
            .map_err(|e| Error::InvalidParams(format!("invalid secret key: {e}")))?;
        let signer = SwSigner::from_xprv(xprv);
        let fingerprint = signer.fingerprint();

        // Claim key: first even-Y child under m/1037'.
        let mut claim_pk_full = None;
        let mut claim_path = None;
        for i in 0u32..=64 {
            let path = DerivationPath::from_str(&format!("{CLAIM_KEY_PATH_PREFIX}/{i}"))
                .map_err(|e| Error::InvalidParams(format!("bad claim path: {e}")))?;
            let child = xprv
                .derive_priv(&secp, &path)
                .map_err(|e| Error::InvalidParams(format!("claim key derive: {e}")))?;
            let pk = child.private_key.public_key(&secp);
            if pk.serialize()[0] == 0x02 {
                claim_pk_full = Some(BtcPublicKey::new(pk));
                claim_path = Some(path);
                break;
            }
        }
        let (claim_pk_full, claim_path) = match (claim_pk_full, claim_path) {
            (Some(pk), Some(path)) => (pk, path),
            _ => {
                return Err(Error::InvalidParams(
                    "no even-Y claim key found under m/1037' within 64 tries".to_string(),
                ));
            }
        };
        let claim_bytes = claim_pk_full.to_bytes();
        let claim_xonly = PubKey::from_bytes(claim_bytes[1..33].try_into().expect("32 bytes"))
            .map_err(|e| Error::InvalidParams(format!("invalid claim pubkey: {e}")))?;

        // Keep custom SLIP-0077 derivation because this signer may not expose
        // deterministic SLIP-0077, but use account-level xpub and origin.
        let mut mac = <hmac::Hmac<Sha512> as hmac::Mac>::new_from_slice(SLIP77_LABEL)
            .expect("hmac key length is always valid");
        mac.update(&config.sk);
        let mbk_hex = mac.finalize().into_bytes()[..32].to_lower_hex_string();
        let account_path = DerivationPath::from_str("m/84'/1'/0'")
            .map_err(|e| Error::InvalidParams(format!("wallet account path: {e}")))?;
        let account_xpub = signer
            .derive_xpub(&account_path)
            .map_err(|e| Error::InvalidParams(format!("wallet account xpub: {e}")))?;
        let descriptor_str = format!(
            "ct(slip77({mbk_hex}),elwpkh([{}/84'/1'/0']{account_xpub}/<0;1>/*))",
            fingerprint
        );
        let descriptor: WolletDescriptor = descriptor_str
            .parse()
            .map_err(|e| Error::InvalidParams(format!("wollet descriptor: {e}")))?;
        let mut wollet_builder = WolletBuilder::new(network, descriptor).utxo_only(true);
        let persist_lock = if let Some(persist_dir) = &config.persist_dir {
            std::fs::create_dir_all(persist_dir)
                .map_err(|e| Error::Client(format!("create Liquid wallet directory: {e}")))?;
            let lock_path = persist_dir.join(".lock");
            let lock = std::fs::OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .open(&lock_path)
                .map_err(|e| Error::Client(format!("open Liquid wallet lock: {e}")))?;
            fs2::FileExt::try_lock_exclusive(&lock).map_err(|e| {
                Error::Client(format!(
                    "Liquid wallet already open at {}; close other process first: {e}",
                    persist_dir.display()
                ))
            })?;
            let file_store = lwk_wollet::FileStore::new(persist_dir.clone())
                .map_err(|e| Error::Client(format!("create Liquid wallet store: {e}")))?;
            wollet_builder = wollet_builder
                .with_stores(Arc::new(file_store))
                .map_err(|e| Error::Client(format!("configure Liquid wallet store: {e}")))?;
            Some(lock)
        } else {
            None
        };
        let wollet = Arc::new(Mutex::new(
            wollet_builder
                .build()
                .map_err(|e| Error::Client(format!("wollet build: {e}")))?,
        ));
        let esplora = Arc::new(Mutex::new(EsploraClient::new(network, &config.esplora_url)));
        #[allow(deprecated)]
        let waterfalls = Arc::new(Mutex::new(
            EsploraClientBuilder::new(&config.waterfalls_url, network)
                .waterfalls(true)
                .utxo_only(true)
                .build()
                .map_err(|e| Error::Client(format!("create Waterfalls client: {e}")))?,
        ));
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| Error::Client(format!("http client: {e}")))?;

        let span = cassis_core::network_span(&config.span, &config.network_id);
        span.in_scope(|| {
            debug!(
                target: "cassis_liquid",
                "adapter ready: esplora={} claim={}",
                config.esplora_url,
                claim_xonly,
            );
        });

        Ok(Arc::new(Self {
            network_id: config.network_id.clone(),
            invoice_pubkey: config.invoice_pubkey,
            span,
            signer,
            fingerprint,
            claim_path,
            claim_pk_full,
            claim_xonly,
            wollet,
            esplora,
            waterfalls,
            http,
            esplora_url: config.esplora_url.clone(),
            network,
            _persist_lock: persist_lock,
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

    /// Build the descriptor for an outgoing HTLC.
    fn build_options(
        &self,
        payment_hash: &Bytes32,
        recipient: &PubKey,
        expiry: u64,
        tip: u64,
    ) -> Result<HtlcSpec, HtlcError> {
        let now = Self::unix_now();
        if expiry <= now {
            return Err(HtlcError::InvalidParams("expiry in the past".into()));
        }
        // The recipient's liquid claim identity is `02 || X` of its
        // x-only key: its adapter normalizes the per-network key to
        // the even-Y representative, exactly like rootstock does for
        // its EVM address mapping.
        let recipient_full = even_y_pubkey(recipient)?;
        let remaining_blocks = expiry.saturating_sub(now) / BLOCK_TIME_SECS;
        let refund_locktime = (tip + remaining_blocks + REFUND_LOCKTIME_SLACK_BLOCKS)
            .min(u64::from(u32::MAX - 1)) as u32;
        Ok(HtlcSpec::build(
            payment_hash,
            recipient_full,
            self.claim_pk_full,
            refund_locktime,
        ))
    }

    /// Sync the wallet with esplora (best-effort: on failure the
    /// cached state is used).
    async fn sync_wallet(&self) -> Result<(), HtlcError> {
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

    async fn lbtc_balance_sat(&self) -> Result<u64, HtlcError> {
        self.sync_wallet().await?;
        let wollet = self.wollet.lock().await;
        let balance = wollet.balance().map_err(error_from_lwk)?;
        Ok(balance.get(&wollet.policy_asset()).copied().unwrap_or(0))
    }

    async fn next_wallet_address(&self) -> Result<Address, HtlcError> {
        let wollet = self.wollet.lock().await;
        let result = wollet.address(None).map_err(error_from_lwk)?;
        Ok(result.address().clone())
    }

    /// Current Liquid block height via the esplora tip endpoint.
    async fn tip_height(&self) -> Result<u64, HtlcError> {
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
            .map_err(|e| HtlcError::Network(format!("tip height parse '{text}': {e}")))
    }

    /// Whether `txid` is already included in a block, via the esplora
    /// tx-status endpoint.
    async fn tx_confirmed(&self, txid: &Txid) -> Result<bool, HtlcError> {
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
            .map_err(|e| HtlcError::Network(format!("tx {txid} status parse: {e}")))?;
        Ok(status.confirmed)
    }

    /// Rebuild the spec a dispatched descriptor must match: the
    /// refund parameters come from the wire, the claim side from this
    /// node's own claim key and the route's payment hash.
    fn incoming_spec(
        &self,
        payment_hash: &Bytes32,
        descriptor: &HtlcDescriptor,
    ) -> Result<(HtlcSpec, OutPoint), HtlcError> {
        let HtlcDescriptor::Liquid {
            lockup_txid,
            lockup_vout,
            refund_pubkey,
            refund_locktime,
        } = descriptor
        else {
            return Err(HtlcError::InvalidParams(format!(
                "unsupported htlc descriptor for liquid network: {descriptor:?}"
            )));
        };
        let txid = Txid::from_str(lockup_txid)
            .map_err(|e| HtlcError::InvalidParams(format!("invalid lockup txid: {e}")))?;
        let refund_pubkey = BtcPublicKey::from_str(refund_pubkey)
            .map_err(|e| HtlcError::InvalidParams(format!("invalid refund pubkey: {e}")))?;
        let spec = HtlcSpec::build(
            payment_hash,
            self.claim_pk_full,
            refund_pubkey,
            *refund_locktime,
        );
        Ok((spec, OutPoint::new(txid, u32::from(*lockup_vout))))
    }

    /// Receiver-side verification of a dispatched HTLC, shared by
    /// `verify_incoming_htlc` and `accept_incoming_htlc`:
    ///
    /// 1. on mainnet, unless the lockup already confirmed, a one-shot
    ///    0-conf check on the pinned lockup txid, whose answer is
    ///    final: the sender only dispatched after waiting for
    ///    coverage itself, so a shortfall here rejects the HTLC (a
    ///    confirmed lockup is past mempool policy and may already
    ///    have been dropped from the 0-conf service's memory; the
    ///    service does not observe testnet at all);
    /// 2. the lockup tx fetched from esplora (mempool or chain): it
    ///    must be non-RBF and the pinned output must pay P2WSH of
    ///    the witness script this node rebuilds from the payment
    ///    hash, its own claim key and the wire's refund parameters —
    ///    which simultaneously checks the hash binding and the
    ///    recipient identity — an explicit L-BTC amount, which is
    ///    returned.
    async fn verified_incoming(
        &self,
        descriptor: &HtlcDescriptor,
        payment_hash: Bytes32,
    ) -> Result<(HtlcSpec, OutPoint, u64), HtlcError> {
        let (spec, outpoint) = self.incoming_spec(&payment_hash, descriptor)?;

        if self.network.is_mainnet() && !self.tx_confirmed(&outpoint.txid).await? {
            zeroconf::check_coverage(&self.http, &outpoint.txid.to_string())
                .await
                .map_err(HtlcError::Network)?;
        }

        let tx = self
            .esplora
            .lock()
            .await
            .get_transaction(outpoint.txid)
            .await
            .map_err(|e| {
                HtlcError::Network(format!(
                    "fetching lockup tx {} from esplora: lwk: {e}",
                    outpoint.txid
                ))
            })?;
        ensure_non_rbf(&tx).map_err(|_| {
            HtlcError::Network(format!(
                "lockup tx {} signals replace-by-fee",
                outpoint.txid
            ))
        })?;
        let output = tx.output.get(outpoint.vout as usize).ok_or_else(|| {
            HtlcError::InvalidParams(format!(
                "lockup tx {} has no output {}",
                outpoint.txid, outpoint.vout
            ))
        })?;
        if output.script_pubkey != spec.lockup_script_pubkey {
            return Err(HtlcError::InvalidParams(format!(
                "lockup output {}:{} does not pay the witness script this node rebuilds from \
                 the payment hash, its claim key and the descriptor's refund parameters \
                 (wrong recipient identity, hash or refund terms)",
                outpoint.txid, outpoint.vout
            )));
        }
        if output.asset != Asset::Explicit(*self.network.policy_asset()) {
            return Err(HtlcError::InvalidParams(format!(
                "lockup output {}:{} is not explicit L-BTC",
                outpoint.txid, outpoint.vout
            )));
        }
        let Value::Explicit(value_sat) = output.value else {
            return Err(HtlcError::InvalidParams(format!(
                "lockup output {}:{} value is not explicit",
                outpoint.txid, outpoint.vout
            )));
        };
        Ok((spec, outpoint, value_sat))
    }

    /// Max witness weight (WU) for a P2WSH spend of `script`.
    fn max_weight_to_satisfy(script: &ElScript, with_preimage: bool) -> usize {
        let script_len = script.len();
        let mut witness_len = 1; // item count
                                 // Branch selector: the 32-byte preimage on claims, an empty
                                 // push on refunds.
        witness_len += if with_preimage { 1 + 32 } else { 1 };
        witness_len += 1 + 73; // der sig + sighash byte
        witness_len += varint_len(script_len) + script_len;
        witness_len * 4 + 64 // conservative overhead for the input shell
    }

    /// Sign `pset` with the software signer and return the extracted
    /// transaction with every input's witness built by hand: the HTLC
    /// input gets `[sig, preimage-or-empty, script]` (the middle item
    /// selects the script branch), plain p2wpkh wallet inputs get
    /// `[sig, pubkey]`.
    ///
    /// Manual witness assembly (instead of `Wollet::finalize`) is
    /// required for the claim path: the preimage is not representable
    /// as a PSBT field, so no generic finalizer can produce it.
    async fn sign_and_extract(
        &self,
        mut pset: PartiallySignedTransaction,
        htlc_input: Option<(OutPoint, Option<[u8; 32]>, &ElScript)>,
    ) -> Result<Transaction, HtlcError> {
        let added = self
            .signer
            .sign(&mut pset)
            .map_err(|e| error_from_lwk(format!("pset sign: {e}")))?;
        if added == 0 {
            return Err(HtlcError::Network(
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
                .ok_or_else(|| HtlcError::Network("pset input missing".into()))?;
            let is_htlc_input = htlc_input
                .as_ref()
                .map(|(o, _, _)| *o == input.previous_output)
                .unwrap_or(false);
            let witness: Vec<Vec<u8>> = if is_htlc_input {
                let sig = psbt_input
                    .partial_sigs
                    .get(&self.claim_pk_full)
                    .ok_or_else(|| {
                        HtlcError::Network("claim signature missing after sign".into())
                    })?;
                let (_, preimage, script) = htlc_input.as_ref().expect("matched above");
                // Witness items are pushed in order, so the branch
                // selector (preimage or empty vector) must sit *after*
                // the signature to end up on top of the stack, where
                // the script's leading OP_HASH160 consumes it.
                let selector = preimage.map(|p| p.to_vec()).unwrap_or_default();
                vec![sig.clone(), selector, script.to_bytes()]
            } else if !psbt_input.partial_sigs.is_empty() {
                // P2WPKH wallet input: [sig, pubkey].
                let (pk, sig) = psbt_input
                    .partial_sigs
                    .iter()
                    .next()
                    .ok_or_else(|| HtlcError::Network("wallet sig missing".into()))?;
                vec![sig.clone(), pk.to_bytes()]
            } else {
                continue;
            };
            input.witness = TxInWitness::empty();
            input.witness.script_witness = witness;
        }
        Ok(tx)
    }

    async fn broadcast(&self, tx: &Transaction) -> Result<Txid, HtlcError> {
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
    ) -> Result<Txid, HtlcError> {
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
            .ok_or_else(|| HtlcError::Network("HTLC input missing from pset".into()))?;
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
    ) -> Result<Txid, HtlcError> {
        let to = Address::from_str(address.trim())
            .map_err(|e| HtlcError::InvalidParams(format!("invalid liquid address: {e}")))?;
        let sats = msat_to_sat(amount_msat)?;
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
            return Err(HtlcError::Network("signer produced no signatures".into()));
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
    pub async fn balance_msat(&self) -> Result<u64, HtlcError> {
        let sats = self.lbtc_balance_sat().await?;
        Ok(sats.saturating_mul(MSAT_PER_SAT))
    }

    /// Confidential L-BTC address for deposits.
    pub async fn deposit_address(&self) -> Result<String, HtlcError> {
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
fn ensure_non_rbf(tx: &Transaction) -> Result<(), HtlcError> {
    if tx
        .input
        .iter()
        .any(|input| input.sequence.to_consensus_u32() < NON_FINAL_SEQUENCE)
    {
        return Err(HtlcError::Network(
            "HTLC lockup transaction signals replace-by-fee".into(),
        ));
    }
    Ok(())
}

fn even_y_pubkey(xonly: &PubKey) -> Result<BtcPublicKey, HtlcError> {
    let mut bytes = [0u8; 33];
    bytes[0] = 0x02;
    bytes[1..].copy_from_slice(xonly.as_bytes());
    let inner = secp256k1::PublicKey::from_slice(&bytes)
        .map_err(|e| HtlcError::InvalidParams(format!("invalid x-only identity: {e}")))?;
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

#[async_trait]
impl NetworkRouterAdapter for LiquidAdapter {
    fn invoice_pubkey(&self) -> PubKey {
        self.invoice_pubkey
    }

    /// Claims happen with the dedicated even-Y claim key derived at
    /// `CLAIM_KEY_PATH_PREFIX`, not the invoice key.
    fn claim_pubkey(&self) -> PubKey {
        self.claim_xonly
    }

    fn network_id(&self) -> NetworkId {
        self.network_id.clone()
    }

    /// Liquid blocks land every minute; polling budget accounts for a
    /// few block confirmations of the lockup.
    fn incoming_delta_secs(&self) -> u64 {
        300
    }

    async fn register_incoming_htlc(
        &self,
        payment_hash: Bytes32,
        min_amount_msat: u64,
        deadline: u64,
    ) -> Result<Option<HtlcDescriptor>, HtlcError> {
        if deadline <= Self::unix_now() {
            return Err(HtlcError::InvalidParams("deadline in the past".into()));
        }
        let sats = msat_to_sat(min_amount_msat).map_err(|e| HtlcError::Network(e.to_string()))?;
        self.incoming
            .lock()
            .await
            .entry(payment_hash)
            .or_insert(PendingIncoming {
                accepted: None,
                expected_sat: sats,
                deadline,
            });
        Ok(None)
    }

    async fn create_outgoing_htlc(
        &self,
        payment_hash: Bytes32,
        amount_msat: u64,
        expiry: u64,
        recipient: PubKey,
    ) -> Result<OutgoingHtlc, HtlcError> {
        let sats = msat_to_sat(amount_msat)?;
        if sats < MIN_LOCK_SATS {
            return Err(HtlcError::InvalidParams(format!(
                "amount {sats} sats is below the minimum lock of {MIN_LOCK_SATS} sats \
                 (claim fees are carved out of the locked value)"
            )));
        }
        let tip = self.tip_height().await?;
        let spec = self.build_options(&payment_hash, &recipient, expiry, tip)?;

        let unconf = spec.lockup_address(self.network.address_params())?;
        self.span.in_scope(|| {
            info!(
                target: "cassis_liquid",
                "locking htlc {}: {} sats -> {unconf} (expiry {})",
                payment_hash.short(),
                sats,
                expiry,
            );
        });

        self.sync_wallet().await?;
        let mut pset = {
            let wollet = self.wollet.lock().await;
            wollet
                .tx_builder()
                .add_explicit_recipient(&unconf, sats, *self.network.policy_asset())
                .map_err(error_from_lwk)?
                .fee_rate(Some(FEE_RATE_SATS_KVB))
                .finish()
                .map_err(error_from_lwk)?
        };
        // 0-conf acceptance requires a non-replaceable lockup: raise
        // any RBF-signaling nSequence to the non-RBF (but still
        // locktime-enabled) value before signing, since signatures
        // commit to sequences.
        for input in pset.inputs_mut() {
            if input
                .sequence
                .is_some_and(|s| s.to_consensus_u32() < NON_FINAL_SEQUENCE)
            {
                input.sequence = Some(Sequence::from_consensus(NON_FINAL_SEQUENCE));
            }
        }
        let added = self
            .signer
            .sign(&mut pset)
            .map_err(|e| error_from_lwk(format!("pset sign: {e}")))?;
        if added == 0 {
            return Err(HtlcError::Network("signer produced no signatures".into()));
        }
        let tx = self
            .wollet
            .lock()
            .await
            .finalize(&mut pset)
            .map_err(error_from_lwk)?;
        ensure_non_rbf(&tx)?;
        let txid = self.broadcast(&tx).await?;

        // Locate the lockup output index in the broadcast tx.
        let vout = tx
            .output
            .iter()
            .position(|o| o.script_pubkey == spec.lockup_script_pubkey)
            .ok_or_else(|| HtlcError::Network("lockup output missing in tx".into()))?
            as u32;
        let outpoint = OutPoint::new(txid, vout);

        self.span.in_scope(|| {
            debug!(target: "cassis_liquid", "htlc locked {}: txid={txid}", payment_hash.short());
        });

        // Record the HTLC before waiting on propagation: if coverage
        // never arrives the lockup still exists on-chain and must
        // stay refundable through `refund_outgoing`.
        self.outgoing.lock().await.insert(
            payment_hash,
            PendingOutgoing {
                spec: spec.clone(),
                outpoint,
                value_sat: sats,
            },
        );

        // Only report the HTLC as deployed once at least 4/5 of the
        // functionaries have seen the lockup, so the receiver's
        // one-shot 0-conf check on DISPATCH cannot race propagation.
        // The 0-conf service only observes mainnet; on testnet a
        // short pause gives esplora time to index the mempool tx
        // before the receiver fetches it.
        if self.network.is_mainnet() {
            zeroconf::wait_for_coverage(&self.span, &txid.to_string())
                .await
                .map_err(HtlcError::Network)?;
            self.span.in_scope(|| {
                debug!(
                    target: "cassis_liquid",
                    "htlc lockup {txid} reached 0-conf functionary coverage",
                );
            });
        } else {
            tokio::time::sleep(Duration::from_secs(TESTNET_PROPAGATION_WAIT_SECS)).await;
        }

        Ok(OutgoingHtlc {
            payment_hash,
            amount_msat,
            expiry,
            recipient: recipient.to_hex(),
            network: self.network_id.clone(),
        })
    }

    async fn claim_incoming(
        &self,
        payment_hash: Bytes32,
        preimage: Bytes32,
    ) -> Result<(), HtlcError> {
        let AcceptedHtlc {
            spec,
            outpoint,
            value_sat,
        } = {
            let incoming = self.incoming.lock().await;
            match incoming.get(&payment_hash).and_then(|s| s.accepted.clone()) {
                Some(accepted) => accepted,
                None => {
                    return Err(HtlcError::InvalidParams(format!(
                        "no incoming HTLC registered for {payment_hash:?}"
                    )));
                }
            }
        };
        // The claim script burns RIPEMD160(payment_hash), so checking
        // the revealed preimage against the route's payment hash also
        // proves it satisfies the script.
        let sha = sha256::Hash::hash(preimage.as_ref());
        if Bytes32(sha.to_byte_array()) != payment_hash {
            return Err(HtlcError::InvalidParams(
                "preimage does not hash to the payment hash".into(),
            ));
        }

        self.span.in_scope(|| {
            info!(
                target: "cassis_liquid",
                "claiming htlc {} amount={} sats on {}",
                payment_hash.short(),
                value_sat,
                self.network_id,
            );
        });

        let txid = self
            .spend_htlc_input(&spec, outpoint, value_sat, Some(preimage.0), None)
            .await?;

        self.span.in_scope(|| {
            info!(target: "cassis_liquid", "htlc claimed for {}: tx={txid}", payment_hash.short());
        });
        self.incoming.lock().await.remove(&payment_hash);
        Ok(())
    }

    async fn refund_outgoing(&self, payment_hash: Bytes32) -> Result<(), HtlcError> {
        let (spec, outpoint, value_sat) = {
            let outgoing = self.outgoing.lock().await;
            match outgoing.get(&payment_hash) {
                Some(slot) => (slot.spec.clone(), slot.outpoint, slot.value_sat),
                None => {
                    return Err(HtlcError::InvalidParams(format!(
                        "no outgoing HTLC for {payment_hash:?}"
                    )));
                }
            }
        };
        let tip = self.tip_height().await?;
        if tip < u64::from(spec.refund_locktime) {
            // `Network` (not `InvalidParams`) so the router treats it
            // as transient and keeps retrying until the CLTV opens.
            return Err(HtlcError::Network(format!(
                "timelock not reached: tip={tip} refund_locktime={}",
                spec.refund_locktime
            )));
        }

        let txid = self
            .spend_htlc_input(&spec, outpoint, value_sat, None, Some(spec.refund_locktime))
            .await?;

        self.span.in_scope(|| {
            info!(target: "cassis_liquid", "htlc refunded {}: tx={txid}", payment_hash.short());
        });
        self.outgoing.lock().await.remove(&payment_hash);
        Ok(())
    }

    async fn watch_preimage(
        &self,
        payment_hash: Bytes32,
        deadline: u64,
    ) -> Result<Bytes32, WatchError> {
        let (spec, lockup) = {
            let outgoing = self.outgoing.lock().await;
            match outgoing.get(&payment_hash) {
                Some(slot) => (slot.spec.clone(), slot.outpoint),
                None => {
                    return Err(WatchError::Network(format!(
                        "no outgoing HTLC for {payment_hash:?}"
                    )));
                }
            }
        };
        let address = spec
            .lockup_address(self.network.address_params())
            .map_err(|e| WatchError::Network(e.to_string()))?;

        loop {
            if Self::unix_now() >= deadline {
                return Err(WatchError::DeadlineExceeded);
            }

            // Poll the address history for a spend of the lockup
            // outpoint, then decode the raw tx and pull the preimage
            // out of the claim witness.
            match self.find_spending_tx(&address, lockup).await {
                Ok(Some(spending_tx)) => {
                    // `extract_preimage` already verified the witness
                    // preimage hashes to `spec.payment_hash`, which is
                    // the route hash this HTLC was built from.
                    match Self::extract_preimage(&spending_tx, lockup, &spec) {
                        Ok(preimage) => {
                            self.span.in_scope(|| {
                                info!(
                                    target: "cassis_liquid",
                                    "preimage observed on {} for {}",
                                    self.network_id,
                                    payment_hash.short(),
                                );
                            });
                            return Ok(Bytes32(preimage));
                        }
                        Err(msg) => {
                            self.span.in_scope(|| {
                                warn!(target: "cassis_liquid", "preimage extraction: {msg}");
                            });
                        }
                    }
                }
                Ok(None) => {}
                Err(msg) => {
                    self.span.in_scope(|| {
                        warn!(target: "cassis_liquid", "watch_preimage poll: {msg}");
                    });
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
        self.verified_incoming(descriptor, payment_hash)
            .await
            .map(|_| ())
    }

    async fn accept_incoming_htlc(
        &self,
        payment_hash: Bytes32,
        descriptor: &HtlcDescriptor,
        deadline: u64,
    ) -> Result<(), HtlcError> {
        // `verified_incoming` rebuilds the expected witness script
        // with this node's own claim key, so an HTLC locked to the
        // wrong identity already failed there.
        let (spec, outpoint, value_sat) = self.verified_incoming(descriptor, payment_hash).await?;

        // The sender's CLTV refund path must not open before this
        // hop's claim deadline, or the sender could race a refund
        // against our claim. Map the unix deadline onto blocks.
        let deadline_blocks = deadline.saturating_sub(Self::unix_now()) / BLOCK_TIME_SECS;
        let tip = self.tip_height().await?;
        if u64::from(spec.refund_locktime) < tip + deadline_blocks {
            return Err(HtlcError::InvalidParams(format!(
                "refund locktime {} opens before the HTLC deadline (tip {tip}, \
                 need at least {})",
                spec.refund_locktime,
                tip + deadline_blocks
            )));
        }

        // Preserve the amount reserved at PREPARE time, then check the
        // pinned lockup output actually covers it.
        let expected_sat = {
            let incoming = self.incoming.lock().await;
            incoming
                .get(&payment_hash)
                .map(|slot| slot.expected_sat)
                .unwrap_or(0)
        };
        if value_sat < expected_sat {
            return Err(HtlcError::Network(format!(
                "locked amount {value_sat} sats is below the reserved {expected_sat} sats"
            )));
        }

        self.span.in_scope(|| {
            debug!(
                target: "cassis_liquid",
                "accepted incoming htlc {} at {}:{} deadline={deadline}",
                payment_hash.short(),
                outpoint.txid,
                outpoint.vout,
            );
        });
        let accepted = AcceptedHtlc {
            spec,
            outpoint,
            value_sat,
        };
        self.incoming
            .lock()
            .await
            .entry(payment_hash)
            .and_modify(|slot| slot.accepted = Some(accepted.clone()))
            .or_insert(PendingIncoming {
                accepted: Some(accepted),
                expected_sat: 0,
                deadline,
            });
        Ok(())
    }

    async fn outgoing_htlc_descriptor(
        &self,
        payment_hash: Bytes32,
    ) -> Result<HtlcDescriptor, HtlcError> {
        let outgoing = self.outgoing.lock().await;
        let slot = outgoing.get(&payment_hash).ok_or_else(|| {
            HtlcError::InvalidParams(format!("no outgoing HTLC for {payment_hash:?}"))
        })?;
        slot.spec.to_descriptor(slot.outpoint)
    }

    /// L-BTC wallet balance must cover the routed amount. Claim/refund
    /// fees are carved out of the HTLC value itself, so no
    /// gas-equivalent reserve is needed on the incoming side.
    async fn can_route(&self, amount_msat: u64) -> Result<(), HtlcError> {
        let needed = msat_to_sat(amount_msat)?;
        let available = self.lbtc_balance_sat().await?;
        if needed > available {
            return Err(HtlcError::InvalidParams(format!(
                "insufficient liquid balance on {}: need {} msat, have {available} msat",
                self.network_id, amount_msat
            )));
        }
        Ok(())
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
    /// `outpoint`. Spend witness layout: `[sig, selector, script]`,
    /// where the selector is the preimage on claims and an empty push
    /// on refunds.
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
        let preimage_bytes = stack.get(1).ok_or("spend witness has no branch selector")?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn xonly_test_pubkey(fill: u8) -> BtcPublicKey {
        let secp = secp256k1::Secp256k1::new();
        let secret = secp256k1::SecretKey::from_slice(&[fill; 32]).unwrap();
        BtcPublicKey::new(secret.public_key(&secp))
    }

    /// The descriptor built from a fixed key must parse as a
    /// WolletDescriptor and the claim-key scan must yield an even-Y
    /// pubkey whose x-only half round-trips.
    #[tokio::test]
    async fn descriptor_and_claim_key_derive_deterministically() {
        let config = default_config(
            NetworkId("liquid::testnet".to_string()),
            [7u8; 32],
            PubKey::from_bytes([9u8; 32]).unwrap(),
            Span::none(),
        );
        let adapter = LiquidAdapter::new(config).await.unwrap();

        let config2 = default_config(
            NetworkId("liquid::testnet".to_string()),
            [7u8; 32],
            PubKey::from_bytes([9u8; 32]).unwrap(),
            Span::none(),
        );
        let adapter2 = LiquidAdapter::new(config2).await.unwrap();

        assert_eq!(
            adapter.claim_pubkey().to_hex(),
            adapter2.claim_pubkey().to_hex()
        );
        // Even-Y: first byte of the compressed pubkey must be 0x02.
        assert_eq!(adapter.claim_pk_full.to_bytes()[0], 0x02);
        // The x-only half matches the compressed key's payload.
        assert_eq!(
            &adapter.claim_pk_full.to_bytes()[1..],
            adapter.claim_pubkey().as_bytes()
        );
    }

    /// The witness script commits to the payment hash's RIPEMD160,
    /// both keys and the refund locktime, and both parties derive the
    /// same lockup script pubkey from the same parameters.
    #[test]
    fn htlc_script_commits_to_expected_values() {
        let payment_hash = Bytes32([42u8; 32]);
        let claimer = xonly_test_pubkey(0xaa);
        let refunder = xonly_test_pubkey(0xbb);

        let spec = HtlcSpec::build(&payment_hash, claimer, refunder, 1234);

        // The spec keeps the route's 32-byte payment hash; the script
        // burns its RIPEMD160.
        assert_eq!(spec.payment_hash, payment_hash);
        assert_eq!(
            payment_hash160(&payment_hash).to_vec(),
            ripemd160::Hash::hash(payment_hash.as_ref())
                .as_byte_array()
                .to_vec()
        );

        let script_hex = spec.witness_script.as_bytes().to_lower_hex_string();
        let hash_hex = payment_hash160(&payment_hash).to_lower_hex_string();
        assert!(script_hex.contains(&hash_hex), "script: {script_hex}");
        assert!(script_hex.contains(&claimer.to_bytes().to_lower_hex_string()));
        assert!(script_hex.contains(&refunder.to_bytes().to_lower_hex_string()));

        // P2WSH lockup script is 34 bytes (0x0020{32}).
        assert_eq!(spec.lockup_script_pubkey.len(), 34);

        // The receiver rebuilds the identical script from the same
        // parameters (its own claim key + the wire's refund params).
        let rebuilt = HtlcSpec::build(&payment_hash, claimer, refunder, 1234);
        assert_eq!(rebuilt.lockup_script_pubkey, spec.lockup_script_pubkey);
    }

    /// The wire descriptor carries the lockup outpoint plus the
    /// refund parameters, and nothing the receiver can derive itself.
    #[test]
    fn descriptor_round_trips_lockup_outpoint() {
        let payment_hash = Bytes32([42u8; 32]);
        let spec = HtlcSpec::build(
            &payment_hash,
            xonly_test_pubkey(0xaa),
            xonly_test_pubkey(0xbb),
            1234,
        );
        let txid = Txid::from_str(&"1f".repeat(32)).unwrap();
        let outpoint = OutPoint::new(txid, 3);

        let descriptor = spec.to_descriptor(outpoint).unwrap();
        let HtlcDescriptor::Liquid {
            lockup_txid,
            lockup_vout,
            refund_pubkey,
            refund_locktime,
        } = &descriptor
        else {
            panic!("expected liquid descriptor");
        };
        assert_eq!(lockup_txid, &txid.to_string());
        assert_eq!(*lockup_vout, 3);
        assert_eq!(
            refund_pubkey,
            &spec.refund_pubkey.to_bytes().to_lower_hex_string()
        );
        assert_eq!(*refund_locktime, 1234);

        // Output indexes beyond the descriptor's u8 are rejected
        // rather than truncated.
        assert!(spec.to_descriptor(OutPoint::new(txid, 300)).is_err());
    }
}
