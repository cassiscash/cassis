//! Liquid network adapter for cassis.
//!
//! Implements [`NetworkAdapter`] on Liquid (Elements) using the
//! Liquid Wallet Kit (LWK): a watch-only wallet over a CT descriptor
//! derived from the node's per-network key, a software PSET signer,
//! and an esplora backend for sync and broadcast.
//!
//! HTLCs are plain P2WSH outputs whose single witness script has two
//! spending paths (boltz-style, with the hash check inside the claim
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
//! * **Claim** (receiver): witness
//!   `[sig, preimage, <true>, script]` — the explicit `OP_TRUE`
//!   selects the IF branch while the preimage stays on the stack for
//!   the hash check, and the receiver signs with its per-network
//!   claim key. The lockup output is *unblinded* (explicit), so no
//!   blinding keys ever cross the protocol.
//! * **Refund** (sender): witness `[sig, <empty>, script]` — the
//!   empty push fails OP_IF, selecting the CLTV branch; recoverable
//!   after an absolute block height derived from the route expiry.
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
    AcceptedIncoming, AdapterError, Bytes32, HtlcDescriptor, HtlcTarget, IncomingRequest,
    IncomingReservation, NetworkAdapter, NetworkId, OperationId, OutgoingPayment, OutgoingRequest,
    PubKey, XOnlyPubKey,
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
use lwk_wollet::{Network, Wollet, WolletBuilder, WolletDescriptor};
use sha2::Sha512;
use std::collections::HashMap;
use std::fs::File;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, Notify};
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

impl From<Error> for AdapterError {
    fn from(e: Error) -> AdapterError {
        match e {
            Error::InvalidParams(s) => AdapterError::InvalidParams(s),
            other => AdapterError::Network(other.to_string()),
        }
    }
}

/// Convert an LWK error (wallet, tx builder, signer or esplora
/// client) into the routing layer's network error. The `lwk: ` prefix
/// keeps the failing subsystem identifiable in router logs.
fn error_from_lwk(e: impl std::fmt::Display) -> AdapterError {
    AdapterError::Network(format!("lwk: {e}"))
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
    pub invoice_pubkey: XOnlyPubKey,
    pub span: Span,
}

/// Canonical config for `liquid` (mainnet) or `liquid::testnet`.
/// Callers may override any field before constructing.
pub fn default_config(
    network_id: NetworkId,
    sk: [u8; 32],
    invoice_pubkey: XOnlyPubKey,
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

fn msat_to_sat(amount_msat: u64) -> Result<u64, AdapterError> {
    if !amount_msat.is_multiple_of(MSAT_PER_SAT) {
        return Err(AdapterError::InvalidParams(format!(
            "amount {amount_msat} msat is not a whole number of satoshis; \
             liquid amounts must be multiples of {MSAT_PER_SAT} msat"
        )));
    }
    Ok(amount_msat / MSAT_PER_SAT)
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

    fn lockup_address(&self, params: &'static AddressParams) -> Result<Address, AdapterError> {
        Address::from_script(&self.lockup_script_pubkey, None, params)
            .ok_or_else(|| AdapterError::InvalidParams("cannot derive lockup address".into()))
    }

    /// Build the wire descriptor: the pinned lockup outpoint plus the
    /// refund parameters the receiver cannot derive itself (the claim
    /// side it rebuilds from its own claim key and the payment hash).
    fn to_descriptor(&self, lockup: OutPoint) -> Result<HtlcDescriptor, AdapterError> {
        Ok(HtlcDescriptor::Liquid {
            lockup_txid: lockup.txid.to_string(),
            lockup_vout: lockup.vout.try_into().map_err(|_| {
                AdapterError::InvalidParams(format!(
                    "lockup output index {} does not fit the descriptor's u8",
                    lockup.vout
                ))
            })?,
            refund_pubkey: PubKey::from_bytes(
                self.refund_pubkey
                    .to_bytes()
                    .try_into()
                    .expect("compressed refund key is 33 bytes"),
            )
            .expect("wallet refund key is valid"),
            refund_locktime: self.refund_locktime,
        })
    }
}

#[derive(Clone, Debug)]
struct LiquidOutgoing {
    recipient: PubKey,
    spec: HtlcSpec,
    outpoint: OutPoint,
    value_sat: u64,
}

#[derive(Clone, Debug)]
struct PendingIncoming {
    payment_hash: Bytes32,
    accepted: Option<AcceptedIncoming>,
    expected_sat: u64,
    deadline: u64,
    arrival: Arc<Notify>,
}

#[derive(Clone, Debug)]
struct FundedHtlc {
    spec: HtlcSpec,
    outpoint: OutPoint,
    value_sat: u64,
}

#[derive(Clone, Debug)]
struct PendingOutgoing {
    payment_hash: Bytes32,
    amount_msat: u64,
    expiry: u64,
    recipient: PubKey,
    funded: Option<FundedHtlc>,
    verified: bool,
}

pub struct LiquidAdapter {
    network_id: NetworkId,
    invoice_pubkey: XOnlyPubKey,
    span: Span,
    signer: SwSigner,
    fingerprint: Fingerprint,
    /// Derivation path of the claim key (even-Y child).
    claim_path: DerivationPath,
    /// Full 33-byte claim pubkey (always `02 || X`).
    claim_pk_full: BtcPublicKey,
    /// x-only half of `claim_pk_full`, the identity counterparties
    /// lock to.
    claim_xonly: XOnlyPubKey,
    wollet: Arc<Mutex<Wollet>>,
    esplora: Arc<Mutex<EsploraClient>>,
    waterfalls: Arc<Mutex<EsploraClient>>,
    http: reqwest::Client,
    esplora_url: String,
    network: Network,
    /// Exclusive lock for `persist_dir`; held while adapter is open.
    _persist_lock: Option<File>,
    incoming: Mutex<HashMap<OperationId, PendingIncoming>>,
    outgoing: Mutex<HashMap<OperationId, PendingOutgoing>>,
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
        let claim_xonly = XOnlyPubKey::from_bytes(claim_bytes[1..33].try_into().expect("32 bytes"))
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
                .truncate(false)
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
    ) -> Result<HtlcSpec, AdapterError> {
        let now = Self::unix_now();
        if expiry <= now {
            return Err(AdapterError::InvalidParams("expiry in the past".into()));
        }
        // Liquid scripts require the full compressed recipient key.
        let recipient_full = even_y_pubkey(recipient)?;
        let remaining_blocks = expiry.saturating_sub(now) / BLOCK_TIME_SECS;
        let refund_locktime = (tip + remaining_blocks).min(u64::from(u32::MAX - 1)) as u32;
        Ok(HtlcSpec::build(
            payment_hash,
            recipient_full,
            self.claim_pk_full,
            refund_locktime,
        ))
    }

    /// Sync the wallet with esplora (best-effort: on failure the
    /// cached state is used).
    async fn sync_wallet(&self) -> Result<(), AdapterError> {
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

    async fn lbtc_balance_sat(&self) -> Result<u64, AdapterError> {
        self.sync_wallet().await?;
        let wollet = self.wollet.lock().await;
        let balance = wollet.balance().map_err(error_from_lwk)?;
        Ok(balance.get(&wollet.policy_asset()).copied().unwrap_or(0))
    }

    async fn next_wallet_address(&self) -> Result<Address, AdapterError> {
        let wollet = self.wollet.lock().await;
        let result = wollet.address(None).map_err(error_from_lwk)?;
        Ok(result.address().clone())
    }

    /// Current Liquid block height via the esplora tip endpoint.
    async fn tip_height(&self) -> Result<u64, AdapterError> {
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
            .map_err(|e| AdapterError::Network(format!("tip height parse '{text}': {e}")))
    }

    /// Whether `txid` is already included in a block, via the esplora
    /// tx-status endpoint.
    async fn tx_confirmed(&self, txid: &Txid) -> Result<bool, AdapterError> {
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
            .map_err(|e| AdapterError::Network(format!("tx {txid} status parse: {e}")))?;
        Ok(status.confirmed)
    }

    /// Rebuild the spec a dispatched descriptor must match: the
    /// refund parameters come from the wire, the claim side from this
    /// node's own claim key and the route's payment hash.
    fn incoming_spec(
        &self,
        payment_hash: &Bytes32,
        descriptor: &HtlcDescriptor,
    ) -> Result<(HtlcSpec, OutPoint), AdapterError> {
        let HtlcDescriptor::Liquid {
            lockup_txid,
            lockup_vout,
            refund_pubkey,
            refund_locktime,
        } = descriptor
        else {
            return Err(AdapterError::InvalidParams(format!(
                "unsupported htlc descriptor for liquid network: {descriptor:?}"
            )));
        };
        let txid = Txid::from_str(lockup_txid)
            .map_err(|e| AdapterError::InvalidParams(format!("invalid lockup txid: {e}")))?;
        let refund_pubkey = BtcPublicKey::from_slice(refund_pubkey.as_bytes())
            .map_err(|e| AdapterError::InvalidParams(format!("invalid refund pubkey: {e}")))?;
        let spec = HtlcSpec::build(
            payment_hash,
            self.claim_pk_full,
            refund_pubkey,
            *refund_locktime,
        );
        Ok((spec, OutPoint::new(txid, u32::from(*lockup_vout))))
    }

    /// Receiver-side verification of a dispatched HTLC:
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
    ) -> Result<(HtlcSpec, OutPoint, u64), AdapterError> {
        let (spec, outpoint) = self.incoming_spec(&payment_hash, descriptor)?;

        if self.network.is_mainnet() && !self.tx_confirmed(&outpoint.txid).await? {
            zeroconf::check_coverage(&self.http, &outpoint.txid.to_string())
                .await
                .map_err(AdapterError::Network)?;
        }

        let tx = self
            .esplora
            .lock()
            .await
            .get_transaction(outpoint.txid)
            .await
            .map_err(|e| {
                AdapterError::Network(format!(
                    "fetching lockup tx {} from esplora: lwk: {e}",
                    outpoint.txid
                ))
            })?;
        ensure_non_rbf(&tx).map_err(|_| {
            AdapterError::Network(format!(
                "lockup tx {} signals replace-by-fee",
                outpoint.txid
            ))
        })?;
        let output = tx.output.get(outpoint.vout as usize).ok_or_else(|| {
            AdapterError::InvalidParams(format!(
                "lockup tx {} has no output {}",
                outpoint.txid, outpoint.vout
            ))
        })?;
        if output.script_pubkey != spec.lockup_script_pubkey {
            return Err(AdapterError::InvalidParams(format!(
                "lockup output {}:{} does not pay the witness script this node rebuilds from \
                 the payment hash, its claim key and the descriptor's refund parameters \
                 (wrong recipient identity, hash or refund terms)",
                outpoint.txid, outpoint.vout
            )));
        }
        if output.asset != Asset::Explicit(*self.network.policy_asset()) {
            return Err(AdapterError::InvalidParams(format!(
                "lockup output {}:{} is not explicit L-BTC",
                outpoint.txid, outpoint.vout
            )));
        }
        let Value::Explicit(value_sat) = output.value else {
            return Err(AdapterError::InvalidParams(format!(
                "lockup output {}:{} value is not explicit",
                outpoint.txid, outpoint.vout
            )));
        };
        let address = spec
            .lockup_address(self.network.address_params())
            .map_err(|e| AdapterError::Network(e.to_string()))?;
        if self
            .find_spending_tx(&address, outpoint)
            .await
            .map_err(AdapterError::Network)?
            .is_some()
        {
            return Err(AdapterError::InvalidParams(format!(
                "lockup outpoint {}:{} is already spent",
                outpoint.txid, outpoint.vout
            )));
        }
        Ok((spec, outpoint, value_sat))
    }

    /// Max witness weight (WU) for a P2WSH spend of `script`.
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
    ) -> Result<Transaction, AdapterError> {
        let added = self
            .signer
            .sign(&mut pset)
            .map_err(|e| error_from_lwk(format!("pset sign: {e}")))?;
        if added == 0 {
            return Err(AdapterError::Network(
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
                .ok_or_else(|| AdapterError::Network("pset input missing".into()))?;
            let is_htlc_input = htlc_input
                .as_ref()
                .map(|(o, _, _)| *o == input.previous_output)
                .unwrap_or(false);
            let witness: Vec<Vec<u8>> = if is_htlc_input {
                let sig = psbt_input
                    .partial_sigs
                    .get(&self.claim_pk_full)
                    .ok_or_else(|| {
                        AdapterError::Network("claim signature missing after sign".into())
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
                    .ok_or_else(|| AdapterError::Network("wallet sig missing".into()))?;
                vec![sig.clone(), pk.to_bytes()]
            } else {
                continue;
            };
            input.witness = TxInWitness::empty();
            input.witness.script_witness = witness;
        }
        Ok(tx)
    }

    async fn broadcast(&self, tx: &Transaction) -> Result<Txid, AdapterError> {
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
    ) -> Result<Txid, AdapterError> {
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
            .ok_or_else(|| AdapterError::Network("HTLC input missing from pset".into()))?;
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
    ) -> Result<Txid, AdapterError> {
        let to = Address::from_str(address.trim())
            .map_err(|e| AdapterError::InvalidParams(format!("invalid liquid address: {e}")))?;
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
            return Err(AdapterError::Network(
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
    pub async fn balance_msat(&self) -> Result<u64, AdapterError> {
        let sats = self.lbtc_balance_sat().await?;
        Ok(sats.saturating_mul(MSAT_PER_SAT))
    }

    /// Confidential L-BTC address for deposits.
    pub async fn deposit_address(&self) -> Result<String, AdapterError> {
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
fn ensure_non_rbf(tx: &Transaction) -> Result<(), AdapterError> {
    if tx
        .input
        .iter()
        .any(|input| input.sequence.to_consensus_u32() < NON_FINAL_SEQUENCE)
    {
        return Err(AdapterError::Network(
            "HTLC lockup transaction signals replace-by-fee".into(),
        ));
    }
    Ok(())
}

fn even_y_pubkey(pubkey: &PubKey) -> Result<BtcPublicKey, AdapterError> {
    let inner = secp256k1::PublicKey::from_slice(pubkey.as_bytes())
        .map_err(|e| AdapterError::InvalidParams(format!("invalid compressed pubkey: {e}")))?;
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
    fn claim_target(&self) -> Result<HtlcTarget, AdapterError> {
        let mut compressed = [0u8; 33];
        compressed[0] = 0x02;
        compressed[1..].copy_from_slice(self.claim_xonly.as_bytes());
        let pubkey = PubKey::from_bytes(compressed)
            .map_err(|e| AdapterError::InvalidParams(format!("invalid claim pubkey: {e}")))?;
        Ok(HtlcTarget::PubKey(pubkey))
    }

    fn validate_incoming_request(&self, request: &IncomingRequest) -> Result<(), AdapterError> {
        if !request.operation_id.is_valid() {
            return Err(AdapterError::InvalidParams(
                "operation_id must be 32 hexadecimal characters".into(),
            ));
        }
        if request.payment_hash.0.iter().all(|byte| *byte == 0) {
            return Err(AdapterError::InvalidParams("zero payment hash".into()));
        }
        if request.amount_msat == 0 {
            return Err(AdapterError::InvalidParams(
                "incoming amount must be > 0".into(),
            ));
        }
        if request
            .preimage
            .is_some_and(|preimage| !request.payment_hash.matches_preimage(&preimage))
        {
            return Err(AdapterError::InvalidParams(
                "incoming preimage does not match payment hash".into(),
            ));
        }
        msat_to_sat(request.amount_msat)?;
        Ok(())
    }

    fn incoming_reservation(
        &self,
        request: &IncomingRequest,
        target: HtlcTarget,
    ) -> IncomingReservation {
        IncomingReservation {
            operation_id: request.operation_id.clone(),
            payment_hash: request.payment_hash,
            network: self.network_id(),
            amount_msat: request.amount_msat,
            deadline: request.deadline,
            target,
        }
    }

    fn validate_incoming_reservation(
        &self,
        reservation: &IncomingReservation,
    ) -> Result<(), AdapterError> {
        if !reservation.operation_id.is_valid() {
            return Err(AdapterError::InvalidParams(
                "operation_id must be 32 hexadecimal characters".into(),
            ));
        }
        if reservation.network != self.network_id() {
            return Err(AdapterError::InvalidParams(format!(
                "reservation network {} does not match adapter {}",
                reservation.network,
                self.network_id()
            )));
        }
        if reservation.payment_hash.0.iter().all(|byte| *byte == 0) {
            return Err(AdapterError::InvalidParams("zero payment hash".into()));
        }
        if reservation.amount_msat == 0 {
            return Err(AdapterError::InvalidParams(
                "incoming amount must be > 0".into(),
            ));
        }
        msat_to_sat(reservation.amount_msat)?;
        if reservation.target != self.claim_target()? {
            return Err(AdapterError::InvalidParams(
                "incoming reservation targets wrong Liquid claim key".into(),
            ));
        }
        Ok(())
    }

    fn validate_incoming_state(
        &self,
        state: &PendingIncoming,
        reservation: &IncomingReservation,
    ) -> Result<(), AdapterError> {
        if state.payment_hash != reservation.payment_hash
            || state.deadline != reservation.deadline
            || state.expected_sat != msat_to_sat(reservation.amount_msat)?
        {
            return Err(AdapterError::InvalidParams(format!(
                "incoming reservation does not match operation {}",
                reservation.operation_id
            )));
        }
        Ok(())
    }

    fn accepted_incoming_matches(left: &AcceptedIncoming, right: &AcceptedIncoming) -> bool {
        left.reservation == right.reservation
            && left.descriptor == right.descriptor
            && left.amount_msat == right.amount_msat
    }

    fn validate_outgoing_request(&self, request: &OutgoingRequest) -> Result<PubKey, AdapterError> {
        if !request.operation_id.is_valid() {
            return Err(AdapterError::InvalidParams(
                "operation_id must be 32 hexadecimal characters".into(),
            ));
        }
        if request.network != self.network_id() {
            return Err(AdapterError::InvalidParams(format!(
                "outgoing network {} does not match adapter {}",
                request.network,
                self.network_id()
            )));
        }
        if request.payment_hash.0.iter().all(|byte| *byte == 0) {
            return Err(AdapterError::InvalidParams("zero payment hash".into()));
        }
        let sats = msat_to_sat(request.amount_msat)?;
        if sats < MIN_LOCK_SATS {
            return Err(AdapterError::InvalidParams(format!(
                "amount {sats} sats is below the minimum lock of {MIN_LOCK_SATS} sats \
                 (claim fees are carved out of the locked value)"
            )));
        }
        match &request.target {
            HtlcTarget::PubKey(pubkey) => Ok(*pubkey),
            HtlcTarget::XOnlyPubKey(_)
            | HtlcTarget::LightningInvoice(_)
            | HtlcTarget::SparkAddress(_) => Err(AdapterError::InvalidParams(
                "liquid requires a full pubkey target".into(),
            )),
        }
    }

    fn validate_outgoing_payment(
        &self,
        payment: &OutgoingPayment,
    ) -> Result<LiquidOutgoing, AdapterError> {
        if !payment.operation_id.is_valid() {
            return Err(AdapterError::InvalidParams(
                "operation_id must be 32 hexadecimal characters".into(),
            ));
        }
        if payment.destination_network != self.network_id() {
            return Err(AdapterError::InvalidParams(format!(
                "outgoing network {} does not match adapter {}",
                payment.destination_network,
                self.network_id()
            )));
        }
        if payment.payment_hash.0.iter().all(|byte| *byte == 0) {
            return Err(AdapterError::InvalidParams("zero payment hash".into()));
        }
        let value_sat = msat_to_sat(payment.amount_msat)?;
        if value_sat < MIN_LOCK_SATS {
            return Err(AdapterError::InvalidParams(format!(
                "Liquid payment amount {value_sat} sats is below minimum {MIN_LOCK_SATS}"
            )));
        }
        let recipient = match &payment.destination {
            HtlcTarget::PubKey(pubkey) => *pubkey,
            HtlcTarget::XOnlyPubKey(_)
            | HtlcTarget::LightningInvoice(_)
            | HtlcTarget::SparkAddress(_) => {
                return Err(AdapterError::InvalidParams(
                    "liquid requires a full pubkey destination".into(),
                ))
            }
        };
        let HtlcDescriptor::Liquid {
            lockup_txid,
            lockup_vout,
            refund_pubkey,
            refund_locktime,
        } = &payment.descriptor
        else {
            return Err(AdapterError::InvalidParams(
                "not a Liquid descriptor".into(),
            ));
        };
        let txid = Txid::from_str(lockup_txid)
            .map_err(|e| AdapterError::InvalidParams(format!("invalid lockup txid: {e}")))?;
        let refund = BtcPublicKey::from_slice(refund_pubkey.as_bytes())
            .map_err(|e| AdapterError::InvalidParams(format!("invalid refund pubkey: {e}")))?;
        if refund != self.claim_pk_full {
            return Err(AdapterError::InvalidParams(
                "Liquid descriptor refund key is not this adapter".into(),
            ));
        }
        if *refund_locktime == 0 {
            return Err(AdapterError::InvalidParams(
                "Liquid descriptor has zero refund locktime".into(),
            ));
        }
        let spec = HtlcSpec::build(
            &payment.payment_hash,
            even_y_pubkey(&recipient)?,
            refund,
            *refund_locktime,
        );
        let outpoint = OutPoint::new(txid, u32::from(*lockup_vout));
        if spec.to_descriptor(outpoint)? != payment.descriptor {
            return Err(AdapterError::InvalidParams(
                "Liquid descriptor does not match outgoing payment".into(),
            ));
        }
        Ok(LiquidOutgoing {
            recipient,
            spec,
            outpoint,
            value_sat,
        })
    }

    fn outgoing_state_matches_request(
        state: &PendingOutgoing,
        request: &OutgoingRequest,
        recipient: &PubKey,
    ) -> Result<(), AdapterError> {
        if state.payment_hash != request.payment_hash
            || state.amount_msat != request.amount_msat
            || state.expiry != request.expiry
            || state.recipient != *recipient
        {
            return Err(AdapterError::InvalidParams(format!(
                "outgoing operation {} already exists with different parameters",
                request.operation_id
            )));
        }
        Ok(())
    }

    fn outgoing_state_matches_payment(
        state: &PendingOutgoing,
        payment: &OutgoingPayment,
        outgoing: &LiquidOutgoing,
    ) -> Result<(), AdapterError> {
        if state.payment_hash != payment.payment_hash
            || state.amount_msat != payment.amount_msat
            || state.expiry != payment.expiry
            || state.recipient != outgoing.recipient
        {
            return Err(AdapterError::InvalidParams(format!(
                "outgoing state does not match operation {}",
                payment.operation_id
            )));
        }
        let funded = state.funded.as_ref().ok_or_else(|| {
            AdapterError::NotFound(format!(
                "outgoing operation {} is still being created",
                payment.operation_id
            ))
        })?;
        if funded.spec.payment_hash != payment.payment_hash
            || funded.outpoint != outgoing.outpoint
            || funded.value_sat != outgoing.value_sat
        {
            return Err(AdapterError::InvalidParams(format!(
                "outgoing state does not match descriptor for operation {}",
                payment.operation_id
            )));
        }
        if funded.spec.witness_script != outgoing.spec.witness_script
            || funded.spec.lockup_script_pubkey != outgoing.spec.lockup_script_pubkey
            || funded.spec.refund_locktime != outgoing.spec.refund_locktime
        {
            return Err(AdapterError::InvalidParams(format!(
                "outgoing state descriptor mismatch for operation {}",
                payment.operation_id
            )));
        }
        Ok(())
    }

    fn outgoing_payment_from_state(
        &self,
        operation_id: &OperationId,
        state: &PendingOutgoing,
    ) -> Result<OutgoingPayment, AdapterError> {
        let funded = state.funded.as_ref().ok_or_else(|| {
            AdapterError::Retryable(format!(
                "outgoing operation {operation_id} is still being created"
            ))
        })?;
        Ok(OutgoingPayment {
            operation_id: operation_id.clone(),
            payment_hash: state.payment_hash,
            amount_msat: state.amount_msat,
            destination: HtlcTarget::PubKey(state.recipient),
            destination_network: self.network_id(),
            expiry: state.expiry,
            descriptor: funded.spec.to_descriptor(funded.outpoint)?,
        })
    }

    async fn discard_unfunded_outgoing(&self, operation_id: &OperationId, payment_hash: Bytes32) {
        let mut outgoing = self.outgoing.lock().await;
        if outgoing
            .get(operation_id)
            .is_some_and(|state| state.payment_hash == payment_hash && state.funded.is_none())
        {
            outgoing.remove(operation_id);
        }
    }

    async fn wait_lockup_propagation(&self, funded: &FundedHtlc) -> Result<(), AdapterError> {
        if self.network.is_mainnet() {
            zeroconf::wait_for_coverage(&self.span, &funded.outpoint.txid.to_string())
                .await
                .map_err(AdapterError::Network)?;
            self.span.in_scope(|| {
                debug!(
                    target: "cassis_liquid",
                    "htlc lockup {} reached 0-conf functionary coverage",
                    funded.outpoint.txid,
                );
            });
        } else {
            tokio::time::sleep(Duration::from_secs(TESTNET_PROPAGATION_WAIT_SECS)).await;
        }
        Ok(())
    }

    async fn verified_outgoing(&self, outgoing: &LiquidOutgoing) -> Result<(), AdapterError> {
        let tx = self
            .esplora
            .lock()
            .await
            .get_transaction(outgoing.outpoint.txid)
            .await
            .map_err(|e| {
                AdapterError::Network(format!(
                    "fetching lockup tx {} from esplora: lwk: {e}",
                    outgoing.outpoint.txid
                ))
            })?;
        ensure_non_rbf(&tx).map_err(|_| {
            AdapterError::Network(format!(
                "lockup tx {} signals replace-by-fee",
                outgoing.outpoint.txid
            ))
        })?;
        let output = tx
            .output
            .get(outgoing.outpoint.vout as usize)
            .ok_or_else(|| {
                AdapterError::InvalidParams(format!(
                    "lockup tx {} has no output {}",
                    outgoing.outpoint.txid, outgoing.outpoint.vout
                ))
            })?;
        if output.script_pubkey != outgoing.spec.lockup_script_pubkey {
            return Err(AdapterError::InvalidParams(
                "Liquid lockup output does not match descriptor script".into(),
            ));
        }
        if output.asset != Asset::Explicit(*self.network.policy_asset()) {
            return Err(AdapterError::InvalidParams(
                "Liquid lockup output is not explicit L-BTC".into(),
            ));
        }
        let Value::Explicit(value_sat) = output.value else {
            return Err(AdapterError::InvalidParams(
                "Liquid lockup output value is not explicit".into(),
            ));
        };
        if value_sat != outgoing.value_sat {
            return Err(AdapterError::InvalidParams(format!(
                "Liquid lockup amount {value_sat} sats does not match payment {} sats",
                outgoing.value_sat
            )));
        }
        let address = outgoing
            .spec
            .lockup_address(self.network.address_params())
            .map_err(|e| AdapterError::Network(e.to_string()))?;
        if self
            .find_spending_tx(&address, outgoing.outpoint)
            .await
            .map_err(AdapterError::Network)?
            .is_some()
        {
            return Err(AdapterError::InvalidParams(format!(
                "Liquid lockup outpoint {}:{} is already spent",
                outgoing.outpoint.txid, outgoing.outpoint.vout
            )));
        }
        Ok(())
    }

    async fn accepted_incoming_from_descriptor(
        &self,
        reservation: &IncomingReservation,
        descriptor: &HtlcDescriptor,
    ) -> Result<AcceptedIncoming, AdapterError> {
        self.validate_incoming_reservation(reservation)?;
        let (_spec, outpoint, value_sat) = self
            .verified_incoming(descriptor, reservation.payment_hash)
            .await?;
        let amount_msat = value_sat.checked_mul(MSAT_PER_SAT).ok_or_else(|| {
            AdapterError::InvalidParams("Liquid HTLC amount overflows msat".into())
        })?;
        if amount_msat < reservation.amount_msat {
            return Err(AdapterError::Network(format!(
                "locked amount {value_sat} sats is below reserved {} sats",
                msat_to_sat(reservation.amount_msat)?
            )));
        }
        let HtlcDescriptor::Liquid {
            refund_locktime, ..
        } = descriptor
        else {
            return Err(AdapterError::InvalidParams(
                "not a Liquid descriptor".into(),
            ));
        };
        let deadline_blocks =
            reservation.deadline.saturating_sub(Self::unix_now()) / BLOCK_TIME_SECS;
        let tip = self.tip_height().await?;
        let required_locktime = tip.saturating_add(deadline_blocks);
        if u64::from(*refund_locktime) < required_locktime {
            return Err(AdapterError::InvalidParams(format!(
                "refund locktime {} opens before the HTLC deadline (tip {tip}, need at least {})",
                refund_locktime, required_locktime
            )));
        }
        self.span.in_scope(|| {
            debug!(
                target: "cassis_liquid",
                "accepted incoming htlc {} at {}:{} deadline={}",
                reservation.payment_hash.short(),
                outpoint.txid,
                outpoint.vout,
                reservation.deadline,
            );
        });
        Ok(AcceptedIncoming {
            reservation: reservation.clone(),
            descriptor: descriptor.clone(),
            amount_msat,
        })
    }

    fn validate_accepted_incoming(
        &self,
        accepted: &AcceptedIncoming,
    ) -> Result<(HtlcSpec, OutPoint, u64), AdapterError> {
        self.validate_incoming_reservation(&accepted.reservation)?;
        let value_sat = msat_to_sat(accepted.amount_msat)?;
        if accepted.amount_msat < accepted.reservation.amount_msat {
            return Err(AdapterError::InvalidParams(
                "accepted Liquid amount is below reservation".into(),
            ));
        }
        let (spec, outpoint) =
            self.incoming_spec(&accepted.reservation.payment_hash, &accepted.descriptor)?;
        Ok((spec, outpoint, value_sat))
    }
}

#[async_trait]
impl NetworkAdapter for LiquidAdapter {
    fn network_id(&self) -> NetworkId {
        self.network_id.clone()
    }

    fn invoice_pubkey(&self) -> XOnlyPubKey {
        self.invoice_pubkey
    }

    fn claim_pubkey(&self) -> XOnlyPubKey {
        self.claim_xonly
    }

    fn incoming_delta_secs(&self) -> u64 {
        300
    }

    async fn reserve_incoming(
        &self,
        request: IncomingRequest,
    ) -> Result<IncomingReservation, AdapterError> {
        self.validate_incoming_request(&request)?;
        let expected_sat = msat_to_sat(request.amount_msat)?;
        let reservation = self.incoming_reservation(&request, self.claim_target()?);
        let mut incoming = self.incoming.lock().await;
        if let Some(existing) = incoming.get(&request.operation_id) {
            self.validate_incoming_state(existing, &reservation)?;
            return Ok(reservation);
        }
        if request.deadline <= Self::unix_now() {
            return Err(AdapterError::InvalidParams("deadline in the past".into()));
        }
        if incoming
            .values()
            .any(|state| state.payment_hash == request.payment_hash)
        {
            return Err(AdapterError::Retryable(
                "Liquid payment hash already has an active reservation".into(),
            ));
        }
        incoming.insert(
            request.operation_id.clone(),
            PendingIncoming {
                payment_hash: request.payment_hash,
                accepted: None,
                expected_sat,
                deadline: request.deadline,
                arrival: Arc::new(Notify::new()),
            },
        );
        Ok(reservation)
    }

    async fn cancel_incoming(&self, reservation: &IncomingReservation) -> Result<(), AdapterError> {
        self.validate_incoming_reservation(reservation)?;
        let mut incoming = self.incoming.lock().await;
        let Some(state) = incoming.get(&reservation.operation_id) else {
            return Ok(());
        };
        self.validate_incoming_state(state, reservation)?;
        if state.accepted.is_some() {
            return Err(AdapterError::InvalidParams(
                "cannot cancel an accepted incoming HTLC".into(),
            ));
        }
        let arrival = state.arrival.clone();
        incoming.remove(&reservation.operation_id);
        arrival.notify_waiters();
        Ok(())
    }

    async fn accept_incoming(
        &self,
        reservation: &IncomingReservation,
        descriptor: &HtlcDescriptor,
    ) -> Result<AcceptedIncoming, AdapterError> {
        self.validate_incoming_reservation(reservation)?;
        {
            let incoming = self.incoming.lock().await;
            let state = incoming.get(&reservation.operation_id).ok_or_else(|| {
                AdapterError::NotFound(format!(
                    "no incoming reservation for operation {}",
                    reservation.operation_id
                ))
            })?;
            self.validate_incoming_state(state, reservation)?;
            if let Some(accepted) = &state.accepted {
                if accepted.descriptor == *descriptor {
                    return Ok(accepted.clone());
                }
                return Err(AdapterError::InvalidParams(format!(
                    "incoming operation {} was accepted with a different descriptor",
                    reservation.operation_id
                )));
            }
        }

        let accepted = self
            .accepted_incoming_from_descriptor(reservation, descriptor)
            .await?;
        let mut incoming = self.incoming.lock().await;
        let state = incoming.get_mut(&reservation.operation_id).ok_or_else(|| {
            AdapterError::NotFound(format!(
                "incoming reservation for operation {} disappeared",
                reservation.operation_id
            ))
        })?;
        self.validate_incoming_state(state, reservation)?;
        if let Some(existing) = &state.accepted {
            if existing.descriptor == accepted.descriptor {
                return Ok(existing.clone());
            }
            return Err(AdapterError::InvalidParams(format!(
                "incoming operation {} was accepted with a different descriptor",
                reservation.operation_id
            )));
        }
        let arrival = state.arrival.clone();
        state.accepted = Some(accepted.clone());
        drop(incoming);
        arrival.notify_waiters();
        Ok(accepted)
    }

    async fn restore_incoming(&self, accepted: &AcceptedIncoming) -> Result<(), AdapterError> {
        {
            let incoming = self.incoming.lock().await;
            if let Some(state) = incoming.get(&accepted.reservation.operation_id) {
                self.validate_incoming_state(state, &accepted.reservation)?;
                if let Some(existing) = &state.accepted {
                    if Self::accepted_incoming_matches(existing, accepted) {
                        return Ok(());
                    }
                    return Err(AdapterError::InvalidParams(format!(
                        "incoming operation {} has different restored state",
                        accepted.reservation.operation_id
                    )));
                }
            } else if incoming
                .values()
                .any(|state| state.payment_hash == accepted.reservation.payment_hash)
            {
                return Err(AdapterError::Retryable(
                    "Liquid payment hash already belongs to another active reservation".into(),
                ));
            }
        }

        let canonical = self
            .accepted_incoming_from_descriptor(&accepted.reservation, &accepted.descriptor)
            .await?;
        if !Self::accepted_incoming_matches(&canonical, accepted) {
            return Err(AdapterError::InvalidParams(
                "restored incoming state does not match its descriptor".into(),
            ));
        }

        let mut incoming = self.incoming.lock().await;
        if let Some(state) = incoming.get(&accepted.reservation.operation_id) {
            self.validate_incoming_state(state, &accepted.reservation)?;
            if let Some(existing) = &state.accepted {
                if Self::accepted_incoming_matches(existing, accepted) {
                    return Ok(());
                }
                return Err(AdapterError::InvalidParams(format!(
                    "incoming operation {} was accepted with a different descriptor",
                    accepted.reservation.operation_id
                )));
            }
            let arrival = state.arrival.clone();
            incoming
                .get_mut(&accepted.reservation.operation_id)
                .expect("entry checked above")
                .accepted = Some(accepted.clone());
            drop(incoming);
            arrival.notify_waiters();
            return Ok(());
        }
        if incoming
            .values()
            .any(|state| state.payment_hash == accepted.reservation.payment_hash)
        {
            return Err(AdapterError::Retryable(
                "Liquid payment hash already belongs to another active reservation".into(),
            ));
        }
        let arrival = Arc::new(Notify::new());
        incoming.insert(
            accepted.reservation.operation_id.clone(),
            PendingIncoming {
                payment_hash: accepted.reservation.payment_hash,
                accepted: Some(accepted.clone()),
                expected_sat: msat_to_sat(accepted.reservation.amount_msat)?,
                deadline: accepted.reservation.deadline,
                arrival: arrival.clone(),
            },
        );
        drop(incoming);
        arrival.notify_waiters();
        Ok(())
    }

    async fn watch_incoming(
        &self,
        reservation: &IncomingReservation,
        deadline: u64,
    ) -> Result<(), AdapterError> {
        self.validate_incoming_reservation(reservation)?;
        let (arrival, accepted, reservation_deadline) = {
            let incoming = self.incoming.lock().await;
            let state = incoming.get(&reservation.operation_id).ok_or_else(|| {
                AdapterError::Retryable(format!(
                    "incoming reservation for operation {} no longer exists",
                    reservation.operation_id
                ))
            })?;
            self.validate_incoming_state(state, reservation)?;
            (
                state.arrival.clone(),
                state.accepted.clone(),
                state.deadline,
            )
        };
        if accepted.is_some() {
            return Ok(());
        }
        let deadline = deadline.min(reservation_deadline);
        loop {
            let now = Self::unix_now();
            if now >= deadline {
                return Err(AdapterError::DeadlineExceeded);
            }
            let wait = Duration::from_secs((deadline - now).clamp(1, POLL_INTERVAL_SECS));
            if tokio::time::timeout(wait, arrival.notified())
                .await
                .is_err()
            {
                continue;
            }
            let incoming = self.incoming.lock().await;
            let state = incoming.get(&reservation.operation_id).ok_or_else(|| {
                AdapterError::Retryable(format!(
                    "incoming reservation for operation {} was canceled",
                    reservation.operation_id
                ))
            })?;
            self.validate_incoming_state(state, reservation)?;
            if state.accepted.is_some() {
                return Ok(());
            }
        }
    }

    async fn claim_incoming(
        &self,
        accepted: &AcceptedIncoming,
        preimage: Bytes32,
    ) -> Result<(), AdapterError> {
        let (spec, outpoint, value_sat) = self.validate_accepted_incoming(accepted)?;
        if !accepted
            .reservation
            .payment_hash
            .matches_preimage(&preimage)
        {
            return Err(AdapterError::InvalidParams(
                "preimage does not hash to the payment hash".into(),
            ));
        }
        let state: Option<PendingIncoming> = {
            let incoming = self.incoming.lock().await;
            let state = incoming.get(&accepted.reservation.operation_id);
            if let Some(state) = state {
                self.validate_incoming_state(state, &accepted.reservation)?;
                let stored = state.accepted.as_ref().ok_or_else(|| {
                    AdapterError::InvalidParams(format!(
                        "incoming operation {} has not been accepted",
                        accepted.reservation.operation_id
                    ))
                })?;
                if !Self::accepted_incoming_matches(stored, accepted) {
                    return Err(AdapterError::InvalidParams(
                        "accepted incoming state does not match adapter state".into(),
                    ));
                }
                Some(state.clone())
            } else {
                None
            }
        };
        if state.is_none() {
            // Successful claim already removed state. Same-handle retry is complete.
            return Ok(());
        }
        self.span.in_scope(|| {
            info!(
                target: "cassis_liquid",
                "claiming htlc {} amount={} sats on {}",
                accepted.reservation.payment_hash.short(),
                value_sat,
                self.network_id,
            );
        });
        let txid = self
            .spend_htlc_input(&spec, outpoint, value_sat, Some(preimage.0), None)
            .await?;
        self.span.in_scope(|| {
            info!(
                target: "cassis_liquid",
                "htlc claimed for {}: tx={txid}",
                accepted.reservation.payment_hash.short()
            );
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
                    "no incoming Liquid reservation for operation {}",
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
        let recipient = self.validate_outgoing_request(&request)?;
        let existing_funded = {
            let mut outgoing = self.outgoing.lock().await;
            if let Some(existing) = outgoing.get(&request.operation_id) {
                Self::outgoing_state_matches_request(existing, &request, &recipient)?;
                let funded = existing.funded.clone();
                if funded.is_none() {
                    return Err(AdapterError::Retryable(format!(
                        "Liquid outgoing operation {} is already being created",
                        request.operation_id
                    )));
                }
                if existing.verified {
                    return self.outgoing_payment_from_state(&request.operation_id, existing);
                }
                funded
            } else {
                if request.expiry <= Self::unix_now() {
                    return Err(AdapterError::InvalidParams("expiry in the past".into()));
                }
                if outgoing
                    .values()
                    .any(|state| state.payment_hash == request.payment_hash)
                {
                    return Err(AdapterError::Retryable(
                        "Liquid payment hash already has an active outgoing payment".into(),
                    ));
                }
                outgoing.insert(
                    request.operation_id.clone(),
                    PendingOutgoing {
                        payment_hash: request.payment_hash,
                        amount_msat: request.amount_msat,
                        expiry: request.expiry,
                        recipient,
                        funded: None,
                        verified: false,
                    },
                );
                None
            }
        };

        if let Some(funded) = existing_funded {
            self.wait_lockup_propagation(&funded).await?;
            let validated = LiquidOutgoing {
                recipient,
                spec: funded.spec.clone(),
                outpoint: funded.outpoint,
                value_sat: funded.value_sat,
            };
            self.verified_outgoing(&validated).await?;
            let mut outgoing = self.outgoing.lock().await;
            let state = outgoing.get_mut(&request.operation_id).ok_or_else(|| {
                AdapterError::NotFound(format!(
                    "outgoing operation {} disappeared during verification",
                    request.operation_id
                ))
            })?;
            state.verified = true;
            return self.outgoing_payment_from_state(&request.operation_id, state);
        }

        let operation_id = request.operation_id.clone();
        let payment_hash = request.payment_hash;
        let funded: Result<FundedHtlc, AdapterError> = async {
            let sats = msat_to_sat(request.amount_msat)?;
            let tip = self.tip_height().await?;
            let spec = self.build_options(&payment_hash, &recipient, request.expiry, tip)?;
            let lockup_address = spec.lockup_address(self.network.address_params())?;
            self.span.in_scope(|| {
                info!(
                    target: "cassis_liquid",
                    "locking htlc {}: {sats} sats -> {lockup_address} (expiry {})",
                    payment_hash.short(),
                    request.expiry,
                );
            });

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
            let added = self
                .signer
                .sign(&mut pset)
                .map_err(|e| error_from_lwk(format!("pset sign: {e}")))?;
            if added == 0 {
                return Err(AdapterError::Network(
                    "signer produced no signatures".into(),
                ));
            }
            let tx = self
                .wollet
                .lock()
                .await
                .finalize(&mut pset)
                .map_err(error_from_lwk)?;
            ensure_non_rbf(&tx)?;
            let vout = tx
                .output
                .iter()
                .position(|output| output.script_pubkey == spec.lockup_script_pubkey)
                .ok_or_else(|| AdapterError::Network("lockup output missing in tx".into()))?
                as u32;
            u8::try_from(vout).map_err(|_| {
                AdapterError::InvalidParams(format!(
                    "lockup output index {vout} does not fit descriptor's u8"
                ))
            })?;
            let txid = self.broadcast(&tx).await?;
            let outpoint = OutPoint::new(txid, vout);
            {
                let mut outgoing = self.outgoing.lock().await;
                let state = outgoing.get_mut(&operation_id).ok_or_else(|| {
                    AdapterError::Network("outgoing operation disappeared after lock".into())
                })?;
                if state.payment_hash != payment_hash {
                    return Err(AdapterError::Network(
                        "outgoing operation state changed after lock".into(),
                    ));
                }
                state.funded = Some(FundedHtlc {
                    spec: spec.clone(),
                    outpoint,
                    value_sat: sats,
                });
            }
            self.span.in_scope(|| {
                debug!(
                    target: "cassis_liquid",
                    "htlc locked {}: txid={txid}",
                    payment_hash.short()
                );
            });
            Ok(FundedHtlc {
                spec,
                outpoint,
                value_sat: sats,
            })
        }
        .await;
        if funded.is_err() {
            self.discard_unfunded_outgoing(&operation_id, payment_hash)
                .await;
        }
        let funded = funded?;
        self.wait_lockup_propagation(&funded).await?;
        let validated = LiquidOutgoing {
            recipient,
            spec: funded.spec,
            outpoint: funded.outpoint,
            value_sat: funded.value_sat,
        };
        self.verified_outgoing(&validated).await?;
        let mut outgoing = self.outgoing.lock().await;
        let state = outgoing.get_mut(&operation_id).ok_or_else(|| {
            AdapterError::NotFound(format!(
                "outgoing operation {operation_id} disappeared after funding"
            ))
        })?;
        state.verified = true;
        self.outgoing_payment_from_state(&operation_id, state)
    }

    async fn watch_outgoing(
        &self,
        payment: &OutgoingPayment,
        deadline: u64,
    ) -> Result<Bytes32, AdapterError> {
        let outgoing = self.validate_outgoing_payment(payment)?;
        let funded = {
            let states = self.outgoing.lock().await;
            let state = states.get(&payment.operation_id).ok_or_else(|| {
                AdapterError::NotFound(format!(
                    "no outgoing payment for operation {}",
                    payment.operation_id
                ))
            })?;
            Self::outgoing_state_matches_payment(state, payment, &outgoing)?;
            state.funded.clone().expect("validated funded state")
        };
        let address = funded
            .spec
            .lockup_address(self.network.address_params())
            .map_err(|e| AdapterError::Network(e.to_string()))?;
        loop {
            if Self::unix_now() >= deadline {
                return Err(AdapterError::DeadlineExceeded);
            }
            match self.find_spending_tx(&address, funded.outpoint).await {
                Ok(Some(spending_tx)) => {
                    match Self::extract_preimage(&spending_tx, funded.outpoint, &funded.spec) {
                        Ok(preimage) => {
                            self.span.in_scope(|| {
                                info!(
                                    target: "cassis_liquid",
                                    "preimage observed on {} for {}",
                                    self.network_id,
                                    payment.payment_hash.short(),
                                );
                            });
                            return Ok(Bytes32(preimage));
                        }
                        Err(message) => self.span.in_scope(|| {
                            warn!(target: "cassis_liquid", "preimage extraction: {message}");
                        }),
                    }
                }
                Ok(None) => {}
                Err(message) => self.span.in_scope(|| {
                    warn!(target: "cassis_liquid", "outgoing watch poll: {message}");
                }),
            }
            tokio::time::sleep(Duration::from_secs(POLL_INTERVAL_SECS)).await;
        }
    }

    async fn refund_outgoing(&self, payment: &OutgoingPayment) -> Result<(), AdapterError> {
        let outgoing = self.validate_outgoing_payment(payment)?;
        let funded = {
            let states = self.outgoing.lock().await;
            let Some(state) = states.get(&payment.operation_id) else {
                // Successful refund already removed state. Same-handle retry is complete.
                return Ok(());
            };
            Self::outgoing_state_matches_payment(state, payment, &outgoing)?;
            state.funded.clone().expect("validated funded state")
        };
        let tip = self.tip_height().await?;
        if tip < u64::from(funded.spec.refund_locktime) {
            return Err(AdapterError::Retryable(format!(
                "timelock not reached: tip={tip} refund_locktime={}",
                funded.spec.refund_locktime
            )));
        }
        let txid = self
            .spend_htlc_input(
                &funded.spec,
                funded.outpoint,
                funded.value_sat,
                None,
                Some(funded.spec.refund_locktime),
            )
            .await?;
        self.span.in_scope(|| {
            info!(
                target: "cassis_liquid",
                "htlc refunded {}: tx={txid}",
                payment.payment_hash.short()
            );
        });
        self.outgoing.lock().await.remove(&payment.operation_id);
        Ok(())
    }

    async fn restore_outgoing(&self, payment: &OutgoingPayment) -> Result<(), AdapterError> {
        let outgoing = self.validate_outgoing_payment(payment)?;
        {
            let states = self.outgoing.lock().await;
            if let Some(state) = states.get(&payment.operation_id) {
                Self::outgoing_state_matches_payment(state, payment, &outgoing)?;
                if state.verified {
                    return Ok(());
                }
            } else if states
                .values()
                .any(|state| state.payment_hash == payment.payment_hash)
            {
                return Err(AdapterError::Retryable(
                    "Liquid payment hash already has another active outgoing payment".into(),
                ));
            }
        }
        self.verified_outgoing(&outgoing).await?;
        let mut states = self.outgoing.lock().await;
        if let Some(state) = states.get_mut(&payment.operation_id) {
            Self::outgoing_state_matches_payment(state, payment, &outgoing)?;
            state.verified = true;
            return Ok(());
        }
        if states
            .values()
            .any(|state| state.payment_hash == payment.payment_hash)
        {
            return Err(AdapterError::Retryable(
                "Liquid payment hash already has another active outgoing payment".into(),
            ));
        }
        states.insert(
            payment.operation_id.clone(),
            PendingOutgoing {
                payment_hash: payment.payment_hash,
                amount_msat: payment.amount_msat,
                expiry: payment.expiry,
                recipient: outgoing.recipient,
                funded: Some(FundedHtlc {
                    spec: outgoing.spec,
                    outpoint: outgoing.outpoint,
                    value_sat: outgoing.value_sat,
                }),
                verified: true,
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
                "restored Liquid reservation differs from persisted state".into(),
            ))
        }
    }

    async fn can_route(&self, amount_msat: u64) -> Result<(), AdapterError> {
        let needed = msat_to_sat(amount_msat)?;
        let available = self.lbtc_balance_sat().await?;
        if needed > available {
            return Err(AdapterError::InvalidParams(format!(
                "insufficient liquid balance on {}: need {} sats, have {available} sats",
                self.network_id, needed
            )));
        }
        Ok(())
    }

    /// Claim fees come from accepted HTLC value, so wallet needs no gas reserve.
    async fn can_claim(&self, _amount_msat: u64) -> Result<(), AdapterError> {
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
            XOnlyPubKey::from_bytes([9u8; 32]).unwrap(),
            Span::none(),
        );
        let adapter = LiquidAdapter::new(config).await.unwrap();

        let config2 = default_config(
            NetworkId("liquid::testnet".to_string()),
            [7u8; 32],
            XOnlyPubKey::from_bytes([9u8; 32]).unwrap(),
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
            &PubKey::from_bytes(
                spec.refund_pubkey
                    .to_bytes()
                    .try_into()
                    .expect("compressed refund key is 33 bytes")
            )
            .unwrap()
        );
        assert_eq!(*refund_locktime, 1234);

        // Output indexes beyond the descriptor's u8 are rejected
        // rather than truncated.
        assert!(spec.to_descriptor(OutPoint::new(txid, 300)).is_err());
    }
}
