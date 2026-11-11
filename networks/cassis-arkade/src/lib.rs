//! Arkade network adapter for cassis.
//!
//! Implements [`NetworkAdapter`] on top of an Arkade operator
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
//! * **Batch expiry**: VTXOs, VHTLCs included, expire with the batch
//!   (commitment transaction) they descend from, after which the
//!   operator may sweep it and they can no longer be spent offchain.
//!   An HTLC must therefore be over [`SWEEP_MARGIN_SECS`] before its
//!   VHTLC's batch expires: receivers check it, and senders refresh
//!   coins into a new batch before locking them.
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
use ark_client::Blockchain;
use ark_client::BoltzReferralId;
use ark_client::Client;
use ark_client::InMemorySwapStorage;
use ark_client::OfflineClient;
use ark_client::OfflineClientConfig;
use ark_client::SqliteContractStore;
use ark_core::contract::{SpendPath, SpendPathKind};
use ark_core::intent::{self, IntentMessage};
use ark_core::send::build_offchain_transactions;
use ark_core::send::sign_ark_transaction;
use ark_core::send::sign_checkpoint_transaction;
use ark_core::send::OffchainTransactions;
use ark_core::send::SendReceiver;
use ark_core::send::VtxoInput;
use ark_core::server::GetVtxosRequestFilter;
use ark_core::server::VirtualTxOutPoint;
use ark_core::vhtlc::VhtlcOptions;
use ark_core::vhtlc::VhtlcScript;
use ark_core::ArkAddress;
use ark_core::ArkNote;
use ark_core::Asset;
use ark_core::BoardingOutput;
use ark_core::VTXO_CONDITION_KEY;
use async_trait::async_trait;
use bitcoin::absolute;
use bitcoin::consensus::Decodable;
use bitcoin::hashes::ripemd160;
use bitcoin::hashes::Hash;
use bitcoin::key::Keypair;
use bitcoin::key::Secp256k1;
use bitcoin::psbt;
use bitcoin::relative;
use bitcoin::secp256k1::schnorr;
use bitcoin::secp256k1::Message;
use bitcoin::taproot::LeafVersion;
use bitcoin::Sequence;
use bitcoin::TxOut;
use bitcoin::VarInt;
use bitcoin::XOnlyPublicKey;
use cassis_core::{
    sats_for_msat, unix_now, Bytes32, Htlc, HtlcDescriptor, HtlcTarget, Network, NetworkError,
    NetworkId, OutgoingState, XOnlyPubKey, MSAT_PER_SAT,
};
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::Once;
use std::time::Duration;
use tracing::{debug, info, Span};

/// Public mainnet operator. Serves gRPC + REST on 443.
pub const MAINNET_SERVER_URL: &str = "https://arkade.computer";
/// Public mutinynet operator ("testnet" for cassis purposes).
pub const TESTNET_SERVER_URL: &str = "https://mutinynet.arkade.sh";
const MAINNET_ESPLORA_URL: &str = "https://mempool.space/api";
const TESTNET_ESPLORA_URL: &str = "https://mutinynet.com/api";

/// How long the SDK may wait for the next batch event. Its default is
/// 30s, but joining a round means waiting for the operator's session:
/// the public mutinynet operator batches every 60s, so the default can
/// time out after the intent was already registered (and leaves the
/// input locked to that intent).
const BATCH_TIMEOUT_SECS: u64 = 300;

/// How long before its VHTLC's batch expires an HTLC must be over:
/// after the expiry the sender still has to get its refund co-signed
/// by the operator, before the batch can be swept.
pub const SWEEP_MARGIN_SECS: u64 = 20 * 60;

/// Longest a node waits between two [`Network::maintain`] runs.
const MAINTENANCE_INTERVAL_SECS: u64 = 60 * 60;

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

const RPC_TIMEOUT_SECS: u64 = 30;
/// The chain the operator at `server_url` runs on.
async fn operator_network(server_url: &str) -> Result<bitcoin::Network, String> {
    let mut client = ark_grpc::Client::new(server_url.to_string());
    let info = async {
        client.connect().await?;
        client.get_info().await
    };
    tokio::time::timeout(Duration::from_secs(RPC_TIMEOUT_SECS), info)
        .await
        .map_err(|_| format!("arkade operator {server_url} did not answer"))?
        .map(|info| info.network)
        .map_err(|e| format!("arkade operator {server_url}: {e}"))
}

/// Convenience conversion into the routing layer's network error.
fn htlc(e: impl std::fmt::Display) -> NetworkError {
    NetworkError::network(e)
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

fn sat_amount(amount_msat: u64) -> bitcoin::Amount {
    bitcoin::Amount::from_sat(sats_for_msat(amount_msat))
}

type ArkClient = Client<esplora::EsploraBlockchain, BdkWallet, InMemorySwapStorage>;

/// A pair built from one unspent VTXO at a VHTLC address.
struct UnspentVtxo {
    outpoint: bitcoin::OutPoint,
    amount: bitcoin::Amount,
    assets: Vec<Asset>,
    /// When its batch expires (unix seconds).
    expires_at: u64,
}

pub struct ArkadeAdapter {
    id: NetworkId,
    network: bitcoin::Network,
    server_url: String,
    span: Span,
    /// The operator rejects scripts whose smallest exit (CSV) delay is
    /// shorter than its advertised unilateral exit delay, measured via
    /// [`exit_delay_secs`]; our delays are floored at this.
    exit_delay_floor_secs: u32,
    keypair: Keypair,
    /// Our x-only key: VHTLC receiver when claiming, sender when locking.
    xonly: XOnlyPublicKey,
    /// Operator signer key reported by GetInfo; both parties of a VHTLC
    /// use the same operator.
    server_pk_xonly: XOnlyPublicKey,
    dust: bitcoin::Amount,
    client: Arc<ArkClient>,
    chain: Arc<esplora::EsploraBlockchain>,
    /// How long the operator's batches last, at least (see
    /// [`Self::learn_batch_lifetime`]); `None` until a VTXO is seen.
    batch_lifetime_secs: Mutex<Option<u64>>,
}

impl ArkadeAdapter {
    /// Connect to the operator of `arkade`, `arkade::mutinynet` or
    /// `arkade::<host>`. VTXOs live with the operator and on-chain;
    /// contract rows are persisted in `data_dir/contracts.db`.
    pub async fn open(
        id: NetworkId,
        secret: [u8; 32],
        data_dir: &Path,
        span: &Span,
    ) -> Result<Self, String> {
        Self::open_with_esplora(id, secret, data_dir, None, span).await
    }

    /// [`open`](Self::open), reading the chain from the Esplora API at
    /// `esplora_url` instead of the public one for the operator's chain
    /// (required on chains without one, like regtest).
    pub async fn open_with_esplora(
        id: NetworkId,
        secret: [u8; 32],
        data_dir: &Path,
        esplora_url: Option<&str>,
        span: &Span,
    ) -> Result<Self, String> {
        install_rustls_crypto_provider();
        let server_url = match id.param() {
            None => MAINNET_SERVER_URL.to_string(),
            Some("mutinynet") => TESTNET_SERVER_URL.to_string(),
            Some(_) => id.host_url()?,
        };
        let network = operator_network(&server_url).await?;
        let esplora_url = match (esplora_url, network) {
            (Some(url), _) => url,
            (None, bitcoin::Network::Bitcoin) => MAINNET_ESPLORA_URL,
            // The only signet arkade operators run on.
            (None, bitcoin::Network::Signet) => TESTNET_ESPLORA_URL,
            (None, other) => {
                return Err(format!(
                    "arkade operator {server_url} is on {other}: it needs an esplora URL"
                ))
            }
        };
        let secp = Secp256k1::new();
        let secret = bitcoin::secp256k1::SecretKey::from_slice(&secret)
            .map_err(|e| format!("invalid arkade key: {e}"))?;
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let chain = Arc::new(esplora::EsploraBlockchain::new(esplora_url)?);
        let wallet = Arc::new(
            BdkWallet::new(keypair, network, esplora_url)
                .map_err(|e| format!("bdk wallet: {e}"))?,
        );
        let client_config = OfflineClientConfig {
            ark_server_url: server_url.clone(),
            boltz_url: String::new(),
            boltz_referral_id: BoltzReferralId::Disabled,
            timeout: Duration::from_secs(BATCH_TIMEOUT_SECS),
            ..Default::default()
        };
        // Persist the SDK's contract rows (VHTLCs and their state) so a
        // restart does not lose them; the operator only knows VTXOs.
        let contracts = SqliteContractStore::new(data_dir.join("contracts.db"))
            .map_err(|e| format!("arkade contract store: {e}"))?;
        let client = OfflineClient::with_keypair(
            client_config,
            keypair,
            chain.clone(),
            wallet,
            Arc::new(InMemorySwapStorage::new()),
        )
        .with_contract_store(Box::new(contracts))
        .connect()
        .await
        .map_err(|e| format!("connect to arkade operator {server_url}: {e}"))?;
        let info = client
            .server_info()
            .await
            .map_err(|e| format!("operator info: {e}"))?;
        let span = cassis_core::network_span(span, &id);
        debug!(parent: &span, "arkade wallet ready: operator={server_url} signer={}", info.signer_pk);
        let adapter = Self {
            id,
            network,
            server_url,
            span,
            exit_delay_floor_secs: exit_delay_secs(info.unilateral_exit_delay),
            keypair,
            xonly: keypair.x_only_public_key().0,
            server_pk_xonly: XOnlyPublicKey::from(info.signer_pk),
            dust: info.dust,
            client: Arc::new(client),
            chain,
            batch_lifetime_secs: Mutex::new(None),
        };
        adapter.learn_batch_lifetime().await;
        Ok(adapter)
    }

    /// Learn how long the operator's batches last (it does not
    /// advertise it) from the VTXOs this wallet ever held: each expires
    /// at most a lifetime after its creation, exactly one when created
    /// in a batch rather than by an offchain send.
    async fn learn_batch_lifetime(&self) {
        let vtxos = match self.client.list_vtxos().await {
            Ok(vtxos) => vtxos,
            Err(error) => {
                debug!(parent: &self.span, "listing VTXOs for the batch lifetime: {error}");
                return;
            }
        };
        let seen = vtxos
            .all()
            .map(|entry| entry.vtxo())
            .filter_map(|vtxo| u64::try_from(vtxo.expires_at - vtxo.created_at).ok())
            .max();
        let mut lifetime = self
            .batch_lifetime_secs
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if seen > *lifetime {
            *lifetime = seen;
            info!(parent: &self.span, "operator batches last {}s", seen.unwrap_or(0));
        }
    }

    /// Settle into a new batch every spendable VTXO whose batch expires
    /// before `deadline`: an offchain send's outputs expire with its
    /// inputs' batch, so a VHTLC funded by them would expire too early.
    async fn refresh_vtxos_expiring_before(&self, deadline: u64) -> Result<(), NetworkError> {
        let expiring = || async {
            let vtxos = self
                .client
                .list_vtxos_filtered(GetVtxosRequestFilter::Spendable)
                .await
                .map_err(|e| NetworkError::network(format!("list VTXOs: {e}")))?;
            Ok::<_, NetworkError>(
                vtxos
                    .spendable_offchain()
                    .map(|entry| entry.vtxo())
                    .filter(|vtxo| expiry_secs(vtxo.expires_at) < deadline)
                    .map(|vtxo| vtxo.outpoint)
                    .collect::<Vec<_>>(),
            )
        };
        let outpoints = expiring().await?;
        if outpoints.is_empty() {
            return Ok(());
        }
        info!(
            parent: &self.span,
            "refreshing {} VTXO(s) whose batch expires before {deadline}",
            outpoints.len()
        );
        let mut rng = rand::rngs::OsRng;
        self.client
            .settle_vtxos(&mut rng, &outpoints, &[])
            .await
            .map_err(|e| NetworkError::network(format!("refresh VTXOs: {e}")))?;
        self.learn_batch_lifetime().await;
        if !expiring().await?.is_empty() {
            return Err(NetworkError::invalid(format!(
                "the operator's batches expire before {deadline}, even refreshed"
            )));
        }
        Ok(())
    }

    fn claim_target(&self) -> HtlcTarget {
        HtlcTarget::XOnlyPubKey(XOnlyPubKey::from_bytes(self.xonly.serialize()).expect("valid key"))
    }

    /// VHTLC options of `htlc`: receiver from the target, sender and
    /// timelocks from the descriptor, server is our operator.
    fn vhtlc_options(&self, htlc: &Htlc) -> Result<VhtlcOptions, NetworkError> {
        let HtlcDescriptor::Arkade {
            sender,
            refund_locktime,
            unilateral_claim_delay,
            unilateral_refund_delay,
            unilateral_refund_without_receiver_delay,
        } = &htlc.descriptor
        else {
            return Err(NetworkError::invalid("not an arkade HTLC"));
        };
        let HtlcTarget::XOnlyPubKey(receiver) = &htlc.target else {
            return Err(NetworkError::invalid(
                "arkade HTLCs are locked to an x-only key",
            ));
        };
        let xonly = |key: &XOnlyPubKey| {
            XOnlyPublicKey::from_slice(key.as_bytes()).map_err(NetworkError::invalid)
        };
        // Consensus sequence numbers round-trip bit for bit
        // (seconds-type sequences set bit 22).
        let sequence = |value: u32| {
            let sequence = Sequence::from_consensus(value);
            if sequence.is_relative_lock_time() {
                Ok(sequence)
            } else {
                Err(NetworkError::invalid(format!(
                    "{value} is not a relative locktime"
                )))
            }
        };
        Ok(VhtlcOptions {
            sender: xonly(sender)?,
            receiver: xonly(receiver)?,
            server: self.server_pk_xonly,
            preimage_hash: vhtlc_payment_hash160(&htlc.payment_hash),
            refund_locktime: *refund_locktime,
            unilateral_claim_delay: sequence(*unilateral_claim_delay)?,
            unilateral_refund_delay: sequence(*unilateral_refund_delay)?,
            unilateral_refund_without_receiver_delay: sequence(
                *unilateral_refund_without_receiver_delay,
            )?,
        })
    }

    fn descriptor(options: &VhtlcOptions) -> HtlcDescriptor {
        HtlcDescriptor::Arkade {
            sender: XOnlyPubKey::from_bytes(options.sender.serialize()).expect("valid key"),
            refund_locktime: options.refund_locktime,
            unilateral_claim_delay: options.unilateral_claim_delay.to_consensus_u32(),
            unilateral_refund_delay: options.unilateral_refund_delay.to_consensus_u32(),
            unilateral_refund_without_receiver_delay: options
                .unilateral_refund_without_receiver_delay
                .to_consensus_u32(),
        }
    }

    /// The operator accepts the VHTLC's timelocks and the receiver keeps
    /// its head start on every unilateral path.
    fn check_timelocks(&self, options: &VhtlcOptions) -> Result<(), NetworkError> {
        if options.refund_locktime < MIN_TIMESTAMP_LOCKTIME {
            return Err(NetworkError::invalid(
                "refund locktime must be a unix timestamp",
            ));
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
                return Err(NetworkError::invalid(format!(
                    "{name} delay must be in seconds"
                )));
            }
            if exit_delay_secs(delay) < self.exit_delay_floor_secs {
                return Err(NetworkError::invalid(format!(
                    "{name} delay is below the operator's minimum exit delay"
                )));
            }
        }
        if exit_delay_secs(options.unilateral_refund_without_receiver_delay)
            <= exit_delay_secs(options.unilateral_claim_delay)
        {
            return Err(NetworkError::invalid(
                "sender-only refund must open after the receiver's unilateral claim",
            ));
        }
        Ok(())
    }

    fn build_options_for_outgoing(
        &self,
        payment_hash: &Bytes32,
        recipient: &XOnlyPubKey,
        expiry: u64,
    ) -> Result<VhtlcOptions, NetworkError> {
        let now = cassis_core::unix_now();
        if expiry <= now {
            return Err(NetworkError::Invalid("expiry in the past".into()));
        }
        let recipient_xonly = XOnlyPublicKey::from_str(recipient.to_hex().as_str())
            .map_err(|e| NetworkError::Invalid(format!("invalid recipient pubkey: {e}")))?;
        // The refund CLTV takes the route expiry directly: cassis
        // expiries are unix seconds, and the operator checks timestamp
        // locktimes against the chain tip's block time.
        let refund_locktime = u32::try_from(expiry)
            .map_err(|_| NetworkError::Invalid(format!("expiry {expiry} overflows nLockTime")))?;
        if refund_locktime < MIN_TIMESTAMP_LOCKTIME {
            return Err(NetworkError::Invalid(format!(
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
        .map_err(|e| NetworkError::Invalid(format!("CSV delay out of range: {e}")))?;

        Ok(VhtlcOptions {
            sender: self.xonly,
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
    fn exit_delay(&self, secs: u32) -> Result<Sequence, NetworkError> {
        Sequence::from_seconds_ceil(secs.max(self.exit_delay_floor_secs))
            .map_err(|e| NetworkError::Invalid(format!("CSV delay out of range: {e}")))
    }

    fn script_for(&self, options: &VhtlcOptions) -> Result<VhtlcScript, NetworkError> {
        VhtlcScript::new(options.clone(), self.network).map_err(htlc)
    }

    /// Timestamp of the chain tip block: what the operator holds
    /// timestamp CLTVs against (not the wall clock).
    async fn tip_time(&self) -> Result<u64, NetworkError> {
        self.chain.tip_time().await.map_err(NetworkError::network)
    }

    /// All VTXO outpoints (spent or not) at the given VHTLC address.
    async fn outpoints_at_address(
        &self,
        vhtlc: &VhtlcScript,
    ) -> Result<Vec<VirtualTxOutPoint>, NetworkError> {
        self.client
            .get_virtual_tx_outpoints(std::iter::once(vhtlc.address()))
            .await
            .map_err(|e| NetworkError::network(format!("get_virtual_tx_outpoints: {e}")))
    }

    /// The single unspent VTXO at the VHTLC address.
    async fn unspent_vtxo_at(&self, options: &VhtlcOptions) -> Result<UnspentVtxo, NetworkError> {
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
                expires_at: expiry_secs(o.expires_at),
            })
            .collect();
        match unspent.len() {
            1 => Ok(unspent.remove(0)),
            0 => Err(NetworkError::Network(
                "no unspent VTXO found at the VHTLC address".into(),
            )),
            n => Err(NetworkError::Network(format!(
                "expected one VTXO at the VHTLC address, found {n}"
            ))),
        }
    }

    async fn our_offchain_address(&self) -> Result<ArkAddress, NetworkError> {
        self.client
            .get_offchain_address()
            .await
            .map(|(addr, _)| addr)
            .map_err(|e| NetworkError::Network(format!("get_offchain_address: {e}")))
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
    ) -> Result<bitcoin::Txid, NetworkError> {
        let server_info = self
            .client
            .server_info()
            .await
            .map_err(|e| NetworkError::Network(format!("server_info: {e}")))?;

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
        .map_err(|_| NetworkError::Network("submit_offchain_transaction_request timed out".into()))?
        .map_err(htlc)?;

        let mut checkpoint_psbt = res
            .signed_checkpoint_txs
            .first()
            .cloned()
            .ok_or_else(|| NetworkError::Network("no checkpoint PSBTs returned".into()))?;
        sign_checkpoint_transaction(sign_fn.clone(), &mut checkpoint_psbt).map_err(htlc)?;

        tokio::time::timeout(
            Duration::from_secs(RPC_TIMEOUT_SECS),
            self.client
                .network_client()
                .finalize_offchain_transaction(ark_txid, vec![checkpoint_psbt]),
        )
        .await
        .map_err(|_| NetworkError::Network("finalize_offchain_transaction timed out".into()))?
        .map_err(htlc)?;

        Ok(ark_txid)
    }

    /// Spend the single VTXO at the VHTLC address back to our own
    /// offchain address, through the claim leaf (with `preimage`) or the
    /// sender-only refund leaf.
    async fn spend_vhtlc(
        &self,
        options: &VhtlcOptions,
        claim: bool,
        preimage: Option<&[u8; 32]>,
    ) -> Result<bitcoin::Txid, NetworkError> {
        let vhtlc = self.script_for(options)?;
        let vtxo = self.unspent_vtxo_at(options).await?;
        let our_address = self.our_offchain_address().await?;
        let (script, locktime) = if claim {
            (vhtlc.claim_script(), None)
        } else {
            (
                vhtlc.refund_without_receiver_script(),
                Some(absolute::LockTime::from_consensus(options.refund_locktime)),
            )
        };
        let control_block = vhtlc
            .taproot_spend_info()
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .ok_or_else(|| NetworkError::network("control block missing for VHTLC leaf"))?;
        let script_pubkey = vhtlc.script_pubkey();
        // `tapscripts` consumes the script: collect it last.
        let tapscripts = vhtlc.tapscripts();
        let input = VtxoInput::new(
            script,
            locktime,
            control_block,
            tapscripts,
            script_pubkey,
            vtxo.amount,
            vtxo.outpoint,
            vtxo.assets,
        );
        let outputs = vec![SendReceiver::bitcoin(our_address, vtxo.amount)];
        self.submit_vhtlc_spend(input, &outputs, &our_address, self.signer_with(preimage))
            .await
    }

    async fn virtual_tx_psbt(&self, txid: bitcoin::Txid) -> Result<Option<psbt::Psbt>, String> {
        let res = tokio::time::timeout(
            Duration::from_secs(RPC_TIMEOUT_SECS),
            self.client
                .network_client()
                .get_virtual_txs(vec![txid.to_string()], None, None),
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

    /// Current offchain balance (confirmed + pre-confirmed spendable
    /// VTXOs) in msat.
    pub async fn balance_msat(&self) -> Result<u64, NetworkError> {
        let balance = self
            .client
            .offchain_balance()
            .await
            .map_err(|e| NetworkError::Network(format!("offchain_balance: {e}")))?;
        let total_sats = balance
            .confirmed()
            .to_sat()
            .saturating_add(balance.pre_confirmed().to_sat());
        Ok(total_sats.saturating_mul(MSAT_PER_SAT))
    }

    /// Include confirmed boarding outputs in the next batch swap.
    /// Returns the commitment transaction ID, or `None` when no
    /// boarding output or recoverable VTXO is ready to settle.
    ///
    /// A `settle` that times out after registering its intent leaves the
    /// boarding input locked to that intent at the operator. Retrying then
    /// fails with `duplicated input`, so clear the stale intent and retry
    /// once.
    pub async fn onboard(&self) -> Result<Option<bitcoin::Txid>, NetworkError> {
        // OsRng (not `thread_rng`) so the returned future stays Send
        // and can be awaited from spawned tasks.
        let mut rng = rand::rngs::OsRng;
        let mut last = String::new();
        for attempt in 0..2 {
            match self.client.settle(&mut rng).await {
                Ok(txid) => return Ok(txid),
                Err(error) => {
                    last = error.to_string();
                    if attempt == 1 || !is_stale_intent_error(&last) {
                        break;
                    }
                    info!(
                        parent: &self.span,
                        "onboard: clearing a stale intent after '{last}'"
                    );
                    if let Err(error) = self.delete_stale_boarding_intents().await {
                        debug!(
                            parent: &self.span,
                            "onboard: no stale boarding intent to delete: {error}"
                        );
                    }
                }
            }
        }
        Err(NetworkError::Network(format!("onboard: {last}")))
    }

    /// Delete queued intents the operator still holds for our boarding
    /// outputs. The SDK only cleans up intent inputs that are VTXOs; a
    /// timed-out settlement of boarding outputs is otherwise stuck
    /// forever ("duplicated input" on every retry).
    async fn delete_stale_boarding_intents(&self) -> Result<(), NetworkError> {
        let info = self
            .client
            .server_info()
            .await
            .map_err(|e| NetworkError::Network(format!("operator info: {e}")))?;
        let secp = Secp256k1::new();
        let boarding = BoardingOutput::new(
            &secp,
            info.signer_pk.x_only_public_key().0,
            self.xonly,
            info.boarding_exit_delay,
            info.network,
        )
        .map_err(|e| NetworkError::Network(format!("boarding output: {e}")))?;
        let utxos = self
            .chain
            .find_outpoints(boarding.address())
            .await
            .map_err(|e| NetworkError::Network(format!("boarding utxos: {e}")))?;
        let (forfeit_script, control_block) = boarding.forfeit_spend_info();
        let inputs: Vec<intent::Input> = utxos
            .into_iter()
            .filter(|utxo| !utxo.is_spent)
            .map(|utxo| {
                let selection = SpendPath::new(
                    SpendPathKind::Forfeit,
                    forfeit_script.clone(),
                    control_block.clone(),
                )
                .select();
                intent::Input::new_with_spend_selection(
                    utxo.outpoint,
                    boarding.exit_delay(),
                    TxOut {
                        value: utxo.amount,
                        script_pubkey: boarding.script_pubkey(),
                    },
                    boarding.tapscripts(),
                    selection,
                    true,
                    false,
                    Vec::new(),
                )
            })
            .collect();
        if inputs.is_empty() {
            return Ok(());
        }
        let keypair = self.keypair;
        let sign_for_onchain =
            |_input: &mut psbt::Input,
             message: Message|
             -> Result<(schnorr::Signature, XOnlyPublicKey), ark_core::Error> {
                Ok((
                    secp.sign_schnorr_no_aux_rand(&message, &keypair),
                    keypair.x_only_public_key().0,
                ))
            };
        let sign_for_vtxo = |_input: &mut psbt::Input,
                             _message: Message|
         -> Result<
            Vec<(schnorr::Signature, XOnlyPublicKey)>,
            ark_core::Error,
        > { Ok(Vec::new()) };
        let delete = intent::make_intent(
            sign_for_vtxo,
            sign_for_onchain,
            inputs,
            Vec::new(),
            IntentMessage::Delete {
                expire_at: unix_now() + 120,
            },
        )
        .map_err(|e| NetworkError::Network(format!("delete intent proof: {e}")))?;
        // An intent currently held by a batch is not queued and cannot be
        // deleted until that batch finishes; retry for about one round.
        let mut last = String::new();
        for attempt in 0..3 {
            match self
                .client
                .network_client()
                .delete_intent(delete.clone())
                .await
            {
                Ok(()) => return Ok(()),
                Err(error) => {
                    last = error.to_string();
                    if attempt < 2 {
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                }
            }
        }
        Err(NetworkError::Network(format!(
            "delete boarding intent: {last}"
        )))
    }

    /// Redeem an arknote (`arknote...`, issued by the operator) into
    /// VTXOs in the next batch. Returns the commitment transaction ID.
    pub async fn redeem_note(&self, note: &str) -> Result<bitcoin::Txid, NetworkError> {
        let note = ArkNote::from_string(note.trim())
            .map_err(|e| NetworkError::Invalid(format!("invalid arknote: {e}")))?;
        let mut rng = rand::rngs::OsRng;
        self.client
            .settle_with_notes(&mut rng, vec![note])
            .await
            .map_err(|e| NetworkError::Network(format!("redeem note: {e}")))?
            .ok_or_else(|| NetworkError::Network("redeem note: nothing settled".into()))
    }

    /// Addresses for manual funding, returned as
    /// `(boarding, onchain, arkade)` strings. VTXOs sent to the
    /// boarding address settle into spendable offchain coins after
    /// they confirm and the node joins a batch swap.
    pub async fn deposit_addresses(&self) -> Result<(String, String, String), NetworkError> {
        let ark_address = self.our_offchain_address().await?;
        let boarding = self
            .client
            .get_boarding_address()
            .await
            .map_err(|e| NetworkError::Network(format!("get_boarding_address: {e}")))?;
        let onchain = self
            .client
            .get_onchain_address()
            .map_err(|e| NetworkError::Network(format!("get_onchain_address: {e}")))?;
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
    ) -> Result<bitcoin::Txid, NetworkError> {
        let to = ArkAddress::decode(address.trim()).map_err(|e| {
            NetworkError::Invalid(format!("invalid arkade address '{address}': {e}"))
        })?;
        let amount = sat_amount(amount_msat);
        self.client
            .send(vec![SendReceiver::bitcoin(to, amount)])
            .await
            .map_err(|e| NetworkError::Network(format!("send: {e}")))
    }

    /// Operator this wallet uses.
    pub fn operator(&self) -> &str {
        &self.server_url
    }
}

#[async_trait]
impl Network for ArkadeAdapter {
    fn id(&self) -> NetworkId {
        self.id.clone()
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
        if htlc.target != self.claim_target() {
            return Err(NetworkError::invalid("HTLC is not addressed to this node"));
        }
        self.verify_htlc(htlc).await
    }

    async fn verify_htlc(&self, htlc: &Htlc) -> Result<(), NetworkError> {
        let options = self.vhtlc_options(htlc)?;
        // The VHTLC address is rebuilt from the payment hash, our key and
        // our operator, so coins there are bound to all three.
        self.check_timelocks(&options)?;
        if u64::from(options.refund_locktime) < htlc.expiry {
            return Err(NetworkError::invalid("refund opens before the expiry"));
        }
        let vtxo = self.unspent_vtxo_at(&options).await?;
        if vtxo.amount < sat_amount(htlc.amount_msat) {
            return Err(NetworkError::invalid("VHTLC is worth less than the HTLC"));
        }
        if vtxo.expires_at < htlc.expiry.saturating_add(SWEEP_MARGIN_SECS) {
            return Err(NetworkError::invalid(format!(
                "VHTLC's batch expires at {}, less than {SWEEP_MARGIN_SECS}s after the HTLC",
                vtxo.expires_at
            )));
        }
        Ok(())
    }

    async fn claim_incoming_htlc(
        &self,
        htlc: &Htlc,
        preimage: Bytes32,
    ) -> Result<(), NetworkError> {
        let options = self.vhtlc_options(htlc)?;
        let txid = self.spend_vhtlc(&options, true, Some(&preimage.0)).await?;
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
        let HtlcTarget::XOnlyPubKey(receiver) = target else {
            return Err(NetworkError::invalid(
                "arkade HTLCs are locked to an x-only key",
            ));
        };
        let amount = sat_amount(amount_msat);
        if amount < self.dust {
            return Err(NetworkError::invalid(format!(
                "{} sats is below the operator's dust limit of {} sats",
                amount.to_sat(),
                self.dust.to_sat()
            )));
        }
        let options = self.build_options_for_outgoing(&payment_hash, receiver, expiry)?;
        self.refresh_vtxos_expiring_before(expiry.saturating_add(SWEEP_MARGIN_SECS))
            .await?;
        let address = self.script_for(&options)?.address();
        let txid = self
            .client
            .send(vec![SendReceiver::bitcoin(address, amount)])
            .await
            .map_err(|e| NetworkError::network(format!("lock: {e}")))?;
        info!(
            parent: &self.span,
            "locked {} sats for {} until {expiry}: tx {txid}",
            amount.to_sat(),
            payment_hash.short()
        );
        Ok(Self::descriptor(&options))
    }

    async fn check_outgoing_htlc(&self, htlc: &Htlc) -> Result<OutgoingState, NetworkError> {
        let options = self.vhtlc_options(htlc)?;
        let vhtlc = self.script_for(&options)?;
        let spent = self
            .outpoints_at_address(&vhtlc)
            .await?
            .into_iter()
            .find_map(|outpoint| outpoint.is_spent.then_some(outpoint.ark_txid).flatten());
        let Some(txid) = spent else {
            return Ok(OutgoingState::Pending);
        };
        let psbt = self
            .virtual_tx_psbt(txid)
            .await
            .map_err(NetworkError::network)?
            .ok_or_else(|| NetworkError::network("spending transaction not found"))?;
        match Self::extract_preimage_from_psbt(&psbt).map_err(NetworkError::network)? {
            Some(preimage) => Ok(OutgoingState::Claimed(Bytes32(preimage))),
            None => Ok(OutgoingState::Refunded),
        }
    }

    async fn refund_outgoing_htlc(&self, htlc: &Htlc) -> Result<(), NetworkError> {
        let options = self.vhtlc_options(htlc)?;
        let tip_time = self.tip_time().await?;
        if u64::from(options.refund_locktime) > tip_time {
            return Err(NetworkError::network(format!(
                "refund opens at {}, chain tip is at {tip_time}",
                options.refund_locktime
            )));
        }
        let txid = self.spend_vhtlc(&options, false, None).await?;
        info!(parent: &self.span, "refunded {}: tx {txid}", htlc.payment_hash.short());
        Ok(())
    }

    async fn can_send(&self, amount_msat: u64) -> Result<(), NetworkError> {
        let available = self.balance_msat().await?;
        let needed = sats_for_msat(amount_msat) * MSAT_PER_SAT;
        if available < needed {
            return Err(NetworkError::invalid(format!(
                "need {needed} msat, wallet has {available} msat"
            )));
        }
        // Every VTXO holds at least the dust limit, so coin selection
        // only leaves sub-dust change when nothing else is left to add,
        // and the operator rejects that output.
        let change = available - needed;
        let dust = self.dust.to_sat() * MSAT_PER_SAT;
        if change > 0 && change < dust {
            return Err(NetworkError::invalid(format!(
                "sending {needed} msat of {available} msat would leave change below the \
                 operator's dust limit of {dust} msat"
            )));
        }
        Ok(())
    }

    /// The operator co-signs claims for free.
    async fn can_receive(&self, _amount_msat: u64) -> Result<(), NetworkError> {
        Ok(())
    }

    /// A quarter of the operator's batch lifetime, so coins get several
    /// chances to be refreshed before they expire.
    fn maintenance_interval(&self) -> Option<Duration> {
        let lifetime = self
            .batch_lifetime_secs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .unwrap_or(MAINTENANCE_INTERVAL_SECS * 4);
        Some(Duration::from_secs(
            (lifetime / 4).clamp(60, MAINTENANCE_INTERVAL_SECS),
        ))
    }

    /// Settle confirmed boarding deposits and recoverable VTXOs, and
    /// refresh VTXOs past half their batch lifetime, so the wallet never
    /// holds coins the operator may sweep.
    async fn maintain(&self) -> Result<(), NetworkError> {
        if let Some(txid) = self.onboard().await? {
            info!(parent: &self.span, "settled boarding outputs in {txid}");
        }
        let lifetime = self
            .batch_lifetime_secs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .unwrap_or(0);
        let horizon = (lifetime / 2).max(SWEEP_MARGIN_SECS * 2);
        self.refresh_vtxos_expiring_before(unix_now() + horizon)
            .await
    }
}

// ---------------------------------------------------------------------------
// Helpers below keep module-private concerns out of the trait impl.
// ---------------------------------------------------------------------------

/// A VTXO's `expires_at` as unix seconds (0 if unset).
fn expiry_secs(expires_at: i64) -> u64 {
    u64::try_from(expires_at).unwrap_or(0)
}

/// Whether a failed batch join may have left an intent queued at the
/// operator (as opposed to failing before registration).
fn is_stale_intent_error(error: &str) -> bool {
    let error = error.to_ascii_lowercase();
    error.contains("duplicated input")
        || error.contains("timed out waiting for batch event")
        || error.contains("operation timed out")
        // The SDK tried its own cleanup first, but only knows how to
        // delete intents that hold VTXOs, not boarding outputs.
        || error.contains("failed to delete the stale intent")
        || error.contains("no vtxo inputs of this wallet")
}

/// tonic gRPC needs a TLS root set installed exactly once per process.
fn install_rustls_crypto_provider() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the VHTLC an outgoing cassis HTLC locks to, so other
    /// implementations (the Arkade wallet's TS payer and payee) can check
    /// they build the same script from the same descriptor.
    #[test]
    fn vhtlc_golden_vector() {
        let secp = Secp256k1::new();
        let key = |byte: u8| {
            let secret = bitcoin::secp256k1::SecretKey::from_slice(&[byte; 32]).unwrap();
            Keypair::from_secret_key(&secp, &secret)
                .x_only_public_key()
                .0
        };
        let claim_delay = Sequence::from_seconds_ceil(UNILATERAL_CLAIM_DELAY_SECS).unwrap();
        let refund_without_receiver_delay =
            Sequence::from_seconds_ceil(exit_delay_secs(claim_delay) + UNILATERAL_REFUND_GAP_SECS)
                .unwrap();
        let options = VhtlcOptions {
            sender: key(1),
            receiver: key(2),
            server: key(3),
            preimage_hash: vhtlc_payment_hash160(&Bytes32([0x11; 32])),
            refund_locktime: 1_800_000_000,
            unilateral_claim_delay: claim_delay,
            unilateral_refund_delay: claim_delay,
            unilateral_refund_without_receiver_delay: refund_without_receiver_delay,
        };
        let HtlcDescriptor::Arkade {
            unilateral_claim_delay,
            unilateral_refund_without_receiver_delay,
            ..
        } = ArkadeAdapter::descriptor(&options)
        else {
            unreachable!()
        };
        let script = VhtlcScript::new(options, bitcoin::Network::Regtest).unwrap();
        println!(
            "sender={} receiver={} server={} claim_delay={unilateral_claim_delay} \
             refund_without_receiver_delay={unilateral_refund_without_receiver_delay} \
             script_pubkey={}",
            key(1),
            key(2),
            key(3),
            script.script_pubkey().to_hex_string()
        );
        assert_eq!(unilateral_claim_delay, 0x0040_0055);
        assert_eq!(unilateral_refund_without_receiver_delay, 0x0040_00aa);
        assert_eq!(
            script.script_pubkey().to_hex_string(),
            "5120bec74228e3b7b5094571c4d5b1a528a91f55e45a852c3e7991b5190fc5418883"
        );
    }
}
