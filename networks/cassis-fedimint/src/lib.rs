//! Fedimint network adapter (LNv2 direct HTLC).
//!
//! A cassis node acts as a Fedimint client of one federation, with the
//! federation's guardians reached over iroh via `fedimint-connectors`
//! (guardian endpoint URLs of the form `iroh://<node-id>` in the
//! federation's `ClientConfig`).
//!
//! The adapter implements [`cassis_core::NetworkAdapter`] on top
//! of LNv2's *direct HTLC* API (fedimint PR #8913): a raw
//! `OutgoingContract` funded between two federation clients, with no
//! gateway involved. This is what lets fedimint honor an
//! externally-supplied `payment_hash` — the property LNv2's invoice
//! flow ("sells its own preimage" via TPE) lacked — and makes
//! fedimint a first-class cassis network.
//!
//! Method mapping (cassis method → LNv2 direct-HTLC operation):
//!
//! | cassis method          | LNv2 operation                                        |
//! |------------------------+-------------------------------------------------------|
//! | `reserve_incoming`     | Park operation state and return our claim public key. |
//! | `accept_incoming`      | Decode the funding descriptor (outpoint + contract),  |
//! |                        | verify the payment image and claim key, store it.     |
//! | `claim_incoming`       | `claim_htlc` with the route preimage + our claim      |
//! |                        | keypair, then await settlement.                       |
//! | `create_outgoing`      | `create_htlc` — fund a contract locked to the         |
//! |                        | recipient's claim key with `PaymentImage::Hash`.      |
//! | `watch_outgoing`       | `await_htlc_resolution` — the federation returns the  |
//! |                        | preimage once the recipient claims.                   |
//! | `refund_outgoing`      | `refund_htlc` after expiration (+ settle).            |
//! | `can_route`            | Client ecash balance check.                           |
//!
//! Identity: the adapter derives one even-parity (0x02-prefixed)
//! claim keypair from its per-network secret at construction and
//! self-reports the x-only half via
//! [`NetworkAdapter::claim_pubkey`]. Every counterparty that
//! locks a contract to us reconstructs the compressed key as
//! `0x02 || x-only`, so lock and claim agree by construction; the
//! descriptors additionally pin the full compressed key.
//!
//! Timelocks: LNv2 contract expirations are measured in the
//! federation's consensus block count. Cassis deadlines are absolute
//! unix seconds; [`SECS_PER_BLOCK`] converts. `refund_htlc` only
//! succeeds once the federation's block count passes the contract's
//! expiration, so [`NetworkAdapter::refund_outgoing`] retries
//! briefly while consensus catches up.

use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bitcoin::hashes::{sha256, Hash};
use fedimint_client::{Client, ClientHandleArc, RootSecret};
use fedimint_connectors::ConnectorRegistry;
use fedimint_core::core::OperationId as FedimintOperationId;
use fedimint_core::db::Database;
use fedimint_core::invite_code::InviteCode;
use fedimint_core::module::registry::ModuleRegistry;
use fedimint_core::{secp256k1, Amount, OutPoint, TransactionId};
use fedimint_derive_secret::DerivableSecret;
use fedimint_lnv2_client::common::contracts::{OutgoingContract, PaymentImage};
use fedimint_lnv2_client::htlc::HtlcError as LnHtlcError;
use fedimint_lnv2_client::LightningClientModule;
use fedimint_mint_client::{
    MintClientInit, MintClientModule, OOBNotes, ReissueExternalNotesState,
    SelectNotesWithAtleastAmount,
};
// `fedimint_client::module` is the renamed `fedimint_client_module` crate.
use fedimint_client::module::oplog::UpdateStreamOrOutcome;
use fedimint_wallet_client::{DepositStateV2, WalletClientInit, WalletClientModule, WithdrawState};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use cassis_core::{
    AcceptedIncoming, AdapterError, Bytes32, HtlcDescriptor, HtlcTarget, IncomingRequest,
    IncomingReservation, NetworkAdapter, NetworkId, OperationId, OutgoingPayment, OutgoingRequest,
    PubKey, XOnlyPubKey,
};

/// Per-hop delta the routing layer gets on fedimint legs. Contract
/// funding and claims are federation consensus outputs — seconds to
/// low minutes. 30 s gives the routing layer the same buffer the
/// other fast ecash networks use.
const INCOMING_DELTA_SECS: u64 = 30;

/// Salt mixed into the per-network secret when constructing the
/// fedimint root derivation. The federation id is added internally
/// by `RootSecret::StandardDoubleDerive`, so this constant simply
/// domain-separates the cassis-fedimint seed from other fedimint
/// clients that might share the same mnemonic.
const ROOT_SECRET_SALT: &[u8] = b"cassis/fedimint/v1";

/// Domain separator for the static claim keypair, hashed together
/// with the per-network secret.
const CLAIM_KEY_DOMAIN: &[u8] = b"cassis/fedimint/claim/v1";

/// Seconds per federation consensus block, used to convert cassis's
/// absolute unix expiry into an LNv2 expiration delta. Matches the
/// convention the fedimint adapter has always used for this
/// federation's block cadence.
const SECS_PER_BLOCK: u64 = 600;

/// How long `claim_incoming` waits for the funding transaction to be
/// observed at the descriptor's outpoint before giving up. The
/// funding is submitted by the upstream hop right before EXECUTE,
/// so by the time a preimage arrives it is long since accepted; this
/// only covers the race where a payee claims immediately after
/// COMMIT.
const FUNDING_GRACE: Duration = Duration::from_secs(60);

/// How long [`NetworkAdapter::refund_outgoing`] retries while
/// the federation's consensus block count has not yet passed the
/// contract's expiration.
const REFUND_RETRY: Duration = Duration::from_secs(120);

/// Incoming operation state. Operation id is map key; payment hash stays
/// inside reservation so duplicate-hash attempts can be rejected without
/// treating hash as attempt identity.
#[derive(Clone)]
struct PendingIncoming {
    /// Payment intent identity, retained separately from operation map key.
    payment_hash: Bytes32,
    reservation: IncomingReservation,
    /// Durable accepted state returned to caller.
    accepted: Option<AcceptedIncoming>,
    /// Filled in by `accept_incoming` once funder's execution identifies
    /// funded contract.
    funded: Option<FundedContract>,
    /// Claim spend submitted by previous call, if any. Recorded before
    /// settlement wait so retry never submits same on-chain action twice.
    claim_op: Option<FedimintOperationId>,
    /// Preimage bound to `claim_op`. Different preimage under same
    /// operation is protocol error, not retry.
    claim_preimage: Option<Bytes32>,
    /// Terminal success marker retained so repeated claims stay idempotent.
    claimed: bool,
    /// Serializes claim submission for this operation while allowing other
    /// operation ids to make progress.
    action_lock: Arc<Mutex<()>>,
}

/// Funded incoming contract: where it lives and what it says.
#[derive(Clone)]
struct FundedContract {
    outpoint: OutPoint,
    contract: OutgoingContract,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RefundState {
    Active,
    Refunded,
    ContractGone,
}

/// Outgoing operation state. Map key is cassis operation id. Native
/// Fedimint operation ids are retained separately for claim/refund recovery.
#[derive(Clone)]
struct OutgoingSlot {
    payment: OutgoingPayment,
    /// Explicit hash state retained after moving map keys to operation ids.
    payment_hash: Bytes32,
    /// Native operation under which `create_htlc` submitted funding.
    #[allow(dead_code)]
    funding_op: FedimintOperationId,
    outpoint: OutPoint,
    contract: OutgoingContract,
    /// Refund spend submitted by previous call, recorded before settlement.
    refund_op: Option<FedimintOperationId>,
    /// Cached successful resolution makes repeated watches idempotent.
    resolution: Option<Bytes32>,
    refund_state: RefundState,
    /// Serializes refund submission for this operation.
    action_lock: Arc<Mutex<()>>,
}

/// Fedimint network adapter.
///
/// One adapter per federation. The constructor joins the federation
/// (downloading the `ClientConfig` over iroh if the address is a
/// `fed1q…` invite code, or re-opening an existing client DB) and
/// starts the client's executor.
///
/// `data_dir` is the node's shared data directory: the federation
/// client DB lives at `data_dir/fedimint/<slug>` for that
/// federation's network id, mirroring how the other wallets store
/// their databases under the node's data dir.
pub struct FedimintAdapter {
    network_id: NetworkId,
    /// Node data directory the federation DB is rooted under
    /// (db files live at `data_dir/fedimint/<slug>/db`).
    data_dir: PathBuf,
    client: ClientHandleArc,
    /// Static claim keypair, derived from the per-network secret with
    /// even (0x02) compressed parity so the advertised identity —
    /// which only carries the x-only half — round-trips losslessly.
    claim_keypair: secp256k1::Keypair,
    claim_pk: secp256k1::PublicKey,
    incoming: Mutex<HashMap<OperationId, PendingIncoming>>,
    outgoing: Mutex<HashMap<OperationId, OutgoingSlot>>,
}

impl FedimintAdapter {
    /// Construct a new adapter for a federation.
    ///
    /// `address` may be:
    /// * a Fedimint invite code (`fed1q…`) — the federation's
    ///   `ClientConfig` is downloaded over iroh/ws and the client is
    ///   joined for the first time,
    /// * a path or identifier prefixed with `db:` — re-open a client
    ///   already joined into that local RocksDB directory.
    ///
    /// `secret` is the per-network 32-byte secret derived by the
    /// cassis daemon's BIP39 key derivation. It is fed into
    /// [`DerivableSecret::new_root`] and then wrapped in
    /// [`RootSecret::StandardDoubleDerive`], which mixes in the
    /// federation id internally; reusing one mnemonic across
    /// federations is therefore safe.
    pub async fn new(
        network_id: NetworkId,
        address: String,
        secret: [u8; 32],
        data_dir: std::path::PathBuf,
    ) -> Result<Self, String> {
        // Connector stack: defaults enable iroh next (`/v1`) and the
        // `iroh://` scheme. Guardian endpoints in the federation
        // config whose scheme is `iroh://` are dialed over iroh QUIC
        // automatically. The federation config dictates the
        // transport; no per-client iroh object is required.
        let connectors = ConnectorRegistry::build_from_client_defaults()
            .bind()
            .await
            .map_err(|e| format!("failed to bind connector registry: {e}"))?;

        // Derive the root secret. `DerivableSecret::new_root` wants
        // `(root_key, salt)`. We expand the 32-byte per-network
        // secret to 64 bytes by HKDF-style repetition so the root
        // has enough entropy. `RootSecret::StandardDoubleDerive`
        // then hashes in the federation id internally — so reusing
        // one mnemonic across federations is safe.
        let mut seed64 = [0u8; 64];
        seed64[..32].copy_from_slice(&secret);
        seed64[32..].copy_from_slice(&secret);
        let root_secret = DerivableSecret::new_root(&seed64, ROOT_SECRET_SALT);
        let root_secret = RootSecret::StandardDoubleDerive(root_secret);

        // RocksDB path: under the node's shared data dir, keyed by a
        // sanitized fragment of the network id (same convention as the
        // other wallets' per-network subdirectories).
        let db_dir = Self::db_dir_for(&network_id, &data_dir);
        tokio::fs::create_dir_all(&db_dir)
            .await
            .map_err(|e| format!("failed to create db dir {}: {e}", db_dir.display()))?;
        let db_path = db_dir.join("db");
        let db: Database = Database::new(
            fedimint_rocksdb::RocksDb::build(db_path)
                .open()
                .await
                .map_err(|e| format!("failed to open RocksDb at {}: {e}", db_dir.display()))?,
            ModuleRegistry::default(),
        );

        let already_initialized = Client::is_initialized(&db).await;

        let mut builder = Client::builder()
            .await
            .map_err(|e| format!("failed to build client builder: {e}"))?;

        // Mint module is REQUIRED as the primary module — it issues
        // the ecash that funds outgoing contracts (and into which
        // incoming contracts pay us). The LNv2 module is the one we
        // drive.
        builder.with_module(MintClientInit);
        builder.with_module(fedimint_lnv2_client::LightningClientInit::default());
        // Wallet module: only needed for on-chain peg-in/peg-out, but
        // it must be registered before opening ANY client so the module
        // exists in the executor's registry (a federation without a
        // wallet module simply never instantiates it).
        builder.with_module(WalletClientInit(None));

        let client: ClientHandleArc = if already_initialized {
            let handle = builder
                .open(connectors, db, root_secret)
                .await
                .map_err(|e| format!("failed to re-open fedimint client: {e}"))?;
            Arc::new(handle)
        } else {
            // First-time join: address must be an invite code.
            let invite = InviteCode::from_str(&address).map_err(|e| {
                format!("failed to parse '{address}' as a Fedimint invite code: {e}")
            })?;
            // `preview` downloads the federation ClientConfig from
            // one peer via the advertised URL (iroh:// in our case).
            let preview = builder
                .preview(connectors.clone(), &invite)
                .await
                .map_err(|e| format!("failed to download federation config: {e}"))?;
            let handle = preview
                .join(db, root_secret)
                .await
                .map_err(|e| format!("failed to join federation: {e}"))?;
            Arc::new(handle)
        };

        // Start the executor so the LN state machines run.
        client.start_executor();

        // Sanity-check that the LNv2 module is present.
        let _ln_module: &LightningClientModule =
            Self::ln_module(&client).map_err(|e| format!("federation has no LNv2 module: {e}"))?;

        let claim_keypair = Self::derive_claim_keypair(&secret);
        let claim_pk = claim_keypair.public_key();

        Ok(Self {
            network_id,
            data_dir,
            client,
            claim_keypair,
            claim_pk,
            incoming: Mutex::new(HashMap::new()),
            outgoing: Mutex::new(HashMap::new()),
        })
    }

    /// Derive the static claim keypair from the per-network secret.
    /// Hash candidates until the compressed public key has even
    /// (0x02) parity: cassis `PubKey`s are x-only, and counterparties
    /// reconstruct our claim key as `0x02 || x-only`, so the claim
    /// key must be parity-normalized for lock and claim to agree.
    fn derive_claim_keypair(secret: &[u8; 32]) -> secp256k1::Keypair {
        let mut seed = sha256::Hash::hash(&[CLAIM_KEY_DOMAIN, secret].concat());
        loop {
            let Ok(sk) = secp256k1::SecretKey::from_slice(&seed.to_byte_array()) else {
                seed = sha256::Hash::hash(&seed.to_byte_array());
                continue;
            };
            let keypair = sk.keypair(secp256k1::SECP256K1);
            if keypair.public_key().serialize()[0] == 0x02 {
                return keypair;
            }
            seed = sha256::Hash::hash(&seed.to_byte_array());
        }
    }

    fn db_dir_for(network_id: &NetworkId, data_dir: &std::path::Path) -> PathBuf {
        let slug = network_id
            .0
            .strip_prefix("fedimint::")
            .unwrap_or(&network_id.0);
        let safe: String = slug
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '-' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        data_dir.join("fedimint").join(safe)
    }

    /// Wallet balance in msat, bitcoin-denominated (same bucket the
    /// outgoing contracts are funded from).
    pub async fn balance_msat(&self) -> Result<u64, String> {
        let balance = self
            .client
            .get_balance_for_btc()
            .await
            .map_err(|e| format!("balance request failed: {e}"))?;
        Ok(balance.msats)
    }

    /// Local RocksDB directory the federation client is opened from.
    pub fn db_dir(&self) -> PathBuf {
        Self::db_dir_for(&self.network_id, &self.data_dir)
    }

    // ==================================================================
    // Raw ecash (out-of-band notes)
    // ==================================================================

    /// Maximum wait for operation outcome streams (reissue, deposit,
    /// withdraw) before they are abandoned.
    const OP_WAIT_SECS: u64 = 3600;

    /// Remove up to `amount_msat` of ecash from the wallet and return
    /// it as a serialized out-of-band note string (base64). The notes
    /// auto-cancel (return to our wallet) after `try_cancel_after`
    /// seconds unless the recipient reissues them.
    pub async fn send_ecash(
        &self,
        amount_msat: u64,
        try_cancel_after_secs: u64,
    ) -> Result<String, String> {
        let mint = self
            .client
            .get_first_module::<MintClientModule>()
            .map_err(|e| format!("federation has no mint module: {e}"))?
            .module;
        let (_operation_id, oob_notes) = mint
            .spend_notes_with_selector(
                &SelectNotesWithAtleastAmount,
                Amount::from_msats(amount_msat),
                Some(Duration::from_secs(try_cancel_after_secs)),
                true,
                serde_json::Value::Null,
            )
            .await
            .map_err(|e| format!("send: {e}"))?;
        Ok(oob_notes.to_string())
    }

    /// Reissue a raw out-of-band ecash note string into our wallet.
    /// When `wait` is set, follows the reissuance until Done/Failed;
    /// the amount reissued is returned either way.
    pub async fn receive_ecash(&self, note: &str, wait: bool) -> Result<u64, String> {
        let oob_notes = OOBNotes::from_str(note).map_err(|e| format!("invalid ecash note: {e}"))?;
        let amount_msat = oob_notes.notes().total_amount().msats;
        let mint = self
            .client
            .get_first_module::<MintClientModule>()
            .map_err(|e| format!("federation has no mint module: {e}"))?
            .module;
        let operation_id = mint
            .reissue_external_notes(oob_notes, serde_json::Value::Null)
            .await
            .map_err(|e| format!("reissue: {e}"))?;
        if wait {
            let stream = mint
                .subscribe_reissue_external_notes(operation_id)
                .await
                .map_err(|e| format!("subscribe reissue: {e}"))?;
            let deadline_reissue =
                tokio::time::Instant::now() + Duration::from_secs(Self::OP_WAIT_SECS);
            Self::until_terminal(stream, deadline_reissue, "reissue", |state| match state {
                ReissueExternalNotesState::Done => Some(Ok(())),
                ReissueExternalNotesState::Failed(e) => Some(Err(format!("reissue failed: {e}"))),
                _ => None,
            })
            .await?;
        }
        Ok(amount_msat)
    }

    /// Allocate a fresh (tweaked) on-chain deposit address owned by
    /// the federation and return it together with its operation id for
    /// [`Self::await_deposit`]. Note the caveats attached to peg-ins in
    /// fedimint: transactions funding the address must stay under
    /// ~40 kB and honor any federation-wide minimum peg-in amount.
    pub async fn deposit_address(&self) -> Result<(String, FedimintOperationId), String> {
        let wallet = self.wallet_module()?;
        let info = wallet
            .allocate_deposit_address_expert_only(serde_json::Value::Null)
            .await
            .map_err(|e| format!("allocate deposit address: {e}"))?;
        Ok((info.address.to_string(), info.operation_id))
    }

    /// Follow a deposit operation (from [`Self::deposit_address`])
    /// until the peg-in is claimed into our ecash wallet
    /// (`Ok(amount_sat)`) or fails. `timeout_secs` caps the total wait.
    pub async fn await_deposit(
        &self,
        operation_id: FedimintOperationId,
        timeout_secs: u64,
    ) -> Result<u64, String> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
        let wallet = self.wallet_module()?;
        let stream = wallet
            .subscribe_deposit(operation_id)
            .await
            .map_err(|e| format!("subscribe deposit: {e}"))?;
        Self::until_terminal(stream, deadline, "deposit", |state| match state {
            DepositStateV2::Claimed { btc_deposited, .. } => Some(Ok(btc_deposited.to_sat())),
            DepositStateV2::Failed(e) => Some(Err(format!("deposit failed: {e}"))),
            _ => None,
        })
        .await
    }

    /// Peg out: withdraw on-chain. Fetches the federation's peg-out
    /// fees for the destination and amount, submits the withdraw
    /// transaction and waits until either the on-chain transaction id
    /// is known or the operation fails. Returns the on-chain txid.
    pub async fn withdraw(&self, address_str: &str, amount_sat: u64) -> Result<String, String> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(Self::OP_WAIT_SECS);
        let wallet = self.wallet_module()?;
        let address = bitcoin::Address::from_str(address_str)
            .map_err(|e| format!("invalid destination address: {e}"))?
            .require_network(wallet.get_network())
            .map_err(|e| format!("destination address not on the federation's network: {e}"))?;
        let amount = bitcoin::Amount::from_sat(amount_sat);
        let fees = wallet
            .get_withdraw_fees(&address, amount)
            .await
            .map_err(|e| format!("peg-out fee query failed: {e}"))?;
        let operation_id = wallet
            .withdraw(&address, amount, fees, serde_json::Value::Null)
            .await
            .map_err(|e| format!("withdraw: {e}"))?;
        let stream = wallet
            .subscribe_withdraw_updates(operation_id)
            .await
            .map_err(|e| format!("subscribe withdraw: {e}"))?;
        let txid = Self::until_terminal(stream, deadline, "withdraw", |state| match state {
            WithdrawState::Succeeded(txid) => Some(Ok(*txid)),
            WithdrawState::Failed(e) => Some(Err(format!("withdraw failed: {e}"))),
            _ => None,
        })
        .await?;
        Ok(txid.to_string())
    }

    /// Follow an operation update stream until a terminal state (or a
    /// deadline).
    async fn until_terminal<S, T>(
        stream: UpdateStreamOrOutcome<S>,
        deadline: tokio::time::Instant,
        what: &str,
        terminal: impl Fn(&S) -> Option<Result<T, String>>,
    ) -> Result<T, String>
    where
        S: std::fmt::Debug + Send,
        T: Send,
    {
        match stream {
            UpdateStreamOrOutcome::Outcome(state) => terminal(&state)
                .unwrap_or_else(|| Err(format!("{what} already finished in a non-final state"))),
            UpdateStreamOrOutcome::UpdateStream(stream) => {
                use futures::StreamExt;
                let mut filtered =
                    std::pin::pin!(stream.filter_map(|state| std::future::ready(terminal(&state))));
                match tokio::time::timeout_at(deadline, filtered.as_mut().next()).await {
                    Ok(Some(result)) => result,
                    Ok(None) => Err(format!("{what} stream ended without a final state")),
                    Err(_) => Err(format!("timed out waiting for {what}")),
                }
            }
        }
    }

    fn wallet_module(&self) -> Result<&WalletClientModule, String> {
        Ok(self
            .client
            .get_first_module::<WalletClientModule>()
            .map_err(|e| format!("federation has no wallet (peg) module: {e}"))?
            .module)
    }

    fn ln_module(client: &ClientHandleArc) -> anyhow::Result<&LightningClientModule> {
        Ok(client.get_first_module::<LightningClientModule>()?.module)
    }

    /// Convert a deadline (unix seconds) into a `tokio::time::Duration`
    /// suitable as a `tokio::time::timeout` deadline.
    fn deadline_to_timeout(deadline: u64) -> Duration {
        let now = unix_now_secs();
        Duration::from_secs(deadline.saturating_sub(now))
    }

    /// Convert a cassis absolute unix expiry into an LNv2 expiration
    /// delta in consensus blocks. Refuses expiries in the past.
    fn expiration_delta(expiry: u64) -> Result<u64, AdapterError> {
        let now = unix_now_secs();
        if expiry <= now {
            return Err(AdapterError::InvalidParams("expiry in the past".into()));
        }
        Ok(expiry.saturating_sub(now).div_ceil(SECS_PER_BLOCK).max(1))
    }

    fn claim_pk_from_cassis(recipient: XOnlyPubKey) -> Result<secp256k1::PublicKey, AdapterError> {
        let mut compressed = [0u8; 33];
        compressed[0] = 0x02;
        compressed[1..].copy_from_slice(recipient.as_bytes());
        secp256k1::PublicKey::from_slice(&compressed)
            .map_err(|e| AdapterError::InvalidParams(format!("invalid recipient pubkey: {e}")))
    }

    /// Validate a funding descriptor against this adapter: right
    /// network, right shape, payment image matches `payment_hash`, and
    /// the contract is locked to our claim key. Returns the decoded
    /// outpoint + contract.
    fn decode_funding(
        &self,
        descriptor: &HtlcDescriptor,
        payment_hash: Bytes32,
    ) -> Result<(OutPoint, OutgoingContract), AdapterError> {
        let (claim_pubkey, funding_txid, funding_out_idx, contract_json) = match descriptor {
            HtlcDescriptor::Fedimint {
                claim_pubkey,
                funding_txid,
                funding_out_idx,
                contract,
            } => (claim_pubkey, funding_txid, funding_out_idx, contract),
            other => {
                return Err(AdapterError::InvalidParams(format!(
                    "unsupported htlc descriptor for fedimint network: {other:?}"
                )))
            }
        };
        let txid_hex = funding_txid.as_deref().ok_or_else(|| {
            AdapterError::InvalidParams("fedimint descriptor has no funding txid".into())
        })?;
        let out_idx = funding_out_idx.ok_or_else(|| {
            AdapterError::InvalidParams("fedimint descriptor has no funding out idx".into())
        })?;
        let contract_json = contract_json.as_deref().ok_or_else(|| {
            AdapterError::InvalidParams("fedimint descriptor has no contract".into())
        })?;

        let claim_pk = secp256k1::PublicKey::from_slice(claim_pubkey.as_bytes())
            .map_err(|e| AdapterError::InvalidParams(format!("descriptor claim pubkey: {e}")))?;
        if claim_pk != self.claim_pk {
            return Err(AdapterError::InvalidParams(
                "descriptor claim pubkey is not ours".into(),
            ));
        }

        let txid = TransactionId::from_str(txid_hex)
            .map_err(|e| AdapterError::InvalidParams(format!("descriptor txid: {e}")))?;
        let contract: OutgoingContract = serde_json::from_str(contract_json)
            .map_err(|e| AdapterError::InvalidParams(format!("descriptor contract: {e}")))?;

        if contract.payment_image
            != PaymentImage::Hash(sha256::Hash::from_byte_array(payment_hash.0))
        {
            return Err(AdapterError::InvalidParams(
                "contract payment image does not match the route payment hash".into(),
            ));
        }
        if contract.claim_pk != self.claim_pk {
            return Err(AdapterError::InvalidParams(
                "contract is not locked to our claim key".into(),
            ));
        }

        Ok((OutPoint { txid, out_idx }, contract))
    }

    fn xonly_claim_pubkey(&self) -> XOnlyPubKey {
        let compressed = self.claim_pk.serialize();
        let mut xonly = [0u8; 32];
        xonly.copy_from_slice(&compressed[1..]);
        XOnlyPubKey(xonly)
    }

    fn incoming_reservation(
        &self,
        request: &IncomingRequest,
    ) -> Result<IncomingReservation, AdapterError> {
        if !request.operation_id.is_valid() {
            return Err(AdapterError::InvalidParams(
                "incoming operation id is invalid".into(),
            ));
        }
        if request.amount_msat == 0 {
            return Err(AdapterError::InvalidParams(
                "incoming amount must be > 0".into(),
            ));
        }
        if request.deadline <= unix_now_secs() {
            return Err(AdapterError::InvalidParams(
                "incoming deadline is in the past".into(),
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

        Ok(IncomingReservation {
            operation_id: request.operation_id.clone(),
            payment_hash: request.payment_hash,
            network: self.network_id.clone(),
            amount_msat: request.amount_msat,
            deadline: request.deadline,
            target: HtlcTarget::XOnlyPubKey(self.xonly_claim_pubkey()),
        })
    }

    fn validate_incoming_reservation(
        &self,
        reservation: &IncomingReservation,
    ) -> Result<(), AdapterError> {
        if !reservation.operation_id.is_valid() {
            return Err(AdapterError::InvalidParams(
                "incoming operation id is invalid".into(),
            ));
        }
        if reservation.amount_msat == 0 {
            return Err(AdapterError::InvalidParams(
                "incoming amount must be > 0".into(),
            ));
        }
        if reservation.network != self.network_id {
            return Err(AdapterError::InvalidParams(
                "incoming reservation targets another network".into(),
            ));
        }
        if reservation.target != HtlcTarget::XOnlyPubKey(self.xonly_claim_pubkey()) {
            return Err(AdapterError::InvalidParams(
                "incoming reservation has wrong claim target".into(),
            ));
        }
        Ok(())
    }

    fn validate_outgoing_request(
        &self,
        request: &OutgoingRequest,
    ) -> Result<XOnlyPubKey, AdapterError> {
        if !request.operation_id.is_valid() {
            return Err(AdapterError::InvalidParams(
                "outgoing operation id is invalid".into(),
            ));
        }
        if request.amount_msat == 0 {
            return Err(AdapterError::InvalidParams("amount must be > 0".into()));
        }
        if request.network != self.network_id {
            return Err(AdapterError::InvalidParams(
                "outgoing request targets another network".into(),
            ));
        }
        let HtlcTarget::XOnlyPubKey(recipient) = &request.target else {
            return Err(AdapterError::InvalidParams(
                "fedimint requires an x-only pubkey target".into(),
            ));
        };
        Self::claim_pk_from_cassis(*recipient)?;
        Self::expiration_delta(request.expiry)?;
        Ok(*recipient)
    }

    fn outgoing_request_matches(payment: &OutgoingPayment, request: &OutgoingRequest) -> bool {
        payment.operation_id == request.operation_id
            && payment.payment_hash == request.payment_hash
            && payment.amount_msat == request.amount_msat
            && payment.destination == request.target
            && payment.destination_network == request.network
            && payment.expiry == request.expiry
    }

    fn outgoing_payments_match(left: &OutgoingPayment, right: &OutgoingPayment) -> bool {
        left.operation_id == right.operation_id
            && left.payment_hash == right.payment_hash
            && left.amount_msat == right.amount_msat
            && left.destination == right.destination
            && left.destination_network == right.destination_network
            && left.expiry == right.expiry
            && left.descriptor == right.descriptor
    }

    fn accepted_incoming_matches(left: &AcceptedIncoming, right: &AcceptedIncoming) -> bool {
        left.reservation == right.reservation
            && left.descriptor == right.descriptor
            && left.amount_msat == right.amount_msat
    }

    /// Decode and validate sender-owned funding descriptor. Unlike incoming
    /// decode, claim key belongs to recipient and therefore cannot be compared
    /// with this adapter's key.
    fn decode_outgoing_funding(
        &self,
        payment: &OutgoingPayment,
    ) -> Result<(OutPoint, OutgoingContract), AdapterError> {
        if !payment.operation_id.is_valid() {
            return Err(AdapterError::InvalidParams(
                "outgoing operation id is invalid".into(),
            ));
        }
        if payment.amount_msat == 0 {
            return Err(AdapterError::InvalidParams(
                "outgoing amount must be > 0".into(),
            ));
        }
        if payment.destination_network != self.network_id {
            return Err(AdapterError::InvalidParams(
                "outgoing payment targets another network".into(),
            ));
        }
        let HtlcTarget::XOnlyPubKey(recipient) = &payment.destination else {
            return Err(AdapterError::InvalidParams(
                "fedimint requires an x-only destination".into(),
            ));
        };

        let HtlcDescriptor::Fedimint {
            claim_pubkey,
            funding_txid,
            funding_out_idx,
            contract: contract_json,
        } = &payment.descriptor
        else {
            return Err(AdapterError::InvalidParams(
                "not a fedimint descriptor".into(),
            ));
        };
        let descriptor_claim_pk = secp256k1::PublicKey::from_slice(claim_pubkey.as_bytes())
            .map_err(|e| AdapterError::InvalidParams(format!("descriptor claim pubkey: {e}")))?;
        let expected_claim_pk = Self::claim_pk_from_cassis(*recipient)?;
        if descriptor_claim_pk != expected_claim_pk {
            return Err(AdapterError::InvalidParams(
                "descriptor claim pubkey does not match outgoing destination".into(),
            ));
        }
        let txid = TransactionId::from_str(funding_txid.as_deref().ok_or_else(|| {
            AdapterError::InvalidParams("fedimint descriptor has no funding txid".into())
        })?)
        .map_err(|e| AdapterError::InvalidParams(format!("descriptor txid: {e}")))?;
        let out_idx = funding_out_idx.ok_or_else(|| {
            AdapterError::InvalidParams("fedimint descriptor has no funding out idx".into())
        })?;
        let contract: OutgoingContract =
            serde_json::from_str(contract_json.as_deref().ok_or_else(|| {
                AdapterError::InvalidParams("fedimint descriptor has no contract".into())
            })?)
            .map_err(|e| AdapterError::InvalidParams(format!("descriptor contract: {e}")))?;

        if contract.claim_pk != descriptor_claim_pk
            || contract.payment_image
                != PaymentImage::Hash(sha256::Hash::from_byte_array(payment.payment_hash.0))
            || contract.amount.msats != payment.amount_msat
        {
            return Err(AdapterError::InvalidParams(
                "fedimint descriptor does not match outgoing payment".into(),
            ));
        }

        Ok((OutPoint { txid, out_idx }, contract))
    }

    fn funding_descriptor(
        outpoint: OutPoint,
        contract: &OutgoingContract,
    ) -> Result<HtlcDescriptor, AdapterError> {
        Ok(HtlcDescriptor::Fedimint {
            claim_pubkey: PubKey::from_bytes(contract.claim_pk.serialize()).map_err(|e| {
                AdapterError::InvalidParams(format!("descriptor claim pubkey: {e}"))
            })?,
            funding_txid: Some(outpoint.txid.to_string()),
            funding_out_idx: Some(outpoint.out_idx),
            contract: Some(
                serde_json::to_string(contract).map_err(|e| {
                    AdapterError::Network(format!("serialize outgoing contract: {e}"))
                })?,
            ),
        })
    }

    fn claim_operation(outpoint: OutPoint) -> FedimintOperationId {
        FedimintOperationId::from_encodable(&("lnv2-htlc-claim", outpoint))
    }

    fn refund_operation(outpoint: OutPoint) -> FedimintOperationId {
        FedimintOperationId::from_encodable(&("lnv2-htlc-refund", outpoint))
    }
}

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn ln_err(e: LnHtlcError) -> AdapterError {
    AdapterError::Network(e.to_string())
}

#[async_trait]
impl NetworkAdapter for FedimintAdapter {
    fn network_id(&self) -> NetworkId {
        self.network_id.clone()
    }

    fn claim_pubkey(&self) -> XOnlyPubKey {
        self.xonly_claim_pubkey()
    }

    fn incoming_delta_secs(&self) -> u64 {
        INCOMING_DELTA_SECS
    }

    /// Reserve operation before upstream funding starts. Same operation and
    /// request returns original reservation; same hash under another operation
    /// is rejected.
    async fn reserve_incoming(
        &self,
        request: IncomingRequest,
    ) -> Result<IncomingReservation, AdapterError> {
        let reservation = self.incoming_reservation(&request)?;
        let mut incoming = self.incoming.lock().await;

        if let Some(existing) = incoming.get(&request.operation_id) {
            if existing.payment_hash != request.payment_hash || existing.reservation != reservation
            {
                return Err(AdapterError::InvalidParams(
                    "incoming operation id was reused with different request".into(),
                ));
            }
            return Ok(existing.reservation.clone());
        }
        if incoming
            .values()
            .any(|slot| slot.payment_hash == request.payment_hash)
        {
            return Err(AdapterError::Retryable(
                "Fedimint payment hash already belongs to another incoming operation".into(),
            ));
        }

        debug!(
            operation_id = %request.operation_id,
            payment_hash = ?request.payment_hash,
            amount_msat = request.amount_msat,
            "fedimint incoming operation reserved"
        );
        incoming.insert(
            request.operation_id,
            PendingIncoming {
                payment_hash: request.payment_hash,
                reservation: reservation.clone(),
                accepted: None,
                funded: None,
                claim_op: None,
                claim_preimage: None,
                claimed: false,
                action_lock: Arc::new(Mutex::new(())),
            },
        );
        Ok(reservation)
    }

    /// Cancel unfunded reservation. Missing operation is successful retry and
    /// never cancels another operation owning same payment hash.
    async fn cancel_incoming(&self, reservation: &IncomingReservation) -> Result<(), AdapterError> {
        self.validate_incoming_reservation(reservation)?;
        let mut incoming = self.incoming.lock().await;
        let Some(slot) = incoming.get(&reservation.operation_id) else {
            return Ok(());
        };
        if &slot.reservation != reservation {
            return Err(AdapterError::InvalidParams(
                "incoming reservation does not match operation state".into(),
            ));
        }
        if slot.accepted.is_some()
            || slot.funded.is_some()
            || slot.claim_op.is_some()
            || slot.claimed
        {
            return Err(AdapterError::InvalidParams(
                "cannot cancel accepted or claimed incoming operation".into(),
            ));
        }
        incoming.remove(&reservation.operation_id);
        Ok(())
    }

    /// Verify and atomically bind funded contract to reservation.
    async fn accept_incoming(
        &self,
        reservation: &IncomingReservation,
        descriptor: &HtlcDescriptor,
    ) -> Result<AcceptedIncoming, AdapterError> {
        self.validate_incoming_reservation(reservation)?;
        let (outpoint, contract) = self.decode_funding(descriptor, reservation.payment_hash)?;
        let amount_msat = contract.amount.msats;
        if amount_msat < reservation.amount_msat {
            return Err(AdapterError::InvalidParams(format!(
                "incoming contract amount {amount_msat} msat below reserved floor {} msat",
                reservation.amount_msat
            )));
        }
        let accepted = AcceptedIncoming {
            reservation: reservation.clone(),
            descriptor: descriptor.clone(),
            amount_msat,
        };

        let mut incoming = self.incoming.lock().await;
        {
            let slot = incoming.get(&reservation.operation_id).ok_or_else(|| {
                AdapterError::NotFound(format!(
                    "no incoming reservation for operation {}",
                    reservation.operation_id
                ))
            })?;
            if &slot.reservation != reservation {
                return Err(AdapterError::InvalidParams(
                    "incoming reservation does not match operation state".into(),
                ));
            }
            if let Some(existing) = &slot.accepted {
                if Self::accepted_incoming_matches(existing, &accepted) {
                    return Ok(existing.clone());
                }
                return Err(AdapterError::InvalidParams(
                    "incoming operation already accepted different funding".into(),
                ));
            }
        }
        if incoming.iter().any(|(operation_id, candidate)| {
            operation_id != &reservation.operation_id
                && candidate.payment_hash == reservation.payment_hash
        }) {
            return Err(AdapterError::Retryable(
                "Fedimint payment hash already belongs to another incoming operation".into(),
            ));
        }

        let slot = incoming
            .get_mut(&reservation.operation_id)
            .expect("incoming operation checked above");
        slot.funded = Some(FundedContract { outpoint, contract });
        slot.accepted = Some(accepted.clone());
        debug!(
            operation_id = %reservation.operation_id,
            payment_hash = ?reservation.payment_hash,
            amount_msat, "fedimint incoming contract accepted"
        );
        Ok(accepted)
    }

    /// Restore accepted operation after process restart. Native claim state is
    /// reconstructed lazily; duplicate restores and same-operation retries are
    /// idempotent.
    async fn restore_incoming(&self, accepted: &AcceptedIncoming) -> Result<(), AdapterError> {
        self.validate_incoming_reservation(&accepted.reservation)?;
        let (outpoint, contract) =
            self.decode_funding(&accepted.descriptor, accepted.reservation.payment_hash)?;
        let amount_msat = contract.amount.msats;
        if amount_msat < accepted.reservation.amount_msat || accepted.amount_msat != amount_msat {
            return Err(AdapterError::InvalidParams(
                "restored incoming amount does not match contract or reservation".into(),
            ));
        }

        let mut incoming = self.incoming.lock().await;
        if let Some(slot) = incoming.get(&accepted.reservation.operation_id) {
            if slot.payment_hash != accepted.reservation.payment_hash
                || slot.reservation != accepted.reservation
            {
                return Err(AdapterError::InvalidParams(
                    "incoming operation id restored with different reservation".into(),
                ));
            }
            if let Some(existing) = &slot.accepted {
                if Self::accepted_incoming_matches(existing, accepted) {
                    return Ok(());
                }
                return Err(AdapterError::InvalidParams(
                    "incoming operation already restored with different funding".into(),
                ));
            }
        }
        if incoming.iter().any(|(operation_id, candidate)| {
            operation_id != &accepted.reservation.operation_id
                && candidate.payment_hash == accepted.reservation.payment_hash
        }) {
            return Err(AdapterError::Retryable(
                "Fedimint payment hash already belongs to another incoming operation".into(),
            ));
        }

        if let Some(slot) = incoming.get_mut(&accepted.reservation.operation_id) {
            slot.accepted = Some(accepted.clone());
            slot.funded = Some(FundedContract { outpoint, contract });
        } else {
            incoming.insert(
                accepted.reservation.operation_id.clone(),
                PendingIncoming {
                    payment_hash: accepted.reservation.payment_hash,
                    reservation: accepted.reservation.clone(),
                    accepted: Some(accepted.clone()),
                    funded: Some(FundedContract { outpoint, contract }),
                    claim_op: None,
                    claim_preimage: None,
                    claimed: false,
                    action_lock: Arc::new(Mutex::new(())),
                },
            );
        }
        Ok(())
    }

    /// Wait for accepted descriptor's contract to appear on federation. Before
    /// acceptance, poll local operation state until deadline.
    async fn watch_incoming(
        &self,
        reservation: &IncomingReservation,
        deadline: u64,
    ) -> Result<(), AdapterError> {
        self.validate_incoming_reservation(reservation)?;
        let deadline = deadline.min(reservation.deadline);
        let ln = Self::ln_module(&self.client)
            .map_err(|e| AdapterError::Network(format!("LNv2 module not available: {e}")))?;

        loop {
            let (funded, claimed) = {
                let incoming = self.incoming.lock().await;
                let slot = incoming.get(&reservation.operation_id).ok_or_else(|| {
                    AdapterError::NotFound(format!(
                        "no incoming reservation for operation {}",
                        reservation.operation_id
                    ))
                })?;
                if &slot.reservation != reservation {
                    return Err(AdapterError::InvalidParams(
                        "incoming reservation does not match operation state".into(),
                    ));
                }
                (slot.funded.clone(), slot.claimed)
            };
            if claimed {
                return Ok(());
            }
            if let Some(funded) = funded {
                let wait = deadline.saturating_sub(unix_now_secs());
                if wait == 0 {
                    return Err(AdapterError::DeadlineExceeded);
                }
                return tokio::time::timeout(
                    Duration::from_secs(wait),
                    ln.await_htlc_funded(funded.outpoint, &funded.contract),
                )
                .await
                .map_err(|_| AdapterError::DeadlineExceeded)?
                .map(|_| ())
                .map_err(ln_err);
            }
            if unix_now_secs() >= deadline {
                return Err(AdapterError::DeadlineExceeded);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Fund direct HTLC and return complete operation recovery state. Map
    /// mutex remains held through native submission so concurrent retries
    /// cannot fund same operation twice.
    async fn claim_reserved_incoming(
        &self,
        reservation: &IncomingReservation,
        preimage: Bytes32,
    ) -> Result<(), AdapterError> {
        let accepted = {
            let incoming = self.incoming.lock().await;
            let slot = incoming.get(&reservation.operation_id).ok_or_else(|| {
                AdapterError::NotFound(format!(
                    "no incoming Fedimint reservation for operation {}",
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
        let claim_pk = Self::claim_pk_from_cassis(recipient)?;
        let expiration_delta = Self::expiration_delta(request.expiry)?;
        let ln = Self::ln_module(&self.client)
            .map_err(|e| AdapterError::Network(format!("LNv2 module not available: {e}")))?;
        let mut outgoing = self.outgoing.lock().await;

        if let Some(existing) = outgoing.get(&request.operation_id) {
            if Self::outgoing_request_matches(&existing.payment, &request) {
                return Ok(existing.payment.clone());
            }
            return Err(AdapterError::InvalidParams(
                "outgoing operation id was reused with different request".into(),
            ));
        }
        if outgoing
            .values()
            .any(|slot| slot.payment_hash == request.payment_hash)
        {
            return Err(AdapterError::Retryable(
                "Fedimint payment hash already belongs to another outgoing operation".into(),
            ));
        }

        let (funding_op, outpoint, contract) = ln
            .create_htlc(
                Amount::from_msats(request.amount_msat),
                PaymentImage::Hash(sha256::Hash::from_byte_array(request.payment_hash.0)),
                claim_pk,
                expiration_delta,
                serde_json::Value::Null,
            )
            .await
            .map_err(ln_err)?;
        let descriptor = Self::funding_descriptor(outpoint, &contract)?;
        let payment = OutgoingPayment {
            operation_id: request.operation_id.clone(),
            payment_hash: request.payment_hash,
            amount_msat: request.amount_msat,
            destination: request.target,
            destination_network: request.network,
            expiry: request.expiry,
            descriptor,
        };
        info!(
            operation_id = %request.operation_id,
            payment_hash = ?request.payment_hash,
            amount_msat = request.amount_msat,
            expiration = contract.expiration,
            "fedimint outgoing HTLC funded"
        );
        outgoing.insert(
            request.operation_id,
            OutgoingSlot {
                payment: payment.clone(),
                payment_hash: request.payment_hash,
                funding_op,
                outpoint,
                contract,
                refund_op: None,
                resolution: None,
                refund_state: RefundState::Active,
                action_lock: Arc::new(Mutex::new(())),
            },
        );
        Ok(payment)
    }

    /// Restore watcher/refund state from payment's embedded descriptor.
    async fn restore_outgoing(&self, payment: &OutgoingPayment) -> Result<(), AdapterError> {
        let (outpoint, contract) = self.decode_outgoing_funding(payment)?;
        let funding_op =
            FedimintOperationId::from_encodable(&("lnv2-htlc-create", contract.clone()));
        let mut outgoing = self.outgoing.lock().await;

        if let Some(existing) = outgoing.get(&payment.operation_id) {
            if Self::outgoing_payments_match(&existing.payment, payment)
                && existing.outpoint == outpoint
                && existing.contract == contract
            {
                return Ok(());
            }
            return Err(AdapterError::InvalidParams(
                "outgoing operation already restored with different payment".into(),
            ));
        }
        if outgoing
            .values()
            .any(|slot| slot.payment_hash == payment.payment_hash)
        {
            return Err(AdapterError::Retryable(
                "Fedimint payment hash already belongs to another outgoing operation".into(),
            ));
        }

        outgoing.insert(
            payment.operation_id.clone(),
            OutgoingSlot {
                payment: payment.clone(),
                payment_hash: payment.payment_hash,
                funding_op,
                outpoint,
                contract,
                refund_op: None,
                resolution: None,
                refund_state: RefundState::Active,
                action_lock: Arc::new(Mutex::new(())),
            },
        );
        Ok(())
    }

    /// Claim accepted incoming operation. Per-operation action lock and native
    /// operation marker make concurrent/repeated calls settle one submission.
    async fn claim_incoming(
        &self,
        accepted: &AcceptedIncoming,
        preimage: Bytes32,
    ) -> Result<(), AdapterError> {
        if !accepted
            .reservation
            .payment_hash
            .matches_preimage(&preimage)
        {
            return Err(AdapterError::InvalidParams(
                "preimage does not match incoming payment hash".into(),
            ));
        }
        let operation_key = accepted.reservation.operation_id.clone();
        let action_lock = {
            let incoming = self.incoming.lock().await;
            let slot = incoming.get(&operation_key).ok_or_else(|| {
                AdapterError::NotFound(format!("no accepted incoming operation {operation_key}"))
            })?;
            let stored = slot.accepted.as_ref().ok_or_else(|| {
                AdapterError::NotFound(format!("incoming operation {operation_key} not accepted"))
            })?;
            if !Self::accepted_incoming_matches(stored, accepted) {
                return Err(AdapterError::InvalidParams(
                    "accepted incoming state does not match operation".into(),
                ));
            }
            if slot.claimed {
                return Ok(());
            }
            if slot
                .claim_preimage
                .is_some_and(|recorded| recorded != preimage)
            {
                return Err(AdapterError::InvalidParams(
                    "incoming operation was already submitted with different preimage".into(),
                ));
            }
            slot.action_lock.clone()
        };
        let _action_guard = action_lock.lock().await;

        let (funded, mut claim_op) = {
            let incoming = self.incoming.lock().await;
            let slot = incoming.get(&operation_key).ok_or_else(|| {
                AdapterError::NotFound(format!("no accepted incoming operation {operation_key}"))
            })?;
            let stored = slot.accepted.as_ref().ok_or_else(|| {
                AdapterError::NotFound(format!("incoming operation {operation_key} not accepted"))
            })?;
            if !Self::accepted_incoming_matches(stored, accepted) {
                return Err(AdapterError::InvalidParams(
                    "accepted incoming state does not match operation".into(),
                ));
            }
            if slot.claimed {
                return Ok(());
            }
            if slot
                .claim_preimage
                .is_some_and(|recorded| recorded != preimage)
            {
                return Err(AdapterError::InvalidParams(
                    "incoming operation was already submitted with different preimage".into(),
                ));
            }
            let funded = slot.funded.clone().ok_or_else(|| {
                AdapterError::NotFound(format!(
                    "incoming operation {operation_key} has no funded contract"
                ))
            })?;
            (funded, slot.claim_op)
        };

        let FundedContract { outpoint, contract } = funded;
        let ln = Self::ln_module(&self.client)
            .map_err(|e| AdapterError::Network(format!("LNv2 module not available: {e}")))?;
        if claim_op.is_none() {
            let now = unix_now_secs();
            let funding_wait = if accepted.reservation.deadline > now {
                FUNDING_GRACE.min(Duration::from_secs(accepted.reservation.deadline - now))
            } else {
                FUNDING_GRACE
            };
            let remaining =
                tokio::time::timeout(funding_wait, ln.await_htlc_funded(outpoint, &contract))
                    .await
                    .map_err(|_| {
                        AdapterError::Network(format!(
                            "incoming operation {operation_key} not funded after {}s",
                            funding_wait.as_secs()
                        ))
                    })?
                    .map_err(ln_err)?;
            debug!(
                operation_id = %operation_key,
                payment_hash = ?accepted.reservation.payment_hash,
                remaining_blocks = remaining,
                "fedimint incoming HTLC confirmed funded; claiming"
            );
        }

        if claim_op.is_none() {
            let ln = Self::ln_module(&self.client)
                .map_err(|e| AdapterError::Network(format!("LNv2 module not available: {e}")))?;
            claim_op = Some(
                match ln
                    .claim_htlc(
                        outpoint,
                        contract,
                        self.claim_keypair,
                        preimage.0,
                        serde_json::Value::Null,
                    )
                    .await
                {
                    Ok(operation_id) => operation_id,
                    Err(LnHtlcError::DuplicateOperation(operation_id)) => operation_id,
                    Err(error @ LnHtlcError::ContractNotFound) => {
                        // Process may have restarted after native submission but
                        // before local marker reached journal. Native claim id is
                        // deterministic, so recover terminal success from it.
                        let expected = Self::claim_operation(outpoint);
                        if ln.await_htlc_operation_settled(expected).await.is_ok() {
                            if let Some(slot) = self.incoming.lock().await.get_mut(&operation_key) {
                                slot.claim_op = Some(expected);
                                slot.claim_preimage = Some(preimage);
                                slot.claimed = true;
                            }
                            return Ok(());
                        }
                        return Err(ln_err(error));
                    }
                    Err(error) => return Err(ln_err(error)),
                },
            );

            // Record before settlement wait. Retry after interrupted wait
            // resumes this native operation instead of submitting again.
            if let Some(slot) = self.incoming.lock().await.get_mut(&operation_key) {
                slot.claim_op = claim_op;
                slot.claim_preimage = Some(preimage);
            }
        }

        let ln = Self::ln_module(&self.client)
            .map_err(|e| AdapterError::Network(format!("LNv2 module not available: {e}")))?;
        ln.await_htlc_operation_settled(claim_op.expect("claim operation recorded"))
            .await
            .map_err(ln_err)?;
        if let Some(slot) = self.incoming.lock().await.get_mut(&operation_key) {
            slot.claimed = true;
        }
        info!(
            operation_id = %operation_key,
            payment_hash = ?accepted.reservation.payment_hash,
            "fedimint incoming HTLC claimed"
        );
        Ok(())
    }

    /// Refund operation after expiry. Per-operation lock prevents duplicate
    /// submissions; native refund id is retained across interrupted waits.
    async fn refund_outgoing(&self, payment: &OutgoingPayment) -> Result<(), AdapterError> {
        let action_lock = {
            let outgoing = self.outgoing.lock().await;
            let slot = outgoing.get(&payment.operation_id).ok_or_else(|| {
                AdapterError::NotFound(format!("no outgoing operation {}", payment.operation_id))
            })?;
            if !Self::outgoing_payments_match(&slot.payment, payment) {
                return Err(AdapterError::InvalidParams(
                    "outgoing payment does not match operation state".into(),
                ));
            }
            if slot.refund_state != RefundState::Active {
                return Ok(());
            }
            if slot.resolution.is_some() {
                return Ok(());
            }
            slot.action_lock.clone()
        };
        let _action_guard = action_lock.lock().await;

        let (outpoint, contract, stored_refund_op) = {
            let outgoing = self.outgoing.lock().await;
            let slot = outgoing.get(&payment.operation_id).ok_or_else(|| {
                AdapterError::NotFound(format!("no outgoing operation {}", payment.operation_id))
            })?;
            if !Self::outgoing_payments_match(&slot.payment, payment) {
                return Err(AdapterError::InvalidParams(
                    "outgoing payment does not match operation state".into(),
                ));
            }
            if slot.refund_state != RefundState::Active || slot.resolution.is_some() {
                return Ok(());
            }
            (slot.outpoint, slot.contract.clone(), slot.refund_op)
        };

        let ln = Self::ln_module(&self.client)
            .map_err(|e| AdapterError::Network(format!("LNv2 module not available: {e}")))?;
        let operation_id = if let Some(operation_id) = stored_refund_op {
            operation_id
        } else {
            let started = tokio::time::Instant::now();
            loop {
                match ln
                    .refund_htlc(outpoint, contract.clone(), serde_json::Value::Null)
                    .await
                {
                    Ok(operation_id) => break operation_id,
                    Err(LnHtlcError::DuplicateOperation(operation_id)) => break operation_id,
                    Err(LnHtlcError::NotExpired(missing)) => {
                        if started.elapsed() >= REFUND_RETRY {
                            return Err(AdapterError::Retryable(format!(
                                "contract still not expired on consensus \
                                 ({missing} blocks to go); retry later"
                            )));
                        }
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                    Err(LnHtlcError::ContractNotFound) => {
                        // Native refund id is deterministic. If process restarted
                        // after submission, recover terminal refund from Fedimint
                        // operation log; otherwise contract was claimed/spent.
                        let expected = Self::refund_operation(outpoint);
                        let refunded = ln.await_htlc_operation_settled(expected).await.is_ok();
                        warn!(
                            operation_id = %payment.operation_id,
                            payment_hash = ?payment.payment_hash,
                            refunded,
                            "fedimint outgoing contract gone; refund terminal"
                        );
                        if let Some(slot) =
                            self.outgoing.lock().await.get_mut(&payment.operation_id)
                        {
                            slot.refund_op = refunded.then_some(expected);
                            slot.refund_state = if refunded {
                                RefundState::Refunded
                            } else {
                                RefundState::ContractGone
                            };
                        }
                        return Ok(());
                    }
                    Err(error) => return Err(ln_err(error)),
                }
            }
        };

        if let Some(slot) = self.outgoing.lock().await.get_mut(&payment.operation_id) {
            slot.refund_op = Some(operation_id);
        }
        ln.await_htlc_operation_settled(operation_id)
            .await
            .map_err(ln_err)?;
        if let Some(slot) = self.outgoing.lock().await.get_mut(&payment.operation_id) {
            slot.refund_state = RefundState::Refunded;
        }
        info!(
            operation_id = %payment.operation_id,
            payment_hash = ?payment.payment_hash,
            "fedimint outgoing HTLC refunded"
        );
        Ok(())
    }

    /// Wait for recipient claim and return preimage. Successful result is
    /// cached in operation state so repeated watches never depend on polling
    /// federation state again.
    async fn watch_outgoing(
        &self,
        payment: &OutgoingPayment,
        deadline: u64,
    ) -> Result<Bytes32, AdapterError> {
        let (outpoint, contract, cached) = {
            let outgoing = self.outgoing.lock().await;
            let slot = outgoing.get(&payment.operation_id).ok_or_else(|| {
                AdapterError::NotFound(format!("no outgoing operation {}", payment.operation_id))
            })?;
            if !Self::outgoing_payments_match(&slot.payment, payment) {
                return Err(AdapterError::InvalidParams(
                    "outgoing payment does not match operation state".into(),
                ));
            }
            if slot.refund_state == RefundState::Refunded {
                return Err(AdapterError::DeadlineExceeded);
            }
            (slot.outpoint, slot.contract.clone(), slot.resolution)
        };
        if let Some(preimage) = cached {
            return Ok(preimage);
        }

        let ln = Self::ln_module(&self.client)
            .map_err(|e| AdapterError::Network(format!("LNv2 module not available: {e}")))?;
        let resolution = tokio::time::timeout(
            Self::deadline_to_timeout(deadline),
            ln.await_htlc_resolution(outpoint, &contract),
        )
        .await
        .map_err(|_| AdapterError::DeadlineExceeded)?
        .map_err(ln_err)?;

        match resolution {
            Some(preimage) => {
                let preimage = Bytes32(preimage);
                if !payment.payment_hash.matches_preimage(&preimage) {
                    return Err(AdapterError::Network(
                        "federation returned preimage for different payment hash".into(),
                    ));
                }
                if let Some(slot) = self.outgoing.lock().await.get_mut(&payment.operation_id) {
                    slot.resolution = Some(preimage);
                }
                info!(
                    operation_id = %payment.operation_id,
                    payment_hash = ?payment.payment_hash,
                    "fedimint outgoing HTLC claimed; preimage revealed"
                );
                Ok(preimage)
            }
            None => {
                warn!(
                    operation_id = %payment.operation_id,
                    payment_hash = ?payment.payment_hash,
                    "fedimint outgoing HTLC expired unclaimed"
                );
                Err(AdapterError::DeadlineExceeded)
            }
        }
    }

    /// PREPARE-time check: does the client hold enough ecash to fund
    /// an outgoing HTLC of `amount_msat`? Outgoing contracts are paid
    /// from the wallet's bitcoin-denominated balance.
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
                "restored Fedimint reservation differs from persisted state".into(),
            ))
        }
    }

    async fn can_route(&self, amount_msat: u64) -> Result<(), AdapterError> {
        if amount_msat == 0 {
            return Err(AdapterError::InvalidParams("amount must be > 0".into()));
        }
        let balance = self
            .client
            .get_balance_for_btc()
            .await
            .map_err(|e| AdapterError::Network(format!("balance request failed: {e}")))?;
        let needed = Amount::from_msats(amount_msat);
        if balance < needed {
            return Err(AdapterError::InvalidParams(format!(
                "insufficient fedimint balance: need {} msat, have {} msat",
                amount_msat, balance.msats
            )));
        }
        Ok(())
    }

    /// Claiming direct HTLC releases funds to this client, so it needs no
    /// upfront balance or gas reserve.
    async fn can_claim(&self, _amount_msat: u64) -> Result<(), AdapterError> {
        Ok(())
    }
}
