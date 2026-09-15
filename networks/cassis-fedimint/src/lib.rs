//! Fedimint network adapter (LNv2 direct HTLC).
//!
//! A cassis node acts as a Fedimint client of one federation, with the
//! federation's guardians reached over iroh via `fedimint-connectors`
//! (guardian endpoint URLs of the form `iroh://<node-id>` in the
//! federation's `ClientConfig`).
//!
//! The adapter implements [`cassis_core::NetworkRouterAdapter`] on top
//! of LNv2's *direct HTLC* API (fedimint PR #8913): a raw
//! `OutgoingContract` funded between two federation clients, with no
//! gateway involved. This is what lets fedimint honor an
//! externally-supplied `payment_hash` — the property LNv2's invoice
//! flow ("sells its own preimage" via TPE) lacked — and makes
//! fedimint a first-class cassis network.
//!
//! Method mapping (cassis method → LNv2 direct-HTLC operation):
//!
//! | cassis method                 | LNv2 operation                                        |
//! |-------------------------------+-------------------------------------------------------|
//! | `register_incoming_htlc`      | Park the hash; return a descriptor carrying our claim |
//! |                               | public key. The funder locks the contract to it.      |
//! | `accept_incoming_htlc`        | Decode the funding descriptor (outpoint + contract),  |
//! |                               | verify the payment image and claim key, store it.     |
//! | `claim_incoming`              | `LightningClientModule::claim_htlc` with the route    |
//! |                               | preimage + our claim keypair, then await settlement.  |
//! | `create_outgoing_htlc`        | `create_htlc` — fund a contract locked to the         |
//! |                               | recipient's claim key with `PaymentImage::Hash`.      |
//! | `outgoing_htlc_descriptor`    | Serialize (outpoint, contract) for the next hop.      |
//! | `watch_preimage`              | `await_htlc_resolution` — the federation returns the  |
//! |                               | preimage once the recipient claims.                   |
//! | `refund_outgoing`             | `refund_htlc` after expiration (+ settle).            |
//! | `can_route`                   | Client ecash balance check.                           |
//!
//! Identity: the adapter derives one even-parity (0x02-prefixed)
//! claim keypair from its per-network secret at construction and
//! self-reports the x-only half via
//! [`NetworkRouterAdapter::claim_pubkey`]. Every counterparty that
//! locks a contract to us reconstructs the compressed key as
//! `0x02 || x-only`, so lock and claim agree by construction; the
//! descriptors additionally pin the full compressed key.
//!
//! Timelocks: LNv2 contract expirations are measured in the
//! federation's consensus block count. Cassis deadlines are absolute
//! unix seconds; [`SECS_PER_BLOCK`] converts. `refund_htlc` only
//! succeeds once the federation's block count passes the contract's
//! expiration, so [`NetworkRouterAdapter::refund_outgoing`] retries
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
use fedimint_core::core::OperationId;
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
    Bytes32, HtlcDescriptor, HtlcError, HtlcTarget, NetworkId, NetworkRouterAdapter,
    OutgoingPayment, PubKey, WatchError, XOnlyPubKey,
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
/// funding is submitted by the upstream hop right before DISPATCH,
/// so by the time a preimage arrives it is long since accepted; this
/// only covers the race where a payee claims immediately after
/// COMMIT.
const FUNDING_GRACE: Duration = Duration::from_secs(60);

/// How long [`NetworkRouterAdapter::refund_outgoing`] retries while
/// the federation's consensus block count has not yet passed the
/// contract's expiration.
const REFUND_RETRY: Duration = Duration::from_secs(120);

/// An incoming HTLC registered at PREPARE time (via
/// [`NetworkRouterAdapter::register_incoming_htlc`]) or at
/// DISPATCH time via `accept_incoming_htlc`.
struct PendingIncoming {
    /// Floor the funding contract's amount must meet.
    min_amount_msat: u64,
    /// Unix seconds the routing layer gave us for this hop.
    deadline: u64,
    /// Filled in by `accept_incoming_htlc` once the funder's
    /// DISPATCH tells us where the contract lives.
    funded: Option<FundedContract>,
    /// The claim spend submitted by a previous
    /// [`NetworkRouterAdapter::claim_incoming`] call, if any. Set
    /// before its settlement is awaited so a retry settles the
    /// existing operation instead of resubmitting it (which the
    /// federation rejects as a duplicate operation).
    claim_op: Option<OperationId>,
}

/// The funded incoming contract: where it lives and what it says.
#[derive(Clone)]
struct FundedContract {
    outpoint: OutPoint,
    contract: OutgoingContract,
}

/// An outgoing HTLC we funded via `create_htlc`, keyed by the cassis
/// payment hash used for the hop. The same `payment_hash` may appear
/// on both the incoming and outgoing side of a hop (cassis's
/// atomic-routing invariant), hence the two maps.
#[derive(Clone)]
struct OutgoingSlot {
    /// The operation `create_htlc` submitted the funding under.
    /// Unused today — `await_htlc_resolution` observes claims via the
    /// federation API directly — but kept so diagnostics can map a
    /// funding outpoint back to its operation.
    #[allow(dead_code)]
    operation_id: OperationId,
    outpoint: OutPoint,
    contract: OutgoingContract,
    /// The refund spend submitted by a previous
    /// [`NetworkRouterAdapter::refund_outgoing`] call, if any. Set
    /// before its settlement is awaited so a retry settles the
    /// existing operation instead of resubmitting it (which the
    /// federation rejects as a duplicate operation).
    refund_op: Option<OperationId>,
}

/// Fedimint network adapter.
///
/// One adapter per federation. The constructor joins the federation
/// (downloading the `ClientConfig` over iroh if the address is a
/// `fed1q…` invite code, or re-opening an existing client DB) and
/// starts the client's executor.
pub struct FedimintAdapter {
    network_id: NetworkId,
    client: ClientHandleArc,
    /// Static claim keypair, derived from the per-network secret with
    /// even (0x02) compressed parity so the advertised identity —
    /// which only carries the x-only half — round-trips losslessly.
    claim_keypair: secp256k1::Keypair,
    claim_pk: secp256k1::PublicKey,
    incoming: Mutex<HashMap<Bytes32, PendingIncoming>>,
    outgoing: Mutex<HashMap<Bytes32, OutgoingSlot>>,
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

        // RocksDB path. The daemon doesn't pass a base path today,
        // so we put it under a fixed dir keyed by a sanitized
        // fragment of the network id.
        let db_dir = Self::db_dir_for(&network_id);
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

    fn db_dir_for(network_id: &NetworkId) -> PathBuf {
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
        PathBuf::from(format!("./cassis-fedimint-db/{safe}"))
    }

    /// Borrow the LNv2 client module from a client handle. The
    /// returned reference is tied to the input borrow; safe to use
    /// across `await` points since `Arc<ClientHandle>` is `Sync`.
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
        Self::db_dir_for(&self.network_id)
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
    pub async fn deposit_address(&self) -> Result<(String, OperationId), String> {
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
        operation_id: OperationId,
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
    fn expiration_delta(expiry: u64) -> Result<u64, HtlcError> {
        let now = unix_now_secs();
        if expiry <= now {
            return Err(HtlcError::InvalidParams("expiry in the past".into()));
        }
        Ok(expiry.saturating_sub(now).div_ceil(SECS_PER_BLOCK).max(1))
    }

    fn claim_pk_from_cassis(recipient: XOnlyPubKey) -> Result<secp256k1::PublicKey, HtlcError> {
        let mut compressed = [0u8; 33];
        compressed[0] = 0x02;
        compressed[1..].copy_from_slice(recipient.as_bytes());
        secp256k1::PublicKey::from_slice(&compressed)
            .map_err(|e| HtlcError::InvalidParams(format!("invalid recipient pubkey: {e}")))
    }

    /// Validate a funding descriptor against this adapter: right
    /// network, right shape, payment image matches `payment_hash`, and
    /// the contract is locked to our claim key. Returns the decoded
    /// outpoint + contract.
    fn decode_funding(
        &self,
        descriptor: &HtlcDescriptor,
        payment_hash: Bytes32,
    ) -> Result<(OutPoint, OutgoingContract), HtlcError> {
        let (claim_pubkey, funding_txid, funding_out_idx, contract_json) = match descriptor {
            HtlcDescriptor::Fedimint {
                claim_pubkey,
                funding_txid,
                funding_out_idx,
                contract,
            } => (claim_pubkey, funding_txid, funding_out_idx, contract),
            other => {
                return Err(HtlcError::InvalidParams(format!(
                    "unsupported htlc descriptor for fedimint network: {other:?}"
                )))
            }
        };
        let txid_hex = funding_txid.as_deref().ok_or_else(|| {
            HtlcError::InvalidParams("fedimint descriptor has no funding txid".into())
        })?;
        let out_idx = funding_out_idx.ok_or_else(|| {
            HtlcError::InvalidParams("fedimint descriptor has no funding out idx".into())
        })?;
        let contract_json = contract_json.as_deref().ok_or_else(|| {
            HtlcError::InvalidParams("fedimint descriptor has no contract".into())
        })?;

        let claim_pk = secp256k1::PublicKey::from_slice(claim_pubkey.as_bytes())
            .map_err(|e| HtlcError::InvalidParams(format!("descriptor claim pubkey: {e}")))?;
        if claim_pk != self.claim_pk {
            return Err(HtlcError::InvalidParams(
                "descriptor claim pubkey is not ours".into(),
            ));
        }

        let txid = TransactionId::from_str(txid_hex)
            .map_err(|e| HtlcError::InvalidParams(format!("descriptor txid: {e}")))?;
        let contract: OutgoingContract = serde_json::from_str(contract_json)
            .map_err(|e| HtlcError::InvalidParams(format!("descriptor contract: {e}")))?;

        if contract.payment_image
            != PaymentImage::Hash(sha256::Hash::from_byte_array(payment_hash.0))
        {
            return Err(HtlcError::InvalidParams(
                "contract payment image does not match the route payment hash".into(),
            ));
        }
        if contract.claim_pk != self.claim_pk {
            return Err(HtlcError::InvalidParams(
                "contract is not locked to our claim key".into(),
            ));
        }

        Ok((OutPoint { txid, out_idx }, contract))
    }
}

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn ln_err(e: LnHtlcError) -> HtlcError {
    HtlcError::Network(e.to_string())
}

#[async_trait]
impl NetworkRouterAdapter for FedimintAdapter {
    fn network_id(&self) -> NetworkId {
        self.network_id.clone()
    }

    /// Advertised identity: the x-only half of the static even-parity
    /// claim key. Doubles as the trait's `invoice_pubkey`; the trait's
    /// default `claim_pubkey` (which forwards to this) then equals the
    /// key we actually sign claims with, and any funder reconstructs
    /// the compressed form as `0x02 || this`.
    fn invoice_pubkey(&self) -> XOnlyPubKey {
        let compressed = self.claim_pk.serialize();
        let mut xonly = [0u8; 32];
        xonly.copy_from_slice(&compressed[1..]);
        XOnlyPubKey(xonly)
    }

    fn incoming_delta_secs(&self) -> u64 {
        INCOMING_DELTA_SECS
    }

    /// Register an expected incoming HTLC. Fedimint has no notion of
    /// "publishing" an incoming contract — the receiver just parks
    /// the payment hash and waits for the funder's DISPATCH to tell
    /// it where the contract lives. Returns a descriptor carrying
    /// our claim public key so the funder knows what to lock to.
    async fn register_incoming_htlc(
        &self,
        payment_hash: Bytes32,
        min_amount_msat: u64,
        deadline: u64,
    ) -> Result<(), HtlcError> {
        let mut incoming = self.incoming.lock().await;
        incoming
            .entry(payment_hash)
            .or_insert_with(|| PendingIncoming {
                min_amount_msat,
                deadline,
                funded: None,
                claim_op: None,
            });
        debug!(
            ?payment_hash,
            min_amount_msat, "fedimint incoming HTLC registered"
        );
        Ok(())
    }

    /// The descriptor a payer needs to fund a previously registered
    /// incoming HTLC: our claim public key.
    async fn htlc_target(&self, _payment_hash: Bytes32) -> Result<HtlcTarget, HtlcError> {
        Ok(HtlcTarget::XOnlyPubKey(self.invoice_pubkey()))
    }

    /// Drop a PREPARE-time registration that will never be funded.
    async fn cancel_incoming_htlc(&self, payment_hash: Bytes32) -> Result<(), HtlcError> {
        self.incoming.lock().await.remove(&payment_hash);
        Ok(())
    }

    /// DISPATCH-time verify: does `descriptor` decode to a contract
    /// funded for `payment_hash`, locked to our claim key?
    async fn verify_incoming_htlc(
        &self,
        descriptor: &HtlcDescriptor,
        payment_hash: Bytes32,
    ) -> Result<(), HtlcError> {
        self.decode_funding(descriptor, payment_hash).map(|_| ())
    }

    /// DISPATCH-time accept: store the funded contract so the later
    /// [`NetworkRouterAdapter::claim_incoming`] call can find it,
    /// checking the locked amount covers the registered floor.
    async fn accept_incoming_htlc(
        &self,
        payment_hash: Bytes32,
        descriptor: &HtlcDescriptor,
        _deadline: u64,
    ) -> Result<(), HtlcError> {
        let (outpoint, contract) = self.decode_funding(descriptor, payment_hash)?;
        let amount_msat = contract.amount.msats;
        let mut incoming = self.incoming.lock().await;
        let slot = incoming.get_mut(&payment_hash).ok_or_else(|| {
            HtlcError::InvalidParams(format!("no incoming HTLC registered for {payment_hash:?}"))
        })?;
        if amount_msat < slot.min_amount_msat {
            return Err(HtlcError::InvalidParams(format!(
                "incoming contract amount {amount_msat} msat below registered \
                 floor {} msat",
                slot.min_amount_msat
            )));
        }
        slot.funded = Some(FundedContract { outpoint, contract });
        debug!(
            ?payment_hash,
            amount_msat, "fedimint incoming HTLC accepted"
        );
        Ok(())
    }

    /// Fund a direct HTLC: lock `amount_msat` of ecash into an
    /// `OutgoingContract` behind `payment_hash`, claimable by
    /// `recipient` until `expiry`. With a fedimint descriptor target
    /// the exact claim key from the descriptor is used; otherwise the
    /// recipient's x-only key is parity-normalized (0x02 prefix).
    async fn create_outgoing_htlc(
        &self,
        payment_hash: Bytes32,
        amount_msat: u64,
        expiry: u64,
        htlc_target: &HtlcTarget,
    ) -> Result<cassis_core::OutgoingHtlc, HtlcError> {
        if amount_msat == 0 {
            return Err(HtlcError::InvalidParams("amount must be > 0".into()));
        }
        let recipient = match htlc_target {
            HtlcTarget::XOnlyPubKey(pubkey) => *pubkey,
            HtlcTarget::PubKey(_) | HtlcTarget::LightningInvoice(_) => {
                return Err(HtlcError::InvalidParams(
                    "fedimint requires a pubkey target".into(),
                ))
            }
        };
        let claim_pk = Self::claim_pk_from_cassis(recipient)?;

        let ln = Self::ln_module(&self.client)
            .map_err(|e| HtlcError::Network(format!("LNv2 module not available: {e}")))?;
        let expiration_delta = Self::expiration_delta(expiry)?;
        let (operation_id, outpoint, contract) = ln
            .create_htlc(
                Amount::from_msats(amount_msat),
                PaymentImage::Hash(sha256::Hash::from_byte_array(payment_hash.0)),
                claim_pk,
                expiration_delta,
                serde_json::Value::Null,
            )
            .await
            .map_err(ln_err)?;

        info!(
            ?payment_hash,
            amount_msat,
            expiration = contract.expiration,
            "fedimint outgoing HTLC funded"
        );

        self.outgoing.lock().await.insert(
            payment_hash,
            OutgoingSlot {
                operation_id,
                outpoint,
                contract,
                refund_op: None,
            },
        );

        Ok(cassis_core::OutgoingHtlc {
            payment_hash,
            amount_msat,
            expiry,
            recipient: recipient.to_hex(),
            network: self.network_id.clone(),
        })
    }

    /// DISPATCH-time accessor: serialize the funded contract and its
    /// outpoint for the next hop's `accept_incoming_htlc`.
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
                HtlcError::InvalidParams(format!("no outgoing HTLC for {payment_hash:?}"))
            })?;
        Ok(HtlcDescriptor::Fedimint {
            claim_pubkey: PubKey::from_bytes(slot.contract.claim_pk.serialize())
                .map_err(|e| HtlcError::InvalidParams(format!("descriptor claim pubkey: {e}")))?,
            funding_txid: Some(slot.outpoint.txid.to_string()),
            funding_out_idx: Some(slot.outpoint.out_idx),
            contract: Some(
                serde_json::to_string(&slot.contract)
                    .map_err(|e| HtlcError::Network(format!("serialize outgoing contract: {e}")))?,
            ),
        })
    }

    async fn restore_outgoing_htlc(
        &self,
        payment: &OutgoingPayment,
        descriptor: Option<&HtlcDescriptor>,
    ) -> Result<(), HtlcError> {
        let descriptor = descriptor.ok_or(HtlcError::Unimplemented)?;
        let (claim_pubkey, funding_txid, funding_out_idx, contract_json) = match descriptor {
            HtlcDescriptor::Fedimint {
                claim_pubkey,
                funding_txid,
                funding_out_idx,
                contract,
            } => (claim_pubkey, funding_txid, funding_out_idx, contract),
            _ => return Err(HtlcError::InvalidParams("not a fedimint descriptor".into())),
        };
        let claim_pk = secp256k1::PublicKey::from_slice(claim_pubkey.as_bytes())
            .map_err(|e| HtlcError::InvalidParams(format!("descriptor claim pubkey: {e}")))?;
        let txid = TransactionId::from_str(funding_txid.as_deref().ok_or_else(|| {
            HtlcError::InvalidParams("fedimint descriptor has no funding txid".into())
        })?)
        .map_err(|e| HtlcError::InvalidParams(format!("descriptor txid: {e}")))?;
        let contract: OutgoingContract =
            serde_json::from_str(contract_json.as_deref().ok_or_else(|| {
                HtlcError::InvalidParams("fedimint descriptor has no contract".into())
            })?)
            .map_err(|e| HtlcError::InvalidParams(format!("descriptor contract: {e}")))?;
        if contract.claim_pk != claim_pk
            || contract.payment_image
                != PaymentImage::Hash(sha256::Hash::from_byte_array(payment.payment_hash.0))
            || contract.amount.msats != payment.amount_msat
        {
            return Err(HtlcError::InvalidParams(
                "fedimint descriptor does not match outgoing payment".into(),
            ));
        }
        let operation_id = OperationId::from_encodable(&("lnv2-htlc-create", contract.clone()));
        self.outgoing.lock().await.insert(
            payment.payment_hash,
            OutgoingSlot {
                operation_id,
                outpoint: OutPoint {
                    txid,
                    out_idx: funding_out_idx.ok_or_else(|| {
                        HtlcError::InvalidParams(
                            "fedimint descriptor has no funding out idx".into(),
                        )
                    })?,
                },
                contract,
                refund_op: None,
            },
        );
        Ok(())
    }

    /// Claim the incoming HTLC with the route preimage. Waits (bounded)
    /// for the funding to be observed, submits the claim with our
    /// claim keypair, and blocks until the federation has accepted the
    /// claim transaction and minted the ecash to our wallet.
    async fn claim_incoming(
        &self,
        payment_hash: Bytes32,
        preimage: Bytes32,
    ) -> Result<(), HtlcError> {
        let ln = Self::ln_module(&self.client)
            .map_err(|e| HtlcError::Network(format!("LNv2 module not available: {e}")))?;
        let (FundedContract { outpoint, contract }, claim_op, funding_wait) = {
            let incoming = self.incoming.lock().await;
            let slot = incoming.get(&payment_hash).ok_or_else(|| {
                HtlcError::InvalidParams(format!(
                    "no incoming HTLC registered for {payment_hash:?}"
                ))
            })?;
            // Clone, don't take: a failed claim must leave the handle
            // in place so the contract stays claimable on retry. The
            // slot entry is only removed after a successful claim
            // below.
            let funded = slot.funded.clone().ok_or_else(|| {
                HtlcError::Network(format!("incoming HTLC for {payment_hash:?} never funded"))
            })?;
            // Cap the funding wait by the hop's own deadline when it
            // still lies in the future; otherwise use the default
            // grace.
            let now = unix_now_secs();
            let wait = if slot.deadline > now {
                FUNDING_GRACE.min(Duration::from_secs(slot.deadline - now))
            } else {
                FUNDING_GRACE
            };
            (funded, slot.claim_op, wait)
        };

        // The claim transaction reveals the preimage; before the
        // first submission, make sure the contract is really funded
        // so we don't burn the reveal on a phantom HTLC. A retry
        // (claim op already submitted) skips this — the first
        // attempt already confirmed the funding.
        if claim_op.is_none() {
            let remaining =
                tokio::time::timeout(funding_wait, ln.await_htlc_funded(outpoint, &contract))
                    .await
                    .map_err(|_| {
                        HtlcError::Network(format!(
                            "incoming HTLC for {payment_hash:?} not funded after {}s",
                            funding_wait.as_secs()
                        ))
                    })?
                    .map_err(ln_err)?;
            debug!(
                ?payment_hash,
                remaining_blocks = remaining,
                "fedimint incoming HTLC confirmed funded; claiming"
            );
        }

        let operation_id = match claim_op {
            Some(operation_id) => operation_id,
            None => {
                let operation_id = ln
                    .claim_htlc(
                        outpoint,
                        contract,
                        self.claim_keypair,
                        preimage.0,
                        serde_json::Value::Null,
                    )
                    .await
                    .map_err(ln_err)?;
                // Record the submitted claim before awaiting its
                // settlement, so a failed settle retries the settle —
                // never the submission (which the federation would
                // reject as a duplicate operation).
                if let Some(slot) = self.incoming.lock().await.get_mut(&payment_hash) {
                    slot.claim_op = Some(operation_id);
                }
                operation_id
            }
        };

        ln.await_htlc_operation_settled(operation_id)
            .await
            .map_err(ln_err)?;

        info!(?payment_hash, "fedimint incoming HTLC claimed");
        self.incoming.lock().await.remove(&payment_hash);
        Ok(())
    }

    /// Refund an outgoing HTLC after its expiration. `refund_htlc`
    /// refuses while the federation's consensus block count has not
    /// yet passed the contract expiration, so retry briefly; the
    /// router calls this right after the unix deadline, and consensus
    /// only needs to catch up.
    async fn refund_outgoing(&self, payment_hash: Bytes32) -> Result<(), HtlcError> {
        let ln = Self::ln_module(&self.client)
            .map_err(|e| HtlcError::Network(format!("LNv2 module not available: {e}")))?;
        let (outpoint, contract, refund_op) = {
            let outgoing = self.outgoing.lock().await;
            let slot = outgoing.get(&payment_hash).ok_or_else(|| {
                HtlcError::InvalidParams(format!("no outgoing HTLC for {payment_hash:?}"))
            })?;
            (slot.outpoint, slot.contract.clone(), slot.refund_op)
        };

        let operation_id = match refund_op {
            // A previous attempt already submitted the refund spend;
            // just wait for its settlement again instead of
            // resubmitting (which the federation rejects as a
            // duplicate operation).
            Some(operation_id) => operation_id,
            None => {
                let started = tokio::time::Instant::now();
                let operation_id = loop {
                    match ln
                        .refund_htlc(outpoint, contract.clone(), serde_json::Value::Null)
                        .await
                    {
                        Ok(operation_id) => {
                            // Record the submitted refund before
                            // awaiting its settlement, so a failed
                            // settle retries the settle — never the
                            // submission.
                            if let Some(slot) = self.outgoing.lock().await.get_mut(&payment_hash) {
                                slot.refund_op = Some(operation_id);
                            }
                            break operation_id;
                        }
                        Err(LnHtlcError::NotExpired(missing)) => {
                            if started.elapsed() >= REFUND_RETRY {
                                return Err(HtlcError::Network(format!(
                                    "contract still not expired on consensus \
                                     ({missing} blocks to go); retry later"
                                )));
                            }
                            tokio::time::sleep(Duration::from_secs(5)).await;
                        }
                        Err(LnHtlcError::ContractNotFound) => {
                            // Nothing is funded at this outpoint
                            // anymore: the recipient claimed (happy
                            // path) or the contract was already spent.
                            // There is nothing left to refund —
                            // terminal.
                            warn!(
                                ?payment_hash,
                                "fedimint outgoing HTLC gone before refund; dropping"
                            );
                            self.outgoing.lock().await.remove(&payment_hash);
                            return Ok(());
                        }
                        Err(e) => return Err(ln_err(e)),
                    }
                };
                operation_id
            }
        };

        ln.await_htlc_operation_settled(operation_id)
            .await
            .map_err(ln_err)?;

        info!(?payment_hash, "fedimint outgoing HTLC refunded");
        self.outgoing.lock().await.remove(&payment_hash);
        Ok(())
    }

    /// Wait for the recipient of our outgoing HTLC to claim. The
    /// federation returns the preimage to the funder once the claim
    /// transaction is accepted; `None` means the contract expired
    /// unclaimed, which maps to cassis's deadline-exceeded.
    async fn watch_preimage(
        &self,
        payment_hash: Bytes32,
        deadline: u64,
    ) -> Result<Bytes32, WatchError> {
        let ln = Self::ln_module(&self.client)
            .map_err(|e| WatchError::Network(format!("LNv2 module not available: {e}")))?;
        let (outpoint, contract) = {
            let outgoing = self.outgoing.lock().await;
            let slot = outgoing.get(&payment_hash).ok_or_else(|| {
                WatchError::Network(format!("no outgoing HTLC for {payment_hash:?}"))
            })?;
            (slot.outpoint, slot.contract.clone())
        };

        let resolution = tokio::time::timeout(
            Self::deadline_to_timeout(deadline),
            ln.await_htlc_resolution(outpoint, &contract),
        )
        .await
        .map_err(|_| WatchError::DeadlineExceeded)?
        .map_err(|e| WatchError::Network(e.to_string()))?;

        match resolution {
            Some(preimage) => {
                info!(
                    ?payment_hash,
                    "fedimint outgoing HTLC claimed; preimage revealed"
                );
                Ok(Bytes32(preimage))
            }
            None => {
                warn!(?payment_hash, "fedimint outgoing HTLC expired unclaimed");
                Err(WatchError::DeadlineExceeded)
            }
        }
    }

    /// PREPARE-time check: does the client hold enough ecash to fund
    /// an outgoing HTLC of `amount_msat`? Outgoing contracts are paid
    /// from the wallet's bitcoin-denominated balance.
    async fn can_route(&self, amount_msat: u64) -> Result<(), HtlcError> {
        let balance = self
            .client
            .get_balance_for_btc()
            .await
            .map_err(|e| HtlcError::Network(format!("balance request failed: {e}")))?;
        let needed = Amount::from_msats(amount_msat);
        if balance < needed {
            return Err(HtlcError::InvalidParams(format!(
                "insufficient fedimint balance: need {} msat, have {} msat",
                amount_msat, balance.msats
            )));
        }
        Ok(())
    }
}
