//! Fedimint network: LNv2 *direct HTLCs* (fedimint PR #8913) — a raw
//! `OutgoingContract` funded between two clients of one federation, no
//! gateway involved.
//!
//! | operation  | LNv2 call                                              |
//! |------------|--------------------------------------------------------|
//! | lock       | `create_htlc` to the receiver's claim key              |
//! | verify     | decode the contract, `await_htlc_funded`               |
//! | claim      | `claim_htlc` with the preimage and our claim keypair   |
//! | check      | `await_htlc_resolution` (briefly)                      |
//! | refund     | `refund_htlc` once consensus passes the expiration     |
//!
//! The claim key is an even-parity key derived from the node's network
//! secret, so the x-only target `02 || x` is exact. Contract
//! expirations count federation consensus blocks; [`SECS_PER_BLOCK`]
//! converts from cassis' unix expiries.

use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bitcoin::hashes::{sha256, Hash};
use cassis_core::{
    unix_now, Bytes32, Htlc, HtlcDescriptor, HtlcTarget, Network, NetworkError, NetworkId,
    OutgoingState, XOnlyPubKey,
};
use fedimint_client::module::oplog::UpdateStreamOrOutcome;
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
use fedimint_wallet_client::{DepositStateV2, WalletClientInit, WalletClientModule, WithdrawState};
use tracing::{info, Span};

/// Contract funding and claims are federation consensus outputs.
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

/// How long verification waits for an incoming contract to be funded.
const FUNDING_WAIT: Duration = Duration::from_secs(30);
/// How long a check waits for the federation to report a resolution.
const RESOLUTION_WAIT: Duration = Duration::from_secs(2);

/// One federation joined as a client. The client database lives in
/// `<data_dir>/db`.
pub struct FedimintAdapter {
    id: NetworkId,
    span: Span,
    client: ClientHandleArc,
    /// Even-parity claim keypair, so the x-only target is exact.
    claim_keypair: secp256k1::Keypair,
}

impl FedimintAdapter {
    /// Open (or join, on first use) the federation of
    /// `fedimint::<invite code>`.
    pub async fn open(
        id: NetworkId,
        secret: [u8; 32],
        data_dir: &Path,
        span: &Span,
    ) -> Result<Self, String> {
        let invite = id.param().ok_or("fedimint network needs an invite code")?;
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

        std::fs::create_dir_all(data_dir).map_err(|e| format!("create {data_dir:?}: {e}"))?;
        let db_path = data_dir.join("db");
        let db: Database = Database::new(
            fedimint_rocksdb::RocksDb::build(db_path.clone())
                .open()
                .await
                .map_err(|e| format!("failed to open RocksDb at {}: {e}", db_path.display()))?,
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
            let invite = InviteCode::from_str(invite)
                .map_err(|e| format!("invalid fedimint invite code: {e}"))?;
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
        let span = cassis_core::network_span(span, &id);
        info!(parent: &span, "fedimint client ready");
        Ok(Self {
            id,
            span,
            client,
            claim_keypair,
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

    fn ln(&self) -> Result<&LightningClientModule, NetworkError> {
        Self::ln_module(&self.client).map_err(NetworkError::network)
    }

    fn claim_target(&self) -> HtlcTarget {
        let x = self.claim_keypair.public_key().serialize();
        HtlcTarget::XOnlyPubKey(
            XOnlyPubKey::from_bytes(x[1..].try_into().expect("32 bytes")).expect("valid key"),
        )
    }

    /// Funding outpoint and contract of `htlc`.
    fn contract(htlc: &Htlc) -> Result<(OutPoint, OutgoingContract), NetworkError> {
        let HtlcDescriptor::Fedimint {
            funding_txid,
            funding_out_idx,
            contract,
        } = &htlc.descriptor
        else {
            return Err(NetworkError::invalid("not a fedimint HTLC"));
        };
        let HtlcTarget::XOnlyPubKey(claim) = &htlc.target else {
            return Err(NetworkError::invalid(
                "fedimint HTLCs are locked to an x-only key",
            ));
        };
        let contract: OutgoingContract =
            serde_json::from_str(contract).map_err(NetworkError::invalid)?;
        if contract.claim_pk != claim_key(claim)? {
            return Err(NetworkError::invalid("contract is locked to another key"));
        }
        if contract.payment_image
            != PaymentImage::Hash(sha256::Hash::from_byte_array(htlc.payment_hash.0))
        {
            return Err(NetworkError::invalid("contract is locked to another hash"));
        }
        let txid = TransactionId::from_str(funding_txid).map_err(NetworkError::invalid)?;
        Ok((
            OutPoint {
                txid,
                out_idx: *funding_out_idx,
            },
            contract,
        ))
    }

    fn claim_operation(outpoint: OutPoint) -> FedimintOperationId {
        FedimintOperationId::from_encodable(&("lnv2-htlc-claim", outpoint))
    }

    fn refund_operation(outpoint: OutPoint) -> FedimintOperationId {
        FedimintOperationId::from_encodable(&("lnv2-htlc-refund", outpoint))
    }
}

/// The compressed key counterparties lock to for x-only identity `x`.
fn claim_key(x: &XOnlyPubKey) -> Result<secp256k1::PublicKey, NetworkError> {
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02;
    compressed[1..].copy_from_slice(x.as_bytes());
    secp256k1::PublicKey::from_slice(&compressed).map_err(NetworkError::invalid)
}

fn ln_err(e: LnHtlcError) -> NetworkError {
    NetworkError::network(e)
}

#[async_trait]
impl Network for FedimintAdapter {
    fn id(&self) -> NetworkId {
        self.id.clone()
    }

    fn incoming_delta_secs(&self) -> u64 {
        INCOMING_DELTA_SECS
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
        let (outpoint, contract) = Self::contract(htlc)?;
        if htlc.target != self.claim_target() {
            return Err(NetworkError::invalid("HTLC is not addressed to this node"));
        }
        if contract.amount.msats < htlc.amount_msat {
            return Err(NetworkError::invalid(
                "contract is worth less than the HTLC",
            ));
        }
        let remaining_blocks = tokio::time::timeout(
            FUNDING_WAIT,
            self.ln()?.await_htlc_funded(outpoint, &contract),
        )
        .await
        .map_err(|_| NetworkError::network("contract is not funded"))?
        .map_err(ln_err)?;
        let needed_blocks = htlc.expiry.saturating_sub(unix_now()) / SECS_PER_BLOCK;
        if remaining_blocks < needed_blocks {
            return Err(NetworkError::invalid("contract expires before the expiry"));
        }
        Ok(())
    }

    async fn claim_incoming_htlc(
        &self,
        htlc: &Htlc,
        preimage: Bytes32,
    ) -> Result<(), NetworkError> {
        let (outpoint, contract) = Self::contract(htlc)?;
        let ln = self.ln()?;
        let operation = match ln
            .claim_htlc(
                outpoint,
                contract,
                self.claim_keypair,
                preimage.0,
                serde_json::Value::Null,
            )
            .await
        {
            Ok(operation) | Err(LnHtlcError::DuplicateOperation(operation)) => operation,
            // Gone: claimed by an earlier attempt of ours, or refunded.
            Err(LnHtlcError::ContractNotFound) => Self::claim_operation(outpoint),
            Err(error) => return Err(ln_err(error)),
        };
        ln.await_htlc_operation_settled(operation)
            .await
            .map_err(ln_err)?;
        info!(parent: &self.span, "claimed {}", htlc.payment_hash.short());
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
                "fedimint HTLCs are locked to an x-only key",
            ));
        };
        let expiration_delta = expiry
            .saturating_sub(unix_now())
            .div_ceil(SECS_PER_BLOCK)
            .max(1);
        let (_, outpoint, contract) = self
            .ln()?
            .create_htlc(
                Amount::from_msats(amount_msat),
                PaymentImage::Hash(sha256::Hash::from_byte_array(payment_hash.0)),
                claim_key(receiver)?,
                expiration_delta,
                serde_json::Value::Null,
            )
            .await
            .map_err(ln_err)?;
        info!(
            parent: &self.span,
            "locked {amount_msat} msat for {} for {expiration_delta} blocks",
            payment_hash.short()
        );
        Ok(HtlcDescriptor::Fedimint {
            funding_txid: outpoint.txid.to_string(),
            funding_out_idx: outpoint.out_idx,
            contract: serde_json::to_string(&contract).map_err(NetworkError::invalid)?,
        })
    }

    async fn check_outgoing_htlc(&self, htlc: &Htlc) -> Result<OutgoingState, NetworkError> {
        let (outpoint, contract) = Self::contract(htlc)?;
        let resolution = tokio::time::timeout(
            RESOLUTION_WAIT,
            self.ln()?.await_htlc_resolution(outpoint, &contract),
        )
        .await;
        match resolution {
            Ok(Ok(Some(preimage))) => Ok(OutgoingState::Claimed(Bytes32(preimage))),
            // Expired unclaimed: refundable, still ours to take back.
            Ok(Ok(None)) | Err(_) => Ok(OutgoingState::Pending),
            Ok(Err(error)) => Err(ln_err(error)),
        }
    }

    async fn refund_outgoing_htlc(&self, htlc: &Htlc) -> Result<(), NetworkError> {
        let (outpoint, contract) = Self::contract(htlc)?;
        let ln = self.ln()?;
        let operation = match ln
            .refund_htlc(outpoint, contract, serde_json::Value::Null)
            .await
        {
            Ok(operation) | Err(LnHtlcError::DuplicateOperation(operation)) => operation,
            Err(LnHtlcError::NotExpired(blocks)) => {
                return Err(NetworkError::network(format!(
                    "contract expires in {blocks} more blocks"
                )))
            }
            // Gone: refunded by an earlier attempt of ours, or claimed.
            Err(LnHtlcError::ContractNotFound) => Self::refund_operation(outpoint),
            Err(error) => return Err(ln_err(error)),
        };
        ln.await_htlc_operation_settled(operation)
            .await
            .map_err(ln_err)?;
        info!(parent: &self.span, "refunded {}", htlc.payment_hash.short());
        Ok(())
    }

    async fn can_send(&self, amount_msat: u64) -> Result<(), NetworkError> {
        let balance = self.balance_msat().await.map_err(NetworkError::network)?;
        if balance < amount_msat {
            return Err(NetworkError::invalid(format!(
                "need {amount_msat} msat, wallet has {balance} msat"
            )));
        }
        Ok(())
    }

    /// Claims are paid from the contract.
    async fn can_receive(&self, _amount_msat: u64) -> Result<(), NetworkError> {
        Ok(())
    }
}
