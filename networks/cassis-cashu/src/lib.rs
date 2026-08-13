use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use cassis_core::{
    AcceptedIncoming, AdapterError, Bytes32, HtlcDescriptor, HtlcTarget, IncomingRequest,
    IncomingReservation, NetworkAdapter, NetworkId, OperationId, OutgoingPayment, OutgoingRequest,
    XOnlyPubKey,
};
use cdk::amount::{FeeAndAmounts, SplitTarget};
use cdk::dhke::{blind_message, unblind_message};
use cdk::mint_url::MintUrl;
use cdk::nuts::nut00::{BlindedMessage, Proofs};
use cdk::nuts::nut07::{CheckStateRequest, State as ProofState};
use cdk::nuts::nut10::SpendingConditions;
use cdk::nuts::nut12::ProofDleq;
use cdk::nuts::nut14::HTLCWitness;
use cdk::nuts::{CurrencyUnit, KeySetInfo, KeysetResponse, Witness};
use cdk::secp256k1::hashes::Hash as _;
use cdk::wallet::MintConnector;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::{Mutex, Notify};
use tracing::Span;

mod errors;
mod htlc;
mod store;

// Re-exported so downstream crates can build and inspect `Proof`
// values without taking their own direct dependency on cdk.
pub use cdk::nuts::nut00::Proof;
pub use cdk::nuts::nut01::PublicKey;
pub use cdk::nuts::nut02::Id as KeysetId;
pub use cdk::secret::Secret;
pub use cdk::Amount;
pub use errors::CashuError as Error;
use errors::{CashuError, CashuResult};
use htlc::{
    add_preimage_to_proofs, build_htlc_outputs, claim_pubkey_from_secret, htlc_conditions, proof_y,
    verify_proofs_htlc, verify_proofs_htlc_locked, verify_proofs_htlc_locked_for_recipient,
};
pub use store::CashuProofStore;

/// Per-output blinding triple from a mint/swap: `(secret, r,
/// amount)`.
type BlindingTriple = (Secret, cdk::nuts::nut01::SecretKey, Amount);

/// Receiver-side state for an outstanding incoming HTLC, parked by
/// [`NetworkAdapter::reserve_incoming`] and keyed by operation id in
/// [`CashuAdapter::incoming`].
pub struct PendingIncoming {
    /// Route payment hash this reservation is for. Payment hashes
    /// identify intent, so it is kept next to the operation id: a
    /// caller holding the wrong reservation must never be able to
    /// accept or claim another operation's contract.
    payment_hash: Bytes32,
    /// SHA-256 of the preimage, hex-encoded the way the cashu
    /// secret `data` field wants it.
    payment_hash_hex: String,
    /// Face value the routing layer asked for, in msat. Echoed back
    /// verbatim in the [`IncomingReservation`] so a retry of the same
    /// operation returns an identical handle.
    amount_msat: u64,
    /// Face value of the HTLC, in sats — the mint-facing floor
    /// [`NetworkAdapter::accept_incoming`] checks the funded proofs
    /// against.
    amount_sat: u64,
    /// Unix deadline after which the receiver gives up waiting
    /// for the sender's proofs to arrive.
    deadline: u64,
    /// HTLC-locked proofs the sender (or previous hop) pushed to
    /// us. Populated by
    /// [`NetworkAdapter::accept_incoming`] in the multi-hop flow, or
    /// by [`NetworkAdapter::create_outgoing`] in the
    /// single-process test flow. None until then; in the
    /// single-process test the create-side fills it in and
    /// notifies `arrival`.
    proofs: Mutex<Option<Proofs>>,
    /// Notified when the matching HTLC proofs have been deposited
    /// by the create-side or by
    /// [`NetworkAdapter::accept_incoming`].
    arrival: Arc<Notify>,
}

/// Sender-side state for an outstanding outgoing HTLC, keyed by
/// operation id in [`CashuAdapter::outgoing`].
struct PendingOutgoing {
    /// Route payment hash these proofs are locked under. Stored so
    /// an operation-keyed lookup can reject a mismatched
    /// [`OutgoingPayment`], and so the same-process test path can
    /// find the receiver-side reservation for the same payment.
    payment_hash: Bytes32,
    /// Face value of the HTLC, in sats.
    #[allow(dead_code)]
    amount_sat: u64,
    /// Face value the caller asked for, in msat. `amount_sat` is
    /// the rounded-up native value the mint actually locked, so the
    /// protocol figure is kept separately for the
    /// [`OutgoingPayment`] handle.
    amount_msat: u64,
    /// Unix locktime after which the sender can refund.
    #[allow(dead_code)]
    locktime: u64,
    /// Destination this lock was funded for, carried so a retry of
    /// the same operation can be checked against the request that
    /// started it.
    destination: HtlcTarget,
    /// NUT-14 spending conditions used to lock the proofs.
    #[allow(dead_code)]
    conditions: SpendingConditions,
    /// Mint keyset the proofs were signed against.
    #[allow(dead_code)]
    keyset_id: KeysetId,
    /// Locked ecash the sender is holding; either spent (preimage
    /// revealed) or still unspent (refundable after locktime).
    proofs: Mutex<Vec<Proof>>,
    /// Counter-party string the sender was asked to deliver to.
    /// Kept for diagnostics; the cross-network hop layer is what
    /// actually hands the proofs to the counter-party.
    #[allow(dead_code)]
    recipient: String,
}

pub struct CashuAdapter {
    network_id: NetworkId,
    #[allow(dead_code)]
    mint_url: MintUrl,
    /// Canonical mint URL string, exactly as given to
    /// [`CashuAdapter::new`]. This is the partition key used for
    /// proof storage (matches `cassis_core::cashu_mint_url`, which
    /// the wallet's sqlite store keys `cashu_proofs` rows by).
    mint_url_str: String,
    /// The mint HTTP client from the cdk wallet layer. It
    /// implements [`MintConnector`], giving us the NUT-01/02/03/07
    /// calls the adapter's DHKE and HTLC logic drives.
    client: cdk::wallet::HttpClient,
    secret_key: [u8; 32],
    /// x-only identity of `secret_key`: the key counterparties must
    /// lock HTLC proofs to for this adapter to be able to claim them.
    ///
    /// Parity is irrelevant here: NUT-11/14 verification is BIP340
    /// x-only, so the `0x02` prefix `pubkey_from_cassis` re-applies is
    /// never checked against the signature.
    claim_pubkey: XOnlyPubKey,
    /// The caller's node span with this adapter's `network` field
    /// attached, entered around every log below so each line carries
    /// both the owning node and the network. Built once in
    /// [`CashuAdapter::new`], since the adapter's methods run on
    /// unrelated tasks where the ambient span is unrelated or absent.
    span: Span,
    keysets: Arc<Mutex<Vec<KeySetInfo>>>,
    /// In-flight outgoing HTLCs we have locked at the mint, keyed by
    /// the operation that funded them. The payment hash lives inside
    /// the entry so a second operation cannot quietly take over an
    /// existing lock, and so a retry of the *same* operation is
    /// answered from state instead of locking funds twice.
    outgoing: Mutex<HashMap<OperationId, PendingOutgoing>>,
    /// Serializes external NUT-03 funding calls. Without this, two
    /// concurrent retries could both pass the map check and lock funds
    /// twice for one operation.
    outgoing_creation_lock: Arc<Mutex<()>>,
    /// In-flight incoming HTLCs we are expecting proofs for, keyed by
    /// the operation that reserved them.
    incoming: Mutex<HashMap<OperationId, PendingIncoming>>,
    /// Persistence for the wallet-held ecash. All proofs the adapter
    /// receives (claims, deposits) are stored here and balances are
    /// computed from it on demand — never held in a field.
    store: Arc<dyn CashuProofStore>,
}

impl CashuAdapter {
    /// Construct a new adapter for a cashu mint.
    ///
    /// Returns an error if `mint_url` is not a syntactically valid
    /// cashu [`MintUrl`]; there is no fallback because a real mint
    /// URL is the only way any cashu method (NUT-01, NUT-02, NUT-03,
    /// NUT-04, NUT-05, NUT-07, …) can succeed. `store` is the
    /// persistence backend for the wallet-held proofs; balances are
    /// always read back from it, never cached in the adapter.
    pub fn new(
        network_id: NetworkId,
        mint_url: String,
        secret_key: [u8; 32],
        store: Arc<dyn CashuProofStore>,
        span: Span,
    ) -> CashuResult<Self> {
        let mint_url_str = mint_url.clone();
        let mint_url = MintUrl::from_str(&mint_url)
            .map_err(|e| CashuError::Nuts(format!("invalid mint url '{mint_url}': {e}")))?;
        let client = cdk::wallet::HttpClient::new(mint_url.clone(), None);
        // Derive up front so a key we cannot sign with is rejected here
        // rather than surfacing later as an unclaimable HTLC.
        let claim_pubkey = claim_pubkey_from_secret(&secret_key)?;
        let span = cassis_core::network_span(&span, &network_id);
        // `debug!`, not `info!`: adapters are rebuilt for every balance
        // query, so this would otherwise fire on each poll.
        span.in_scope(|| {
            tracing::debug!(
                target: "cassis_cashu",
                "adapter ready: mint={mint_url_str} claim_pubkey={}",
                claim_pubkey.to_hex(),
            );
        });
        Ok(Self {
            network_id,
            mint_url,
            mint_url_str,
            client,
            secret_key,
            claim_pubkey,
            span,
            keysets: Arc::new(Mutex::new(Vec::new())),
            outgoing: Mutex::new(HashMap::new()),
            outgoing_creation_lock: Arc::new(Mutex::new(())),
            incoming: Mutex::new(HashMap::new()),
            store,
        })
    }

    /// Lazily fetch and cache the mint's active keysets (NUT-02).
    /// We don't filter by unit here — callers pick the keyset they
    /// want; `active_keyset_id` is the one that prefers sat.
    async fn ensure_keysets(&self) -> CashuResult<Vec<KeySetInfo>> {
        {
            let cached = self.keysets.lock().await;
            if !cached.is_empty() {
                return Ok(cached.clone());
            }
        }
        let resp: KeysetResponse = self.client.get_mint_keysets().await?;
        let active: Vec<KeySetInfo> = resp.keysets.into_iter().filter(|k| k.active).collect();
        let mut guard = self.keysets.lock().await;
        *guard = active.clone();
        Ok(active)
    }

    /// Public accessor for the mint's active keyset table.
    /// The wallet uses this when decoding a NUT-00 V3 token:
    /// V3 carries short keyset ids, and `Token::proofs` needs
    /// the full set to expand them.
    pub async fn keysets(&self) -> CashuResult<Vec<KeySetInfo>> {
        self.ensure_keysets().await
    }

    /// Pick the mint's active sat-denominated keyset id, falling
    /// back to the first active keyset if no sat keyset is
    /// advertised.
    async fn active_keyset_id(&self) -> CashuResult<KeysetId> {
        let keysets = self.ensure_keysets().await?;
        keysets
            .iter()
            .find(|k| k.unit == CurrencyUnit::Sat)
            .or(keysets.first())
            .map(|k| k.id)
            .ok_or(CashuError::NoKeyset)
    }

    /// Fetch the public key material for `keyset_id` (NUT-01).
    /// Needed to unblind mint signatures back into spendable
    /// ecash. cdk's [`MintConnector::get_mint_keyset`] returns
    /// the single `KeySet` directly (unlike the old
    /// `KeysResponse` wrapper).
    async fn get_keys(&self, keyset_id: &KeysetId) -> CashuResult<cdk::nuts::Keys> {
        let ks = self.client.get_mint_keyset(*keyset_id).await?;
        Ok(ks.keys)
    }

    /// Convert a sat-denominated amount into the keyset's
    /// per-input fee in parts-per-thousand plus a powers-of-two
    /// denomination schedule. NUT-03 swaps must split outputs
    /// into power-of-two amounts to match the mint's keyset, and
    /// the per-input fee (NUT-02) is what we must add to the
    /// swap total.
    fn build_fee_and_amounts(keyset: &KeySetInfo) -> FeeAndAmounts {
        let amounts: Vec<u64> = (0..32).map(|x| 2u64.pow(x)).collect();
        (keyset.input_fee_ppk, amounts).into()
    }

    /// Split a sat amount into the powers-of-two denominations a
    /// swap input can carry.
    fn split_for_swap(
        amount_sat: u64,
        fee_and_amounts: &FeeAndAmounts,
    ) -> CashuResult<Vec<Amount>> {
        let amount = Amount::from(amount_sat);
        let split = amount
            .split_targeted(&SplitTarget::None, fee_and_amounts)
            .map_err(|e| CashuError::Nuts(format!("split_for_swap: {e}")))?;
        Ok(split)
    }

    /// Persist new proofs to the wallet's store. Production caller:
    /// the cross-network hop layer after melting an incoming
    /// Lightning payment (NUT-05) or minting via NUT-04, and the
    /// adapter itself after claiming an HTLC. Test caller: a fixture.
    pub async fn add_balance(&self, proofs: Vec<Proof>) -> CashuResult<()> {
        self.store.insert_proofs(&self.mint_url_str, &proofs)
    }

    /// Test/diagnostic accessor: read the proofs currently held for
    /// this mint from the store.
    pub async fn balance(&self) -> Vec<Proof> {
        self.store
            .list_proofs(&self.mint_url_str)
            .unwrap_or_default()
    }

    /// Look up a sender-side HTLC's proofs (test/diagnostic
    /// accessor). The map is keyed by operation id, so this scans it
    /// for the entry carrying `payment_hash`.
    pub async fn outgoing_proofs(&self, payment_hash: Bytes32) -> Option<Vec<Proof>> {
        let outgoing = self.outgoing.lock().await;
        let slot = outgoing
            .values()
            .find(|slot| slot.payment_hash == payment_hash)?;
        let proofs = slot.proofs.lock().await.clone();
        drop(outgoing);
        Some(proofs)
    }

    /// Look up a receiver-side pending incoming HTLC by payment hash
    /// (test/diagnostic accessor).
    pub async fn incoming_slot(&self, payment_hash: Bytes32) -> Option<PendingIncoming> {
        let incoming = self.incoming.lock().await;
        let slot = incoming
            .values()
            .find(|slot| slot.payment_hash == payment_hash)?;
        let proofs = slot.proofs.lock().await.clone();
        Some(PendingIncoming {
            payment_hash: slot.payment_hash,
            payment_hash_hex: slot.payment_hash_hex.clone(),
            amount_msat: slot.amount_msat,
            amount_sat: slot.amount_sat,
            deadline: slot.deadline,
            proofs: Mutex::new(proofs),
            arrival: slot.arrival.clone(),
        })
    }

    /// Build the handle for a parked incoming entry. Both
    /// [`NetworkAdapter::reserve_incoming`] and its retry path go
    /// through here, so the same operation can never be answered with
    /// two different reservations.
    fn incoming_reservation(
        &self,
        operation_id: &OperationId,
        slot: &PendingIncoming,
    ) -> IncomingReservation {
        IncomingReservation {
            operation_id: operation_id.clone(),
            payment_hash: slot.payment_hash,
            network: self.network_id.clone(),
            amount_msat: slot.amount_msat,
            deadline: slot.deadline,
            // Cashu is addressed by claim key: counterparties lock the
            // HTLC proofs to the key this adapter signs NUT-14
            // witnesses with.
            target: HtlcTarget::XOnlyPubKey(self.claim_pubkey),
        }
    }

    /// The [`AcceptedIncoming`] already committed for `reservation`,
    /// if this operation has one. Makes a repeated
    /// [`NetworkAdapter::accept_incoming`] idempotent: the proof set
    /// accepted the first time stays authoritative and the returned
    /// descriptor is rebuilt from it, so a caller's journal never
    /// records a payload other than the one that was verified.
    async fn accepted_incoming(
        &self,
        reservation: &IncomingReservation,
    ) -> Result<Option<AcceptedIncoming>, AdapterError> {
        let stored = {
            let incoming = self.incoming.lock().await;
            let Some(slot) = incoming.get(&reservation.operation_id) else {
                return Ok(None);
            };
            if slot.payment_hash != reservation.payment_hash
                || slot.amount_msat != reservation.amount_msat
                || slot.deadline != reservation.deadline
            {
                return Err(AdapterError::InvalidParams(
                    "Cashu reservation operation id does not match this payment state".into(),
                ));
            }
            let stored = slot.proofs.lock().await.clone();
            stored
        };
        let Some(proofs) = stored.filter(|proofs| !proofs.is_empty()) else {
            return Ok(None);
        };
        let amount_sat: u64 = proofs.iter().map(|proof| u64::from(proof.amount)).sum();
        Ok(Some(AcceptedIncoming {
            reservation: reservation.clone(),
            descriptor: cashu_descriptor(&proofs)?,
            amount_msat: amount_sat.saturating_mul(1000),
        }))
    }

    /// The [`OutgoingPayment`] for an attempt this adapter has already
    /// funded, or `None` when the operation is unknown. An entry that
    /// is recorded without proofs is an error rather than `None`, so a
    /// retry can never mistake a half-recorded lock for "not started
    /// yet" and fund the same amount twice.
    async fn funded_outgoing(
        &self,
        operation_id: &OperationId,
    ) -> Result<Option<OutgoingPayment>, AdapterError> {
        let (payment_hash, amount_msat, destination, expiry, proofs) = {
            let outgoing = self.outgoing.lock().await;
            let Some(slot) = outgoing.get(operation_id) else {
                return Ok(None);
            };
            let proofs = slot.proofs.lock().await.clone();
            (
                slot.payment_hash,
                slot.amount_msat,
                slot.destination.clone(),
                slot.locktime,
                proofs,
            )
        };
        if proofs.is_empty() {
            return Err(AdapterError::Retryable(
                "outgoing Cashu lock is recorded without proofs".into(),
            ));
        }
        Ok(Some(OutgoingPayment {
            operation_id: operation_id.clone(),
            payment_hash,
            amount_msat,
            destination,
            destination_network: self.network_id.clone(),
            expiry,
            descriptor: cashu_descriptor(&proofs)?,
        }))
    }

    /// The parked receiver-side entry for `payment_hash`, if this
    /// adapter holds a reservation for it. The incoming map is keyed by
    /// operation, so hash lookups scan it.
    async fn receiver_operation(&self, payment_hash: Bytes32) -> Option<OperationId> {
        let incoming = self.incoming.lock().await;
        incoming
            .iter()
            .find(|(_, slot)| slot.payment_hash == payment_hash)
            .map(|(operation_id, _)| operation_id.clone())
    }

    /// Build `n` fresh blinding triples (`secret`, `r`,
    /// `amount`) for a swap's outputs. Uses [`Secret::generate`]
    /// for each output; NUT-13 deterministic chains would be
    /// nicer but require the `wallet` feature, which we already
    /// pull in.
    fn fresh_outputs(
        n: usize,
        keyset_id: KeysetId,
        amounts: &[Amount],
    ) -> CashuResult<(Vec<BlindingTriple>, Vec<BlindedMessage>)> {
        let mut triples = Vec::with_capacity(n);
        let mut outputs = Vec::with_capacity(n);
        for &amount in amounts {
            let secret = Secret::generate();
            let (blinded, r) = blind_message(&secret.to_bytes(), None)
                .map_err(|e| CashuError::Nuts(format!("blind_message: {e}")))?;
            triples.push((secret, r, amount));
            outputs.push(BlindedMessage::new(amount, keyset_id, blinded));
        }
        Ok((triples, outputs))
    }

    /// Unblind a swap response into [`Proof`]s using a parallel
    /// list of `(secret, r, amount)` triples.
    fn unblind_response(
        response: cdk::nuts::nut03::SwapResponse,
        triples: Vec<BlindingTriple>,
        keys: &cdk::nuts::Keys,
    ) -> CashuResult<Proofs> {
        let mut proofs = Vec::with_capacity(response.signatures.len());
        for (sig, (secret, r, amount)) in response.signatures.into_iter().zip(triples) {
            let amount_key = keys
                .amount_key(amount)
                .ok_or_else(|| CashuError::Nuts("amount key missing".into()))?;
            let c = unblind_message(&sig.c, &r, &amount_key)
                .map_err(|e| CashuError::Nuts(format!("unblind: {e}")))?;
            let dleq: Option<ProofDleq> = sig.dleq.map(|d| ProofDleq::new(d.e, d.s, r.clone()));
            proofs.push(Proof {
                amount,
                keyset_id: sig.keyset_id,
                secret,
                c,
                witness: None,
                dleq,
                p2pk_e: None,
            });
        }
        Ok(proofs)
    }

    /// Pure NUT-03 swap: take any set of valid proofs in, return
    /// the new proofs in the active keyset. The inputs are burned
    /// at the mint, and the outputs are persisted to the wallet
    /// store before being returned. Used by the wallet's "receive"
    /// flow to swap arbitrary proofs into the wallet's preferred
    /// keyset.
    pub async fn redeem_proofs(&self, proofs: Proofs) -> CashuResult<Proofs> {
        if proofs.is_empty() {
            return Ok(Vec::new());
        }
        let keyset_id = self.active_keyset_id().await?;
        let keysets = self.ensure_keysets().await?;
        let keyset = keysets
            .iter()
            .find(|k| k.id == keyset_id)
            .cloned()
            .ok_or(CashuError::NoKeyset)?;
        let total: u64 = proofs.iter().map(|p| u64::from(p.amount)).sum();
        let fee_and_amounts = Self::build_fee_and_amounts(&keyset);
        let split = Self::split_for_swap(total, &fee_and_amounts)?;
        let keys = self.get_keys(&keyset_id).await?;
        let (triples, outputs) = Self::fresh_outputs(split.len(), keyset_id, &split)?;
        let request = cdk::nuts::nut03::SwapRequest::new(proofs, outputs);
        let response = self.client.post_swap(request).await?;
        let new_proofs = Self::unblind_response(response, triples, &keys)?;
        self.store.insert_proofs(&self.mint_url_str, &new_proofs)?;
        Ok(new_proofs)
    }

    /// Per-input fee (in sats) for the keyset the inputs are in.
    /// Rounds up: a 3-input swap on a keyset with input_fee_ppk
    /// 1000 pays 3 sats.
    fn input_fee_sat(num_inputs: usize, input_fee_ppk: u64) -> u64 {
        (input_fee_ppk.saturating_mul(num_inputs as u64)).div_ceil(1000)
    }

    /// Greedy pick: from `available` (assumed sorted by the
    /// caller) take the first proofs in `keyset_id` until their
    /// total amount covers `amount_sat` *plus* the mint's per-input
    /// fee for the picked set. Returns `(picked, picked_total,
    /// fee_sat)` where `picked_total >= amount_sat + fee_sat` when
    /// enough proofs exist (the surplus is the change). Empty
    /// `available` or no matching keyset returns `([], 0, 0)`.
    fn pick_inputs(
        available: &[Proof],
        keyset_id: KeysetId,
        amount_sat: u64,
        input_fee_ppk: u64,
    ) -> (Vec<Proof>, u64, u64) {
        let mut picked: Vec<Proof> = Vec::new();
        let mut total: u64 = 0;
        for proof in available {
            if proof.keyset_id != keyset_id {
                continue;
            }
            picked.push(proof.clone());
            total = total.saturating_add(u64::from(proof.amount));
            let fee_sat = Self::input_fee_sat(picked.len(), input_fee_ppk);
            if total >= amount_sat.saturating_add(fee_sat) {
                break;
            }
        }
        let fee_sat = Self::input_fee_sat(picked.len(), input_fee_ppk);
        (picked, total, fee_sat)
    }

    /// Wallet "send" helper: pick proofs from the wallet store
    /// whose net amount (after the mint's per-input fee) covers
    /// `amount_sat`, swap them at the mint, and return the
    /// outgoing proofs (for the recipient) plus the change proofs
    /// (for the wallet) plus the inputs the adapter has marked
    /// spent. The consumed inputs are removed from the store and
    /// the change is persisted automatically.
    ///
    /// Only proofs in the active keyset are eligible; the input
    /// fee is deducted by the mint and the surplus is returned as
    /// change. Empty store or insufficient funds is an error.
    pub async fn swap_proofs_for_amount(&self, amount_sat: u64) -> CashuResult<SendResult> {
        if amount_sat == 0 {
            return Err(CashuError::Nuts("amount must be > 0".into()));
        }
        let keyset_id = self.active_keyset_id().await?;
        let keysets = self.ensure_keysets().await?;
        let keyset = keysets
            .iter()
            .find(|k| k.id == keyset_id)
            .cloned()
            .ok_or(CashuError::NoKeyset)?;
        let input_fee_ppk = keyset.input_fee_ppk;
        let available = self.store.list_proofs(&self.mint_url_str)?;

        // Pick inputs covering `amount_sat` plus the per-input fee.
        // `pick_inputs` keeps adding proofs until the total is
        // `>= amount_sat + fee`, so any surplus is change.
        let (picked, total_in, fee_sat) =
            Self::pick_inputs(&available, keyset_id, amount_sat, input_fee_ppk);
        if total_in < amount_sat.saturating_add(fee_sat) {
            return Err(CashuError::Nuts(format!(
                "insufficient cashu balance: need {} sat (amount + fee), have {} sat",
                amount_sat.saturating_add(fee_sat),
                total_in
            )));
        }
        let change_sat = total_in.saturating_sub(amount_sat).saturating_sub(fee_sat);

        // Build outputs: amount_sat for the recipient + change_sat
        // back to the wallet, each in the active keyset's
        // denomination schedule.
        let fee_and_amounts = Self::build_fee_and_amounts(&keyset);
        let output_amounts = Self::split_for_swap(amount_sat, &fee_and_amounts)?;
        let change_amounts = if change_sat > 0 {
            Self::split_for_swap(change_sat, &fee_and_amounts)?
        } else {
            Vec::new()
        };
        let n_output = output_amounts.len();
        let mut all_amounts = output_amounts;
        all_amounts.extend(change_amounts);

        let keys = self.get_keys(&keyset_id).await?;
        let (triples, blinded_outputs) =
            Self::fresh_outputs(all_amounts.len(), keyset_id, &all_amounts)?;
        let request = cdk::nuts::nut03::SwapRequest::new(picked.clone(), blinded_outputs);
        let response = self.client.post_swap(request).await?;
        // The mint burned the picked inputs; drop them from the
        // store so balances stay accurate.
        self.store.remove_proofs(&self.mint_url_str, &picked)?;
        let new_proofs = Self::unblind_response(response, triples, &keys)?;
        // The mint returns signatures in the same order as the
        // blinded messages; the first n_output are the
        // recipient's portion, the rest is change.
        if new_proofs.len() < n_output {
            return Err(CashuError::Nuts(format!(
                "mint returned {} proofs, expected at least {n_output}",
                new_proofs.len()
            )));
        }
        let (output, change) = new_proofs.split_at(n_output);
        // Persist the change back to the wallet.
        if !change.is_empty() {
            self.store.insert_proofs(&self.mint_url_str, change)?;
        }
        Ok(SendResult {
            inputs_used: picked,
            output: output.to_vec(),
            change: change.to_vec(),
        })
    }

    async fn verify_mint_proofs(
        &self,
        proofs: &Proofs,
        payment_hash: Bytes32,
    ) -> Result<(), AdapterError> {
        if proofs.is_empty() {
            return Err(AdapterError::InvalidParams("empty Cashu proof set".into()));
        }
        let keyset_id = proofs[0].keyset_id;
        if proofs.iter().any(|proof| proof.keyset_id != keyset_id) {
            return Err(AdapterError::InvalidParams(
                "Cashu proof set mixes keysets".into(),
            ));
        }
        let keysets = self
            .ensure_keysets()
            .await
            .map_err(|error| AdapterError::Network(error.to_string()))?;
        let keyset = keysets
            .iter()
            .find(|keyset| keyset.id == keyset_id)
            .ok_or_else(|| AdapterError::InvalidParams("unknown Cashu keyset".into()))?;
        if !keyset.active || keyset.unit != CurrencyUnit::Sat {
            return Err(AdapterError::InvalidParams(
                "Cashu HTLC keyset is not active sat keyset".into(),
            ));
        }
        let recipient = PublicKey::from_slice(&self.claim_pubkey.0)
            .map_err(|error| AdapterError::InvalidParams(error.to_string()))?;
        verify_proofs_htlc_locked_for_recipient(proofs, &payment_hash.0, &recipient)
            .map_err(|error| AdapterError::InvalidParams(error.to_string()))?;
        let ys = proofs
            .iter()
            .map(proof_y)
            .collect::<CashuResult<Vec<_>>>()
            .map_err(|error| AdapterError::Network(error.to_string()))?;
        let response = self
            .client
            .post_check_state(CheckStateRequest { ys })
            .await
            .map_err(|error| AdapterError::Network(error.to_string()))?;
        if response.states.len() != proofs.len() {
            return Err(AdapterError::InvalidParams(
                "mint returned incomplete proof state set".into(),
            ));
        }
        for state in response.states {
            match state.state {
                ProofState::Unspent => {}
                ProofState::Pending | ProofState::Reserved => {
                    return Err(AdapterError::Retryable(
                        "Cashu proof is not settled yet".into(),
                    ));
                }
                ProofState::Spent | ProofState::PendingSpent => {
                    return Err(AdapterError::InvalidParams(
                        "Cashu proof is already spent".into(),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Result of [`CashuAdapter::swap_proofs_for_amount`]. The adapter
/// has already removed `inputs_used` from the store (the mint burned
/// them) and persisted `change` in the wallet; `output` is the
/// proof set to hand to the recipient.
#[derive(Clone, Debug)]
pub struct SendResult {
    pub inputs_used: Vec<Proof>,
    pub output: Vec<Proof>,
    pub change: Vec<Proof>,
}

#[async_trait]
impl NetworkAdapter for CashuAdapter {
    fn network_id(&self) -> NetworkId {
        self.network_id.clone()
    }

    /// Report the key we actually sign NUT-14 witnesses with, which is
    /// `self.secret_key`. Callers construct this adapter with different
    /// keys depending on the role (the payee uses its node key; a
    /// routing hop uses its per-network key), so deriving the identity
    /// from the signing key keeps the advertised identity truthful
    /// either way.
    ///
    /// Computed once in [`CashuAdapter::new`], so an unusable signing
    /// key fails loudly at construction rather than silently
    /// advertising an identity we cannot claim with.
    fn claim_pubkey(&self) -> XOnlyPubKey {
        self.claim_pubkey
    }

    /// Cashu contracts are confirmed in seconds (the swap endpoint
    /// returns the new blind signatures atomically with the
    /// input spend). 30 s gives the routing layer a comfortable
    /// margin to claim before the outgoing expiry kicks in.
    fn incoming_delta_secs(&self) -> u64 {
        30
    }

    /// Reserve an expected incoming HTLC. Cashu has no notion of
    /// "publishing" an incoming contract — the receiver just sits
    /// and waits for the sender to push the HTLC-locked proofs
    /// over (via the cross-network hop layer, out of band from
    /// the mint itself). We park an entry in
    /// [`CashuAdapter::incoming`], keyed by `request.operation_id`;
    /// the actual wait happens at
    /// [`NetworkAdapter::watch_incoming`] and
    /// [`NetworkAdapter::claim_incoming`] time, where we
    /// block on a [`Notify`] until the proofs land.
    ///
    /// A retry of the same operation returns the reservation already
    /// on record. A *different* operation claiming the same payment
    /// hash is rejected: a payment hash identifies intent, and one
    /// intent must never be reservable — or claimable — twice.
    async fn reserve_incoming(
        &self,
        request: IncomingRequest,
    ) -> Result<IncomingReservation, AdapterError> {
        if request.amount_msat == 0 {
            return Err(AdapterError::InvalidParams(
                "incoming amount must be > 0".into(),
            ));
        }
        if request.deadline <= now_unix_secs() {
            return Err(AdapterError::InvalidParams("deadline in the past".into()));
        }
        if request
            .preimage
            .is_some_and(|preimage| !request.payment_hash.matches_preimage(&preimage))
        {
            return Err(AdapterError::InvalidParams(
                "incoming preimage does not match payment hash".into(),
            ));
        }
        // Cashu works in sats; round the msat floor up.
        let amount_sat = request.amount_msat.div_ceil(1000).max(1);
        let mut incoming = self.incoming.lock().await;
        match incoming.get(&request.operation_id) {
            Some(slot)
                if slot.payment_hash == request.payment_hash
                    && slot.amount_msat == request.amount_msat
                    && slot.deadline == request.deadline =>
            {
                return Ok(self.incoming_reservation(&request.operation_id, slot));
            }
            Some(_) => {
                return Err(AdapterError::InvalidParams(
                    "Cashu operation id is already reserved for another payment hash".into(),
                ));
            }
            None => {}
        }
        if incoming
            .values()
            .any(|slot| slot.payment_hash == request.payment_hash)
        {
            return Err(AdapterError::Retryable(
                "Cashu payment hash already has an active reservation".into(),
            ));
        }
        incoming.insert(
            request.operation_id.clone(),
            PendingIncoming {
                payment_hash: request.payment_hash,
                payment_hash_hex: lowercase_hex::encode(request.payment_hash.0),
                amount_msat: request.amount_msat,
                amount_sat,
                deadline: request.deadline,
                proofs: Mutex::new(None),
                arrival: Arc::new(Notify::new()),
            },
        );
        let slot = incoming
            .get(&request.operation_id)
            .expect("reservation just inserted");
        Ok(self.incoming_reservation(&request.operation_id, slot))
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
                "restored Cashu reservation differs from persisted state".into(),
            ))
        }
    }

    /// Drop an unfunded reservation. Cashu holds nothing at the mint
    /// for an unfunded incoming HTLC — the sender simply never pushes
    /// the proofs — so releasing is a local delete.
    ///
    /// Cancelling unknown or already-cancelled operation is a no-op.
    /// Accepted/funded operation cannot be cancelled through this path.
    async fn cancel_incoming(&self, reservation: &IncomingReservation) -> Result<(), AdapterError> {
        let mut incoming = self.incoming.lock().await;
        let Some(slot) = incoming.get(&reservation.operation_id) else {
            return Ok(());
        };
        if slot.payment_hash != reservation.payment_hash
            || slot.amount_msat != reservation.amount_msat
            || slot.deadline != reservation.deadline
        {
            return Err(AdapterError::InvalidParams(
                "Cashu reservation operation id does not match this payment state".into(),
            ));
        }
        if slot.proofs.lock().await.is_some() {
            return Err(AdapterError::InvalidParams(
                "cannot cancel an accepted incoming Cashu operation".into(),
            ));
        }
        incoming.remove(&reservation.operation_id);
        Ok(())
    }

    /// Verify a funded incoming HTLC and commit it to its
    /// reservation. The proofs are checked against the mint (NUT-07)
    /// *and* against this adapter's claim key, so a descriptor we
    /// cannot actually spend is rejected before the hop commits its
    /// outgoing HTLC.
    async fn accept_incoming(
        &self,
        reservation: &IncomingReservation,
        descriptor: &HtlcDescriptor,
    ) -> Result<AcceptedIncoming, AdapterError> {
        // Re-accept of an operation we already committed: hand back
        // the proofs on record. Re-running the mint check here would
        // see them as spent once the claim has run, turning a
        // harmless retry into a failure.
        if let Some(accepted) = self.accepted_incoming(reservation).await? {
            return Ok(accepted);
        }
        let proofs = proofs_from_descriptor(descriptor)?;
        self.verify_mint_proofs(&proofs, reservation.payment_hash)
            .await?;
        let conditions = SpendingConditions::try_from(&proofs[0].secret)
            .map_err(|error| AdapterError::InvalidParams(error.to_string()))?;
        if conditions
            .locktime()
            .is_none_or(|locktime| locktime < reservation.deadline)
        {
            return Err(AdapterError::InvalidParams(
                "Cashu refund locktime opens before claim deadline".into(),
            ));
        }
        let amount_sat: u64 = proofs.iter().map(|p| u64::from(p.amount)).sum();
        let arrival = {
            let mut incoming = self.incoming.lock().await;
            let slot = incoming.get_mut(&reservation.operation_id).ok_or_else(|| {
                AdapterError::NotFound(format!(
                    "no incoming Cashu reservation for operation {}",
                    reservation.operation_id
                ))
            })?;
            if slot.payment_hash != reservation.payment_hash
                || slot.amount_msat != reservation.amount_msat
                || slot.deadline != reservation.deadline
            {
                return Err(AdapterError::InvalidParams(
                    "Cashu reservation operation id does not match this payment state".into(),
                ));
            }
            if amount_sat < slot.amount_sat {
                return Err(AdapterError::InvalidParams(format!(
                    "Cashu HTLC amount {amount_sat} sat below reserved {} sat",
                    slot.amount_sat
                )));
            }
            *slot.proofs.lock().await = Some(proofs);
            slot.arrival.clone()
        };
        arrival.notify_one();
        Ok(AcceptedIncoming {
            reservation: reservation.clone(),
            descriptor: descriptor.clone(),
            // Cashu denominates sats; report the observed native
            // amount in protocol msat.
            amount_msat: amount_sat.saturating_mul(1000),
        })
    }

    /// Rebuild the receiver-side wait state from a journal replay.
    ///
    /// Only local checks run here: the mint was already consulted when
    /// the HTLC was accepted, and a restart must not turn into a
    /// network round-trip that can fail while funds sit locked and
    /// claimable. The proofs are re-checked against the route hash and
    /// this adapter's claim key, and must still cover the reservation.
    async fn restore_incoming(&self, accepted: &AcceptedIncoming) -> Result<(), AdapterError> {
        let reservation = &accepted.reservation;
        let proofs = proofs_from_descriptor(&accepted.descriptor)?;
        if proofs.is_empty() {
            return Err(AdapterError::InvalidParams(
                "empty Cashu HTLC descriptor".into(),
            ));
        }
        let recipient = PublicKey::from_slice(&self.claim_pubkey.0)
            .map_err(|error| AdapterError::InvalidParams(error.to_string()))?;
        verify_proofs_htlc_locked_for_recipient(&proofs, &reservation.payment_hash.0, &recipient)
            .map_err(|error| AdapterError::InvalidParams(error.to_string()))?;
        let amount_sat: u64 = proofs.iter().map(|proof| u64::from(proof.amount)).sum();
        let amount_sat_floor = reservation.amount_msat.div_ceil(1000).max(1);
        if amount_sat < amount_sat_floor {
            return Err(AdapterError::InvalidParams(format!(
                "Cashu HTLC amount {amount_sat} sat below reserved {amount_sat_floor} sat"
            )));
        }
        let arrival = {
            let mut incoming = self.incoming.lock().await;
            // Keep an existing `Notify` so a waiter parked on the live
            // entry is not stranded by the replay.
            let arrival = incoming
                .get(&reservation.operation_id)
                .map(|slot| slot.arrival.clone())
                .unwrap_or_else(|| Arc::new(Notify::new()));
            incoming.insert(
                reservation.operation_id.clone(),
                PendingIncoming {
                    payment_hash: reservation.payment_hash,
                    payment_hash_hex: lowercase_hex::encode(reservation.payment_hash.0),
                    amount_msat: reservation.amount_msat,
                    amount_sat: amount_sat_floor,
                    deadline: reservation.deadline,
                    proofs: Mutex::new(Some(proofs)),
                    arrival: arrival.clone(),
                },
            );
            arrival
        };
        arrival.notify_waiters();
        Ok(())
    }

    /// Wait until the sender's proofs for this reservation have
    /// landed. The mint pushes nothing, so this parks on the same
    /// [`Notify`] the claimer waits on.
    async fn watch_incoming(
        &self,
        reservation: &IncomingReservation,
        deadline: u64,
    ) -> Result<(), AdapterError> {
        let (arrival, reservation_deadline) = {
            let incoming = self.incoming.lock().await;
            let slot = incoming.get(&reservation.operation_id).ok_or_else(|| {
                AdapterError::NotFound(format!(
                    "no incoming Cashu reservation for operation {}",
                    reservation.operation_id
                ))
            })?;
            if slot.payment_hash != reservation.payment_hash
                || slot.amount_msat != reservation.amount_msat
                || slot.deadline != reservation.deadline
            {
                return Err(AdapterError::InvalidParams(
                    "Cashu reservation operation id does not match this payment state".into(),
                ));
            }
            (slot.arrival.clone(), slot.deadline)
        };
        let ready = {
            let incoming = self.incoming.lock().await;
            let slot = incoming.get(&reservation.operation_id).ok_or_else(|| {
                AdapterError::NotFound(format!(
                    "no incoming Cashu reservation for operation {}",
                    reservation.operation_id
                ))
            })?;
            let ready = slot.proofs.lock().await.is_some();
            ready
        };
        if ready {
            return Ok(());
        }
        let deadline = deadline.min(reservation_deadline);
        loop {
            if now_unix_secs() >= deadline {
                return Err(AdapterError::DeadlineExceeded);
            }
            let wait = deadline.saturating_sub(now_unix_secs()).max(1);
            if tokio::time::timeout(std::time::Duration::from_secs(wait), arrival.notified())
                .await
                .is_err()
            {
                return Err(AdapterError::DeadlineExceeded);
            }
            let ready = {
                let incoming = self.incoming.lock().await;
                let Some(slot) = incoming.get(&reservation.operation_id) else {
                    return Err(AdapterError::NotFound(
                        "incoming Cashu reservation disappeared".to_string(),
                    ));
                };
                let ready = slot.proofs.lock().await.is_some();
                ready
            };
            if ready {
                return Ok(());
            }
        }
    }

    /// Claim an accepted incoming HTLC by swapping its locked proofs
    /// at the mint with `preimage` attached as a witness. The
    /// locktime is irrelevant on this path (the receiver is
    /// always allowed to spend per NUT-14).
    async fn claim_incoming(
        &self,
        accepted: &AcceptedIncoming,
        preimage: Bytes32,
    ) -> Result<(), AdapterError> {
        let payment_hash = accepted.reservation.payment_hash;
        // Check the preimage against the hash before it goes anywhere
        // near the mint: publishing a wrong preimage would make the
        // whole upstream chain claimable and settle nothing here.
        if !payment_hash.matches_preimage(&preimage) {
            return Err(AdapterError::InvalidParams(
                "preimage does not match the payment hash".into(),
            ));
        }
        let (arrival, deadline, proofs_slot) = {
            let incoming = self.incoming.lock().await;
            let slot = incoming
                .get(&accepted.reservation.operation_id)
                .ok_or_else(|| {
                    AdapterError::NotFound(format!(
                        "no incoming Cashu reservation for operation {}",
                        accepted.reservation.operation_id
                    ))
                })?;
            if slot.payment_hash != payment_hash {
                return Err(AdapterError::InvalidParams(
                    "Cashu reservation operation id does not match this payment".into(),
                ));
            }
            let proofs_slot = slot.proofs.lock().await.clone();
            let arrival = slot.arrival.clone();
            let slot_deadline = slot.deadline;
            (arrival, slot_deadline, proofs_slot)
        };
        // Block (with a small grace) until the proofs have
        // landed. The cross-network hop layer populates them
        // either via accept_incoming (multi-hop path) or via
        // create_outgoing on this same adapter (single-process test
        // path).
        if proofs_slot.is_none() {
            let grace = wait_grace_secs(deadline);
            if tokio::time::timeout(std::time::Duration::from_secs(grace), arrival.notified())
                .await
                .is_err()
            {
                return Err(AdapterError::Network(
                    "timed out waiting for HTLC proofs to arrive".into(),
                ));
            }
        }

        // Re-read after the (possible) wait.
        let locked: Proofs = {
            let incoming = self.incoming.lock().await;
            let slot = incoming
                .get(&accepted.reservation.operation_id)
                .ok_or_else(|| {
                    AdapterError::NotFound(format!(
                        "no incoming Cashu reservation for operation {}",
                        accepted.reservation.operation_id
                    ))
                })?;
            let proofs = slot.proofs.lock().await.clone();
            drop(incoming);
            proofs.ok_or_else(|| AdapterError::Network("HTLC proofs missing".into()))?
        };
        if locked.is_empty() {
            return Err(AdapterError::Network("HTLC proofs missing".into()));
        }

        // Sanity check the preimage actually matches the hash
        // the proofs are locked under. This is the receiver
        // path of NUT-14 and is what makes the swap at the
        // mint valid.
        // This is the point of no return for a payee: adding the
        // preimage to the witness and swapping at the mint publishes it,
        // making the whole upstream chain claimable. Log it before it
        // becomes public knowledge.
        self.span.in_scope(|| {
            tracing::info!(
                target: "cassis_cashu",
                "revealing preimage to mint for {} ({} proof(s))",
                payment_hash.short(),
                locked.len(),
            );
        });
        let mut proofs = locked;
        let signing_key = cdk::nuts::nut01::SecretKey::from_slice(&self.secret_key)
            .map_err(|e| AdapterError::Network(format!("invalid Cashu signing key: {e}")))?;
        add_preimage_to_proofs(&mut proofs, &preimage.0, &signing_key)
            .map_err(|e| AdapterError::InvalidParams(e.to_string()))?;
        verify_proofs_htlc(&proofs).map_err(|e| AdapterError::InvalidParams(e.to_string()))?;

        // Build the swap-to-self: outputs use unrestricted
        // spending conditions (no HTLC, no P2PK) so the
        // receiver can spend the resulting ecash directly.
        let keyset_id = proofs[0].keyset_id;
        let total_sat: u64 = proofs.iter().map(|p| u64::from(p.amount)).sum();
        let keyset = self
            .ensure_keysets()
            .await
            .map_err(|e| AdapterError::Network(e.to_string()))?
            .iter()
            .find(|k| k.id == keyset_id)
            .cloned()
            .ok_or_else(|| {
                AdapterError::Network(format!("mint no longer advertises keyset {keyset_id}"))
            })?;
        let fee_and_amounts = Self::build_fee_and_amounts(&keyset);
        let split = Self::split_for_swap(total_sat, &fee_and_amounts)
            .map_err(|e| AdapterError::Network(e.to_string()))?;
        let keys = self
            .get_keys(&keyset_id)
            .await
            .map_err(|e| AdapterError::Network(e.to_string()))?;
        let (triples, outputs) = Self::fresh_outputs(split.len(), keyset_id, &split)
            .map_err(|e| AdapterError::Network(e.to_string()))?;
        let request = cdk::nuts::nut03::SwapRequest::new(proofs, outputs);
        let response = self
            .client
            .post_swap(request)
            .await
            .map_err(|e| AdapterError::Network(e.to_string()))?;
        let new_proofs = Self::unblind_response(response, triples, &keys)
            .map_err(|e| AdapterError::Network(e.to_string()))?;
        // Add the freshly-minted proofs to the receiver's wallet
        // store so the adapter can spend them on future hops.
        self.add_balance(new_proofs)
            .await
            .map_err(|e| AdapterError::Network(e.to_string()))?;
        self.span.in_scope(|| {
            tracing::info!(
                target: "cassis_cashu",
                "htlc claimed for {}: {total_sat} sat swapped to unrestricted proofs",
                payment_hash.short(),
            );
        });

        // Drop the receiver's reservation now it is settled.
        self.incoming
            .lock()
            .await
            .remove(&accepted.reservation.operation_id);
        Ok(())
    }

    /// Claim straight from reservation state, for the native receive
    /// path where the caller only kept the reservation handle. The
    /// proofs deposited by [`NetworkAdapter::accept_incoming`] (or by
    /// the same-adapter create path) are all a claim needs, so this
    /// rebuilds the accepted handle and takes the normal claim route.
    async fn claim_reserved_incoming(
        &self,
        reservation: &IncomingReservation,
        preimage: Bytes32,
    ) -> Result<(), AdapterError> {
        let accepted = self.accepted_incoming(reservation).await?.ok_or_else(|| {
            AdapterError::Retryable(format!(
                "Cashu reservation {} is not funded yet",
                reservation.operation_id
            ))
        })?;
        self.claim_incoming(&accepted, preimage).await
    }

    /// Lock `request.amount_msat` of ecash behind the route payment
    /// hash by swapping unrestricted proofs (already in the adapter's
    /// local balance — see [`CashuAdapter::add_balance`] for the
    /// funding path) for HTLC-locked ones via NUT-03. The resulting
    /// proofs are stashed in [`CashuAdapter::outgoing`] and any
    /// matching incoming waiter is notified; the base64 descriptor
    /// travels back to the sender inside the returned
    /// [`OutgoingPayment`].
    async fn create_outgoing(
        &self,
        request: OutgoingRequest,
    ) -> Result<OutgoingPayment, AdapterError> {
        let _creation_guard = self.outgoing_creation_lock.lock().await;
        let recipient = match &request.target {
            HtlcTarget::XOnlyPubKey(pubkey) => *pubkey,
            HtlcTarget::PubKey(_)
            | HtlcTarget::LightningInvoice(_)
            | HtlcTarget::SparkAddress(_) => {
                return Err(AdapterError::InvalidParams(
                    "cashu requires a pubkey target".into(),
                ))
            }
        };
        if request.amount_msat == 0 {
            return Err(AdapterError::InvalidParams("amount must be > 0".into()));
        }
        if request.expiry <= now_unix_secs() {
            return Err(AdapterError::InvalidParams("expiry in the past".into()));
        }
        // Retry of an attempt we already funded: hand back the very
        // same payment rather than locking the funds a second time.
        if let Some(existing) = self.funded_outgoing(&request.operation_id).await? {
            if existing.payment_hash != request.payment_hash
                || existing.amount_msat != request.amount_msat
                || existing.destination != request.target
            {
                return Err(AdapterError::InvalidParams(
                    "outgoing retry does not match the operation already in flight".into(),
                ));
            }
            return Ok(existing);
        }
        if self
            .outgoing
            .lock()
            .await
            .values()
            .any(|slot| slot.payment_hash == request.payment_hash)
        {
            return Err(AdapterError::Retryable(
                "Cashu payment hash already has a live outgoing lock".into(),
            ));
        }
        let payment_hash = request.payment_hash;
        let amount_msat = request.amount_msat;
        let expiry = request.expiry;
        self.span.in_scope(|| {
            tracing::info!(
                target: "cassis_cashu",
                "preparing htlc {} amount={} msat locked to={}",
                payment_hash.short(),
                amount_msat,
                recipient.to_hex(),
            );
        });
        let amount_sat = amount_msat.div_ceil(1000).max(1);
        let keyset_id = self
            .active_keyset_id()
            .await
            .map_err(|e| AdapterError::Network(e.to_string()))?;
        let keysets = self
            .ensure_keysets()
            .await
            .map_err(|e| AdapterError::Network(e.to_string()))?;
        let keyset = keysets
            .iter()
            .find(|k| k.id == keyset_id)
            .ok_or_else(|| AdapterError::Network("active keyset disappeared".into()))?
            .clone();
        let receiver_pubkey = PublicKey::from_slice(&recipient.0)
            .map_err(|e| AdapterError::InvalidParams(e.to_string()))?;

        // Build the HTLC-locked outputs. The mint signs them
        // under the spending conditions embedded in each
        // blinded-message secret.
        let outputs = build_htlc_outputs(
            amount_sat,
            keyset_id,
            &payment_hash.0,
            expiry,
            &receiver_pubkey,
        )
        .map_err(|e| match e {
            CashuError::HtlcExpired => AdapterError::InvalidParams("expiry in past".into()),
            other => AdapterError::Network(other.to_string()),
        })?;
        let n_output = outputs.premints.len();

        // Pull unrestricted input proofs from the local
        // balance. The cross-network hop layer is expected to
        // top up the balance (NUT-04 mint, NUT-05 melt, or a
        // direct deposit) before any `pay_invoice` lands on the
        // cashu network. The greedy pick may overshoot
        // `amount_sat`; the surplus is returned as change below,
        // otherwise the mint rejects the swap as unbalanced
        // (inputs must equal outputs + fee).
        let available = self
            .store
            .list_proofs(&self.mint_url_str)
            .map_err(|e| AdapterError::Network(e.to_string()))?;
        let (inputs, inputs_total, fee_sat) =
            Self::pick_inputs(&available, keyset_id, amount_sat, keyset.input_fee_ppk);
        if inputs_total < amount_sat.saturating_add(fee_sat) {
            return Err(AdapterError::Network(format!(
                "insufficient cashu balance: need {} sat (amount + fee), have {} sat",
                amount_sat.saturating_add(fee_sat),
                inputs_total
            )));
        }
        let change_sat = inputs_total
            .saturating_sub(amount_sat)
            .saturating_sub(fee_sat);

        // Build unrestricted change outputs for the surplus so
        // the swap stays balanced.
        let fee_and_amounts = Self::build_fee_and_amounts(&keyset);
        let change_amounts = if change_sat > 0 {
            Self::split_for_swap(change_sat, &fee_and_amounts)
                .map_err(|e| AdapterError::Network(e.to_string()))?
        } else {
            Vec::new()
        };
        let (change_triples, change_blinded) =
            Self::fresh_outputs(change_amounts.len(), keyset_id, &change_amounts)
                .map_err(|e| AdapterError::Network(e.to_string()))?;

        let mut output_blinded = outputs
            .premints
            .iter()
            .map(|p| p.blinded_message.clone())
            .collect::<Vec<_>>();
        output_blinded.extend(change_blinded);

        let swap = cdk::nuts::nut03::SwapRequest::new(inputs.clone(), output_blinded);
        let response = self
            .client
            .post_swap(swap)
            .await
            .map_err(|e| AdapterError::Network(e.to_string()))?;
        // The mint burned the input proofs at the swap; drop them
        // from the wallet store so balances stay accurate.
        self.store
            .remove_proofs(&self.mint_url_str, &inputs)
            .map_err(|e| AdapterError::Network(e.to_string()))?;
        let keys = self
            .get_keys(&keyset_id)
            .await
            .map_err(|e| AdapterError::Network(e.to_string()))?;

        // Re-build the (secret, r, amount) triples in the same
        // order so the unblind lines up. The premints carry the
        // secrets and blinding factors; the response carries the
        // mint's blind signatures. HTLC premints come first,
        // change triples after.
        let mut triples: Vec<BlindingTriple> = outputs
            .premints
            .into_iter()
            .map(|p| (p.secret, p.r, p.amount))
            .collect();
        triples.extend(change_triples);
        let new_proofs = Self::unblind_response(response, triples, &keys)
            .map_err(|e| AdapterError::Network(e.to_string()))?;
        if new_proofs.len() < n_output {
            return Err(AdapterError::Network(format!(
                "mint returned {} proofs, expected at least {n_output}",
                new_proofs.len()
            )));
        }
        let (proofs, change) = new_proofs.split_at(n_output);
        // The proofs are freshly locked (no witness, locktime still in
        // the future), so `verify_htlc` cannot validate them; check
        // the secret structure against the payment hash instead.
        verify_proofs_htlc_locked(proofs, &payment_hash.0)
            .map_err(|e| AdapterError::Network(e.to_string()))?;
        // Persist the change back to the wallet.
        if !change.is_empty() {
            self.store
                .insert_proofs(&self.mint_url_str, change)
                .map_err(|e| AdapterError::Network(e.to_string()))?;
        }

        let conditions = htlc_conditions(&payment_hash.0, expiry, &receiver_pubkey)
            .map_err(|e| AdapterError::InvalidParams(e.to_string()))?;
        {
            let mut outgoing = self.outgoing.lock().await;
            outgoing.insert(
                request.operation_id.clone(),
                PendingOutgoing {
                    payment_hash,
                    amount_sat,
                    amount_msat,
                    locktime: expiry,
                    destination: request.target.clone(),
                    conditions,
                    keyset_id,
                    proofs: Mutex::new(proofs.to_vec()),
                    recipient: recipient.to_hex(),
                },
            );
        }
        // Cross-pollinate the incoming map for same-adapter receive flows.
        // The arrival notify wakes any waiting claimer.
        if let Some(receiver) = self.receiver_operation(payment_hash).await {
            let mut incoming = self.incoming.lock().await;
            if let Some(slot) = incoming.get_mut(&receiver) {
                *slot.proofs.lock().await = Some(proofs.to_vec());
                slot.arrival.notify_one();
            }
        }

        // Hand back the handle built from the state we just recorded,
        // so a retry can never see a different descriptor.
        self.funded_outgoing(&request.operation_id)
            .await
            .map(|payment| payment.expect("outgoing lock just recorded"))
    }

    /// Re-arm the sender-side watcher for a funded outgoing HTLC.
    /// Everything needed lives in `payment.descriptor`, so a journal
    /// replay rebuilds the state without asking the mint.
    async fn restore_outgoing(&self, payment: &OutgoingPayment) -> Result<(), AdapterError> {
        let proofs = proofs_from_descriptor(&payment.descriptor)?;
        if proofs.is_empty() {
            return Err(AdapterError::InvalidParams(
                "empty Cashu HTLC descriptor".into(),
            ));
        }
        let conditions = SpendingConditions::try_from(&proofs[0].secret)
            .map_err(|e| AdapterError::InvalidParams(format!("decode Cashu conditions: {e}")))?;
        let locktime = match &conditions {
            SpendingConditions::HTLCConditions {
                data,
                conditions: Some(conditions),
            } => {
                if data.as_byte_array() != &payment.payment_hash.0 {
                    return Err(AdapterError::InvalidParams(
                        "Cashu descriptor hash does not match outgoing payment".into(),
                    ));
                }
                conditions.locktime.ok_or_else(|| {
                    AdapterError::InvalidParams("Cashu HTLC has no refund locktime".into())
                })?
            }
            _ => {
                return Err(AdapterError::InvalidParams(
                    "descriptor is not a Cashu HTLC".into(),
                ))
            }
        };
        let amount_sat: u64 = proofs.iter().map(|proof| u64::from(proof.amount)).sum();
        if amount_sat < payment.amount_msat.div_ceil(1000) {
            return Err(AdapterError::InvalidParams(
                "Cashu descriptor amount is below outgoing payment".into(),
            ));
        }
        // Already tracking this attempt: keep the live proofs rather
        // than swapping in the journal copy.
        {
            let outgoing = self.outgoing.lock().await;
            if let Some(slot) = outgoing.get(&payment.operation_id) {
                return if slot.payment_hash == payment.payment_hash {
                    Ok(())
                } else {
                    Err(AdapterError::InvalidParams(
                        "outgoing operation id is already funding another payment hash".into(),
                    ))
                };
            }
        }
        let recipient = match &payment.destination {
            HtlcTarget::XOnlyPubKey(pubkey) => pubkey.to_hex(),
            HtlcTarget::PubKey(_)
            | HtlcTarget::LightningInvoice(_)
            | HtlcTarget::SparkAddress(_) => {
                return Err(AdapterError::InvalidParams(
                    "cashu requires a pubkey destination".into(),
                ))
            }
        };
        self.outgoing.lock().await.insert(
            payment.operation_id.clone(),
            PendingOutgoing {
                payment_hash: payment.payment_hash,
                amount_sat,
                amount_msat: payment.amount_msat,
                locktime,
                destination: payment.destination.clone(),
                conditions,
                keyset_id: proofs[0].keyset_id,
                proofs: Mutex::new(proofs),
                recipient,
            },
        );
        Ok(())
    }

    /// Refund an outgoing HTLC after the locktime has passed.
    /// We swap the locked proofs back at the mint with
    /// unrestricted output conditions (no witness). NUT-14
    /// allows the sender path once the locktime is reached.
    async fn refund_outgoing(&self, payment: &OutgoingPayment) -> Result<(), AdapterError> {
        let (proofs, locktime) = {
            let outgoing = self.outgoing.lock().await;
            let slot = outgoing.get(&payment.operation_id).ok_or_else(|| {
                AdapterError::NotFound(format!(
                    "no outgoing Cashu lock for operation {}",
                    payment.operation_id
                ))
            })?;
            if slot.payment_hash != payment.payment_hash {
                return Err(AdapterError::InvalidParams(
                    "outgoing operation id does not match this payment".into(),
                ));
            }
            let proofs = slot.proofs.lock().await.clone();
            let locktime = slot.locktime;
            (proofs, locktime)
        };
        if proofs.is_empty() {
            return Err(AdapterError::InvalidParams(
                "outgoing HTLC has no proofs".into(),
            ));
        }
        if now_unix_secs() <= locktime {
            return Err(AdapterError::Retryable(
                "locktime has not yet passed; cannot refund".into(),
            ));
        }
        let keyset_id = proofs[0].keyset_id;
        let total_sat: u64 = proofs.iter().map(|p| u64::from(p.amount)).sum();
        let keyset = self
            .ensure_keysets()
            .await
            .map_err(|e| AdapterError::Network(e.to_string()))?
            .iter()
            .find(|k| k.id == keyset_id)
            .cloned()
            .ok_or_else(|| {
                AdapterError::Network(format!("mint no longer advertises keyset {keyset_id}"))
            })?;
        let fee_and_amounts = Self::build_fee_and_amounts(&keyset);
        let split = Self::split_for_swap(total_sat, &fee_and_amounts)
            .map_err(|e| AdapterError::Network(e.to_string()))?;
        let keys = self
            .get_keys(&keyset_id)
            .await
            .map_err(|e| AdapterError::Network(e.to_string()))?;
        let (triples, outputs) = Self::fresh_outputs(split.len(), keyset_id, &split)
            .map_err(|e| AdapterError::Network(e.to_string()))?;
        let request = cdk::nuts::nut03::SwapRequest::new(proofs, outputs);
        let response = self
            .client
            .post_swap(request)
            .await
            .map_err(|e| AdapterError::Network(e.to_string()))?;
        // The refunded proofs are unrestricted ecash we hold again;
        // persist them so the wallet can spend them later.
        let refunded = Self::unblind_response(response, triples, &keys)
            .map_err(|e| AdapterError::Network(e.to_string()))?;
        self.add_balance(refunded)
            .await
            .map_err(|e| AdapterError::Network(e.to_string()))?;
        self.outgoing.lock().await.remove(&payment.operation_id);
        Ok(())
    }

    /// Wait for the receiver of our outgoing HTLC to claim. We
    /// poll NUT-07's `check_state` endpoint for each proof; once
    /// any proof is `SPENT`, the receiver has swapped it (with
    /// the preimage witness) and we can read the preimage off
    /// the proof's witness.
    async fn watch_outgoing(
        &self,
        payment: &OutgoingPayment,
        deadline: u64,
    ) -> Result<Bytes32, AdapterError> {
        let proofs: Proofs = {
            let outgoing = self.outgoing.lock().await;
            let slot = outgoing.get(&payment.operation_id).ok_or_else(|| {
                AdapterError::NotFound(format!(
                    "no outgoing Cashu lock for operation {}",
                    payment.operation_id
                ))
            })?;
            if slot.payment_hash != payment.payment_hash {
                return Err(AdapterError::InvalidParams(
                    "outgoing operation id does not match this payment".into(),
                ));
            }
            let proofs = slot.proofs.lock().await.clone();
            drop(outgoing);
            proofs
        };
        if proofs.is_empty() {
            return Err(AdapterError::Network("outgoing HTLC has no proofs".into()));
        }
        let payment_hash = payment.payment_hash;
        let ys: Vec<_> = proofs
            .iter()
            .map(proof_y)
            .collect::<CashuResult<Vec<_>>>()
            .map_err(|e| AdapterError::Network(e.to_string()))?;
        let req = CheckStateRequest { ys };

        let poll_interval = std::time::Duration::from_secs(2);
        loop {
            let resp = self
                .client
                .post_check_state(req.clone())
                .await
                .map_err(|e| AdapterError::Network(e.to_string()))?;
            let spent = resp
                .states
                .iter()
                .find(|s| s.state == ProofState::Spent)
                .cloned();
            if let Some(spent) = spent {
                let preimage_hex = match spent.witness.as_ref() {
                    Some(Witness::HTLCWitness(HTLCWitness { preimage, .. })) => preimage.clone(),
                    _ => {
                        return Err(AdapterError::Network(
                            "HTLC spent but no preimage in witness (refund path?)".into(),
                        ));
                    }
                };
                let bytes = cdk::util::hex::decode(&preimage_hex)
                    .map_err(|e| AdapterError::Network(format!("decode preimage: {e}")))?;
                if bytes.len() != 32 {
                    return Err(AdapterError::Network("preimage wrong length".into()));
                }
                let mut out = [0u8; 32];
                out.copy_from_slice(&bytes);
                let preimage = Bytes32(out);
                if !payment_hash.matches_preimage(&preimage) {
                    return Err(AdapterError::Network(
                        "mint revealed a preimage for a different payment hash".into(),
                    ));
                }
                self.span.in_scope(|| {
                    tracing::info!(
                        target: "cassis_cashu",
                        "preimage revealed in mint witness for {}",
                        payment_hash.short(),
                    );
                });
                return Ok(preimage);
            }
            if now_unix_secs() >= deadline {
                return Err(AdapterError::DeadlineExceeded);
            }
            tokio::time::sleep(poll_interval).await;
        }
    }

    /// PREPARE-time check: do we have enough unrestricted ecash
    /// in the wallet store to back an outgoing HTLC of
    /// `amount_msat`? We round up to sats the same way
    /// [`NetworkAdapter::create_outgoing`] does, so
    /// a green light here means the actual swap won't fail for
    /// lack of funds.
    async fn can_route(&self, amount_msat: u64) -> Result<(), AdapterError> {
        let amount_sat = amount_msat.div_ceil(1000).max(1);
        let keyset_id = self
            .active_keyset_id()
            .await
            .map_err(|e| AdapterError::Network(e.to_string()))?;
        let proofs = self
            .store
            .list_proofs(&self.mint_url_str)
            .map_err(|e| AdapterError::Network(e.to_string()))?;

        let total_sat: u64 = proofs
            .iter()
            .filter(|p| p.keyset_id == keyset_id)
            .map(|p| u64::from(p.amount))
            .sum();
        if total_sat < amount_sat {
            return Err(AdapterError::InvalidParams(format!(
                "insufficient cashu balance: need {amount_sat} sat, have {total_sat} sat"
            )));
        }
        Ok(())
    }

    /// Claiming a Cashu HTLC swaps proofs we already hold for
    /// unrestricted ones at the mint: the claim costs no balance of
    /// its own, so there is nothing to pre-check here.
    async fn can_claim(&self, _amount_msat: u64) -> Result<(), AdapterError> {
        Ok(())
    }
}

/// Serialize a NUT-14 proof list into the wire descriptor the hop
/// protocol carries. The reverse direction is
/// [`proofs_from_descriptor`].
fn cashu_descriptor(proofs: &Proofs) -> Result<HtlcDescriptor, AdapterError> {
    if proofs.is_empty() {
        return Err(AdapterError::Network("outgoing HTLC has no proofs".into()));
    }
    let mut encoded = Vec::with_capacity(proofs.len());
    for proof in proofs {
        let json = serde_json::to_string(proof)
            .map_err(|e| AdapterError::Network(format!("encode proof: {e}")))?;
        encoded.push(BASE64.encode(json.as_bytes()));
    }
    Ok(HtlcDescriptor::Cashu {
        proofs_b64: encoded,
    })
}

/// Decode the base64-encoded NUT-14 proof list out of a
/// [`HtlcDescriptor::Cashu`]. Any other variant is a hard error:
/// cashu is the only network with a populated descriptor today.
fn proofs_from_descriptor(descriptor: &HtlcDescriptor) -> Result<Proofs, AdapterError> {
    match descriptor {
        HtlcDescriptor::Cashu { proofs_b64 } => {
            let mut out = Vec::with_capacity(proofs_b64.len());
            for s in proofs_b64 {
                let raw = BASE64
                    .decode(s)
                    .map_err(|e| AdapterError::Network(format!("base64 decode: {e}")))?;
                let proof: Proof = serde_json::from_slice(&raw)
                    .map_err(|e| AdapterError::Network(format!("decode proof: {e}")))?;
                out.push(proof);
            }
            Ok(out)
        }
        other => Err(AdapterError::Network(format!(
            "unsupported htlc descriptor for cashu network: {other:?}"
        ))),
    }
}

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn wait_grace_secs(deadline: u64) -> u64 {
    deadline.saturating_sub(now_unix_secs()).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use store::InMemoryProofStore;

    fn test_store() -> Arc<dyn CashuProofStore> {
        Arc::new(InMemoryProofStore::new())
    }

    #[test]
    fn new_accepts_a_valid_mint_url() {
        let adapter = CashuAdapter::new(
            NetworkId("mint.example.com".to_string()),
            "https://mint.example.com".to_string(),
            [1u8; 32],
            test_store(),
            Span::none(),
        );
        assert!(adapter.is_ok(), "valid url should construct");
    }

    #[test]
    fn new_rejects_garbage_mint_url() {
        let adapter = CashuAdapter::new(
            NetworkId("not a url".to_string()),
            "not a url".to_string(),
            [1u8; 32],
            test_store(),
            Span::none(),
        );
        assert!(
            adapter.is_err(),
            "garbage url must be rejected, not silently replaced"
        );
    }

    #[test]
    fn new_rejects_empty_mint_url() {
        let adapter = CashuAdapter::new(
            NetworkId("".to_string()),
            "".to_string(),
            [1u8; 32],
            test_store(),
            Span::none(),
        );
        assert!(adapter.is_err(), "empty url must be rejected");
    }

    #[test]
    fn input_fee_zero_ppk_pays_nothing() {
        assert_eq!(CashuAdapter::input_fee_sat(0, 0), 0);
        assert_eq!(CashuAdapter::input_fee_sat(10, 0), 0);
    }

    #[test]
    fn input_fee_one_ppk_rounds_up() {
        // 1000 ppk = 1 sat per input. 3 inputs = 3 sats.
        assert_eq!(CashuAdapter::input_fee_sat(1, 1000), 1);
        assert_eq!(CashuAdapter::input_fee_sat(3, 1000), 3);
        // 500 ppk = 0.5 sat per input, rounds up.
        assert_eq!(CashuAdapter::input_fee_sat(1, 500), 1);
        assert_eq!(CashuAdapter::input_fee_sat(2, 500), 1);
    }

    #[test]
    fn input_fee_does_not_panic_on_large_ppk() {
        // Saturating mul: a 32-bit ppk times a 32-bit count is
        // bounded; the function must not overflow.
        let _ = CashuAdapter::input_fee_sat(usize::MAX, u64::MAX);
    }

    fn fake_proof(amount: u64, keyset: KeysetId) -> Proof {
        Proof {
            amount: Amount::from(amount),
            keyset_id: keyset,
            secret: Secret::generate(),
            c: cdk::nuts::nut01::PublicKey::from_str(
                "02bc9097997d81afb2cc7346b5e4345a9346bd2a506eb7958598a72f0cf85163ea",
            )
            .unwrap(),
            witness: None,
            dleq: None,
            p2pk_e: None,
        }
    }

    #[test]
    fn pick_inputs_skips_wrong_keyset() {
        let target = KeysetId::from_str("009a1f293253e41e").unwrap();
        let other = KeysetId::from_str("009a1f293253e41f").unwrap();
        let proofs = vec![
            fake_proof(1, other),
            fake_proof(2, target),
            fake_proof(4, other),
            fake_proof(8, target),
        ];
        let (picked, total, fee) = CashuAdapter::pick_inputs(&proofs, target, 5, 0);
        // 2-sat is the first matching proof; 4-sat is skipped
        // (wrong keyset); 8-sat is the second matching proof
        // and meets the 5-sat target. Both target-keyset
        // proofs are picked, the other-keyset one is not.
        assert_eq!(picked.len(), 2);
        assert_eq!(total, 10);
        assert_eq!(fee, 0);
        assert!(picked.iter().all(|p| p.keyset_id == target));
    }

    #[test]
    fn pick_inputs_stops_once_target_reached() {
        let target = KeysetId::from_str("009a1f293253e41e").unwrap();
        let proofs = vec![
            fake_proof(1, target),
            fake_proof(2, target),
            fake_proof(4, target),
        ];
        let (picked, total, fee) = CashuAdapter::pick_inputs(&proofs, target, 3, 0);
        // 1 + 2 already meets the 3-sat target; the 4 should
        // not be picked.
        assert_eq!(picked.len(), 2);
        assert_eq!(total, 3);
        assert_eq!(fee, 0);
    }

    #[test]
    fn pick_inputs_returns_empty_when_nothing_matches() {
        let target = KeysetId::from_str("009a1f293253e41e").unwrap();
        let other = KeysetId::from_str("009a1f293253e41f").unwrap();
        let proofs = vec![fake_proof(1, other), fake_proof(2, other)];
        let (picked, total, fee) = CashuAdapter::pick_inputs(&proofs, target, 1, 0);
        assert!(picked.is_empty());
        assert_eq!(total, 0);
        assert_eq!(fee, 0);
    }

    #[test]
    fn pick_inputs_covers_amount_plus_fee() {
        let target = KeysetId::from_str("009a1f293253e41e").unwrap();
        // 1000 ppk = 1 sat per input.
        let proofs = vec![fake_proof(4, target), fake_proof(8, target)];
        // 4 sat covers amount 4 but not amount 4 + 1 sat fee;
        // the picker must keep going and grab the 8.
        let (picked, total, fee) = CashuAdapter::pick_inputs(&proofs, target, 4, 1000);
        assert_eq!(picked.len(), 2);
        assert_eq!(total, 12);
        assert_eq!(fee, 2);
        // total >= amount + fee holds.
        assert!(total >= 4 + fee);
    }
}
