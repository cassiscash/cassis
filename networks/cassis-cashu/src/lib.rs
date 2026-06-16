use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use cassis_core::{
    Bytes32, HtlcDescriptor, HtlcError, IncomingHtlc, NetworkId, NetworkRouterAdapter,
    OutgoingHtlc, WatchError,
};
use cdk::amount::{FeeAndAmounts, SplitTarget};
use cdk::dhke::{blind_message, unblind_message};
use cdk::mint_url::MintUrl;
use cdk::nuts::nut00::{BlindedMessage, Proofs};
use cdk::nuts::nut02::Id as KeysetId;
use cdk::nuts::nut07::{CheckStateRequest, State as ProofState};
use cdk::nuts::nut10::SpendingConditions;
use cdk::nuts::nut12::ProofDleq;
use cdk::nuts::nut14::HTLCWitness;
use cdk::nuts::{CurrencyUnit, KeySetInfo, KeysetResponse, Witness};
use cdk::secret::Secret;
use cdk::wallet::MintConnector;
use cdk::Amount;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::{Mutex, Notify};

mod errors;
mod htlc;
mod store;

pub use cdk::nuts::nut00::Proof;
pub use errors::CashuError as Error;
use errors::{CashuError, CashuResult};
use htlc::{
    add_preimage_to_proofs, build_htlc_outputs, htlc_conditions, proof_y, verify_proofs_htlc,
    verify_proofs_htlc_locked,
};
pub use store::CashuProofStore;

/// Receiver-side state for an outstanding incoming HTLC.
pub struct PendingIncoming {
    /// SHA-256 of the preimage, hex-encoded the way the cashu
    /// secret `data` field wants it.
    payment_hash_hex: String,
    /// Face value of the HTLC, in sats.
    amount_sat: u64,
    /// Unix deadline after which the receiver gives up waiting
    /// for the sender's proofs to arrive.
    deadline: u64,
    /// HTLC-locked proofs the sender (or previous hop) pushed to
    /// us. Populated by
    /// [`NetworkRouterAdapter::accept_incoming_htlc`] in the
    /// multi-hop flow, or by
    /// [`NetworkRouterAdapter::create_outgoing_htlc`] in the
    /// single-process test flow. None until then; in the
    /// single-process test the create-side fills it in and
    /// notifies `arrival`.
    proofs: Mutex<Option<Proofs>>,
    /// Notified when the matching HTLC proofs have been deposited
    /// by the create-side or by
    /// [`NetworkRouterAdapter::accept_incoming_htlc`].
    arrival: Arc<Notify>,
}

/// Sender-side state for an outstanding outgoing HTLC.
struct PendingOutgoing {
    /// Face value of the HTLC, in sats.
    #[allow(dead_code)]
    amount_sat: u64,
    /// Unix locktime after which the sender can refund.
    #[allow(dead_code)]
    locktime: u64,
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
    #[allow(dead_code)]
    secret_key: [u8; 32],
    keysets: Arc<Mutex<Vec<KeySetInfo>>>,
    /// In-flight outgoing HTLCs we have locked at the mint, keyed
    /// by the payment hash so the cross-network hop layer can pair
    /// each sender-side lock with the matching receiver-side
    /// claim.
    outgoing: Mutex<HashMap<Bytes32, PendingOutgoing>>,
    /// In-flight incoming HTLCs we are expecting proofs for, keyed
    /// by the same payment hash.
    incoming: Mutex<HashMap<Bytes32, PendingIncoming>>,
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
    ) -> CashuResult<Self> {
        let mint_url_str = mint_url.clone();
        let mint_url = MintUrl::from_str(&mint_url)
            .map_err(|e| CashuError::Nuts(format!("invalid mint url '{mint_url}': {e}")))?;
        let client = cdk::wallet::HttpClient::new(mint_url.clone(), None);
        Ok(Self {
            network_id,
            mint_url,
            mint_url_str,
            client,
            secret_key,
            keysets: Arc::new(Mutex::new(Vec::new())),
            outgoing: Mutex::new(HashMap::new()),
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
    /// accessor).
    pub async fn outgoing_proofs(&self, payment_hash: Bytes32) -> Option<Vec<Proof>> {
        let outgoing = self.outgoing.lock().await;
        let slot = outgoing.get(&payment_hash)?;
        let proofs = slot.proofs.lock().await.clone();
        drop(outgoing);
        Some(proofs)
    }

    /// Look up a receiver-side pending incoming HTLC.
    pub async fn incoming_slot(&self, payment_hash: Bytes32) -> Option<PendingIncoming> {
        let incoming = self.incoming.lock().await;
        let slot = incoming.get(&payment_hash)?;
        let proofs = slot.proofs.lock().await.clone();
        Some(PendingIncoming {
            payment_hash_hex: slot.payment_hash_hex.clone(),
            amount_sat: slot.amount_sat,
            deadline: slot.deadline,
            proofs: Mutex::new(proofs),
            arrival: slot.arrival.clone(),
        })
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
    ) -> CashuResult<(
        Vec<(Secret, cdk::nuts::nut01::SecretKey, Amount)>,
        Vec<BlindedMessage>,
    )> {
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
        triples: Vec<(Secret, cdk::nuts::nut01::SecretKey, Amount)>,
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
impl NetworkRouterAdapter for CashuAdapter {
    fn network_id(&self) -> NetworkId {
        self.network_id.clone()
    }

    /// Cashu contracts are confirmed in seconds (the swap endpoint
    /// returns the new blind signatures atomically with the
    /// input spend). 30 s gives the routing layer a comfortable
    /// margin to claim before the outgoing expiry kicks in.
    fn incoming_delta_secs(&self) -> u64 {
        30
    }

    /// Register an expected incoming HTLC. Cashu has no notion of
    /// "publishing" an incoming contract — the receiver just sits
    /// and waits for the sender to push the HTLC-locked proofs
    /// over (via the cross-network hop layer, out of band from
    /// the mint itself). We park an entry in
    /// [`CashuAdapter::incoming`] and return immediately; the
    /// actual wait happens at
    /// [`NetworkRouterAdapter::claim_incoming`] time, where we
    /// block on a [`Notify`] until the proofs land.
    async fn watch_incoming_htlc(
        &self,
        payment_hash: Bytes32,
        min_amount_msat: u64,
        deadline: u64,
    ) -> Result<IncomingHtlc, WatchError> {
        // Cashu works in sats; round the msat floor up.
        let min_amount_sat = min_amount_msat.div_ceil(1000).max(1);
        let arrival = Arc::new(Notify::new());
        let payment_hash_hex = htlc::payment_hash_hex(&payment_hash.0);
        let mut incoming = self.incoming.lock().await;
        incoming.insert(
            payment_hash,
            PendingIncoming {
                payment_hash_hex,
                amount_sat: min_amount_sat,
                deadline,
                proofs: Mutex::new(None),
                arrival,
            },
        );
        Ok(IncomingHtlc {
            payment_hash,
            amount_msat: min_amount_msat,
            expiry: deadline,
            sender: String::new(),
            network: self.network_id.clone(),
        })
    }

    /// Lock `amount_msat` of ecash behind `payment_hash` by
    /// swapping unrestricted proofs (already in the adapter's
    /// local balance — see [`CashuAdapter::add_balance`] for the
    /// funding path) for HTLC-locked ones via NUT-03. The
    /// resulting proofs are stashed in [`CashuAdapter::outgoing`]
    /// and any matching incoming waiter is notified.
    async fn create_outgoing_htlc(
        &self,
        payment_hash: Bytes32,
        amount_msat: u64,
        expiry: u64,
        recipient: &str,
    ) -> Result<OutgoingHtlc, HtlcError> {
        if amount_msat == 0 {
            return Err(HtlcError::InvalidParams("amount must be > 0".into()));
        }
        if expiry <= now_unix_secs() {
            return Err(HtlcError::InvalidParams("expiry in the past".into()));
        }
        let amount_sat = amount_msat.div_ceil(1000).max(1);
        let keyset_id = self
            .active_keyset_id()
            .await
            .map_err(|e| HtlcError::Network(e.to_string()))?;
        let keysets = self
            .ensure_keysets()
            .await
            .map_err(|e| HtlcError::Network(e.to_string()))?;
        let keyset = keysets
            .iter()
            .find(|k| k.id == keyset_id)
            .ok_or_else(|| HtlcError::Network("active keyset disappeared".into()))?
            .clone();
        let conditions = htlc_conditions(&payment_hash.0, expiry)
            .map_err(|e| HtlcError::InvalidParams(e.to_string()))?;
        let _ = conditions; // included in the swap's blinded-message secrets by build_htlc_outputs

        // Build the HTLC-locked outputs. The mint signs them
        // under the spending conditions embedded in each
        // blinded-message secret.
        let outputs = build_htlc_outputs(amount_sat, keyset_id, &payment_hash.0, expiry).map_err(
            |e| match e {
                CashuError::HtlcExpired => HtlcError::InvalidParams("expiry in past".into()),
                other => HtlcError::Network(other.to_string()),
            },
        )?;
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
            .map_err(|e| HtlcError::Network(e.to_string()))?;
        let (inputs, inputs_total, fee_sat) =
            Self::pick_inputs(&available, keyset_id, amount_sat, keyset.input_fee_ppk);
        if inputs_total < amount_sat.saturating_add(fee_sat) {
            return Err(HtlcError::Network(format!(
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
                .map_err(|e| HtlcError::Network(e.to_string()))?
        } else {
            Vec::new()
        };
        let (change_triples, change_blinded) =
            Self::fresh_outputs(change_amounts.len(), keyset_id, &change_amounts)
                .map_err(|e| HtlcError::Network(e.to_string()))?;

        let mut output_blinded = outputs
            .premints
            .iter()
            .map(|p| p.blinded_message.clone())
            .collect::<Vec<_>>();
        output_blinded.extend(change_blinded);

        let request = cdk::nuts::nut03::SwapRequest::new(inputs.clone(), output_blinded);
        let response = self
            .client
            .post_swap(request)
            .await
            .map_err(|e| HtlcError::Network(e.to_string()))?;
        // The mint burned the input proofs at the swap; drop them
        // from the wallet store so balances stay accurate.
        self.store
            .remove_proofs(&self.mint_url_str, &inputs)
            .map_err(|e| HtlcError::Network(e.to_string()))?;
        let keys = self
            .get_keys(&keyset_id)
            .await
            .map_err(|e| HtlcError::Network(e.to_string()))?;

        // Re-build the (secret, r, amount) triples in the same
        // order so the unblind lines up. The premints carry the
        // secrets and blinding factors; the response carries the
        // mint's blind signatures. HTLC premints come first,
        // change triples after.
        let mut triples: Vec<(Secret, cdk::nuts::nut01::SecretKey, Amount)> = outputs
            .premints
            .into_iter()
            .map(|p| (p.secret, p.r, p.amount))
            .collect();
        triples.extend(change_triples);
        let new_proofs = Self::unblind_response(response, triples, &keys)
            .map_err(|e| HtlcError::Network(e.to_string()))?;
        if new_proofs.len() < n_output {
            return Err(HtlcError::Network(format!(
                "mint returned {} proofs, expected at least {n_output}",
                new_proofs.len()
            )));
        }
        let (proofs, change) = new_proofs.split_at(n_output);
        // The proofs are freshly locked (no witness, locktime still in
        // the future), so `verify_htlc` cannot validate them; check
        // the secret structure against the payment hash instead.
        verify_proofs_htlc_locked(proofs, &payment_hash.0)
            .map_err(|e| HtlcError::Network(e.to_string()))?;
        // Persist the change back to the wallet.
        if !change.is_empty() {
            self.store
                .insert_proofs(&self.mint_url_str, change)
                .map_err(|e| HtlcError::Network(e.to_string()))?;
        }

        {
            let mut outgoing = self.outgoing.lock().await;
            outgoing.insert(
                payment_hash,
                PendingOutgoing {
                    amount_sat,
                    locktime: expiry,
                    conditions: htlc_conditions(&payment_hash.0, expiry)
                        .map_err(|e| HtlcError::InvalidParams(e.to_string()))?,
                    keyset_id,
                    proofs: Mutex::new(proofs.to_vec()),
                    recipient: recipient.to_string(),
                },
            );
        }
        // Cross-pollinate the incoming map so a same-process
        // claim_incoming call (legacy test path) can find the
        // proofs without going through the cross-network
        // descriptor. The arrival notify wakes any waiting
        // claimer.
        let arrival = {
            let mut incoming = self.incoming.lock().await;
            if let Some(slot) = incoming.get_mut(&payment_hash) {
                *slot.proofs.lock().await = Some(proofs.to_vec());
                Some(slot.arrival.clone())
            } else {
                None
            }
        };
        if let Some(arrival) = arrival {
            arrival.notify_one();
        }

        Ok(OutgoingHtlc {
            payment_hash,
            amount_msat,
            expiry,
            recipient: recipient.to_string(),
            network: self.network_id.clone(),
        })
    }

    /// Claim an incoming HTLC by swapping its locked proofs at
    /// the mint with `preimage` attached as a witness. The
    /// locktime is irrelevant on this path (the receiver is
    /// always allowed to spend per NUT-14).
    async fn claim_incoming(
        &self,
        payment_hash: Bytes32,
        preimage: Bytes32,
    ) -> Result<(), HtlcError> {
        let (arrival, deadline, proofs_slot) = {
            let incoming = self.incoming.lock().await;
            match incoming.get(&payment_hash) {
                Some(s) => (s.arrival.clone(), s.deadline, s.proofs.lock().await.clone()),
                None => {
                    return Err(HtlcError::InvalidParams(format!(
                        "no incoming HTLC registered for {payment_hash:?}"
                    )));
                }
            }
        };
        // Block (with a small grace) until the proofs have
        // landed. The cross-network hop layer populates them
        // either via create_outgoing_htlc (same-process test
        // path) or via accept_incoming_htlc (multi-hop path).
        if proofs_slot.is_none() {
            let grace = wait_grace_secs(deadline);
            if tokio::time::timeout(std::time::Duration::from_secs(grace), arrival.notified())
                .await
                .is_err()
            {
                return Err(HtlcError::Network(
                    "timed out waiting for HTLC proofs to arrive".into(),
                ));
            }
        }

        // Re-read after the (possible) wait.
        let locked: Proofs = {
            let incoming = self.incoming.lock().await;
            let slot = incoming.get(&payment_hash).ok_or_else(|| {
                HtlcError::Network(format!("no incoming HTLC for {payment_hash:?}"))
            })?;
            let proofs = slot.proofs.lock().await.clone();
            drop(incoming);
            proofs.ok_or_else(|| HtlcError::Network("HTLC proofs missing".into()))?
        };
        if locked.is_empty() {
            return Err(HtlcError::Network("HTLC proofs missing".into()));
        }

        // Sanity check the preimage actually matches the hash
        // the proofs are locked under. This is the receiver
        // path of NUT-14 and is what makes the swap at the
        // mint valid.
        let mut proofs = locked;
        add_preimage_to_proofs(&mut proofs, &preimage.0);
        verify_proofs_htlc(&proofs).map_err(|e| HtlcError::InvalidParams(e.to_string()))?;

        // Build the swap-to-self: outputs use unrestricted
        // spending conditions (no HTLC, no P2PK) so the
        // receiver can spend the resulting ecash directly.
        let keyset_id = proofs[0].keyset_id;
        let total_sat: u64 = proofs.iter().map(|p| u64::from(p.amount)).sum();
        let keyset = self
            .ensure_keysets()
            .await
            .map_err(|e| HtlcError::Network(e.to_string()))?
            .iter()
            .find(|k| k.id == keyset_id)
            .cloned()
            .ok_or_else(|| {
                HtlcError::Network(format!("mint no longer advertises keyset {keyset_id}"))
            })?;
        let fee_and_amounts = Self::build_fee_and_amounts(&keyset);
        let split = Self::split_for_swap(total_sat, &fee_and_amounts)
            .map_err(|e| HtlcError::Network(e.to_string()))?;
        let keys = self
            .get_keys(&keyset_id)
            .await
            .map_err(|e| HtlcError::Network(e.to_string()))?;
        let (triples, outputs) = Self::fresh_outputs(split.len(), keyset_id, &split)
            .map_err(|e| HtlcError::Network(e.to_string()))?;
        let request = cdk::nuts::nut03::SwapRequest::new(proofs, outputs);
        let response = self
            .client
            .post_swap(request)
            .await
            .map_err(|e| HtlcError::Network(e.to_string()))?;
        let new_proofs = Self::unblind_response(response, triples, &keys)
            .map_err(|e| HtlcError::Network(e.to_string()))?;
        // Add the freshly-minted proofs to the receiver's wallet
        // store so the adapter can spend them on future hops.
        self.add_balance(new_proofs)
            .await
            .map_err(|e| HtlcError::Network(e.to_string()))?;

        // Drop the receiver's wait registration.
        let mut incoming = self.incoming.lock().await;
        incoming.remove(&payment_hash);
        Ok(())
    }

    /// Refund an outgoing HTLC after the locktime has passed.
    /// We swap the locked proofs back at the mint with
    /// unrestricted output conditions (no witness). NUT-14
    /// allows the sender path once the locktime is reached.
    async fn refund_outgoing(&self, payment_hash: Bytes32) -> Result<(), HtlcError> {
        let (proofs, locktime) = {
            let outgoing = self.outgoing.lock().await;
            let slot = outgoing.get(&payment_hash).ok_or_else(|| {
                HtlcError::InvalidParams(format!("no outgoing HTLC for {payment_hash:?}"))
            })?;
            let proofs = slot.proofs.lock().await.clone();
            (proofs, slot.locktime)
        };
        if proofs.is_empty() {
            return Err(HtlcError::InvalidParams(
                "outgoing HTLC has no proofs".into(),
            ));
        }
        if now_unix_secs() <= locktime {
            return Err(HtlcError::InvalidParams(
                "locktime has not yet passed; cannot refund".into(),
            ));
        }
        let keyset_id = proofs[0].keyset_id;
        let total_sat: u64 = proofs.iter().map(|p| u64::from(p.amount)).sum();
        let keyset = self
            .ensure_keysets()
            .await
            .map_err(|e| HtlcError::Network(e.to_string()))?
            .iter()
            .find(|k| k.id == keyset_id)
            .cloned()
            .ok_or_else(|| {
                HtlcError::Network(format!("mint no longer advertises keyset {keyset_id}"))
            })?;
        let fee_and_amounts = Self::build_fee_and_amounts(&keyset);
        let split = Self::split_for_swap(total_sat, &fee_and_amounts)
            .map_err(|e| HtlcError::Network(e.to_string()))?;
        let keys = self
            .get_keys(&keyset_id)
            .await
            .map_err(|e| HtlcError::Network(e.to_string()))?;
        let (triples, outputs) = Self::fresh_outputs(split.len(), keyset_id, &split)
            .map_err(|e| HtlcError::Network(e.to_string()))?;
        let request = cdk::nuts::nut03::SwapRequest::new(proofs, outputs);
        let response = self
            .client
            .post_swap(request)
            .await
            .map_err(|e| HtlcError::Network(e.to_string()))?;
        // The refunded proofs are unrestricted ecash we hold again;
        // persist them so the wallet can spend them later.
        let refunded = Self::unblind_response(response, triples, &keys)
            .map_err(|e| HtlcError::Network(e.to_string()))?;
        self.add_balance(refunded)
            .await
            .map_err(|e| HtlcError::Network(e.to_string()))?;
        let mut outgoing = self.outgoing.lock().await;
        outgoing.remove(&payment_hash);
        Ok(())
    }

    /// Wait for the receiver of our outgoing HTLC to claim. We
    /// poll NUT-07's `check_state` endpoint for each proof; once
    /// any proof is `SPENT`, the receiver has swapped it (with
    /// the preimage witness) and we can read the preimage off
    /// the proof's witness.
    async fn watch_preimage(
        &self,
        payment_hash: Bytes32,
        deadline: u64,
    ) -> Result<Bytes32, WatchError> {
        let proofs: Proofs = {
            let outgoing = self.outgoing.lock().await;
            let slot = outgoing.get(&payment_hash).ok_or_else(|| {
                WatchError::Network(format!("no outgoing HTLC for {payment_hash:?}"))
            })?;
            let proofs = slot.proofs.lock().await.clone();
            drop(outgoing);
            proofs
        };
        if proofs.is_empty() {
            return Err(WatchError::Network("outgoing HTLC has no proofs".into()));
        }
        let ys: Vec<_> = proofs
            .iter()
            .map(proof_y)
            .collect::<CashuResult<Vec<_>>>()
            .map_err(|e| WatchError::Network(e.to_string()))?;
        let req = CheckStateRequest { ys };

        let poll_interval = std::time::Duration::from_secs(2);
        loop {
            let resp = self
                .client
                .post_check_state(req.clone())
                .await
                .map_err(|e| WatchError::Network(e.to_string()))?;
            let spent = resp
                .states
                .iter()
                .find(|s| s.state == ProofState::Spent)
                .cloned();
            if let Some(spent) = spent {
                let preimage_hex = match spent.witness.as_ref() {
                    Some(Witness::HTLCWitness(HTLCWitness { preimage, .. })) => preimage.clone(),
                    _ => {
                        return Err(WatchError::Network(
                            "HTLC spent but no preimage in witness (refund path?)".into(),
                        ));
                    }
                };
                let bytes = cdk::util::hex::decode(&preimage_hex)
                    .map_err(|e| WatchError::Network(format!("decode preimage: {e}")))?;
                if bytes.len() != 32 {
                    return Err(WatchError::Network("preimage wrong length".into()));
                }
                let mut out = [0u8; 32];
                out.copy_from_slice(&bytes);
                return Ok(Bytes32(out));
            }
            if now_unix_secs() >= deadline {
                return Err(WatchError::DeadlineExceeded);
            }
            tokio::time::sleep(poll_interval).await;
        }
    }

    /// PREPARE-time check: do we have enough unrestricted ecash
    /// in the wallet store to back an outgoing HTLC of
    /// `amount_msat`? We round up to sats the same way
    /// [`NetworkRouterAdapter::create_outgoing_htlc`] does, so
    /// a green light here means the actual swap won't fail for
    /// lack of funds.
    async fn can_route(&self, amount_msat: u64) -> Result<(), HtlcError> {
        let amount_sat = amount_msat.div_ceil(1000).max(1);
        let keyset_id = self
            .active_keyset_id()
            .await
            .map_err(|e| HtlcError::Network(e.to_string()))?;
        let proofs = self
            .store
            .list_proofs(&self.mint_url_str)
            .map_err(|e| HtlcError::Network(e.to_string()))?;

        let total_sat: u64 = proofs
            .iter()
            .filter(|p| p.keyset_id == keyset_id)
            .map(|p| u64::from(p.amount))
            .sum();
        if total_sat < amount_sat {
            return Err(HtlcError::InvalidParams(format!(
                "insufficient cashu balance: need {amount_sat} sat, have {total_sat} sat"
            )));
        }
        Ok(())
    }

    /// DISPATCH-time verify: does `descriptor` decode to NUT-14
    /// HTLC proofs locked to `payment_hash`? Caller is the hop's
    /// *incoming* adapter, called right after the router receives
    /// a DISPATCH and before it commits an outgoing HTLC.
    async fn verify_incoming_htlc(
        &self,
        descriptor: &HtlcDescriptor,
        payment_hash: Bytes32,
    ) -> Result<(), HtlcError> {
        let proofs = proofs_from_descriptor(descriptor)?;
        verify_proofs_htlc_locked(&proofs, &payment_hash.0)
            .map_err(|e| HtlcError::Network(e.to_string()))?;
        Ok(())
    }

    /// DISPATCH-time accept: store the proofs from `descriptor` in
    /// the incoming map and notify any waiting claimer. Called
    /// after [`NetworkRouterAdapter::verify_incoming_htlc`]
    /// succeeds. The hop is then free to create its outgoing
    /// HTLC.
    async fn accept_incoming_htlc(
        &self,
        payment_hash: Bytes32,
        descriptor: &HtlcDescriptor,
        deadline: u64,
    ) -> Result<(), HtlcError> {
        let proofs = proofs_from_descriptor(descriptor)?;
        verify_proofs_htlc_locked(&proofs, &payment_hash.0)
            .map_err(|e| HtlcError::Network(e.to_string()))?;
        let amount_sat: u64 = proofs.iter().map(|p| u64::from(p.amount)).sum();
        let payment_hash_hex = htlc::payment_hash_hex(&payment_hash.0);
        let mut incoming = self.incoming.lock().await;
        match incoming.get_mut(&payment_hash) {
            Some(slot) => {
                *slot.proofs.lock().await = Some(proofs);
            }
            None => {
                let slot = PendingIncoming {
                    payment_hash_hex,
                    amount_sat,
                    deadline,
                    proofs: Mutex::new(Some(proofs)),
                    arrival: Arc::new(Notify::new()),
                };
                incoming.insert(payment_hash, slot);
            }
        }
        let arrival = incoming
            .get(&payment_hash)
            .map(|s| s.arrival.clone())
            .ok_or_else(|| HtlcError::Network("incoming slot vanished".into()))?;
        drop(incoming);
        arrival.notify_one();
        Ok(())
    }

    /// DISPATCH-time accessor: serialize the proofs of the
    /// outgoing HTLC just produced by
    /// [`NetworkRouterAdapter::create_outgoing_htlc`] as a
    /// [`HtlcDescriptor::Cashu`] for the hop's reply.
    async fn outgoing_htlc_descriptor(
        &self,
        payment_hash: Bytes32,
    ) -> Result<HtlcDescriptor, HtlcError> {
        let proofs: Proofs = {
            let outgoing = self.outgoing.lock().await;
            let slot = outgoing.get(&payment_hash).ok_or_else(|| {
                HtlcError::InvalidParams(format!("no outgoing HTLC for {payment_hash:?}"))
            })?;
            let cloned = slot.proofs.lock().await.clone();
            let _ = slot;
            let _ = outgoing;
            cloned
        };
        if proofs.is_empty() {
            return Err(HtlcError::Network("outgoing HTLC has no proofs".into()));
        }
        let mut encoded = Vec::with_capacity(proofs.len());
        for proof in &proofs {
            let json = serde_json::to_string(proof)
                .map_err(|e| HtlcError::Network(format!("encode proof: {e}")))?;
            encoded.push(BASE64.encode(json.as_bytes()));
        }
        Ok(HtlcDescriptor::Cashu {
            proofs_b64: encoded,
        })
    }
}

/// Decode the base64-encoded NUT-14 proof list out of a
/// [`HtlcDescriptor::Cashu`]. Any other variant is a hard error:
/// cashu is the only network with a populated descriptor today.
fn proofs_from_descriptor(descriptor: &HtlcDescriptor) -> Result<Proofs, HtlcError> {
    match descriptor {
        HtlcDescriptor::Cashu { proofs_b64 } => {
            let mut out = Vec::with_capacity(proofs_b64.len());
            for s in proofs_b64 {
                let raw = BASE64
                    .decode(s)
                    .map_err(|e| HtlcError::Network(format!("base64 decode: {e}")))?;
                let proof: Proof = serde_json::from_slice(&raw)
                    .map_err(|e| HtlcError::Network(format!("decode proof: {e}")))?;
                out.push(proof);
            }
            Ok(out)
        }
        other => Err(HtlcError::Network(format!(
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
            [0u8; 32],
            test_store(),
        );
        assert!(adapter.is_ok(), "valid url should construct");
    }

    #[test]
    fn new_rejects_garbage_mint_url() {
        let adapter = CashuAdapter::new(
            NetworkId("not a url".to_string()),
            "not a url".to_string(),
            [0u8; 32],
            test_store(),
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
            [0u8; 32],
            test_store(),
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
