use async_trait::async_trait;
use cashu::amount::{FeeAndAmounts, SplitTarget};
use cashu::dhke::{blind_message, unblind_message};
use cashu::nuts::nut00::{BlindedMessage, Proofs};
use cashu::nuts::nut02::Id as KeysetId;
use cashu::nuts::nut07::{CheckStateRequest, State as ProofState};
use cashu::nuts::nut10::SpendingConditions;
use cashu::nuts::nut12::ProofDleq;
use cashu::nuts::nut14::HTLCWitness;
use cashu::nuts::{CurrencyUnit, KeySetInfo, KeysetResponse, Proof, Witness};
use cashu::secret::Secret;
use cashu::MintUrl;
use cashu::Amount;
use cassis_core::{
    Bytes32, HtlcError, IncomingHtlc, NetworkId, NetworkRouterAdapter, OutgoingHtlc,
    WatchError,
};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::{Mutex, Notify};

mod errors;
mod htlc;
mod mint_client;

use errors::{CashuError, CashuResult};
use htlc::{add_preimage_to_proofs, build_htlc_outputs, htlc_conditions, proof_y, verify_proofs_htlc};
use mint_client::MintClient;

pub use errors::CashuError as Error;

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
    /// Notified when the matching HTLC proofs have been deposited
    /// into the shared store by the cross-network hop layer (or,
    /// in tests, by [`CashuAdapter::deposit_outgoing_proofs`]).
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
    client: MintClient,
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
    /// Local ecash balance the adapter can spend. Funded by the
    /// cross-network hop layer (Lightning deposit → NUT-04 mint →
    /// NUT-03 swap into the active keyset) before any outgoing
    /// HTLC is created.
    available: Mutex<Vec<Proof>>,
}

impl CashuAdapter {
    /// Construct a new adapter for a cashu mint.
    ///
    /// Returns an error if `mint_url` is not a syntactically valid
    /// cashu [`MintUrl`]; there is no fallback because a real mint
    /// URL is the only way any cashu method (NUT-01, NUT-02, NUT-03,
    /// NUT-04, NUT-05, NUT-07, …) can succeed.
    pub fn new(
        network_id: NetworkId,
        mint_url: String,
        secret_key: [u8; 32],
    ) -> CashuResult<Self> {
        let mint_url = MintUrl::from_str(&mint_url)
            .map_err(|e| CashuError::Nuts(format!("invalid mint url '{mint_url}': {e}")))?;
        let client = MintClient::new(mint_url.clone(), None);
        Ok(Self {
            network_id,
            mint_url,
            client,
            secret_key,
            keysets: Arc::new(Mutex::new(Vec::new())),
            outgoing: Mutex::new(HashMap::new()),
            incoming: Mutex::new(HashMap::new()),
            available: Mutex::new(Vec::new()),
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
        let resp: KeysetResponse = self.client.get_keysets().await?;
        let active: Vec<KeySetInfo> = resp
            .keysets
            .into_iter()
            .filter(|k| k.active)
            .collect();
        let mut guard = self.keysets.lock().await;
        *guard = active.clone();
        Ok(active)
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
    /// ecash.
    async fn get_keys(&self, keyset_id: &KeysetId) -> CashuResult<cashu::nuts::Keys> {
        let resp = self.client.get_keys(keyset_id).await?;
        resp.keysets
            .into_iter()
            .find(|ks| &ks.id == keyset_id)
            .map(|ks| ks.keys)
            .ok_or(CashuError::NoKeyset)
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

    /// Add unrestricted proofs to the adapter's local balance.
    /// Production caller: the cross-network hop layer after
    /// melting an incoming Lightning payment (NUT-05) or minting
    /// via NUT-04. Test caller: a fixture.
    pub async fn add_balance(&self, proofs: Vec<Proof>) {
        let mut balance = self.available.lock().await;
        balance.extend(proofs);
    }

    /// Test/diagnostic accessor: read the current local balance.
    pub async fn balance(&self) -> Vec<Proof> {
        self.available.lock().await.clone()
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
        incoming.get(&payment_hash).map(|s| PendingIncoming {
            payment_hash_hex: s.payment_hash_hex.clone(),
            amount_sat: s.amount_sat,
            deadline: s.deadline,
            arrival: s.arrival.clone(),
        })
    }

    /// Pull unrestricted proofs from the local balance whose
    /// total amount is at least `amount_sat + fee_sat`. Returns
    /// the selected proofs and the change (if any) is left in
    /// place for the next call.
    async fn take_unrestricted_proofs(
        &self,
        amount_sat: u64,
        keyset_id: KeysetId,
    ) -> CashuResult<Proofs> {
        let balance = self.available.lock().await;
        let mut picked: Vec<Proof> = Vec::new();
        let mut total: u64 = 0;
        for proof in balance.iter() {
            if proof.keyset_id != keyset_id {
                continue;
            }
            picked.push(proof.clone());
            total = total.saturating_add(u64::from(proof.amount));
            if total >= amount_sat {
                break;
            }
        }
        if total < amount_sat {
            return Err(CashuError::Nuts(format!(
                "insufficient balance: need {amount_sat} sat, have {total} sat"
            )));
        }
        Ok(picked)
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
    ) -> CashuResult<(Vec<(Secret, cashu::nuts::nut01::SecretKey, Amount)>, Vec<BlindedMessage>)>
    {
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
        response: cashu::nuts::nut03::SwapResponse,
        triples: Vec<(Secret, cashu::nuts::nut01::SecretKey, Amount)>,
        keys: &cashu::nuts::Keys,
    ) -> CashuResult<Proofs> {
        let mut proofs = Vec::with_capacity(response.signatures.len());
        for (sig, (secret, r, amount)) in response.signatures.into_iter().zip(triples) {
            let amount_key = keys
                .amount_key(amount)
                .ok_or_else(|| CashuError::Nuts("amount key missing".into()))?;
            let c = unblind_message(&sig.c, &r, &amount_key)
                .map_err(|e| CashuError::Nuts(format!("unblind: {e}")))?;
            let dleq: Option<ProofDleq> = sig
                .dleq
                .map(|d| ProofDleq::new(d.e, d.s, r.clone()));
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
    /// block on a [`Notify`] until the sender's proofs land.
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
        let outputs = build_htlc_outputs(amount_sat, keyset_id, &payment_hash.0, expiry)
            .map_err(|e| match e {
                CashuError::HtlcExpired => HtlcError::InvalidParams("expiry in past".into()),
                other => HtlcError::Network(other.to_string()),
            })?;
        let output_blinded = outputs
            .premints
            .iter()
            .map(|p| p.blinded_message.clone())
            .collect::<Vec<_>>();

        // Pull unrestricted input proofs from the local
        // balance. The cross-network hop layer is expected to
        // top up the balance (NUT-04 mint, NUT-05 melt, or a
        // direct deposit) before any `pay_invoice` lands on the
        // cashu network.
        let inputs = self
            .take_unrestricted_proofs(amount_sat, keyset_id)
            .await
            .map_err(|e| HtlcError::Network(e.to_string()))?;

        let request = cashu::nuts::nut03::SwapRequest::new(inputs, output_blinded);
        let response = self
            .client
            .swap(&request)
            .await
            .map_err(|e| HtlcError::Network(e.to_string()))?;
        let keys = self
            .get_keys(&keyset_id)
            .await
            .map_err(|e| HtlcError::Network(e.to_string()))?;

        // Re-build the (secret, r, amount) triples in the same
        // order so the unblind lines up. The premints carry the
        // secrets and blinding factors; the response carries the
        // mint's blind signatures.
        let triples: Vec<(Secret, cashu::nuts::nut01::SecretKey, Amount)> = outputs
            .premints
            .into_iter()
            .map(|p| (p.secret, p.r, p.amount))
            .collect();
        let proofs = Self::unblind_response(response, triples, &keys)
            .map_err(|e| HtlcError::Network(e.to_string()))?;
        verify_proofs_htlc(&proofs).map_err(|e| HtlcError::Network(e.to_string()))?;
        let _ = keyset; // currently unused beyond the lookup

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
                    proofs: Mutex::new(proofs),
                    recipient: recipient.to_string(),
                },
            );
        }
        // Wake any receiver awaiting these proofs.
        let arrival = {
            let incoming = self.incoming.lock().await;
            incoming.get(&payment_hash).map(|s| s.arrival.clone())
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
        htlc: &IncomingHtlc,
        preimage: Bytes32,
    ) -> Result<(), HtlcError> {
        let arrival = {
            let incoming = self.incoming.lock().await;
            incoming
                .get(&htlc.payment_hash)
                .map(|s| s.arrival.clone())
        };
        let Some(arrival) = arrival else {
            return Err(HtlcError::InvalidParams(format!(
                "no incoming HTLC registered for {:?}",
                htlc.payment_hash
            )));
        };
        // Block (with a small grace) until the sender's proofs
        // have landed in the shared store. The cross-network
        // hop layer is responsible for actually moving the
        // proofs between adapters.
        let grace = wait_grace_secs(htlc.expiry);
        if tokio::time::timeout(std::time::Duration::from_secs(grace), arrival.notified())
            .await
            .is_err()
        {
            return Err(HtlcError::Network(
                "timed out waiting for HTLC proofs to arrive".into(),
            ));
        }

        // Pull the locked proofs from the shared store.
        let locked: Proofs = {
            let outgoing = self.outgoing.lock().await;
            let slot = outgoing.get(&htlc.payment_hash).ok_or_else(|| {
                HtlcError::Network(format!(
                    "no outgoing HTLC proofs for {:?}",
                    htlc.payment_hash
                ))
            })?;
            let proofs = slot.proofs.lock().await.clone();
            drop(outgoing);
            proofs
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
                HtlcError::Network(format!(
                    "mint no longer advertises keyset {keyset_id}"
                ))
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
        let request = cashu::nuts::nut03::SwapRequest::new(proofs, outputs);
        let response = self
            .client
            .swap(&request)
            .await
            .map_err(|e| HtlcError::Network(e.to_string()))?;
        let new_proofs = Self::unblind_response(response, triples, &keys)
            .map_err(|e| HtlcError::Network(e.to_string()))?;
        // Add the freshly-minted proofs to the receiver's
        // local balance so the adapter can spend them on
        // future hops.
        self.add_balance(new_proofs).await;

        // Drop the receiver's wait registration.
        let mut incoming = self.incoming.lock().await;
        incoming.remove(&htlc.payment_hash);
        Ok(())
    }

    /// Refund an outgoing HTLC after the locktime has passed.
    /// We swap the locked proofs back at the mint with
    /// unrestricted output conditions (no witness). NUT-14
    /// allows the sender path once the locktime is reached.
    async fn refund_outgoing(&self, htlc: &OutgoingHtlc) -> Result<(), HtlcError> {
        let proofs: Proofs = {
            let outgoing = self.outgoing.lock().await;
            let slot = outgoing.get(&htlc.payment_hash).ok_or_else(|| {
                HtlcError::InvalidParams(format!(
                    "no outgoing HTLC for {:?}",
                    htlc.payment_hash
                ))
            })?;
            let proofs = slot.proofs.lock().await.clone();
            drop(outgoing);
            proofs
        };
        if proofs.is_empty() {
            return Err(HtlcError::InvalidParams(
                "outgoing HTLC has no proofs".into(),
            ));
        }
        if now_unix_secs() <= htlc.expiry {
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
                HtlcError::Network(format!(
                    "mint no longer advertises keyset {keyset_id}"
                ))
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
        let request = cashu::nuts::nut03::SwapRequest::new(proofs, outputs);
        let response = self
            .client
            .swap(&request)
            .await
            .map_err(|e| HtlcError::Network(e.to_string()))?;
        let _ = Self::unblind_response(response, triples, &keys)
            .map_err(|e| HtlcError::Network(e.to_string()))?;
        let mut outgoing = self.outgoing.lock().await;
        outgoing.remove(&htlc.payment_hash);
        Ok(())
    }

    /// Wait for the receiver of our outgoing HTLC to claim. We
    /// poll NUT-07's `check_state` endpoint for each proof; once
    /// any proof is `SPENT`, the receiver has swapped it (with
    /// the preimage witness) and we can read the preimage off
    /// the proof's witness.
    async fn watch_preimage(
        &self,
        htlc: &OutgoingHtlc,
        deadline: u64,
    ) -> Result<Bytes32, WatchError> {
        let proofs: Proofs = {
            let outgoing = self.outgoing.lock().await;
            let slot = outgoing.get(&htlc.payment_hash).ok_or_else(|| {
                WatchError::Network(format!("no outgoing HTLC for {:?}", htlc.payment_hash))
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
                .check_state(&req)
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
                let bytes = cashu::util::hex::decode(&preimage_hex)
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

    #[test]
    fn new_accepts_a_valid_mint_url() {
        let adapter = CashuAdapter::new(
            NetworkId("cashu::mint.example.com".to_string()),
            "https://mint.example.com".to_string(),
            [0u8; 32],
        );
        assert!(adapter.is_ok(), "valid url should construct");
    }

    #[test]
    fn new_rejects_garbage_mint_url() {
        let adapter = CashuAdapter::new(
            NetworkId("cashu::not a url".to_string()),
            "not a url".to_string(),
            [0u8; 32],
        );
        assert!(adapter.is_err(), "garbage url must be rejected, not silently replaced");
    }

    #[test]
    fn new_rejects_empty_mint_url() {
        let adapter = CashuAdapter::new(
            NetworkId("cashu::".to_string()),
            "".to_string(),
            [0u8; 32],
        );
        assert!(adapter.is_err(), "empty url must be rejected");
    }
}

