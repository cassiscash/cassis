//! Cashu network: NUT-14 HTLCs on one mint.
//!
//! * **Lock**: swap wallet proofs at the mint for proofs whose secret is
//!   a NUT-14 HTLC (payment hash, receiver key, refund key, refund
//!   locktime). The proofs themselves are the descriptor handed to the
//!   receiver.
//! * **Verify**: the proofs are locked to us and the hash, carry the
//!   mint's DLEQ signature proof, and the mint reports them unspent.
//! * **Claim**: swap them at the mint with the preimage and our
//!   signature as witness.
//! * **Watch**: the mint reports the spent proof's witness, which holds
//!   the preimage.
//! * **Refund**: after the locktime the sender swaps them back, signing
//!   as the refund key: holding the proofs alone is not enough.
//!
//! Wallet proofs live in `<data_dir>/proofs.json`. Every swap is
//! journaled in `<data_dir>/pending.json` until its outputs are held:
//! if the mint's answer is lost, upkeep asks for their signatures again
//! (NUT-09).

mod htlc;
mod wallet;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use cassis_core::{
    sats_for_msat, unix_now, Bytes32, Htlc, HtlcDescriptor, InvoiceTarget, Network, NetworkError,
    NetworkId, OutgoingState, XOnlyPubKey,
};
use cdk::amount::{FeeAndAmounts, SplitTarget};
use cdk::dhke::{blind_message, unblind_message};
use cdk::mint_url::MintUrl;
use cdk::nuts::nut00::{BlindedMessage, Proofs};
use cdk::nuts::nut07::{CheckStateRequest, ProofState, State};
use cdk::nuts::nut12::ProofDleq;
use cdk::nuts::nut14::HTLCWitness;
use cdk::nuts::{CurrencyUnit, KeySetInfo, Keys, RestoreRequest, Token, Witness};
use cdk::wallet::MintConnector;
use htlc::{htlc_outputs, sign_refund, HtlcTerms};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::str::FromStr;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::{info, Span};
use wallet::{PendingOutput, PendingSwap, Wallet};

pub use cdk::nuts::nut00::Proof;
pub use cdk::nuts::nut01::PublicKey;
pub use cdk::nuts::nut02::Id as KeysetId;
pub use cdk::secret::Secret;
pub use cdk::Amount;

/// Per-output blinding data of a swap: `(secret, r, amount)`.
type Blinding = (Secret, cdk::nuts::nut01::SecretKey, Amount);

/// How long the mint's keysets are trusted before asking again: it may
/// rotate them.
const KEYSETS_TTL: Duration = Duration::from_secs(10 * 60);
/// How often a long-running node looks for swaps to recover.
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(10 * 60);
/// A journaled swap this old got no answer: its request is over.
const SWAP_RECOVERY_AGE_SECS: u64 = 120;

fn network_error(error: impl std::fmt::Display) -> NetworkError {
    NetworkError::network(error)
}

pub struct CashuAdapter {
    id: NetworkId,
    mint_url: MintUrl,
    client: cdk::wallet::HttpClient,
    secret_key: cdk::nuts::nut01::SecretKey,
    /// Key counterparties lock HTLC proofs to. NUT-11/14 signatures are
    /// BIP340, so parity does not matter.
    claim_pubkey: XOnlyPubKey,
    span: Span,
    /// The mint's active keysets, as of when they were fetched.
    keysets: Mutex<Option<(Instant, Vec<KeySetInfo>)>>,
    /// The mint's keys by keyset, which never change.
    keys: Mutex<HashMap<KeysetId, Keys>>,
    wallet: Wallet,
}

impl CashuAdapter {
    /// Open the wallet of mint `id` (`cashu::<host>`), keeping proofs
    /// under `data_dir`.
    pub fn open(
        id: NetworkId,
        secret: [u8; 32],
        data_dir: &Path,
        span: &Span,
    ) -> Result<Self, String> {
        let mint_url = MintUrl::from_str(&mint_url(&id)?).map_err(|e| e.to_string())?;
        let secret_key = cdk::nuts::nut01::SecretKey::from_slice(&secret)
            .map_err(|e| format!("invalid cashu key: {e}"))?;
        let compressed = secret_key.public_key().to_bytes();
        let claim_pubkey = XOnlyPubKey::from_bytes(compressed[1..].try_into().expect("33 bytes"))
            .map_err(|e| format!("invalid claim key: {e:?}"))?;
        Ok(Self {
            client: cdk::wallet::HttpClient::new(mint_url.clone(), None),
            mint_url,
            secret_key,
            claim_pubkey,
            span: cassis_core::network_span(span, &id),
            keysets: Mutex::new(None),
            keys: Mutex::new(HashMap::new()),
            wallet: Wallet::open(data_dir)?,
            id,
        })
    }

    fn claim_target(&self) -> InvoiceTarget {
        InvoiceTarget::Cashu {
            network: self.id.clone(),
            target: self.claim_pubkey,
        }
    }

    /// Put already-owned proofs in the wallet (e.g. migrated from an
    /// older store) without touching the mint.
    pub fn import_proofs(&self, proofs: &[Proof]) -> Result<(), String> {
        self.wallet.add(proofs)
    }

    pub fn mint_url(&self) -> String {
        self.mint_url.to_string()
    }

    /// Spendable ecash, in msat.
    pub fn balance_msat(&self) -> Result<u64, String> {
        Ok(sum_sats(&self.wallet.proofs()?) * 1000)
    }

    /// Redeem a cashu token from this mint into the wallet. Returns the
    /// amount received, in sats.
    pub async fn receive_token(&self, token: &str) -> Result<u64, String> {
        let token = Token::from_str(token.trim()).map_err(|e| format!("invalid token: {e}"))?;
        if token.mint_url().map_err(|e| e.to_string())? != self.mint_url {
            return Err(format!("token is not from {}", self.mint_url));
        }
        let proofs = token
            .proofs(&self.keysets().await.map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        self.redeem(proofs).await.map_err(|e| e.to_string())
    }

    /// Take `amount_sat` out of the wallet as a token anyone can redeem.
    pub async fn send_token(&self, amount_sat: u64) -> Result<String, String> {
        let proofs = self
            .take(amount_sat, None)
            .await
            .map_err(|e| e.to_string())?;
        Ok(Token::new(self.mint_url.clone(), proofs, None, CurrencyUnit::Sat).to_string())
    }

    async fn keysets(&self) -> Result<Vec<KeySetInfo>, NetworkError> {
        let mut cached = self.keysets.lock().await;
        if let Some((fetched, keysets)) = cached.as_ref() {
            if fetched.elapsed() < KEYSETS_TTL {
                return Ok(keysets.clone());
            }
        }
        let response = self
            .client
            .get_mint_keysets()
            .await
            .map_err(network_error)?;
        let keysets: Vec<KeySetInfo> = response
            .keysets
            .into_iter()
            .filter(|keyset| keyset.active && keyset.unit == CurrencyUnit::Sat)
            .collect();
        *cached = Some((Instant::now(), keysets.clone()));
        Ok(keysets)
    }

    /// The mint's keys of `keyset`.
    async fn keys(&self, keyset: KeysetId) -> Result<Keys, NetworkError> {
        let mut cached = self.keys.lock().await;
        if let Some(keys) = cached.get(&keyset) {
            return Ok(keys.clone());
        }
        let keys = self
            .client
            .get_mint_keyset(keyset)
            .await
            .map_err(network_error)?
            .keys;
        cached.insert(keyset, keys.clone());
        Ok(keys)
    }

    async fn active_keyset(&self) -> Result<KeySetInfo, NetworkError> {
        self.keysets()
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| NetworkError::network("mint has no active sat keyset"))
    }

    /// Swap `inputs` for fresh proofs: `outputs_sat` locked by `htlc`
    /// (unrestricted when `None`) plus unrestricted change for whatever
    /// is left after the mint's input fee. Returns the outputs; change
    /// goes to the wallet.
    async fn swap(
        &self,
        inputs: Proofs,
        outputs_sat: u64,
        htlc: Option<&HtlcTerms>,
    ) -> Result<Proofs, NetworkError> {
        let keyset = self.active_keyset().await?;
        let fee = input_fee_sat(inputs.len(), keyset.input_fee_ppk);
        let change_sat = sum_sats(&inputs)
            .checked_sub(outputs_sat + fee)
            .ok_or_else(|| NetworkError::invalid("inputs do not cover outputs and fee"))?;
        let fee_and_amounts: FeeAndAmounts = (
            keyset.input_fee_ppk,
            (0..32).map(|x| 2u64.pow(x)).collect::<Vec<_>>(),
        )
            .into();
        let mut blindings: Vec<Blinding> = Vec::new();
        let mut messages: Vec<BlindedMessage> = Vec::new();
        match htlc {
            Some(terms) => {
                for (blinding, message) in htlc_outputs(terms, outputs_sat, keyset.id)? {
                    blindings.push(blinding);
                    messages.push(message);
                }
            }
            None => plain_outputs(
                outputs_sat,
                keyset.id,
                &fee_and_amounts,
                &mut blindings,
                &mut messages,
            )?,
        }
        let locked = messages.len();
        plain_outputs(
            change_sat,
            keyset.id,
            &fee_and_amounts,
            &mut blindings,
            &mut messages,
        )?;
        let keys = self.keys(keyset.id).await?;
        // If the answer is lost the inputs are spent all the same:
        // [`CashuAdapter::recover_swaps`] finds the outputs again.
        let pending = PendingSwap {
            id: rand::random(),
            created_at: unix_now(),
            keyset: keyset.id,
            outputs: blindings
                .iter()
                .map(|(secret, r, amount)| PendingOutput {
                    secret: secret.clone(),
                    r: r.clone(),
                    amount: *amount,
                })
                .collect(),
        };
        self.wallet.begin_swap(&pending).map_err(network_error)?;
        let response = self
            .client
            .post_swap(cdk::nuts::nut03::SwapRequest::new(inputs.clone(), messages))
            .await
            .map_err(network_error)?;
        let mut proofs = Vec::with_capacity(blindings.len());
        for (signature, (secret, r, amount)) in response.signatures.into_iter().zip(blindings) {
            proofs.push(unblind(&keys, signature, secret, r, amount)?);
        }
        let change = proofs.split_off(locked);
        self.wallet.add(&change).map_err(network_error)?;
        self.wallet.end_swap(pending.id).map_err(network_error)?;
        Ok(proofs)
    }

    /// Finish the journaled swaps whose answer never came: ask the mint
    /// for the signatures of their outputs again, keep the unrestricted
    /// ones, and take back the HTLC-locked ones once they can be
    /// refunded (nothing else tracks them: funding failed as far as the
    /// node knows).
    async fn recover_swaps(&self) -> Result<(), NetworkError> {
        let now = unix_now();
        for swap in self.wallet.pending_swaps().map_err(network_error)? {
            if swap.created_at + SWAP_RECOVERY_AGE_SECS > now {
                continue;
            }
            let keys = self.keys(swap.keyset).await?;
            let mut outputs = Vec::with_capacity(swap.outputs.len());
            for output in &swap.outputs {
                let (blinded, _) = blind_message(&output.secret.to_bytes(), Some(output.r.clone()))
                    .map_err(NetworkError::invalid)?;
                outputs.push(BlindedMessage::new(output.amount, swap.keyset, blinded));
            }
            let restored = self
                .client
                .post_restore(RestoreRequest {
                    outputs: outputs.clone(),
                })
                .await
                .map_err(network_error)?;
            let mut plain = Vec::new();
            let mut locked = Vec::new();
            for (message, signature) in restored.outputs.iter().zip(restored.signatures) {
                let Some(index) = outputs
                    .iter()
                    .position(|output| output.blinded_secret == message.blinded_secret)
                else {
                    continue;
                };
                let output = &swap.outputs[index];
                let proof = unblind(
                    &keys,
                    signature,
                    output.secret.clone(),
                    output.r.clone(),
                    output.amount,
                )?;
                match HtlcTerms::of(&proof) {
                    Ok(terms) => locked.push((index, terms, proof)),
                    Err(_) => plain.push(proof),
                }
            }
            if !plain.is_empty() {
                info!(parent: &self.span, "recovered {} sat of a lost swap", sum_sats(&plain));
                self.wallet.add(&plain).map_err(network_error)?;
            }
            // Locked outputs stay journaled until their refund opens.
            let mut waiting = Vec::new();
            for (index, terms, mut proof) in locked {
                let state = self.states(&vec![proof.clone()]).await?.remove(0).state;
                if state != State::Unspent {
                    continue;
                }
                if terms.locktime > now {
                    waiting.push(swap.outputs[index].clone());
                    continue;
                }
                sign_refund(&mut proof, &self.secret_key)?;
                let refunded = self.redeem(vec![proof]).await?;
                info!(parent: &self.span, "refunded {refunded} sat locked by a lost swap");
            }
            if waiting.is_empty() {
                self.wallet.end_swap(swap.id).map_err(network_error)?;
            } else {
                self.wallet
                    .replace_swap(&PendingSwap {
                        outputs: waiting,
                        ..swap
                    })
                    .map_err(network_error)?;
            }
        }
        Ok(())
    }

    /// Swap `proofs` into unrestricted wallet proofs, minus the mint
    /// fee. Returns the amount added, in sats.
    async fn redeem(&self, proofs: Proofs) -> Result<u64, NetworkError> {
        let fee = input_fee_sat(proofs.len(), self.active_keyset().await?.input_fee_ppk);
        let total = sum_sats(&proofs);
        let fresh = self.swap(proofs, total.saturating_sub(fee), None).await?;
        self.wallet.add(&fresh).map_err(network_error)?;
        Ok(sum_sats(&fresh))
    }

    /// Spend wallet proofs worth `amount_sat` (plus input fees) into
    /// fresh proofs, HTLC-locked when `htlc` is given.
    async fn take(
        &self,
        amount_sat: u64,
        htlc: Option<&HtlcTerms>,
    ) -> Result<Proofs, NetworkError> {
        let keyset = self.active_keyset().await?;
        let inputs = self
            .wallet
            .select(keyset.id, amount_sat, keyset.input_fee_ppk)
            .map_err(NetworkError::invalid)?;
        // The inputs leave the wallet before the swap: if the swap fails
        // they may be spent anyway, and spending them twice would fail.
        match self.swap(inputs.clone(), amount_sat, htlc).await {
            Ok(outputs) => Ok(outputs),
            Err(error) => {
                // Back go the inputs the mint still has unspent, or all
                // of them when it cannot say: a spent one fails the next
                // swap, which sorts them out here.
                let unspent = match self.states(&inputs).await {
                    Ok(states) => inputs
                        .into_iter()
                        .zip(states)
                        .filter(|(_, state)| state.state == State::Unspent)
                        .map(|(proof, _)| proof)
                        .collect(),
                    Err(_) => inputs,
                };
                self.wallet.add(&unspent).map_err(network_error)?;
                Err(error)
            }
        }
    }

    async fn states(&self, proofs: &Proofs) -> Result<Vec<ProofState>, NetworkError> {
        let ys = proofs
            .iter()
            .map(|proof| proof.y())
            .collect::<Result<Vec<_>, _>>()
            .map_err(NetworkError::invalid)?;
        let response = self
            .client
            .post_check_state(CheckStateRequest { ys })
            .await
            .map_err(network_error)?;
        if response.states.len() != proofs.len() {
            return Err(NetworkError::network(
                "mint returned an incomplete state set",
            ));
        }
        Ok(response.states)
    }

    async fn unspent(&self, proofs: &Proofs) -> Result<bool, NetworkError> {
        Ok(self
            .states(proofs)
            .await?
            .iter()
            .all(|state| state.state == State::Unspent))
    }

    /// How the first spent proof of `proofs` was spent, if any is.
    async fn spent_state(&self, proofs: &Proofs) -> Result<Option<Spent>, NetworkError> {
        for state in self.states(proofs).await? {
            if state.state != State::Spent {
                continue;
            }
            // A refund's witness carries an empty preimage.
            let preimage = match state.witness {
                Some(Witness::HTLCWitness(HTLCWitness { preimage, .. })) => {
                    Bytes32::from_str(&preimage).ok()
                }
                _ => None,
            };
            return Ok(Some(match preimage {
                Some(preimage) => Spent::Claimed(preimage),
                None => Spent::WithoutPreimage,
            }));
        }
        Ok(None)
    }
}

#[async_trait]
impl Network for CashuAdapter {
    fn id(&self) -> NetworkId {
        self.id.clone()
    }

    async fn receive_target(
        &self,
        _payment_hash: Bytes32,
        _amount_msat: u64,
        _expiry: u64,
    ) -> Result<InvoiceTarget, NetworkError> {
        Ok(self.claim_target())
    }

    async fn cancel_receive(&self, _payment_hash: Bytes32) -> Result<(), NetworkError> {
        Ok(())
    }

    async fn verify_incoming_htlc(&self, htlc: &Htlc) -> Result<(), NetworkError> {
        if !htlc.descriptor.pays(&self.claim_target()) {
            return Err(NetworkError::invalid("HTLC is not addressed to this node"));
        }
        self.verify_htlc(htlc).await
    }

    async fn verify_htlc(&self, htlc: &Htlc) -> Result<(), NetworkError> {
        let (proofs, receiver) = decode_proofs(&htlc.descriptor)?;
        let claim_key = cashu_key(&receiver)?;
        // A proof listed twice would count twice and claim once.
        let mut secrets = HashSet::new();
        if !proofs.iter().all(|proof| secrets.insert(&proof.secret)) {
            return Err(NetworkError::invalid("cashu HTLC lists a proof twice"));
        }
        for proof in &proofs {
            let terms = HtlcTerms::of(proof)?;
            if terms.payment_hash != htlc.payment_hash {
                return Err(NetworkError::invalid("proof is locked to another hash"));
            }
            if terms.receiver.x_only_public_key() != claim_key.x_only_public_key() {
                return Err(NetworkError::invalid("proof is locked to another key"));
            }
            if terms.locktime < htlc.expiry {
                return Err(NetworkError::invalid(
                    "proof refund opens before the expiry",
                ));
            }
        }
        // Only the mint's signature makes a proof worth anything: check
        // it against the keyset (NUT-12) before asking about its state.
        let keysets = self.keysets().await?;
        let mut fee_ppk = 0u64;
        for proof in &proofs {
            let Some(keyset) = keysets.iter().find(|keyset| keyset.id == proof.keyset_id) else {
                return Err(NetworkError::invalid(
                    "proof is not from an active sat keyset",
                ));
            };
            fee_ppk = fee_ppk.saturating_add(keyset.input_fee_ppk);
            let keys = self.keys(proof.keyset_id).await?;
            let key = keys
                .amount_key(proof.amount)
                .ok_or_else(|| NetworkError::invalid("proof amount has no mint key"))?;
            proof
                .verify_dleq(key)
                .map_err(|e| NetworkError::invalid(format!("proof signature: {e}")))?;
        }
        // The claim pays the mint's fee on every proof: many small
        // proofs must still leave the HTLC amount.
        if sum_sats(&proofs).saturating_sub(fee_ppk.div_ceil(1000))
            < sats_for_msat(htlc.amount_msat)
        {
            return Err(NetworkError::invalid(
                "proofs are worth less than the HTLC after the mint's fee",
            ));
        }
        if !self.unspent(&proofs).await? {
            return Err(NetworkError::invalid("proofs are already spent or pending"));
        }
        Ok(())
    }

    async fn claim_incoming_htlc(
        &self,
        htlc: &Htlc,
        preimage: Bytes32,
    ) -> Result<(), NetworkError> {
        let (mut proofs, _) = decode_proofs(&htlc.descriptor)?;
        info!(parent: &self.span, "revealing preimage to the mint for {}", htlc.payment_hash.short());
        for proof in &mut proofs {
            proof.add_preimage(lowercase_hex::encode(preimage.0));
            proof
                .sign_p2pk(self.secret_key.clone())
                .map_err(NetworkError::invalid)?;
        }
        match self.redeem(proofs.clone()).await {
            Ok(_) => Ok(()),
            // An earlier attempt whose answer was lost claimed them:
            // upkeep recovers what it swapped them for.
            Err(_) if self.spent_state(&proofs).await? == Some(Spent::Claimed(preimage)) => Ok(()),
            Err(error) => Err(error),
        }
    }

    async fn create_outgoing_htlc(
        &self,
        payment_hash: Bytes32,
        amount_msat: u64,
        expiry: u64,
        target: &InvoiceTarget,
    ) -> Result<HtlcDescriptor, NetworkError> {
        let InvoiceTarget::Cashu {
            target: receiver, ..
        } = target
        else {
            return Err(NetworkError::invalid(
                "cashu HTLCs are locked to an x-only key",
            ));
        };
        let terms = HtlcTerms {
            payment_hash,
            receiver: cashu_key(receiver)?,
            refund: cashu_key(&self.claim_pubkey)?,
            locktime: expiry,
        };
        let proofs = self.take(sats_for_msat(amount_msat), Some(&terms)).await?;
        info!(
            parent: &self.span,
            "locked {} sat for {} until {expiry}",
            sum_sats(&proofs),
            payment_hash.short()
        );
        encode_proofs(&proofs, *receiver)
    }

    async fn check_outgoing_htlc(&self, htlc: &Htlc) -> Result<OutgoingState, NetworkError> {
        let (proofs, _) = decode_proofs(&htlc.descriptor)?;
        match self.spent_state(&proofs).await? {
            None => Ok(OutgoingState::Pending),
            Some(Spent::Claimed(preimage)) => Ok(OutgoingState::Claimed(preimage)),
            Some(Spent::WithoutPreimage) => {
                // Until the locktime only the receiver can spend, with
                // the preimage: a mint that does not show it (NUT-07
                // makes the witness optional) must not pass for a refund.
                let refundable = proofs.iter().all(|proof| {
                    HtlcTerms::of(proof).is_ok_and(|terms| terms.locktime <= unix_now())
                });
                if refundable {
                    Ok(OutgoingState::Refunded)
                } else {
                    Err(NetworkError::network(
                        "proofs were spent before their refund opened, and the mint does not \
                         show the preimage",
                    ))
                }
            }
        }
    }

    async fn refund_outgoing_htlc(&self, htlc: &Htlc) -> Result<(), NetworkError> {
        let (mut proofs, _) = decode_proofs(&htlc.descriptor)?;
        for proof in &mut proofs {
            sign_refund(proof, &self.secret_key)?;
        }
        self.redeem(proofs).await.map(|_| ())
    }

    async fn can_send(&self, amount_msat: u64) -> Result<(), NetworkError> {
        let keyset = self.active_keyset().await?;
        self.wallet
            .select_preview(keyset.id, sats_for_msat(amount_msat), keyset.input_fee_ppk)
            .map_err(NetworkError::invalid)
    }

    /// Claims are paid from the claimed proofs.
    async fn can_receive(&self, _amount_msat: u64) -> Result<(), NetworkError> {
        Ok(())
    }

    fn maintenance_interval(&self) -> Option<Duration> {
        Some(MAINTENANCE_INTERVAL)
    }

    /// Recover the swaps whose answer was lost.
    async fn maintain(&self) -> Result<(), NetworkError> {
        self.recover_swaps().await
    }
}

/// How spent HTLC proofs were spent, as far as the mint shows.
#[derive(Debug, PartialEq, Eq)]
enum Spent {
    Claimed(Bytes32),
    /// A refund, or a claim on a mint that does not show witnesses.
    WithoutPreimage,
}

/// The proof `signature` signs, unblinded.
fn unblind(
    keys: &Keys,
    signature: cdk::nuts::BlindSignature,
    secret: Secret,
    r: cdk::nuts::nut01::SecretKey,
    amount: Amount,
) -> Result<Proof, NetworkError> {
    let key = keys
        .amount_key(amount)
        .ok_or_else(|| NetworkError::network("mint has no key for amount"))?;
    Ok(Proof {
        amount,
        keyset_id: signature.keyset_id,
        c: unblind_message(&signature.c, &r, &key).map_err(network_error)?,
        dleq: signature.dleq.map(|d| ProofDleq::new(d.e, d.s, r)),
        secret,
        witness: None,
        p2pk_e: None,
    })
}

/// `https://<host>` for a `cashu::<host>` id, `http` for loopback hosts.
pub fn mint_url(id: &NetworkId) -> Result<String, String> {
    if id.kind() != "cashu" {
        return Err(format!("{id} is not a cashu network"));
    }
    id.host_url()
}

/// The cdk key of an x-only identity: its even-Y point. NUT-11/14
/// signatures are BIP340, so parity does not matter.
fn cashu_key(key: &XOnlyPubKey) -> Result<PublicKey, NetworkError> {
    let compressed = cassis_core::PubKey::from_x_only(key).map_err(NetworkError::invalid)?;
    PublicKey::from_slice(compressed.as_bytes()).map_err(NetworkError::invalid)
}

fn sum_sats(proofs: &[Proof]) -> u64 {
    proofs.iter().map(|proof| u64::from(proof.amount)).sum()
}

/// Mint input fee for `inputs` proofs at `input_fee_ppk`, rounded up.
fn input_fee_sat(inputs: usize, input_fee_ppk: u64) -> u64 {
    input_fee_ppk.saturating_mul(inputs as u64).div_ceil(1000)
}

fn plain_outputs(
    amount_sat: u64,
    keyset: KeysetId,
    fee_and_amounts: &FeeAndAmounts,
    blindings: &mut Vec<Blinding>,
    messages: &mut Vec<BlindedMessage>,
) -> Result<(), NetworkError> {
    if amount_sat == 0 {
        return Ok(());
    }
    let split = Amount::from(amount_sat)
        .split_targeted(&SplitTarget::None, fee_and_amounts)
        .map_err(NetworkError::invalid)?;
    for amount in split {
        let secret = Secret::generate();
        let (blinded, r) =
            blind_message(&secret.to_bytes(), None).map_err(NetworkError::invalid)?;
        messages.push(BlindedMessage::new(amount, keyset, blinded));
        blindings.push((secret, r, amount));
    }
    Ok(())
}

fn encode_proofs(proofs: &Proofs, target: XOnlyPubKey) -> Result<HtlcDescriptor, NetworkError> {
    let proofs_b64 = proofs
        .iter()
        .map(|proof| serde_json::to_string(proof).map(|json| BASE64.encode(json)))
        .collect::<Result<_, _>>()
        .map_err(NetworkError::invalid)?;
    Ok(HtlcDescriptor::Cashu { proofs_b64, target })
}

/// The proofs of a cashu HTLC and the key they are locked to.
fn decode_proofs(descriptor: &HtlcDescriptor) -> Result<(Proofs, XOnlyPubKey), NetworkError> {
    let HtlcDescriptor::Cashu { proofs_b64, target } = descriptor else {
        return Err(NetworkError::invalid("not a cashu HTLC"));
    };
    if proofs_b64.is_empty() {
        return Err(NetworkError::invalid("cashu HTLC without proofs"));
    }
    let proofs = proofs_b64
        .iter()
        .map(|encoded| {
            let json = BASE64.decode(encoded).map_err(NetworkError::invalid)?;
            serde_json::from_slice(&json).map_err(NetworkError::invalid)
        })
        .collect::<Result<_, _>>()?;
    Ok((proofs, *target))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_fee_rounds_up() {
        assert_eq!(input_fee_sat(3, 0), 0);
        assert_eq!(input_fee_sat(1, 1), 1);
        assert_eq!(input_fee_sat(3, 1000), 3);
        assert_eq!(input_fee_sat(usize::MAX, u64::MAX), u64::MAX / 1000 + 1);
    }

    #[test]
    fn descriptors_round_trip() {
        let proof: Proof = serde_json::from_str(
            r#"{"amount":2,"id":"009a1f293253e41e","secret":"407915bc212be61a77e3e6d2aeb4c727980bda51cd06a6afc29e2861768a7837","C":"02bc9097997d81afb2cc7346b5e4345a9346bd2a506eb7958598a72f0cf85163ea"}"#,
        )
        .unwrap();
        let compressed = cdk::nuts::nut01::SecretKey::from_slice(&[1; 32])
            .unwrap()
            .public_key()
            .to_bytes();
        let target = XOnlyPubKey::from_bytes(compressed[1..].try_into().unwrap()).unwrap();
        let descriptor = encode_proofs(&vec![proof.clone()], target).unwrap();
        assert_eq!(decode_proofs(&descriptor).unwrap(), (vec![proof], target));
        let lightning = HtlcDescriptor::Lightning {
            target: "lnbc".into(),
        };
        assert!(decode_proofs(&lightning).is_err());
    }
}
