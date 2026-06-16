//! NUT-14 HTLC helpers for Cashu proofs.
//!
//! Cashu's HTLC model is built on NUT-14 (Hashed Time Locked Contracts):
//! the sender locks ecash behind a SHA-256 hash; the receiver can spend
//! the ecash by swapping the locked proofs at the mint with a preimage
//! witness, and the sender can reclaim them after the locktime passes
//! via the same swap endpoint (without a witness).
//!
//! [`CashuAdapter`] uses these helpers to:
//! * build the [`SpendingConditions`] attached to a swap's outputs
//!   ([`htlc_conditions`], [`build_htlc_outputs`]),
//! * turn a swap response back into [`Proof`]s
//!   ([`construct_proofs`]),
//! * verify a preimage was actually revealed
//!   ([`verify_proofs_htlc`], [`extract_preimage`], [`proof_y`]).

#[allow(unused_imports)]
use cdk::dhke::{blind_message, construct_proofs as dhke_construct_proofs};
use cdk::nuts::nut00::{BlindedMessage, PreMint, Proof, Proofs};
use cdk::nuts::nut10::{Secret as Nut10Secret, SpendingConditions};
use cdk::nuts::{Conditions, Id as KeysetId, Witness};
use cdk::secret::Secret;
use cdk::util::unix_time;
use cdk::Amount;

use crate::errors::{CashuError, CashuResult};

/// SHA-256 of the preimage in hex, exactly the form NUT-14 stores in
/// the secret's `data` field.
pub fn payment_hash_hex(payment_hash: &[u8; 32]) -> String {
    lowercase_hex::encode(payment_hash)
}

/// Build the NUT-14 spending conditions for an HTLC whose preimage
/// hash is `payment_hash` and whose sender-refund path becomes
/// available at `locktime` (unix seconds). `locktime` is required to
/// be in the future; the resulting [`SpendingConditions`] embed it
/// as a tag so the mint will accept the swap.
pub fn htlc_conditions(payment_hash: &[u8; 32], locktime: u64) -> CashuResult<SpendingConditions> {
    let conditions = Conditions::new(Some(locktime), None, None, None, None, None)
        .map_err(|e| CashuError::Nuts(format!("invalid NUT-10 conditions: {e}")))?;
    SpendingConditions::new_htlc_hash(&payment_hash_hex(payment_hash), Some(conditions))
        .map_err(|e| CashuError::Nuts(format!("invalid NUT-14 spending conditions: {e}")))
}

/// Pre-built HTLC outputs for a swap: a list of [`PreMint`] entries
/// (one per output denomination) plus the total amount they sum to.
pub struct HtlcOutputs {
    pub premints: Vec<PreMint>,
    #[allow(dead_code)]
    pub total: Amount,
}

/// Build a set of HTLC-locked blinded outputs that the mint will sign.
///
/// `amount_sat` is the sat-denominated face value (Cashu works in
/// sats, not msats); `keyset_id` selects which keyset the mint signs
/// with. The output split follows Cashu's standard powers-of-two
/// denomination policy (1, 2, 4, 8, ...). The [`SpendingConditions`]
/// returned by [`htlc_conditions`] are attached to every blinded
/// message so the mint signs them under the HTLC.
pub fn build_htlc_outputs(
    amount_sat: u64,
    keyset_id: KeysetId,
    payment_hash: &[u8; 32],
    locktime: u64,
) -> CashuResult<HtlcOutputs> {
    let conditions = htlc_conditions(payment_hash, locktime)?;
    let amount = Amount::from(amount_sat);
    let fee_and_amounts = default_fee_and_amounts();
    let split = amount
        .split(&fee_and_amounts)
        .map_err(|e| CashuError::Nuts(format!("cannot split HTLC amount: {e}")))?;
    let mut premints = Vec::with_capacity(split.len());
    for part in split {
        let nut10_secret: Nut10Secret = conditions.clone().into();
        let secret: Secret = nut10_secret
            .try_into()
            .map_err(|e| CashuError::Nuts(format!("invalid NUT-10 secret: {e}")))?;
        let (blinded, r) = blind_message(&secret.to_bytes(), None)
            .map_err(|e| CashuError::Nuts(format!("blind_message: {e}")))?;
        let blinded_message = BlindedMessage::new(part, keyset_id, blinded);
        premints.push(PreMint {
            secret,
            blinded_message,
            r,
            amount: part,
        });
    }
    Ok(HtlcOutputs {
        premints,
        total: amount,
    })
}

/// Default cashu swap-fee schedule: zero fee, the standard powers of
/// two (1, 2, 4, …, 2^31). Sufficient for splitting amounts into
/// HTLC-locked outputs when the caller doesn't track a per-keyset
/// fee schedule of its own.
pub fn default_fee_and_amounts() -> cdk::amount::FeeAndAmounts {
    (0u64, (0..32).map(|x| 2u64.pow(x)).collect::<Vec<_>>()).into()
}

/// Attach the preimage to a set of proofs so the mint will accept
/// them in a subsequent NUT-03 swap (i.e. so the receiver can
/// claim). `preimage` is the 32-byte raw preimage (not its hex
/// encoding).
pub fn add_preimage_to_proofs(proofs: &mut [Proof], preimage: &[u8; 32]) {
    let preimage_hex = lowercase_hex::encode(preimage);
    for proof in proofs.iter_mut() {
        proof.add_preimage(preimage_hex.clone());
    }
}

/// Construct NUT-00 [`Proof`]s from a swap response and the pre-mint
/// state the caller used to construct the swap request.
#[allow(dead_code)]
pub fn construct_proofs(
    response: cdk::nuts::nut03::SwapResponse,
    premints: Vec<PreMint>,
    keys: &cdk::nuts::Keys,
) -> CashuResult<Proofs> {
    let mut secrets = Vec::with_capacity(premints.len());
    let mut rs = Vec::with_capacity(premints.len());
    for pm in premints {
        secrets.push(pm.secret);
        rs.push(pm.r);
    }
    let promises = response.signatures;
    dhke_construct_proofs(promises, rs, secrets, keys)
        .map_err(|e| CashuError::Nuts(format!("construct_proofs: {e}")))
}

/// Verify that a set of proofs is correctly locked under NUT-14
/// HTLC conditions. Only meaningful once a preimage witness is
/// attached (the receiver path) or after the locktime has passed
/// (the sender-refund path); [`verify_htlc`] rejects a locked proof
/// with no witness while its locktime is still in the future, because
/// the refund path does not exist yet.
pub fn verify_proofs_htlc(proofs: &[Proof]) -> CashuResult<()> {
    for proof in proofs {
        proof
            .verify_htlc()
            .map_err(|e| CashuError::Nuts(format!("HTLC verification failed: {e}")))?;
    }
    Ok(())
}

/// Verify that `proofs` are structurally HTLC-locked to
/// `payment_hash`, without requiring a preimage witness or a passed
/// locktime. Each proof's secret must decode to a NUT-10 secret of
/// HTLC kind whose `data` field is the payment hash. This is the
/// check the sender runs right after a swap, and the mid-hop receiver
/// runs at DISPATCH time, when the proofs are freshly locked and no
/// witness is available yet.
pub fn verify_proofs_htlc_locked(proofs: &[Proof], payment_hash: &[u8; 32]) -> CashuResult<()> {
    let expected = payment_hash_hex(payment_hash);
    for proof in proofs {
        let nut10: Nut10Secret = serde_json::from_str(&proof.secret.to_string())
            .map_err(|e| CashuError::Nuts(format!("decode proof secret: {e}")))?;
        if nut10.kind() != cdk::nuts::nut10::Kind::HTLC {
            return Err(CashuError::Nuts(format!(
                "proof secret kind {:?} is not HTLC",
                nut10.kind()
            )));
        }
        let data = nut10.secret_data().data().to_string();
        if data != expected {
            return Err(CashuError::Nuts(format!(
                "proof HTLC hash mismatch: expected {expected}, got {data}"
            )));
        }
    }
    Ok(())
}

/// Extract the preimage from the first proof in `proofs` that carries
/// an HTLC witness. Returns [`CashuError::HtlcExpired`] if no proof
/// carries a witness (the preimage was never revealed, so either
/// nobody claimed or the locktime expired before claim).
#[allow(dead_code)]
pub fn extract_preimage(proofs: &[Proof]) -> CashuResult<[u8; 32]> {
    for proof in proofs {
        if let Some(Witness::HTLCWitness(witness)) = &proof.witness {
            return witness
                .preimage_data()
                .map_err(|e| CashuError::Nuts(format!("decode preimage: {e}")));
        }
    }
    Err(CashuError::HtlcExpired)
}

/// Compute the Y (hash-to-curve of the secret) for a proof. NUT-07's
/// `check_state` request takes Ys, not full proofs, so callers need
/// this to poll the mint.
pub fn proof_y(proof: &Proof) -> CashuResult<cdk::nuts::PublicKey> {
    proof
        .y()
        .map_err(|e| CashuError::Nuts(format!("proof.y: {e}")))
}

/// Re-export so callers don't need to import the underlying NUT-14 type.
#[allow(unused_imports)]
pub use cdk::nuts::nut14::HTLCWitness;

/// Assert that a locktime (unix seconds) is strictly in the future.
#[allow(dead_code)]
pub fn assert_locktime_in_future(locktime: u64) -> CashuResult<()> {
    if locktime <= unix_time() {
        return Err(CashuError::HtlcExpired);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cdk::nuts::nut02::Id as KeysetId;
    use std::str::FromStr;

    fn random_payment_hash() -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for byte in bytes.iter_mut() {
            *byte = (unix_time() as u8).wrapping_add(0x42);
        }
        bytes
    }

    #[test]
    fn htlc_conditions_embeds_hash_and_locktime() {
        let hash = random_payment_hash();
        let locktime = unix_time() + 60;
        let cond = htlc_conditions(&hash, locktime).expect("valid");
        let hex = payment_hash_hex(&hash);
        match cond {
            SpendingConditions::HTLCConditions { data, conditions } => {
                assert_eq!(data.to_string(), hex);
                let c = conditions.expect("conditions set");
                assert_eq!(c.locktime, Some(locktime));
            }
            _ => panic!("expected HTLC spending conditions"),
        }
    }

    #[test]
    fn htlc_conditions_rejects_past_locktime() {
        let hash = random_payment_hash();
        let past = unix_time().saturating_sub(10);
        assert!(htlc_conditions(&hash, past).is_err());
    }

    #[test]
    fn build_htlc_outputs_splits_powers_of_two() {
        let hash = random_payment_hash();
        let locktime = unix_time() + 120;
        let keyset_id = KeysetId::from_str("009a1f293253e41e").unwrap();
        let out = build_htlc_outputs(11, keyset_id, &hash, locktime).expect("valid");
        // 11 = 8 + 2 + 1
        let amounts: Vec<u64> = out.premints.iter().map(|p| u64::from(p.amount)).collect();
        assert_eq!(amounts.iter().sum::<u64>(), 11);
        assert_eq!(amounts.len(), 3);
    }

    #[test]
    fn add_preimage_and_extract_round_trips() {
        let hash = random_payment_hash();
        let locktime = unix_time() + 60;
        let keyset_id = KeysetId::from_str("009a1f293253e41e").unwrap();
        let out = build_htlc_outputs(4, keyset_id, &hash, locktime).expect("valid");
        let (preimage, _blinded_message, r, amount) = {
            let pm = &out.premints[0];
            (
                pm.secret.clone(),
                pm.blinded_message.clone(),
                pm.r.clone(),
                pm.amount,
            )
        };
        // Build a fake proof with a witness and check preimage
        // round-trip. We can't easily construct a real
        // C value without the mint's signature, so the test
        // focuses on the witness attachment path.
        let mut proof = Proof {
            amount,
            keyset_id,
            secret: preimage,
            c: cdk::nuts::nut01::PublicKey::from_str(
                "02bc9097997d81afb2cc7346b5e4345a9346bd2a506eb7958598a72f0cf85163ea",
            )
            .unwrap(),
            witness: None,
            dleq: None,
            p2pk_e: None,
        };
        let preimage_bytes = [0xabu8; 32];
        add_preimage_to_proofs(std::slice::from_mut(&mut proof), &preimage_bytes);
        let extracted = extract_preimage(&[proof]).expect("preimage present");
        assert_eq!(extracted, preimage_bytes);
        let _ = r; // silence
    }

    #[test]
    fn payment_hash_hex_is_lowercase_and_padded() {
        let hash = [0u8; 32];
        let s = payment_hash_hex(&hash);
        assert_eq!(s.len(), 64);
        assert!(s
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn assert_locktime_in_future_works() {
        assert!(assert_locktime_in_future(unix_time() + 1).is_ok());
        assert!(assert_locktime_in_future(unix_time()).is_err());
        assert!(assert_locktime_in_future(unix_time().saturating_sub(1)).is_err());
    }
}
