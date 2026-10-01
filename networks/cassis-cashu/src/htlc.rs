//! NUT-14 HTLC terms carried in proof secrets.

use crate::{Blinding, PublicKey};
use cassis_core::{Bytes32, NetworkError};
use cdk::dhke::blind_message;
use cdk::nuts::nut00::{BlindedMessage, Proof};
use cdk::nuts::nut01::SecretKey;
use cdk::nuts::nut02::Id as KeysetId;
use cdk::nuts::nut10::{Secret as Nut10Secret, SpendingConditions};
use cdk::nuts::nut14::HTLCWitness;
use cdk::nuts::{Conditions, Witness};
use cdk::secp256k1::hashes::Hash as _;
use cdk::secret::Secret;
use cdk::Amount;

/// What a NUT-14 HTLC proof is locked to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HtlcTerms {
    pub payment_hash: Bytes32,
    /// Only key that may claim with the preimage.
    pub receiver: PublicKey,
    /// Only key that may refund, once the locktime has passed: the
    /// funder's. Without one the mint lets anyone holding the proofs
    /// take them back.
    pub refund: PublicKey,
    /// Unix time after which the proof can be refunded.
    pub locktime: u64,
}

impl HtlcTerms {
    pub fn of(proof: &Proof) -> Result<Self, NetworkError> {
        let SpendingConditions::HTLCConditions {
            data,
            conditions: Some(conditions),
        } = SpendingConditions::try_from(&proof.secret).map_err(NetworkError::invalid)?
        else {
            return Err(NetworkError::invalid("proof is not an HTLC with terms"));
        };
        let [receiver] = conditions.pubkeys.as_deref().unwrap_or_default() else {
            return Err(NetworkError::invalid(
                "HTLC proof must name exactly one receiver",
            ));
        };
        let [refund] = conditions.refund_keys.as_deref().unwrap_or_default() else {
            return Err(NetworkError::invalid(
                "HTLC proof must name exactly one refund key",
            ));
        };
        Ok(Self {
            payment_hash: Bytes32(data.to_byte_array()),
            receiver: *receiver,
            refund: *refund,
            locktime: conditions
                .locktime
                .ok_or_else(|| NetworkError::invalid("HTLC proof has no refund locktime"))?,
        })
    }

    fn conditions(&self) -> Result<SpendingConditions, NetworkError> {
        let conditions = Conditions::new(
            Some(self.locktime),
            Some(vec![self.receiver]),
            Some(vec![self.refund]),
            Some(1),
            None,
            Some(1),
        )
        .map_err(NetworkError::invalid)?;
        SpendingConditions::new_htlc_hash(
            &lowercase_hex::encode(self.payment_hash.0),
            Some(conditions),
        )
        .map_err(NetworkError::invalid)
    }
}

/// Witness `proof` for the refund path: no preimage, signed by the
/// refund key `key`.
pub fn sign_refund(proof: &mut Proof, key: &SecretKey) -> Result<(), NetworkError> {
    proof.witness = Some(Witness::HTLCWitness(HTLCWitness::default()));
    proof.sign_p2pk(key.clone()).map_err(NetworkError::invalid)
}

/// Blinded outputs worth `amount_sat`, each with a secret locked by
/// `terms`, in power-of-two denominations.
pub fn htlc_outputs(
    terms: &HtlcTerms,
    amount_sat: u64,
    keyset: KeysetId,
) -> Result<Vec<(Blinding, BlindedMessage)>, NetworkError> {
    let conditions = terms.conditions()?;
    (0..64)
        .filter(|bit| amount_sat & (1 << bit) != 0)
        .map(|bit| {
            let amount = Amount::from(1u64 << bit);
            let nut10: Nut10Secret = conditions.clone().into();
            let secret: Secret = nut10.try_into().map_err(NetworkError::invalid)?;
            let (blinded, r) =
                blind_message(&secret.to_bytes(), None).map_err(NetworkError::invalid)?;
            Ok((
                (secret, r, amount),
                BlindedMessage::new(amount, keyset, blinded),
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cdk::nuts::SigFlag;

    fn terms() -> HtlcTerms {
        HtlcTerms {
            payment_hash: Bytes32([7; 32]),
            receiver: SecretKey::generate().public_key(),
            refund: SecretKey::generate().public_key(),
            locktime: 2_000_000_000,
        }
    }

    #[test]
    fn outputs_split_in_powers_of_two() {
        let keyset = KeysetId::from_str("009a1f293253e41e").unwrap();
        let outputs = htlc_outputs(&terms(), 13, keyset).unwrap();
        let amounts: Vec<u64> = outputs.iter().map(|(b, _)| u64::from(b.2)).collect();
        assert_eq!(amounts, vec![1, 4, 8]);
    }

    #[test]
    fn terms_round_trip_through_the_secret() {
        let terms = terms();
        let keyset = KeysetId::from_str("009a1f293253e41e").unwrap();
        let ((secret, _, amount), _) = htlc_outputs(&terms, 1, keyset).unwrap().remove(0);
        let proof = Proof {
            amount,
            keyset_id: keyset,
            secret,
            c: SecretKey::generate().public_key(),
            witness: None,
            dleq: None,
            p2pk_e: None,
        };
        assert_eq!(HtlcTerms::of(&proof).unwrap(), terms);
    }

    /// A proof locked by `terms` whose locktime has already passed.
    /// Built by hand: `Conditions::new` refuses past locktimes.
    fn expired_proof(terms: &HtlcTerms) -> Proof {
        let conditions = Conditions {
            locktime: Some(1),
            pubkeys: Some(vec![terms.receiver]),
            refund_keys: Some(vec![terms.refund]),
            num_sigs: Some(1),
            sig_flag: SigFlag::SigInputs,
            num_sigs_refund: Some(1),
        };
        let spending = SpendingConditions::new_htlc_hash(
            &lowercase_hex::encode(terms.payment_hash.0),
            Some(conditions),
        )
        .unwrap();
        let nut10: Nut10Secret = spending.into();
        Proof {
            amount: Amount::from(1),
            keyset_id: KeysetId::from_str("009a1f293253e41e").unwrap(),
            secret: nut10.try_into().unwrap(),
            c: SecretKey::generate().public_key(),
            witness: None,
            dleq: None,
            p2pk_e: None,
        }
    }

    #[test]
    fn only_the_refund_key_refunds_after_the_locktime() {
        let refund_key = SecretKey::generate();
        let terms = HtlcTerms {
            refund: refund_key.public_key(),
            ..terms()
        };
        // Holding the proofs is not enough.
        assert!(expired_proof(&terms).verify_htlc().is_err());
        let mut stranger = expired_proof(&terms);
        sign_refund(&mut stranger, &SecretKey::generate()).unwrap();
        assert!(stranger.verify_htlc().is_err());
        let mut funder = expired_proof(&terms);
        sign_refund(&mut funder, &refund_key).unwrap();
        funder.verify_htlc().unwrap();
    }

    use std::str::FromStr;
}
