//! NUT-14 HTLC terms carried in proof secrets.

use crate::{Blinding, PublicKey};
use cassis_core::{Bytes32, NetworkError};
use cdk::dhke::blind_message;
use cdk::nuts::nut00::{BlindedMessage, Proof};
use cdk::nuts::nut02::Id as KeysetId;
use cdk::nuts::nut10::{Secret as Nut10Secret, SpendingConditions};
use cdk::nuts::Conditions;
use cdk::secp256k1::hashes::Hash as _;
use cdk::secret::Secret;
use cdk::Amount;

/// What a NUT-14 HTLC proof is locked to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HtlcTerms {
    pub payment_hash: Bytes32,
    /// Only key that may claim with the preimage.
    pub receiver: PublicKey,
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
        Ok(Self {
            payment_hash: Bytes32(data.to_byte_array()),
            receiver: *receiver,
            locktime: conditions
                .locktime
                .ok_or_else(|| NetworkError::invalid("HTLC proof has no refund locktime"))?,
        })
    }

    fn conditions(&self) -> Result<SpendingConditions, NetworkError> {
        let conditions = Conditions::new(
            Some(self.locktime),
            Some(vec![self.receiver]),
            None,
            Some(1),
            None,
            None,
        )
        .map_err(NetworkError::invalid)?;
        SpendingConditions::new_htlc_hash(
            &lowercase_hex::encode(self.payment_hash.0),
            Some(conditions),
        )
        .map_err(NetworkError::invalid)
    }
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
    use cdk::nuts::nut01::SecretKey;

    fn terms() -> HtlcTerms {
        HtlcTerms {
            payment_hash: Bytes32([7; 32]),
            receiver: SecretKey::generate().public_key(),
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

    use std::str::FromStr;
}
