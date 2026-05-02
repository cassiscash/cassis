//! NUT-14 HTLC helpers for Cashu proofs.

use cashu::nuts::{nut00::Proof, Conditions, SpendingConditions, Witness};
use cashu::util::hex;

/// A bundle of HTLC-locked proofs plus the metadata needed to refund them.
#[derive(Debug, Clone)]
pub struct HtlcProofs {
    pub proofs: Vec<Proof>,
    pub payment_hash: [u8; 32],
    pub locktime: u64,
}

impl HtlcProofs {
    /// Create the NUT-14 spending conditions for an HTLC.
    pub fn spending_conditions(
        payment_hash: [u8; 32],
        locktime: u64,
    ) -> std::result::Result<SpendingConditions, cashu::nuts::nut14::Error> {
        let hash_hex = hex::encode(payment_hash);
        let conditions = Conditions::new(Some(locktime), None, None, None, None, None)
            .map_err(|e| cashu::nuts::nut14::Error::LocktimeInPast)?;
        SpendingConditions::new_htlc_hash(&hash_hex, Some(conditions))
    }

    /// Add a preimage witness to a set of proofs so they can be spent.
    pub fn add_preimage_to_proofs(proofs: &mut [Proof], preimage: [u8; 32]) {
        let preimage_hex = hex::encode(preimage);
        for proof in proofs.iter_mut() {
            proof.add_preimage(preimage_hex.clone());
        }
    }

    /// Verify that a set of proofs has valid HTLC spending conditions.
    pub fn verify_proofs_htlc(
        proofs: &[Proof],
    ) -> std::result::Result<(), cashu::nuts::nut14::Error> {
        for proof in proofs {
            proof.verify_htlc()?;
        }
        Ok(())
    }

    /// Extract the preimage bytes from a proof's HTLC witness.
    pub fn extract_preimage(
        proofs: &[Proof],
    ) -> std::result::Result<[u8; 32], cashu::nuts::nut14::Error> {
        for proof in proofs {
            if let Some(Witness::HTLCWitness(ref witness)) = proof.witness {
                return witness.preimage_data();
            }
        }
        Err(cashu::nuts::nut14::Error::Preimage)
    }
}