use crate::{CashuResult, Proof};
use std::sync::Mutex;

/// Persistence for every proof the adapter holds. The adapter keeps
/// no in-memory proof set: balances are always computed from the
/// store on demand, and every proof received (via
/// [`crate::CashuAdapter::claim_incoming`]) or spent (via a NUT-03
/// swap) is written through an implementation of this trait.
pub trait CashuProofStore: Send + Sync {
    /// Append `proofs` to the wallet's proof set for `mint_url`.
    fn insert_proofs(&self, mint_url: &str, proofs: &[Proof]) -> CashuResult<()>;

    /// Read every proof currently held for `mint_url`.
    fn list_proofs(&self, mint_url: &str) -> CashuResult<Vec<Proof>>;

    /// Remove `proofs` from the store (e.g. inputs burned by a swap
    /// at the mint). No-op for proofs that are not present.
    fn remove_proofs(&self, mint_url: &str, proofs: &[Proof]) -> CashuResult<()>;
}

/// Trivial in-memory proof store, used by unit tests and any
/// non-persistent deployment. Rows are keyed by `mint_url`.
#[allow(dead_code)]
pub struct InMemoryProofStore {
    proofs: Mutex<Vec<(String, Proof)>>,
}

#[allow(dead_code)]
impl InMemoryProofStore {
    pub fn new() -> Self {
        Self {
            proofs: Mutex::new(Vec::new()),
        }
    }
}

impl Default for InMemoryProofStore {
    fn default() -> Self {
        Self::new()
    }
}

impl CashuProofStore for InMemoryProofStore {
    fn insert_proofs(&self, mint_url: &str, proofs: &[Proof]) -> CashuResult<()> {
        self.proofs
            .lock()
            .unwrap()
            .extend(proofs.iter().map(|p| (mint_url.to_string(), p.clone())));
        Ok(())
    }

    fn list_proofs(&self, mint_url: &str) -> CashuResult<Vec<Proof>> {
        Ok(self
            .proofs
            .lock()
            .unwrap()
            .iter()
            .filter(|(m, _)| m == mint_url)
            .map(|(_, p)| p.clone())
            .collect())
    }

    fn remove_proofs(&self, mint_url: &str, proofs: &[Proof]) -> CashuResult<()> {
        let secrets: Vec<String> = proofs.iter().map(|p| p.secret.to_string()).collect();
        self.proofs.lock().unwrap().retain(|(m, p)| {
            if m != mint_url {
                return true;
            }
            !secrets.contains(&p.secret.to_string())
        });
        Ok(())
    }
}
