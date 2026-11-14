//! The ecash wallet: unrestricted proofs kept in one JSON file.

use crate::{Amount, KeysetId, Proof, Secret};
use cdk::nuts::nut01::SecretKey;
use fs2::FileExt;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::path::{Path, PathBuf};

/// File of the swaps asked of the mint whose outputs are not held yet.
const PENDING: &str = "pending.json";

/// One output of a [`PendingSwap`]: what unblinds the mint's signature.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PendingOutput {
    pub secret: Secret,
    pub r: SecretKey,
    pub amount: Amount,
}

/// A swap asked of the mint: if its answer is lost, the mint can still
/// be asked for the signatures of these outputs (NUT-09).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PendingSwap {
    pub id: u64,
    pub created_at: u64,
    pub keyset: KeysetId,
    pub outputs: Vec<PendingOutput>,
}

pub struct Wallet {
    dir: PathBuf,
}

impl Wallet {
    pub fn open(dir: &Path) -> Result<Self, String> {
        std::fs::create_dir_all(dir).map_err(|e| format!("create {dir:?}: {e}"))?;
        Ok(Self {
            dir: dir.to_path_buf(),
        })
    }

    pub fn proofs(&self) -> Result<Vec<Proof>, String> {
        self.update(|proofs| Ok(proofs.clone()))
    }

    /// Add `new` proofs, except those the wallet already has.
    pub fn add(&self, new: &[Proof]) -> Result<(), String> {
        self.update(|proofs| {
            for proof in new {
                if !proofs.iter().any(|held| held.secret == proof.secret) {
                    proofs.push(proof.clone());
                }
            }
            Ok(())
        })
    }

    /// Journal the outputs of a swap about to be asked of the mint, so
    /// they can be restored if its answer is lost.
    pub fn begin_swap(&self, swap: &PendingSwap) -> Result<(), String> {
        self.update_file(PENDING, |swaps: &mut Vec<PendingSwap>| {
            swaps.push(swap.clone());
            Ok(())
        })
    }

    /// Forget the swap `id`: its outputs are held, or will never exist.
    pub fn end_swap(&self, id: u64) -> Result<(), String> {
        self.update_file(PENDING, |swaps: &mut Vec<PendingSwap>| {
            swaps.retain(|swap| swap.id != id);
            Ok(())
        })
    }

    /// Replace the journaled swap `swap.id` by `swap`.
    pub fn replace_swap(&self, swap: &PendingSwap) -> Result<(), String> {
        self.update_file(PENDING, |swaps: &mut Vec<PendingSwap>| {
            for held in swaps.iter_mut().filter(|held| held.id == swap.id) {
                *held = swap.clone();
            }
            Ok(())
        })
    }

    pub fn pending_swaps(&self) -> Result<Vec<PendingSwap>, String> {
        self.update_file(PENDING, |swaps: &mut Vec<PendingSwap>| Ok(swaps.clone()))
    }

    /// Remove and return proofs of `keyset` covering `amount_sat` plus
    /// the input fee they cost.
    pub fn select(
        &self,
        keyset: KeysetId,
        amount_sat: u64,
        fee_ppk: u64,
    ) -> Result<Vec<Proof>, String> {
        self.update(|proofs| {
            let picked = pick(proofs, keyset, amount_sat, fee_ppk)?;
            proofs.retain(|proof| !picked.contains(proof));
            Ok(picked)
        })
    }

    /// Whether [`Wallet::select`] would succeed.
    pub fn select_preview(
        &self,
        keyset: KeysetId,
        amount_sat: u64,
        fee_ppk: u64,
    ) -> Result<(), String> {
        pick(&self.proofs()?, keyset, amount_sat, fee_ppk).map(|_| ())
    }

    /// Read-modify-write under an exclusive file lock, so concurrent
    /// processes on the same wallet never lose proofs.
    fn update<T>(&self, f: impl FnOnce(&mut Vec<Proof>) -> Result<T, String>) -> Result<T, String> {
        self.update_file("proofs.json", f)
    }

    /// [`Wallet::update`] of the list kept in the file `name`.
    fn update_file<I, T>(
        &self,
        name: &str,
        f: impl FnOnce(&mut Vec<I>) -> Result<T, String>,
    ) -> Result<T, String>
    where
        I: Serialize + DeserializeOwned + Clone + PartialEq,
    {
        let lock = File::create(self.dir.join("proofs.lock")).map_err(|e| e.to_string())?;
        lock.lock_exclusive()
            .map_err(|e| format!("lock wallet: {e}"))?;
        let path = self.dir.join(name);
        let mut items: Vec<I> = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| format!("read wallet: {e}"))?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(format!("read wallet: {error}")),
        };
        let before = items.clone();
        let result = f(&mut items)?;
        if items != before {
            let temporary = self.dir.join(format!("{name}.tmp"));
            let bytes = serde_json::to_vec(&items).map_err(|e| e.to_string())?;
            std::fs::write(&temporary, bytes).map_err(|e| format!("write wallet: {e}"))?;
            std::fs::rename(&temporary, &path).map_err(|e| format!("write wallet: {e}"))?;
        }
        Ok(result)
    }
}

/// Largest proofs of `keyset` first until they cover `amount_sat` and
/// the input fee of the picked set.
fn pick(
    proofs: &[Proof],
    keyset: KeysetId,
    amount_sat: u64,
    fee_ppk: u64,
) -> Result<Vec<Proof>, String> {
    let mut candidates: Vec<&Proof> = proofs.iter().filter(|p| p.keyset_id == keyset).collect();
    candidates.sort_by_key(|proof| std::cmp::Reverse(u64::from(proof.amount)));
    let mut picked = Vec::new();
    let mut total = 0u64;
    for proof in candidates {
        let needed = amount_sat + crate::input_fee_sat(picked.len(), fee_ppk);
        if total >= needed {
            break;
        }
        total += u64::from(proof.amount);
        picked.push(proof.clone());
    }
    let needed = amount_sat + crate::input_fee_sat(picked.len(), fee_ppk);
    if total < needed {
        return Err(format!(
            "insufficient cashu balance: need {needed} sat with fees, have {total} sat"
        ));
    }
    Ok(picked)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cdk::nuts::nut01::SecretKey;
    use std::str::FromStr;

    fn proof(amount: u64, keyset: &str) -> Proof {
        Proof {
            amount: amount.into(),
            keyset_id: KeysetId::from_str(keyset).unwrap(),
            secret: cdk::secret::Secret::generate(),
            c: SecretKey::generate().public_key(),
            witness: None,
            dleq: None,
            p2pk_e: None,
        }
    }

    const ACTIVE: &str = "009a1f293253e41e";
    const OTHER: &str = "00ad268c4d1f5826";

    #[test]
    fn picks_largest_first_and_covers_fees() {
        let proofs = vec![
            proof(1, ACTIVE),
            proof(8, ACTIVE),
            proof(4, ACTIVE),
            proof(16, OTHER),
        ];
        let keyset = KeysetId::from_str(ACTIVE).unwrap();
        let picked = pick(&proofs, keyset, 9, 0).unwrap();
        assert_eq!(
            picked
                .iter()
                .map(|p| u64::from(p.amount))
                .collect::<Vec<_>>(),
            vec![8, 4]
        );
        // One sat of fee per input: 8 + 4 covers 10 + 2, but 11 + 3
        // is out of reach.
        assert_eq!(pick(&proofs, keyset, 10, 1000).unwrap().len(), 2);
        assert!(pick(&proofs, keyset, 11, 1000).is_err());
        assert!(pick(&proofs, keyset, 14, 0).is_err());
    }

    #[test]
    fn select_removes_what_it_returns() {
        let dir = std::env::temp_dir().join(format!("cassis-cashu-{}", rand_suffix()));
        let wallet = Wallet::open(&dir).unwrap();
        wallet.add(&[proof(2, ACTIVE), proof(4, ACTIVE)]).unwrap();
        let picked = wallet
            .select(KeysetId::from_str(ACTIVE).unwrap(), 3, 0)
            .unwrap();
        assert_eq!(picked.len(), 1);
        assert_eq!(wallet.proofs().unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    fn rand_suffix() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
    }
}
