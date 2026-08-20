//! Every key a node uses, derived from one 12-word BIP39 mnemonic.

use crate::network::NetworkId;
use hmac::{Hmac, Mac};
use ritualistic::SecretKey;
use sha2::Sha512;
use std::str::FromStr;

pub const SEED_WORD_COUNT: usize = 12;

/// NIP-06 path of the node key (account 0): the same key a Nostr client
/// derives from this mnemonic. Pinned so a node's identity never drifts.
const NODE_DERIVATION_PATH: &str = "m/44'/1237'/0'/0/0";

type HmacSha512 = Hmac<Sha512>;

#[derive(thiserror::Error, Debug)]
pub enum SeedError {
    #[error("could not parse BIP39 mnemonic: {0}")]
    InvalidMnemonic(#[from] bip39::Error),
    #[error("expected a {SEED_WORD_COUNT}-word mnemonic, got {0} words")]
    WrongWordCount(usize),
    #[error("BIP32 derivation failed: {0}")]
    Derivation(String),
}

#[derive(Clone)]
pub struct NodeKeys {
    seed: [u8; 64],
    /// Node identity: signs route announcements and names the payee of
    /// every invoice.
    pub node: SecretKey,
    /// Secret of the node's iroh endpoint.
    pub iroh: [u8; 32],
}

impl NodeKeys {
    pub fn from_mnemonic(mnemonic: &str) -> Result<Self, SeedError> {
        let words = mnemonic.split_whitespace().count();
        if words != SEED_WORD_COUNT {
            return Err(SeedError::WrongWordCount(words));
        }
        let seed = bip39::Mnemonic::parse(mnemonic)?.to_seed("");
        let path = bip32::DerivationPath::from_str(NODE_DERIVATION_PATH)
            .map_err(|e| SeedError::Derivation(e.to_string()))?;
        let node = bip32::XPrv::derive_from_path(seed, &path)
            .map_err(|e| SeedError::Derivation(e.to_string()))?
            .to_bytes();
        let node =
            SecretKey::from_bytes(node).map_err(|e| SeedError::Derivation(format!("{e:?}")))?;
        let iroh = hmac(&seed, b"cassis/iroh", None);
        Ok(Self { seed, node, iroh })
    }

    /// Secret of the endpoint serving this node's Cassis Order Protocol
    /// flows: stable, so a printed `cop:` URI keeps working, and distinct
    /// from [`NodeKeys::iroh`], which answers `cassis-hop`.
    pub fn order_endpoint_secret(&self) -> [u8; 32] {
        hmac(&self.seed, b"cassis/order", None)
    }

    /// Signing key of this node on `network`: the first 32 bytes of
    /// `HMAC-SHA512(seed, "cassis/network/<id>" || counter)` that form a
    /// valid secp256k1 scalar.
    pub fn network_secret(&self, network: &NetworkId) -> [u8; 32] {
        let label = format!("cassis/network/{network}");
        (0u32..)
            .map(|counter| hmac(&self.seed, label.as_bytes(), Some(counter)))
            .find(|candidate| secp256k1::SecretKey::from_byte_array(*candidate).is_ok())
            .expect("a valid scalar turns up with overwhelming probability")
    }
}

fn hmac(seed: &[u8; 64], label: &[u8], counter: Option<u32>) -> [u8; 32] {
    let mut mac = HmacSha512::new_from_slice(seed).expect("hmac accepts any key length");
    mac.update(label);
    if let Some(counter) = counter {
        mac.update(&counter.to_be_bytes());
    }
    mac.finalize().into_bytes()[..32]
        .try_into()
        .expect("32 bytes")
}

/// Fresh 12-word mnemonic from the OS CSPRNG.
pub fn generate_mnemonic() -> String {
    use rand::RngCore;
    let mut entropy = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut entropy);
    bip39::Mnemonic::from_entropy(&entropy)
        .expect("16 bytes is valid BIP39 entropy")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn rejects_non_twelve_word_mnemonics() {
        assert!(matches!(
            NodeKeys::from_mnemonic(&format!("abandon abandon abandon {MNEMONIC}")),
            Err(SeedError::WrongWordCount(15))
        ));
    }

    #[test]
    fn node_key_matches_nip6_test_vector() {
        let keys = NodeKeys::from_mnemonic(
            "leader monkey parrot ring guide accident before fence cannon height naive bean",
        )
        .unwrap();
        assert_eq!(
            keys.node.to_hex(),
            "7f7ff03d123792d6ac594bfa67bf6d0c0ab55b6b1fdb6249303fe861f1ccba9a"
        );
        assert_eq!(
            keys.node.pubkey().to_hex(),
            "17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917"
        );
    }

    #[test]
    fn network_keys_are_deterministic_and_distinct() {
        let keys = NodeKeys::from_mnemonic(MNEMONIC).unwrap();
        let liquid = NetworkId("liquid".into());
        let arkade = NetworkId("arkade".into());
        assert_eq!(keys.network_secret(&liquid), keys.network_secret(&liquid));
        assert_ne!(keys.network_secret(&liquid), keys.network_secret(&arkade));
        assert_ne!(&keys.network_secret(&liquid), keys.node.as_bytes());
    }

    #[test]
    fn generated_mnemonics_have_twelve_words() {
        assert_eq!(
            generate_mnemonic().split_whitespace().count(),
            SEED_WORD_COUNT
        );
    }
}
