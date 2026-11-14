//! Every key a node uses, derived from one 12-word BIP39 mnemonic: each is
//! `HMAC-SHA512(seed, "cassis/<label>")`, truncated to 32 bytes.

use crate::network::NetworkId;
use hmac::{Hmac, Mac};
use ritualistic::SecretKey;
use sha2::Sha512;

pub const SEED_WORD_COUNT: usize = 12;

type HmacSha512 = Hmac<Sha512>;

#[derive(thiserror::Error, Debug)]
pub enum SeedError {
    #[error("could not parse BIP39 mnemonic: {0}")]
    InvalidMnemonic(#[from] bip39::Error),
    #[error("expected a {SEED_WORD_COUNT}-word mnemonic, got {0} words")]
    WrongWordCount(usize),
}

#[derive(Clone)]
pub struct NodeKeys {
    seed: [u8; 64],
    /// Node identity: signs route announcements and names the payee of
    /// every invoice.
    pub node: SecretKey,
    /// Secret of the node's iroh endpoint, whose public key is the
    /// node's identity as a payee: it signs its invoices and receive
    /// authorizations (see [`crate::offline`]), and gateways and
    /// preimage servers know the node by it.
    pub iroh: [u8; 32],
}

impl NodeKeys {
    pub fn from_mnemonic(mnemonic: &str) -> Result<Self, SeedError> {
        let words = mnemonic.split_whitespace().count();
        if words != SEED_WORD_COUNT {
            return Err(SeedError::WrongWordCount(words));
        }
        let seed = bip39::Mnemonic::parse(mnemonic)?.to_seed("");
        let node = SecretKey::from_bytes(scalar(&seed, b"cassis/node"))
            .expect("scalar() yields a valid secp256k1 secret");
        let iroh = hmac(&seed, b"cassis/iroh", None);
        Ok(Self { seed, node, iroh })
    }

    /// Secret of the endpoint serving this node's Cassis Order Protocol
    /// flows: stable, so a printed `cop:` URI keeps working, and distinct
    /// from [`NodeKeys::iroh`], which answers `cassis-hop`.
    pub fn order_endpoint_secret(&self) -> [u8; 32] {
        hmac(&self.seed, b"cassis/order", None)
    }

    /// Secret of the endpoint serving a router's admin interface: stable,
    /// so its `hyperb://` address keeps working, and distinct from
    /// [`NodeKeys::iroh`], so the interface outlives node restarts.
    pub fn admin_endpoint_secret(&self) -> [u8; 32] {
        hmac(&self.seed, b"cassis/admin", None)
    }

    /// Key a preimage server derives its preimages with (see
    /// [`crate::offline::PreimageIssuance`]).
    pub fn preimage_server_secret(&self) -> [u8; 32] {
        hmac(&self.seed, b"cassis/preimage-server", None)
    }

    /// Signing key of this node on `network`.
    pub fn network_secret(&self, network: &NetworkId) -> [u8; 32] {
        scalar(&self.seed, format!("cassis/network/{network}").as_bytes())
    }
}

/// The first `HMAC-SHA512(seed, label || counter)` whose leading 32 bytes
/// form a valid secp256k1 scalar.
fn scalar(seed: &[u8; 64], label: &[u8]) -> [u8; 32] {
    (0u32..)
        .map(|counter| hmac(seed, label, Some(counter)))
        .find(|candidate| secp256k1::SecretKey::from_byte_array(*candidate).is_ok())
        .expect("a valid scalar turns up with overwhelming probability")
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

/// A fresh wallet key for one network, from the OS CSPRNG: a valid
/// secp256k1 scalar, which every network takes. Daemons and wallets
/// write it to their config when a network is added; nothing derives
/// it.
pub fn new_network_secret() -> [u8; 32] {
    use rand::RngCore;
    loop {
        let mut candidate = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut candidate);
        if secp256k1::SecretKey::from_byte_array(candidate).is_ok() {
            return candidate;
        }
    }
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
    fn keys_are_deterministic_and_distinct() {
        let keys = NodeKeys::from_mnemonic(MNEMONIC).unwrap();
        let again = NodeKeys::from_mnemonic(MNEMONIC).unwrap();
        assert_eq!(keys.node.as_bytes(), again.node.as_bytes());
        assert_eq!(keys.iroh, again.iroh);
        let secrets = [
            *keys.node.as_bytes(),
            keys.iroh,
            keys.order_endpoint_secret(),
            keys.admin_endpoint_secret(),
            keys.preimage_server_secret(),
        ];
        for (i, a) in secrets.iter().enumerate() {
            for b in &secrets[i + 1..] {
                assert_ne!(a, b);
            }
        }
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
