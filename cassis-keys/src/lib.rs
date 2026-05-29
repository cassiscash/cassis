use cassis_core::NetworkId;
use hmac::{Hmac, Mac};
use ritualistic::SecretKey;
use sha2::Sha512;
use std::collections::HashMap;
use std::str::FromStr;

/// BIP39 mnemonic words expected.
pub const SEED_WORD_COUNT: usize = 12;

/// NIP-6 derivation path for the Nostr signing key (account 0).
///
/// See <https://nips.nostr.com/6>: BIP32 path `m/44'/1237'/<account>'/0/0`
/// using the Nostr SLIP44 coin type 1237.
const NOSTR_DERIVATION_PATH: &str = "m/44'/1237'/0'/0/0";

type HmacSha512 = Hmac<Sha512>;

#[derive(thiserror::Error, Debug)]
pub enum SeedError {
    #[error("could not parse BIP39 mnemonic: {0}")]
    InvalidMnemonic(#[from] bip39::Error),
    #[error("expected a {expected}-word mnemonic, got {actual} words")]
    WrongWordCount { expected: usize, actual: usize },
    #[error("invalid BIP32 derivation path: {0}")]
    InvalidPath(String),
    #[error("BIP32 derivation failed: {0}")]
    DerivationFailed(String),
    #[error("derived key is not a valid secp256k1 scalar")]
    InvalidScalar,
    #[error("derived key output range exhausted for label '{label}'")]
    DerivationExhausted { label: String },
}

/// All keys derived from a BIP39 seed. Shared by `cassis-router` and
/// `cassis-cli`: the router uses it for route-announcement signing and
/// adapter construction; the CLI uses it for the same plus stable
/// inbound identity on the receiver side.
#[derive(Debug, Clone)]
pub struct DerivedKeys {
    /// Nostr signing key used to sign route-announcement events.
    pub nostr: SecretKey,
    /// Iroh transport key used for peer-to-peer connections.
    pub iroh: iroh::SecretKey,
    /// One signing key per network the node participates in.
    pub networks: HashMap<NetworkId, SecretKey>,
}

/// Parse a BIP39 mnemonic and return its 64-byte seed.
///
/// The passphrase is empty, matching the common "no passphrase" convention.
pub fn parse_seed(mnemonic: &str) -> Result<[u8; 64], SeedError> {
    let word_count = mnemonic.split_whitespace().count();
    if word_count != SEED_WORD_COUNT {
        return Err(SeedError::WrongWordCount {
            expected: SEED_WORD_COUNT,
            actual: word_count,
        });
    }
    let mnemonic = bip39::Mnemonic::parse(mnemonic)?;
    Ok(mnemonic.to_seed(""))
}

/// Derive every key the node needs from a BIP39 mnemonic.
///
/// The Nostr signing key is derived per NIP-6 at the BIP32 path
/// `m/44'/1237'/0'/0/0` (account 0). Per-network signing keys use a
/// SLIP-21-style derivation: each key is the first 32 bytes of
/// `HMAC-SHA512(key = seed, message = label || counter)`, where the label is
/// `cassis/network/<network_id>`. Outputs that are not valid secp256k1 secret
/// scalars are skipped by incrementing the counter, which happens with
/// negligible probability.
pub fn derive_keys(mnemonic: &str, network_ids: Vec<NetworkId>) -> Result<DerivedKeys, SeedError> {
    let seed = parse_seed(mnemonic)?;

    let nostr = derive_nostr_secret_key(&seed)?;
    let iroh = derive_iroh_secret_key(&seed);

    let mut networks = HashMap::with_capacity(network_ids.len());
    for network_id in network_ids {
        let label = format!("cassis/network/{network_id}");
        let secret = derive_secret_key(&seed, label.as_bytes())
            .map_err(|label| SeedError::DerivationExhausted { label })?;
        networks.insert(network_id, secret);
    }

    Ok(DerivedKeys { nostr, iroh, networks })
}

/// Generate a fresh 12-word BIP39 mnemonic using the OS CSPRNG.
pub fn generate_mnemonic() -> Result<String, SeedError> {
    use rand::rngs::OsRng;
    use rand::RngCore;
    // 128 bits of entropy = 12 words.
    let mut entropy = [0u8; 16];
    OsRng.fill_bytes(&mut entropy);
    let mnemonic = bip39::Mnemonic::from_entropy(&entropy)?;
    Ok(mnemonic.to_string())
}

/// Derive the Nostr signing key from the BIP39 seed per NIP-6.
fn derive_nostr_secret_key(seed: &[u8; 64]) -> Result<SecretKey, SeedError> {
    let path = bip32::DerivationPath::from_str(NOSTR_DERIVATION_PATH)
        .map_err(|err| SeedError::InvalidPath(err.to_string()))?;
    let xprv = bip32::XPrv::derive_from_path(seed, &path)
        .map_err(|err| SeedError::DerivationFailed(err.to_string()))?;
    let bytes: [u8; 32] = xprv.to_bytes();
    SecretKey::from_bytes(bytes).map_err(|_| SeedError::InvalidScalar)
}

fn derive_secret_key(seed: &[u8; 64], label: &[u8]) -> Result<SecretKey, String> {
    for counter in 0u32.. {
        let mut mac = HmacSha512::new_from_slice(seed).expect("hmac accepts any key length");
        mac.update(label);
        mac.update(&counter.to_be_bytes());
        let out = mac.finalize().into_bytes();

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&out[..32]);

        if let Ok(secret) = SecretKey::from_bytes(bytes) {
            return Ok(secret);
        }

        if counter == u32::MAX {
            return Err(
                String::from_utf8_lossy(label).into_owned(),
            );
        }
    }
    unreachable!()
}

fn derive_iroh_secret_key(seed: &[u8; 64]) -> iroh::SecretKey {
    let mut mac = HmacSha512::new_from_slice(seed).expect("hmac accepts any key length");
    mac.update(b"cassis/iroh");
    let out = mac.finalize().into_bytes();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&out[..32]);
    iroh::SecretKey::from(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn rejects_non_twelve_word_mnemonics() {
        let fifteen =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        assert!(matches!(
            derive_keys(fifteen, vec![]),
            Err(SeedError::WrongWordCount { expected: 12, .. })
        ));
    }

    #[test]
    fn nostr_key_matches_nip6_test_vector() {
        let mnemonic =
            "leader monkey parrot ring guide accident before fence cannon height naive bean";
        let keys = derive_keys(mnemonic, vec![]).unwrap();
        assert_eq!(
            keys.nostr.to_hex(),
            "7f7ff03d123792d6ac594bfa67bf6d0c0ab55b6b1fdb6249303fe861f1ccba9a",
            "nostr private key must match NIP-6 account-0 test vector"
        );
        assert_eq!(
            keys.nostr.pubkey().to_hex(),
            "17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917",
            "nostr pubkey must match NIP-6 account-0 test vector"
        );
    }

    #[test]
    fn derives_deterministic_keys() {
        let ids = vec![NetworkId("liquid".into()), NetworkId("ark".into())];
        let a = derive_keys(TEST_MNEMONIC, ids.clone()).unwrap();
        let b = derive_keys(TEST_MNEMONIC, ids.clone()).unwrap();
        assert_eq!(a.nostr.as_bytes(), b.nostr.as_bytes());
        assert_eq!(
            a.networks.get(&ids[0]).unwrap().as_bytes(),
            b.networks.get(&ids[0]).unwrap().as_bytes()
        );
        assert_ne!(a.nostr.as_bytes(), a.networks.get(&ids[0]).unwrap().as_bytes());
    }

    #[test]
    fn different_networks_get_different_keys() {
        let ids = vec![NetworkId("liquid".into()), NetworkId("ark".into())];
        let keys = derive_keys(TEST_MNEMONIC, ids.clone()).unwrap();
        assert_ne!(
            keys.networks.get(&ids[0]).unwrap().as_bytes(),
            keys.networks.get(&ids[1]).unwrap().as_bytes()
        );
    }

    #[test]
    fn generate_mnemonic_produces_twelve_words() {
        let m = generate_mnemonic().unwrap();
        assert_eq!(m.split_whitespace().count(), SEED_WORD_COUNT);
    }
}
