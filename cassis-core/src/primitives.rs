use serde::{Deserialize, Serialize};
use std::fmt;

pub use ritualistic::PubKey as XOnlyPubKey;

/// Millisatoshi per satoshi.
pub const MSAT_PER_SAT: u64 = 1000;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Bytes32(pub [u8; 32]);

impl Bytes32 {
    pub fn short(&self) -> String {
        format!("…{}", self)[60..].to_string()
    }

    pub fn random() -> Self {
        Self(rand::random())
    }

    /// SHA-256 of these bytes: the payment hash of a preimage.
    pub fn sha256(&self) -> Bytes32 {
        use sha2::{Digest, Sha256};
        Bytes32(Sha256::digest(self.0).into())
    }

    /// True when `preimage` is a SHA-256 preimage of this hash.
    pub fn matches_preimage(&self, preimage: &Bytes32) -> bool {
        preimage.sha256() == *self
    }
}

impl fmt::Debug for Bytes32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", lowercase_hex::encode(self.0))
    }
}

impl fmt::Display for Bytes32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", lowercase_hex::encode(self.0))
    }
}

impl AsRef<[u8]> for Bytes32 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::str::FromStr for Bytes32 {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut bytes = [0u8; 32];
        lowercase_hex::decode_to_slice(value.trim(), &mut bytes)
            .map_err(|e| format!("expected 32 hex-encoded bytes: {e}"))?;
        Ok(Bytes32(bytes))
    }
}

impl Serialize for Bytes32 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&lowercase_hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for Bytes32 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// Full compressed secp256k1 public key: parity byte plus 32-byte X coordinate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PubKey(pub [u8; 33]);

impl PubKey {
    pub fn from_bytes(bytes: [u8; 33]) -> Result<Self, secp256k1::Error> {
        secp256k1::PublicKey::from_slice(&bytes)?;
        Ok(Self(bytes))
    }

    /// The even-Y (`0x02`) point with X coordinate `x`. Networks whose
    /// scripts need a full key address an x-only identity this way.
    pub fn from_x_only(x: &XOnlyPubKey) -> Result<Self, secp256k1::Error> {
        let mut bytes = [0u8; 33];
        bytes[0] = 0x02;
        bytes[1..].copy_from_slice(x.as_bytes());
        Self::from_bytes(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 33] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        lowercase_hex::encode(self.0)
    }

    pub fn x_only(&self) -> XOnlyPubKey {
        XOnlyPubKey::from_bytes(self.0[1..].try_into().expect("32-byte X coordinate"))
            .expect("compressed public key contains valid X coordinate")
    }

    pub fn to_ecdsa_key(&self) -> secp256k1::PublicKey {
        secp256k1::PublicKey::from_slice(&self.0).expect("validated compressed public key")
    }
}

impl std::str::FromStr for PubKey {
    type Err = secp256k1::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut bytes = [0u8; 33];
        lowercase_hex::decode_to_slice(value, &mut bytes)
            .map_err(|_| secp256k1::Error::InvalidPublicKey)?;
        Self::from_bytes(bytes)
    }
}

impl Serialize for PubKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for PubKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// Ed25519 public key that is a Solana address, written in base58 like
/// Solana's own tools write it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Ed25519PubKey(pub [u8; 32]);

impl Ed25519PubKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Ed25519PubKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&bs58::encode(self.0).into_string())
    }
}

impl std::str::FromStr for Ed25519PubKey {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let bytes = bs58::decode(value.trim())
            .into_vec()
            .map_err(|e| format!("expected a base58 key: {e}"))?;
        Ok(Self(bytes.try_into().map_err(|bytes: Vec<u8>| {
            format!("expected a 32-byte key, got {} bytes", bytes.len())
        })?))
    }
}

impl Serialize for Ed25519PubKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Ed25519PubKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// Address of a Starknet contract (an account): a field element, below
/// the Starknet prime, as 32 big-endian bytes. Written `0x` and 64 hex
/// digits, and read with or without leading zeros.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StarknetAddress(pub [u8; 32]);

/// The Starknet prime, `2^251 + 17 * 2^192 + 1`, big-endian.
const STARKNET_PRIME: [u8; 32] = {
    let mut prime = [0u8; 32];
    prime[0] = 0x08;
    prime[7] = 0x11;
    prime[31] = 0x01;
    prime
};

impl StarknetAddress {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, String> {
        if bytes >= STARKNET_PRIME {
            return Err("not a Starknet field element".into());
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for StarknetAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", lowercase_hex::encode(self.0))
    }
}

impl std::str::FromStr for StarknetAddress {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.trim();
        let digits = value.strip_prefix("0x").unwrap_or(value);
        if digits.is_empty() || digits.len() > 64 {
            return Err("expected a Starknet address of up to 64 hex digits".into());
        }
        let padded = format!("{digits:0>64}");
        let mut bytes = [0u8; 32];
        lowercase_hex::decode_to_slice(padded.to_ascii_lowercase(), &mut bytes)
            .map_err(|e| format!("expected a hex Starknet address: {e}"))?;
        Self::from_bytes(bytes)
    }
}

impl Serialize for StarknetAddress {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for StarknetAddress {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// Opaque identifier of one protocol attempt (a PREPARE reservation, a
/// COMMIT). Payment hashes identify payment intent; operation ids
/// identify attempts.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct OperationId(pub [u8; 16]);

impl OperationId {
    /// Fresh 128-bit identifier.
    pub fn random() -> Self {
        Self(rand::random())
    }
}

impl fmt::Debug for OperationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl fmt::Display for OperationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&lowercase_hex::encode(self.0))
    }
}

impl std::str::FromStr for OperationId {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut bytes = [0u8; 16];
        lowercase_hex::decode_to_slice(value, &mut bytes)
            .map_err(|e| format!("expected 16 hex-encoded bytes: {e}"))?;
        Ok(Self(bytes))
    }
}

impl Serialize for OperationId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for OperationId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// Current unix time in seconds, portable across native and wasm.
///
/// `SystemTime::now()` panics on `wasm32-unknown-unknown`, so on wasm
/// the time is read from `Date.now()`.
pub fn unix_now() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        (js_sys::Date::now() / 1000.0) as u64
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// Satoshis a sat-denominated network locks for `amount_msat`: rounded
/// up, so the receiver always sees at least the agreed msat amount.
/// Every sat-denominated network uses this one rule on both sides.
pub fn sats_for_msat(amount_msat: u64) -> u64 {
    amount_msat.div_ceil(MSAT_PER_SAT)
}
