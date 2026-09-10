use std::fmt;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Bytes32(pub [u8; 32]);

impl Bytes32 {
    pub fn short(&self) -> String {
        format!("…{}", self)[60..].to_string()
    }

    /// True when `preimage` is a SHA-256 preimage of this hash.
    pub fn matches_preimage(&self, preimage: &Bytes32) -> bool {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(preimage.0);
        let out = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&out);
        hash == self.0
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

impl serde::Serialize for Bytes32 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&lowercase_hex::encode(self.0))
    }
}

impl<'de> serde::Deserialize<'de> for Bytes32 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <String as serde::Deserialize>::deserialize(deserializer)?;
        let mut bytes = [0u8; 32];
        lowercase_hex::decode_to_slice(&s, &mut bytes).map_err(serde::de::Error::custom)?;
        Ok(Bytes32(bytes))
    }
}
