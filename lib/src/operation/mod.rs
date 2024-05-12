use secp256k1::hashes::{sha256, Hash};
use std::fmt;

mod transfer;
mod trust;

pub use transfer::Transfer;
pub use trust::Trust;

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(tag = "tag")]
pub enum Operation {
    #[serde(rename = "t")]
    Trust(Trust),
    #[serde(rename = "x")]
    Transfer(Transfer),
    #[serde(rename = "u")]
    Unknown,
}

pub trait OperationOps {
    const TAG: u8;

    fn write_serialized(&self, buf: &mut Vec<u8>);

    fn size(&self) -> usize;
    fn size_nosig(&self) -> usize;

    fn sighash(&self) -> [u8; 32] {
        let mut nosig = vec![0u8; self.size_nosig()];
        self.write_serialized(&mut nosig);
        let digest = sha256::Hash::hash(&nosig);
        digest.to_byte_array()
    }

    fn deserialize(buf: &[u8]) -> Self;
}

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Operation::Transfer(t) => Transfer::fmt(t, f),
            Operation::Trust(t) => Trust::fmt(t, f),
            Operation::Unknown => write!(f, "<unknown>"),
        }
    }
}

impl Operation {
    pub fn sighash(&self) -> [u8; 32] {
        match self {
            Operation::Transfer(t) => t.sighash(),
            Operation::Trust(t) => t.sighash(),
            Operation::Unknown => [0u8; 32],
        }
    }

    pub fn size(&self) -> usize {
        match self {
            Operation::Transfer(t) => t.size(),
            Operation::Trust(t) => t.size(),
            Operation::Unknown => 0,
        }
    }

    pub fn write_serialized(&self, buf: &mut Vec<u8>) {
        match self {
            Operation::Transfer(t) => t.write_serialized(buf),
            Operation::Trust(t) => t.write_serialized(buf),
            Operation::Unknown => {}
        }
    }

    pub fn deserialize(buf: &[u8]) -> Self {
        match buf[0] {
            Transfer::TAG => Operation::Transfer(Transfer::deserialize(buf)),
            Trust::TAG => Operation::Trust(Trust::deserialize(buf)),
            _ => Operation::Unknown,
        }
    }
}

#[cfg(feature = "redb")]
impl redb::Value for Operation {
    fn type_name() -> redb::TypeName {
        redb::TypeName::new("operation")
    }

    type AsBytes<'a> = Vec<u8>;
    type SelfType<'a> = Operation;

    fn as_bytes<'a, 'b: 'a>(op: &'a Self::SelfType<'b>) -> Self::AsBytes<'a>
    where
        Self: 'a,
        Self: 'b,
    {
        match op {
            Operation::Transfer(t) => Transfer::as_bytes(t),
            Operation::Trust(t) => Trust::as_bytes(t).to_vec(),
            Operation::Unknown => vec![],
        }
    }

    fn fixed_width() -> Option<usize> {
        None
    }

    fn from_bytes<'a>(data: &'a [u8]) -> Self::SelfType<'a>
    where
        Self: 'a,
    {
        Self::deserialize(data)
    }
}
