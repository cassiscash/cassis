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

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Operation::Transfer(t) => Transfer::fmt(t, f),
            Operation::Trust(t) => Trust::fmt(t, f),
            Operation::Unknown => write!(f, "<unknown>"),
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
        match data[0] {
            Transfer::TAG => Operation::Transfer(Transfer::from_bytes(data)),
            Trust::TAG => Operation::Trust(Trust::from_bytes(data)),
            _ => Operation::Unknown,
        }
    }
}
