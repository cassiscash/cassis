use byteorder::{ByteOrder, LE};
use secp256k1::XOnlyPublicKey;
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::helpers;

#[derive(Debug, Serialize, Deserialize)]
pub struct Trust {
    pub ts: u32,
    pub from: u32,
    #[serde(
        serialize_with = "helpers::serialize_xonlypubkey",
        deserialize_with = "helpers::deserialize_xonlypubkey"
    )]
    pub to: XOnlyPublicKey,
    pub amount: u32,
    #[serde(with = "hex::serde")]
    pub sig: [u8; 64],
}

impl Default for Trust {
    fn default() -> Self {
        Trust {
            ts: 0,
            from: 0,
            to: XOnlyPublicKey::from_slice(&[0; 32]).unwrap(),
            amount: 1,
            sig: [0; 64],
        }
    }
}

impl fmt::Display for Trust {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "<trust {}-[{}]->{} at {}>",
            self.from,
            self.amount,
            hex::encode(self.to.serialize()),
            self.ts
        )
    }
}

impl Trust {
    pub const TAG: u8 = b't';

    const SIZE: usize = 1 + 4 + 4 + 32 + 4 + 64;

    pub fn write_serialized(&self, buf: &mut Vec<u8>) {
        buf[0] = Trust::TAG;
        LE::write_u32(&mut buf[1..5], self.ts);
        LE::write_u32(&mut buf[5..9], self.from);
        buf[9..41].copy_from_slice(&self.to.serialize());
        LE::write_u32(&mut buf[41..45], self.amount);
    }

    pub fn size_nosig(&self) -> usize {
        Trust::SIZE - 64
    }
}

#[cfg(feature = "redb")]
impl redb::Value for Trust {
    fn type_name() -> redb::TypeName {
        redb::TypeName::new("trust")
    }

    type AsBytes<'a> = Vec<u8>;
    type SelfType<'a> = Trust;

    fn as_bytes<'a, 'b: 'a>(t: &'a Self::SelfType<'b>) -> Self::AsBytes<'a>
    where
        Self: 'a,
        Self: 'b,
    {
        let mut buf = vec![0; Trust::SIZE];
        t.write_serialized(&mut buf);
        buf[45..109].copy_from_slice(&t.sig);
        buf
    }

    fn fixed_width() -> Option<usize> {
        Some(Trust::SIZE)
    }

    fn from_bytes<'a>(data: &'a [u8]) -> Self::SelfType<'a>
    where
        Self: 'a,
    {
        Trust {
            ts: LE::read_u32(&data[1..5]),
            from: LE::read_u32(&data[5..9]),
            to: XOnlyPublicKey::from_slice(&data[9..41]).unwrap(),
            amount: LE::read_u32(&data[41..45]),
            sig: data[45..109].try_into().unwrap(),
        }
    }
}
