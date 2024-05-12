use byteorder::{ByteOrder, LE};
use secp256k1::{
    hashes::{sha256, Hash},
    XOnlyPublicKey,
};
use std::{
    fmt,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::key::{PublicKey, SecretKey};
use crate::OperationOps;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Trust {
    pub ts: u32,
    pub from: u32,
    pub to: PublicKey,
    pub amount: u32,
    #[serde(with = "hex::serde")]
    pub sig: [u8; 64],
}

impl Default for Trust {
    fn default() -> Self {
        Trust {
            ts: 0,
            from: 0,
            to: PublicKey(XOnlyPublicKey::from_slice(&[0; 32]).unwrap()),
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

impl OperationOps for Trust {
    const TAG: u8 = b't';

    fn write_serialized(&self, buf: &mut Vec<u8>) {
        buf[0] = Trust::TAG;
        LE::write_u32(&mut buf[1..5], self.ts);
        LE::write_u32(&mut buf[5..9], self.from);
        buf[9..41].copy_from_slice(&self.to.serialize());
        LE::write_u32(&mut buf[41..45], self.amount);
    }

    fn size_nosig(&self) -> usize {
        Trust::SIZE - 64
    }

    fn size(&self) -> usize {
        Trust::SIZE
    }

    fn deserialize(buf: &[u8]) -> Self {
        Trust {
            ts: LE::read_u32(&buf[1..5]),
            from: LE::read_u32(&buf[5..9]),
            to: PublicKey(XOnlyPublicKey::from_slice(&buf[9..41]).unwrap()),
            amount: LE::read_u32(&buf[41..45]),
            sig: buf[45..109].try_into().unwrap(),
        }
    }
}

impl Trust {
    const SIZE: usize = 1 + 4 + 4 + 32 + 4 + 64;

    pub fn new(secret_key: SecretKey, from: u32, to: PublicKey, amount: u32) -> Self {
        Self::new_with_time(secret_key, SystemTime::now(), from, to, amount)
    }

    pub fn new_with_time(
        secret_key: SecretKey,
        when: SystemTime,
        from: u32,
        to: PublicKey,
        amount: u32,
    ) -> Self {
        // build
        let mut t = Trust {
            ts: when
                .duration_since(UNIX_EPOCH)
                .expect("time went backwards")
                .as_secs() as u32,
            from,
            to,
            amount,
            sig: [0; 64],
        };

        // sign
        let mut nosig = vec![0; t.size_nosig()];
        t.write_serialized(&mut nosig);
        let digest = sha256::Hash::hash(&nosig);
        let message = secp256k1::Message::from_digest(digest.to_byte_array());
        t.sig = secret_key.0.sign_schnorr(message).serialize();

        t
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
        Self::deserialize(data)
    }
}
