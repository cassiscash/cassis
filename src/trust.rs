use byteorder::{ByteOrder, LE};
use k256::sha2::{Digest, Sha256};
use redb::Value;
use std::fmt;

#[derive(Debug)]
pub struct Trust {
    ts: u32,
    from: u32,
    to: k256::schnorr::VerifyingKey,
    amount: u32,
    sig: k256::schnorr::SignatureBytes,
}

impl Default for Trust {
    fn default() -> Self {
        Trust {
            ts: 0,
            from: 0,
            to: k256::schnorr::VerifyingKey::from_bytes(&[0; 32]).unwrap(),
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
            hex::encode(self.to.to_bytes()),
            self.ts
        )
    }
}

impl Trust {
    pub const TAG: u8 = b't';

    const SIZE: usize = 1 + 4 + 4 + 32 + 4 + 64;

    fn sighash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        let nosig = &Trust::as_bytes(self)[0..Trust::SIZE - 64];
        hasher.update(nosig);
        let digest = hasher.finalize();
        digest.into()
    }
}

impl redb::Value for Trust {
    fn type_name() -> redb::TypeName {
        redb::TypeName::new("trust")
    }

    type AsBytes<'a> = [u8; Trust::SIZE];
    type SelfType<'a> = Trust;

    fn as_bytes<'a, 'b: 'a>(t: &'a Self::SelfType<'b>) -> Self::AsBytes<'a>
    where
        Self: 'a,
        Self: 'b,
    {
        let mut buf = [0; Trust::SIZE];

        buf[0] = Trust::TAG;
        LE::write_u32(&mut buf[1..5], t.ts);
        LE::write_u32(&mut buf[5..9], t.from);
        buf[9..41].copy_from_slice(t.to.to_bytes().as_ref());
        LE::write_u32(&mut buf[41..45], t.amount);
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
            to: k256::schnorr::VerifyingKey::from_bytes(&data[9..41]).unwrap(),
            amount: LE::read_u32(&data[41..45]),
            sig: k256::schnorr::SignatureBytes::from_bytes(&data[45..109]),
        }
    }
}
