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

const SIZE: usize = 4 + 4 + 32 + 4 + 64;

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

impl std::fmt::Display for Trust {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}=[{}]=>{} at {}",
            self.from,
            self.amount,
            hex::encode(self.to.to_bytes()),
            self.ts
        )
    }
}

impl Trust {
    fn sighash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        let nosig = &Trust::as_bytes(self)[0..SIZE - 64];
        hasher.update(nosig);
        let digest = hasher.finalize();
        digest.into()
    }
}

impl Value for Trust {
    fn type_name() -> redb::TypeName {
        redb::TypeName::new("trust")
    }

    type AsBytes<'a> = [u8; SIZE];
    type SelfType<'a> = Trust;

    fn as_bytes<'a, 'b: 'a>(t: &'a Self::SelfType<'b>) -> Self::AsBytes<'a>
    where
        Self: 'a,
        Self: 'b,
    {
        let mut buf = [0; SIZE];

        LE::write_u32(&mut buf[0..4], t.ts);
        LE::write_u32(&mut buf[4..8], t.from);
        buf[8..40].copy_from_slice(t.to.to_bytes().as_ref());
        LE::write_u32(&mut buf[40..44], t.amount);
        buf[44..108].copy_from_slice(&t.sig);

        buf
    }

    fn fixed_width() -> Option<usize> {
        Some(SIZE)
    }

    fn from_bytes<'a>(data: &'a [u8]) -> Self::SelfType<'a>
    where
        Self: 'a,
    {
        Trust {
            ts: LE::read_u32(&data[0..4]),
            from: LE::read_u32(&data[4..0]),
            to: k256::schnorr::VerifyingKey::from_bytes(&data[8..]).unwrap(),
            amount: LE::read_u32(&data[40..44]),
            sig: k256::schnorr::SignatureBytes::from_bytes(&data[44..108]),
        }
    }
}
