use byteorder::{ByteOrder, LE};
use k256::sha2::{Digest, Sha256};
use redb::Value;
use std::fmt;

#[derive(Debug)]
pub struct Transfer {
    ts: u32,
    hops: Vec<Hop>,
    sigs: Vec<HopSig>,
}

impl Default for Transfer {
    fn default() -> Self {
        Transfer {
            ts: 0,
            hops: vec![],
            sigs: vec![],
        }
    }
}

impl fmt::Display for Transfer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "<transfer ")?;
        for hop in &self.hops {
            write!(f, "{} ", hop)?;
        }
        write!(f, "at {}>", self.ts)
    }
}

impl Transfer {
    pub const TAG: u8 = b'x';

    pub fn sighash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        let nosig = &Transfer::as_bytes(self)[0..self.size_nosig()];
        hasher.update(nosig);
        let digest = hasher.finalize();
        digest.into()
    }

    fn size_nosig(&self) -> usize {
        return 1 + 4 + self.hops.len() * Hop::SIZE;
    }

    fn size(&self) -> usize {
        return self.size_nosig() + self.sigs.len() * HopSig::SIZE;
    }
}

impl redb::Value for Transfer {
    fn type_name() -> redb::TypeName {
        redb::TypeName::new("transfer")
    }

    type AsBytes<'a> = Vec<u8>;
    type SelfType<'a> = Transfer;

    fn as_bytes<'a, 'b: 'a>(t: &'a Self::SelfType<'b>) -> Self::AsBytes<'a>
    where
        Self: 'a,
        Self: 'b,
    {
        let mut buf = vec![0; t.size()];

        buf[0] = Transfer::TAG;
        LE::write_u32(&mut buf[1..5], t.ts);
        buf[5] = t
            .hops
            .len()
            .try_into()
            .expect("can't have more than 128 hops");
        buf[6] = t
            .sigs
            .len()
            .try_into()
            .expect("can't have more than 128 hops");

        for (i, hop) in t.hops.iter().enumerate() {
            hop.write_to(&mut buf[7 + i * Hop::SIZE..7 + (i + 1) * Hop::SIZE]);
        }

        let start: usize = 7 + t.hops.len() * Hop::SIZE;
        for (i, hsig) in t.sigs.iter().enumerate() {
            hsig.write_to(&mut buf[start + i * HopSig::SIZE..start + (i + 1) * HopSig::SIZE]);
        }

        buf
    }

    fn fixed_width() -> Option<usize> {
        None
    }

    fn from_bytes<'a>(data: &'a [u8]) -> Self::SelfType<'a>
    where
        Self: 'a,
    {
        let mut i = 0;

        let nhops = data[5].into();
        let mut hops = Vec::with_capacity(nhops);
        while i < nhops {
            hops.push(Hop::from_bytes(&data[7 + i..]));
            i += Hop::SIZE;
        }

        i = 0;
        let start: usize = 7 + nhops * Hop::SIZE;
        let nsigs = data[6].into();
        let mut sigs = Vec::with_capacity(nsigs);
        while i < nhops {
            sigs.push(HopSig::from_bytes(&data[start + i..]));
            i += HopSig::SIZE;
        }

        Transfer {
            ts: LE::read_u32(&data[1..5]),
            hops,
            sigs,
        }
    }
}

#[derive(Debug)]
struct Hop {
    from: u32,
    to: u32,
    amount: u32,
}

impl Hop {
    const SIZE: usize = 12;

    fn from_bytes(data: &[u8]) -> Hop {
        Hop {
            from: LE::read_u32(&data[0..4]),
            amount: LE::read_u32(&data[4..8]),
            to: LE::read_u32(&data[8..12]),
        }
    }

    fn write_to(&self, buf: &mut [u8]) {
        LE::write_u32(&mut buf[0..4], self.from);
        LE::write_u32(&mut buf[4..8], self.amount);
        LE::write_u32(&mut buf[8..12], self.to);
    }
}

impl std::fmt::Display for Hop {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}-[{}]->{}", self.from, self.amount, self.to)
    }
}

#[derive(Debug)]
struct HopSig {
    hop_index: u8,
    sig: k256::schnorr::SignatureBytes,
}

impl HopSig {
    const SIZE: usize = 65;

    fn from_bytes(data: &[u8]) -> HopSig {
        HopSig {
            hop_index: data[0],
            sig: k256::schnorr::SignatureBytes::from_bytes(&data[1..]),
        }
    }

    fn write_to(&self, buf: &mut [u8]) {
        buf[0] = self.hop_index;
        buf[1..].copy_from_slice(&self.sig);
    }
}
