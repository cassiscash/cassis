use byteorder::{ByteOrder, LE};
use std::fmt;

use crate::OperationOps;

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct Transfer {
    pub ts: u32,
    pub hops: Vec<Hop>,
    pub sigs: Vec<PeerSig>,
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

impl OperationOps for Transfer {
    const TAG: u8 = b'x';

    fn write_serialized(&self, buf: &mut [u8]) {
        buf[0] = Transfer::TAG;
        LE::write_u32(&mut buf[1..5], self.ts);
        buf[5] = self
            .hops
            .len()
            .try_into()
            .expect("can'self have more than 128 hops");
        buf[6] = self
            .sigs
            .len()
            .try_into()
            .expect("can'self have more than 128 hops");

        for (i, hop) in self.hops.iter().enumerate() {
            hop.write_to(&mut buf[7 + i * Hop::SIZE..7 + (i + 1) * Hop::SIZE]);
        }
    }

    fn size(&self) -> usize {
        return self.size_nosig() + self.sigs.len() * PeerSig::SIZE;
    }

    fn size_nosig(&self) -> usize {
        return 1 + 4 + self.hops.len() * Hop::SIZE;
    }

    fn deserialize(buf: &[u8]) -> Self {
        let mut i = 0;

        let nhops = buf[5].into();
        let mut hops = Vec::with_capacity(nhops);
        while i < nhops {
            hops.push(Hop::from_bytes(&buf[7 + i..]));
            i += Hop::SIZE;
        }

        i = 0;
        let start: usize = 7 + nhops * Hop::SIZE;
        let nsigs = buf[6].into();
        let mut sigs = Vec::with_capacity(nsigs);
        while i < nhops {
            sigs.push(PeerSig::from_bytes(&buf[start + i..]));
            i += PeerSig::SIZE;
        }

        Transfer {
            ts: LE::read_u32(&buf[1..5]),
            hops,
            sigs,
        }
    }
}

#[cfg(feature = "redb")]
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
        t.write_serialized(&mut buf);
        let start: usize = 7 + t.hops.len() * Hop::SIZE;
        for (i, hsig) in t.sigs.iter().enumerate() {
            hsig.write_to(&mut buf[start + i * PeerSig::SIZE..start + (i + 1) * PeerSig::SIZE]);
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
        Self::deserialize(data)
    }
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct Hop {
    pub from: u32,
    pub to: u32,
    pub amount: u32,
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

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct PeerSig {
    pub peer_idx: u32,
    #[serde(with = "hex::serde")]
    pub sig: [u8; 64],
}

impl PeerSig {
    const SIZE: usize = 68;

    fn from_bytes(data: &[u8]) -> PeerSig {
        PeerSig {
            peer_idx: LE::read_u32(&data[0..4]),
            sig: data[4..68].try_into().unwrap(),
        }
    }

    fn write_to(&self, buf: &mut [u8]) {
        LE::write_u32(&mut buf[0..4], self.peer_idx);
        buf[4..68].copy_from_slice(&self.sig);
    }
}
