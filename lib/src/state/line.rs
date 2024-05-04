use byteorder::{ByteOrder, LE};

#[derive(serde::Serialize, Debug)]
pub struct Line {
    // peers sorted by serial number
    pub peers: (u32, u32),
    // (trust_from_2_to_1, trust_from_1_to_2)
    pub trust: (u32, u32),
    // when balance is negative it means 2 owes 1, when it is positive 1 owes 2
    pub balance: i64,
}

impl Line {
    const SIZE: usize = 4 + 4 + 4 + 4 + 8;

    pub fn build_key(peer1: u32, peer2: u32) -> u64 {
        let (first, second) = if peer1 < peer2 {
            (peer1, peer2)
        } else {
            (peer2, peer1)
        };

        ((first as u64) << 32) | second as u64
    }
}

#[cfg(feature = "redb")]
impl redb::Value for Line {
    fn type_name() -> redb::TypeName {
        redb::TypeName::new("line")
    }

    type AsBytes<'a> = Vec<u8>;
    type SelfType<'a> = Line;

    fn as_bytes<'a, 'b: 'a>(line: &'a Self::SelfType<'b>) -> Self::AsBytes<'a>
    where
        Self: 'a,
        Self: 'b,
    {
        let mut buf = vec![0; Line::SIZE];
        LE::write_u32(&mut buf[0..4], line.peers.0);
        LE::write_u32(&mut buf[4..8], line.peers.1);
        LE::write_u32(&mut buf[8..12], line.trust.0);
        LE::write_u32(&mut buf[12..16], line.trust.1);
        LE::write_i64(&mut buf[16..24], line.balance);
        buf
    }

    fn fixed_width() -> Option<usize> {
        Some(Line::SIZE)
    }

    fn from_bytes<'a>(data: &'a [u8]) -> Self::SelfType<'a>
    where
        Self: 'a,
    {
        Line {
            peers: (LE::read_u32(&data[0..4]), LE::read_u32(&data[4..8])),
            trust: (LE::read_u32(&data[8..12]), LE::read_u32(&data[12..16])),
            balance: LE::read_i64(&data[16..24]),
        }
    }
}
