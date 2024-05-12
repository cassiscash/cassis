use anyhow::Context;
use byteorder::{ByteOrder, LE};
use secp256k1::hashes::{sha256, Hash};
use std::{fs, io::Write, os::unix::fs::FileExt, path::Path};

use cassis::Operation;

pub struct LogStore {
    offset_file: fs::File,
    log_file: fs::File,
    hash_file: fs::File,
}

impl LogStore {
    pub fn init(path: &Path) -> Result<Self, anyhow::Error> {
        let offset_file = fs::OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(path.join("offset"))
            .context("on offset file")?;

        let log_file = fs::OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(path.join("log"))
            .context("on log file")?;

        let hash_file = fs::OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(path.join(format!("hash_{:0>2}", 0)))
            .context("on hash file")?;

        Ok(LogStore {
            offset_file,
            log_file,
            hash_file,
        })
    }

    pub fn read_operation(&self, idx: u64) -> Result<Operation, anyhow::Error> {
        let mut buf_offset = vec![0u8; 4];
        self.offset_file
            .read_exact_at(&mut buf_offset, idx * 2)
            .context(format!("offset_file at {}", idx * 2))?;
        let offset = LE::read_u32(&buf_offset);

        let mut buf_size = vec![0u8; 2];
        self.log_file
            .read_exact_at(&mut buf_size, offset as u64)
            .context(format!("log_file at {}", offset))?;
        let size = LE::read_u16(&buf_size);

        let mut buf_op = vec![0u8; size as usize];
        self.log_file
            .read_exact_at(&mut buf_op, offset as u64 + 2)
            .context(format!("log_file at {}", offset + 2))?;

        Ok(Operation::deserialize(&buf_op))
    }

    pub fn append_operation(&self, op: Operation) -> Result<(), anyhow::Error> {
        let curr_len = self.log_file.metadata().context("log file metadata")?.len();

        let size = op.size();
        let mut sizebuf = [0u8; 2];
        LE::write_u16(&mut sizebuf, size as u16);
        self.log_file.write_all(&sizebuf);

        let mut serbuf = vec![0u8; size];
        op.write_serialized(&mut serbuf);
        self.log_file.write_all(&serbuf);

        let mut offsetbuf = vec![0u8; 4];
        LE::write_u32(&mut offsetbuf, curr_len as u32);
        self.offset_file.write_all(&offsetbuf);

        self.offset_file.flush();
        self.log_file.flush();

        let hash = sha256::Hash::hash(&serbuf).as_byte_array();
        self.hash_file.write(hash);
        self.hash_file.flush();

        Ok(())
    }
}
