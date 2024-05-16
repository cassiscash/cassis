use anyhow::Context;
use byteorder::{ByteOrder, LE};
use secp256k1::hashes::{sha256, Hash};
use std::{env, ops::RangeBounds, path::Path, thread};

use cassis::Operation;

pub fn start() {
    let _join = thread::spawn(|| {
        let log: LogStore = {
            let logstore_path = env::var("STORE_PATH").unwrap_or("logstore".to_string());
            let ls =
                LogStore::init(&Path::new(&logstore_path)).expect("failed to instantiate logstore");
            ls.check_and_heal()
                .expect("failed to check and heal logstore");
            ls
        };
    });
}

pub struct LogStore {
    offset_mmap: mmap_simple::Mmap,
    log_mmap: mmap_simple::Mmap,
    hash_mmap: mmap_simple::Mmap,
}

impl LogStore {
    pub fn init(path: &Path) -> Result<Self, anyhow::Error> {
        Ok(LogStore {
            offset_mmap: mmap_simple::Mmap::new(&path.join("offset"))
                .context("failed to mmap offset file")?,
            log_mmap: mmap_simple::Mmap::new(&path.join("log"))
                .context("failed to mmap log file")?,
            hash_mmap: mmap_simple::Mmap::new(&path.join("hash"))
                .context("failed to mmap hash file")?,
        })
    }

    pub fn check_and_heal(&self) -> Result<(), anyhow::Error> {
        // check how many offsets we have written
        let mut offsetlen = self.offset_mmap.size as usize;

        // this is the size of the log file -- we'll see if this is correct
        let mut loglen = self.log_mmap.size as usize;

        // now check if we have access to the latest log we should according to the offsets file
        let mut already_read_at_least_one_size = false;
        loop {
            // if we had dangling bytes written, ignore them
            if offsetlen % 4 != 0 {
                offsetlen -= 1;
            }

            let read_last_op: Result<(), anyhow::Error> = {
                let offset = LE::read_u32(
                    self.offset_mmap
                        .read((offsetlen as usize / 4 - 1) * 4, 4)
                        .context("failed to read index of last log")?
                        .as_slice(),
                ) as usize;
                let op_size = LE::read_u16(
                    self.log_mmap
                        .read(offset, 2)
                        .inspect_err(|err| {
                            if already_read_at_least_one_size {
                                // if we have already read one size further on in this file then this shouldn't have failed at all
                                // are we going crazy?
                                panic!("shouldn't have failed to read a part of the file before another part that had already succeeded: {}", err);
                            }
                        })
                        .context("failed to read size of last log")?
                        .as_slice(),
                );

                already_read_at_least_one_size = true;

                // optimistically set the correct log file size to the current offset + size
                // if this fails later we will overwrite this variable anyway until it doesn't fail
                loglen = offset + 2 + (op_size as usize);

                self.log_mmap
                    .read_with(offset + 2, op_size as usize, |buf| ())
                    .context("failed to read last log operation")?;

                Ok(())
            };

            match read_last_op {
                Err(err) => {
                    tracing::warn!("log file not ok: {}; healing", err);

                    // last log line is broken, so let's try the previous
                    offsetlen -= 4;
                }
                Ok(()) => {
                    // truncate files to the points in which they are good
                    self.offset_mmap
                        .drop_from_tail(self.offset_mmap.size as usize - offsetlen);
                    self.log_mmap
                        .drop_from_tail(self.offset_mmap.size as usize - loglen);

                    break;
                }
            }
        }

        // check hashes file size
        let hashlen = self.hash_mmap.size as usize;
        if hashlen != (offsetlen / 4) * 32 {
            panic!("fix this later");
        }

        Ok(())
    }

    pub fn append_operation(&self, op: &Operation) -> Result<(), anyhow::Error> {
        self.offset_mmap.append_with(4, |w| {
            LE::write_u32(w, self.log_mmap.size as u32);
        })?;

        let mut hash: &[u8; 32];
        self.log_mmap.append_with(2 + op.size() as usize, |w| {
            LE::write_u16(w, op.size() as u16);
            op.write_serialized(&mut w[2..]);

            hash = sha256::Hash::hash(&w[2..]).as_byte_array();
        })?;

        self.hash_mmap.append(hash)?;
        Ok(())
    }

    pub fn read_operation(&self, idx: u32) -> Result<Operation, anyhow::Error> {
        self.read_operation_at_offset(self.get_offset_for_idx(idx)?)
            .map(|(op, _)| op)
    }

    fn get_offset_for_idx(&self, idx: u32) -> Result<u32, anyhow::Error> {
        let mut offset = 0u32;
        self.offset_mmap
            .read_with(idx as usize * 4, 4, |r| {
                offset = LE::read_u32(r);
            })
            .with_context(|| format!("failed to read offset_file at {}", idx * 2))?;
        Ok(offset)
    }

    fn read_operation_at_offset(&self, offset: u32) -> Result<(Operation, u32), anyhow::Error> {
        let mut size = 0u16;
        self.log_mmap
            .read_with(offset as usize, 2, |r| {
                size = LE::read_u16(r);
            })
            .with_context(|| format!("failed to read log_file at {}", offset))?;

        let mut op: Operation;
        self.log_mmap
            .read_with(offset as usize + 2, size as usize, |r| {
                op = Operation::deserialize(r);
            })
            .with_context(|| format!("failed to read log_file at {}", offset + 2))?;

        Ok((op, offset + 2 + size as u32))
    }

    pub fn iter(&self) -> LogStoreIter<'_> {
        LogStoreIter {
            store: self,
            offset: 0,
            offset_end: None,
        }
    }

    pub fn range(&self, range: impl RangeBounds<u32>) -> Result<LogStoreIter<'_>, anyhow::Error> {
        let offset_start = match range.start_bound() {
            std::ops::Bound::Unbounded => 0,
            std::ops::Bound::Included(idx) => self.get_offset_for_idx(*idx)?,
            std::ops::Bound::Excluded(idx) => self.get_offset_for_idx(idx + 1)?,
        };
        let offset_end = match range.end_bound() {
            std::ops::Bound::Unbounded => None,
            std::ops::Bound::Included(idx) => Some(self.get_offset_for_idx(*idx)?),
            std::ops::Bound::Excluded(idx) => Some(self.get_offset_for_idx(idx + 1)?),
        };

        Ok(LogStoreIter {
            store: self,
            offset: offset_start,
            offset_end,
        })
    }
}

pub(crate) struct LogStoreIter<'a> {
    store: &'a LogStore,
    offset: u32,
    offset_end: Option<u32>,
}

impl<'a> Iterator for LogStoreIter<'a> {
    type Item = &'a Operation;

    fn next(&mut self) -> Option<Self::Item> {
        if Some(self.offset) == self.offset_end {
            return None;
        }

        match self.store.read_operation_at_offset(self.offset) {
            Ok((op, next_offset)) => {
                self.offset = next_offset;
                Some(&op)
            }
            Err(_) => None,
        }
    }
}
