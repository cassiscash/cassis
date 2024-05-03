use anyhow::{anyhow, Context};
use cassis::operation::Operation;
use secp256k1::{
    hashes::{sha256, Hash},
    schnorr::Signature,
    Message,
};
use std::{
    collections::{hash_map::Entry, HashMap},
    hash::BuildHasherDefault,
    sync::RwLock,
};

use crate::db;

pub struct State {
    pub keys: Vec<cassis::PublicKey>,
    pub key_indexes: HashMap<[u8; 32], u32>,
    pub lines: HashMap<u64, Line, BuildHasherDefault<nohash_hasher::NoHashHasher<u64>>>,
    pub op_serial: u64,
}

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
    fn build_key(peer1: u32, peer2: u32) -> u64 {
        let (first, second) = if peer1 < peer2 {
            (peer1, peer2)
        } else {
            (peer2, peer1)
        };

        ((first as u64) << 32) | second as u64
    }
}

pub fn init(initial_key: cassis::PublicKey) -> Result<RwLock<State>, anyhow::Error> {
    let mut state = State {
        keys: vec![initial_key],
        key_indexes: HashMap::with_capacity(500),
        lines: HashMap::with_capacity_and_hasher(1000, BuildHasherDefault::default()),
        op_serial: 0,
    };

    state.key_indexes.insert(initial_key.serialize(), 0);

    let txn = db::DB.begin_read()?;
    {
        let table = txn.open_table(db::LOG)?;
        for (i, row) in table.range(0..)?.enumerate() {
            let (key, operation) = row.with_context(|| format!("at row index {}", i))?;

            let serial = key.value();
            if i as u64 != serial {
                return Err(anyhow!("row index ({}) != serial key ({})", i, serial));
            }
            state.op_serial = serial;

            let op = operation.value();
            process(&mut state, &op);
        }
    }
    Ok(RwLock::new(state))
}

// just check if everything is ok to be applied
pub fn validate(state: &State, op: &Operation) -> Result<(), anyhow::Error> {
    match op {
        Operation::Unknown => return Err(anyhow!("Unknown shouldn't have been stored")),
        Operation::Trust(t) => {
            // get idx of _to_ key or add new key to list
            let key: [u8; 32] = t.to.serialize();
            match state.key_indexes.get(&key) {
                Some(idx) => {
                    // can't trust yourself
                    if *idx == t.from {
                        return Err(anyhow!("can't trust yourself"));
                    }
                }
                None => {}
            }

            // check existence of t.from
            let _ = match state.keys.get(t.from as usize) {
                None => return Err(anyhow!("from key doesn't exist")),
                Some(key) => {
                    // verify signature
                    let mut nosig = vec![0u8; t.size_nosig()];
                    t.write_serialized(&mut nosig);
                    let digest = sha256::Hash::hash(&nosig);
                    let message = Message::from_digest(digest.to_byte_array());
                    if Signature::from_slice(&t.sig)
                        .and_then(|sig| key.verify(&sig, &message))
                        .is_err()
                    {
                        return Err(anyhow!("invalid signature"));
                    }
                }
            };

            Ok(())
        }
        Operation::Transfer(t) => {
            // we'll use this to check who are the senders, i.e. who lost money
            let mut deltas: Vec<Delta> = Vec::with_capacity(t.hops.len() * 2);
            struct Delta {
                peer_idx: u32,
                delta: i64,
            }

            // meanwhile we'll also check if each transfer is allowed according by the existing trust
            for hop in t.hops.iter() {
                // check if hop has any amount whatsoever
                if hop.amount == 0 {
                    return Err(anyhow!("hop can't have zero amount"));
                }

                // check if there is enough trust
                match state.lines.get(&Line::build_key(hop.from, hop.to)) {
                    None => return Err(anyhow!("no line available for transfer")),
                    Some(line) => {
                        let can_send = if hop.from == line.peers.0 {
                            line.trust.0 as i64 - line.balance
                        } else {
                            line.trust.1 as i64 + line.balance
                        } as i64;
                        if hop.to as i64 > can_send {
                            return Err(anyhow!("not enough credit in line"));
                        }
                    }
                }

                // check who lost money in this transfer
                let fidx = deltas
                    .iter()
                    .position(|delta| delta.peer_idx == hop.from)
                    .unwrap_or_else(|| {
                        let idx = deltas.len();
                        deltas.push(Delta {
                            peer_idx: hop.from,
                            delta: 0,
                        });
                        idx
                    });
                deltas[fidx].delta -= hop.amount as i64;
                let tidx = deltas
                    .iter()
                    .position(|delta| delta.peer_idx == hop.to)
                    .unwrap_or_else(|| {
                        let idx = deltas.len();
                        deltas.push(Delta {
                            peer_idx: hop.to,
                            delta: 0,
                        });
                        idx
                    });
                deltas[tidx].delta += hop.amount as i64;
            }

            // people who lost money in this must have provided a signature
            let senders = deltas.iter().filter_map(|delta| {
                if delta.delta < 0 {
                    Some(delta.peer_idx)
                } else {
                    None
                }
            });
            for sender in senders {
                if t.sigs
                    .iter()
                    .find(|peer_sig| peer_sig.peer_idx == sender)
                    .is_none()
                {
                    return Err(anyhow!("missing signature from sender {}", sender));
                }
            }

            // verify all signatures
            let mut nosig = vec![0u8; t.size_nosig()];
            t.write_serialized(&mut nosig);
            let digest = sha256::Hash::hash(&nosig);
            let message = Message::from_digest(digest.to_byte_array());
            for isig in t.sigs.iter() {
                let _ = match state.keys.get(isig.peer_idx as usize) {
                    None => return Err(anyhow!("signing key doesn't exist")),
                    Some(key) => {
                        if Signature::from_slice(&isig.sig)
                            .and_then(|sig| key.verify(&sig, &message))
                            .is_err()
                        {
                            return Err(anyhow!("invalid signature"));
                        }
                    }
                };
            }

            Ok(())
        }
    }
}

// just apply the changes
pub fn process(state: &mut State, op: &Operation) {
    match op {
        Operation::Unknown => {}
        Operation::Trust(t) => {
            // get idx of _to_ key or add new key to list
            let to_idx = match state.key_indexes.entry(t.to.serialize()) {
                Entry::Occupied(entry) => *entry.get(),
                Entry::Vacant(entry) => {
                    // add new key to the end of list
                    let next = state.keys.len() as u32;
                    state.keys.push(t.to.to_owned());
                    entry.insert(next);
                    next
                }
            };

            // update line state or create new
            match state.lines.entry(Line::build_key(to_idx, t.from)) {
                Entry::Occupied(mut entry) => {
                    let line = entry.get_mut();

                    if t.from < to_idx {
                        line.trust.0 = t.amount;
                    } else {
                        line.trust.1 = t.amount;
                    }
                }
                Entry::Vacant(entry) => {
                    entry.insert(if t.from < to_idx {
                        Line {
                            peers: (t.from, to_idx),
                            trust: (0, t.amount),
                            balance: 0,
                        }
                    } else {
                        Line {
                            peers: (to_idx, t.from),
                            trust: (t.amount, 0),
                            balance: 0,
                        }
                    });
                }
            }
        }
        Operation::Transfer(t) => {
            for hop in t.hops.iter() {
                let line = state
                    .lines
                    .get_mut(&Line::build_key(hop.from, hop.to))
                    .expect("we have just checked this");

                line.balance = line.balance
                    + if line.peers.0 == hop.from {
                        hop.amount as i64
                    } else {
                        -(hop.amount as i64)
                    }
            }
        }
    }
}
