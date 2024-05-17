use anyhow::anyhow;
use std::{
    collections::{hash_map::Entry, HashMap},
    hash::BuildHasherDefault,
};

pub mod line;

pub use line::Line;

use crate::operation::{Operation, OperationOps};
use crate::PublicKey;

#[derive(Debug)]
pub struct State {
    pub keys: Vec<PublicKey>,
    pub key_indexes: HashMap<[u8; 32], u32>,
    pub lines: HashMap<u64, Line, BuildHasherDefault<nohash_hasher::NoHashHasher<u64>>>,
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
                Some(key) => key.verify(&t.sig, &t.sighash()),
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
            for isig in t.sigs.iter() {
                let _ = match state.keys.get(isig.peer_idx as usize) {
                    None => return Err(anyhow!("signing key doesn't exist")),
                    Some(key) => key.verify(&isig.sig, &t.sighash()),
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
