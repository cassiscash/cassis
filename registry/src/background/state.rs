use secp256k1::hashes::{sha256, Hash};
use std::{collections::HashMap, hash::BuildHasherDefault};

use crate::background::LogStore;

pub fn init(initial_key: cassis::PublicKey, ls: &LogStore) -> Result<cassis::State, anyhow::Error> {
    let mut state = cassis::State {
        keys: vec![initial_key],
        key_indexes: HashMap::with_capacity(500),
        lines: HashMap::with_capacity_and_hasher(1000, BuildHasherDefault::default()),
    };

    state.key_indexes.insert(initial_key.serialize(), 0);

    for op in ls.iter() {
        cassis::state::process(&mut state, &op);
    }
    Ok(state)
}

pub fn hash_and_sign_log_entry(
    secret_key: cassis::SecretKey,
    op: &cassis::Operation,
    previous_entry_hash: [u8; 32],
) -> cassis::SecretKey {
    let op_sighash = sha256::Hash::hash(&op.sighash());
    let mut concat = [0u8; 64];
    concat[0..32].copy_from_slice(op_sighash.as_byte_array());
    concat[32..64].copy_from_slice(&previous_entry_hash);
    // let digest = sha256::Hash::hash(&concat);
    // let message = Message::from_digest(digest.to_byte_array());
    secret_key
}
