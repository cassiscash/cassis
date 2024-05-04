use anyhow::{anyhow, Context};
use std::{collections::HashMap, hash::BuildHasherDefault, sync::RwLock};

use crate::db;

pub fn init(initial_key: cassis::PublicKey) -> Result<RwLock<cassis::State>, anyhow::Error> {
    let mut state = cassis::State {
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
            cassis::state::process(&mut state, &op);
        }
    }
    Ok(RwLock::new(state))
}
