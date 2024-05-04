use cassis::operation::Operation;
use lazy_static::lazy_static;
use redb::{Database, TableDefinition};

lazy_static! {
    pub static ref DB: Database =
        Database::create("registry.redb").expect("failed to open database");
}

pub const LOG: TableDefinition<u64, Operation> = TableDefinition::new("log");

pub fn ensure_tables() {
    let txn = DB.begin_write().unwrap();
    {
        let _ = txn.open_table(LOG);
    }
    txn.commit().unwrap();
}
