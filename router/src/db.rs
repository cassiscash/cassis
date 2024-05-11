use lazy_static::lazy_static;
use redb::{Database, TableDefinition};

use cassis::state::Line;

lazy_static! {
    pub static ref DB: Database = Database::create("router.redb").expect("failed to open database");
}

pub const LINES: TableDefinition<u64, Line> = TableDefinition::new("lines");

pub fn ensure_tables() {
    let txn = DB.begin_write().unwrap();
    {
        let _ = txn.open_table(LINES);
    }
    txn.commit().unwrap();
}
