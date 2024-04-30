use lazy_static::lazy_static;

use redb::{Database, TableDefinition};

use crate::operation::Operation;

lazy_static! {
    pub static ref DB: Database = Database::create("db.redb").expect("failed to open database");
}

pub const LOG: TableDefinition<u64, Operation> = TableDefinition::new("log");
