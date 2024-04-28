use axum::{
    routing::{get, post},
    Router,
};
use lazy_static::lazy_static;
use redb::{Database, TableDefinition};

mod operation;
mod transfer;
mod trust;

use operation::Operation;

lazy_static! {
    static ref DB: Database = Database::create("db.redb").expect("failed to open database");
}

const LOG_TABLE: TableDefinition<u64, Operation> = TableDefinition::new("log");

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", get(|| async { "cassis" }))
        .route("/append", post(append_op))
        .route("/log", get(get_log));

    println!("listening on http://localhost:3000");
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn append_op() -> String {
    let write_txn = DB.begin_write().unwrap();
    let op = Operation::Trust(trust::Trust::default());
    {
        let mut table = write_txn.open_table(LOG_TABLE).unwrap();
        table.insert(&1, op).unwrap();
    }
    let _ = write_txn.commit().expect("failed to create log table");

    format!("")
}

async fn get_log() -> String {
    let txn = DB.begin_read().unwrap();
    let table = txn
        .open_table(LOG_TABLE)
        .expect("failed to open table when reading log");

    let mut res = String::with_capacity(150);
    for row in table.range(0..).expect("failed to open iterator") {
        let (_, v) = row.unwrap();
        res.push_str(format!("{}", v.value()).as_str());
        res.push_str(",");
    }
    res
}
