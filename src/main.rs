use axum::{
    routing::{get, post},
    Router,
};
use std::sync::Arc;

mod db;
mod operation;
mod state;

use db::DB;
use operation::Operation;
use state::State;

#[tokio::main]
async fn main() {
    let state = state::init().expect("failed to init state from db");
    let shared_state = Arc::new(state);

    let app = Router::new()
        .route("/", get(|| async { "cassis" }))
        .route("/append", post(append_op).with_state(shared_state.clone()))
        .route("/log", get(get_log).with_state(shared_state.clone()));

    println!("listening on http://localhost:3000");
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn append_op(axum::extract::State(_state): axum::extract::State<Arc<State>>) -> String {
    let write_txn = DB.begin_write().unwrap();
    let op = Operation::Trust(operation::Trust::default());
    {
        let mut table = write_txn.open_table(db::LOG).unwrap();
        table.insert(&1, op).unwrap();
    }
    let _ = write_txn.commit().expect("failed to create log table");

    format!("")
}

async fn get_log(axum::extract::State(_state): axum::extract::State<Arc<State>>) -> String {
    let txn = DB.begin_read().unwrap();
    let table = txn
        .open_table(db::LOG)
        .expect("failed to open table when reading log");

    let mut res = String::with_capacity(150);
    for row in table.range(0..).expect("failed to open iterator") {
        let (_, v) = row.unwrap();
        res.push_str(format!("{}", v.value()).as_str());
        res.push_str(",");
    }
    res
}
