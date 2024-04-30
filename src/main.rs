use axum::{
    http::status::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use db::DB;
use operation::Operation;
use state::{process, validate, State};
use std::{
    cmp::min,
    sync::{Arc, RwLock},
};

mod db;
mod helpers;
mod operation;
mod state;

#[tokio::main]
async fn main() {
    db::ensure_tables();

    let state = state::init().expect("failed to init state from db");
    let shared_state = Arc::new(state);

    let app = axum::Router::new()
        .route("/", get(|| async { "cassis" }))
        .route("/append", post(append_op).with_state(shared_state.clone()))
        .route("/log", get(get_log).with_state(shared_state.clone()));

    println!("listening on http://localhost:3000");
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn append_op(
    axum::extract::State(state): axum::extract::State<Arc<RwLock<State>>>,
    axum::extract::Json(op): axum::extract::Json<Operation>,
) -> axum::response::Response {
    let mut state = state.write().unwrap();

    // validate this operation
    let _ = match validate(&state, &op) {
        Err(err) => return (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
        _ => {}
    };

    // once we know it's ok we save it
    if DB
        .begin_write()
        .map_err(|err| anyhow::Error::from(err))
        .and_then(|txn| {
            {
                let mut table = txn.open_table(db::LOG)?;
                table.insert(&1, &op)?;
            }
            txn.commit()?;
            Ok(())
        })
        .is_err()
    {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    // and then we apply the changes
    process(&mut state, &op);

    StatusCode::OK.into_response()
}

#[derive(serde::Deserialize)]
struct GetLogParams {
    since: Option<u64>,
}

async fn get_log(
    axum::extract::State(state): axum::extract::State<Arc<RwLock<State>>>,
    axum::extract::Query(qs): axum::extract::Query<GetLogParams>,
) -> axum::response::Response {
    let state = state.read().unwrap();
    let mut res: Vec<operation::Operation> = Vec::with_capacity(150);

    // fetch from start to end, but limit to 50 results
    let (start, end): (u64, u64) = match qs.since {
        Some(since) => (since, min(since + 50, state.op_serial)),
        None if state.op_serial > 50 => (state.op_serial - 50, state.op_serial),
        None => (0, state.op_serial),
    };

    if DB
        .begin_read()
        .map_err(|err| anyhow::Error::from(err))
        .and_then(|txn| {
            {
                let table = txn.open_table(db::LOG)?;
                for row in table.range(start..end)? {
                    let (_, v) = row.unwrap();
                    res.push(v.value());
                }
            }
            Ok(())
        })
        .is_err()
    {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    axum::response::Json(res).into_response()
}
