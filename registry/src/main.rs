use axum::{
    http::status::StatusCode,
    response::{IntoResponse, Json},
    routing::{get, post},
};
use cassis::Operation;
use db::DB;
use futures::StreamExt;
use lazy_static::lazy_static;
use std::{
    env,
    sync::{Arc, RwLock},
};
use tokio::sync::broadcast;

mod db;
mod state;

lazy_static! {
    static ref SERVER_KEY: cassis::SecretKey =
        cassis::SecretKey::from_hex(&env::var("SECRET_KEY").unwrap_or(
            "c668bcc0d81d647f2c9ac035df7a6d7e672de709abb8bbd5fe5bb8778f748263".to_string(),
        ))
        .expect("invalid SECRET_KEY");
}

#[tokio::main]
async fn main() {
    db::ensure_tables();

    let state = state::init(SERVER_KEY.public()).expect("failed to init state from db");
    let shared_state = Arc::new(state);

    let (streamer, listener) = broadcast::channel::<serde_json::Value>(12);
    let shared_listener = Arc::new(listener);

    let app = axum::Router::new()
        .route("/", get(|| async { "cassis-registry" }))
        .route("/append", post(append_op).layer(axum::Extension(streamer)))
        .route("/log", get(get_log).layer(axum::Extension(shared_listener)))
        .route(
            "/idx/:pubkey",
            get(get_key_id).with_state(shared_state.clone()),
        )
        .route("/lines", get(get_lines).with_state(shared_state.clone()))
        .with_state(shared_state.clone());

    println!(
        "listening on http://localhost:6000 with key {}",
        SERVER_KEY.public()
    );
    let listener = tokio::net::TcpListener::bind("0.0.0.0:6000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn append_op(
    axum::extract::State(state): axum::extract::State<Arc<RwLock<cassis::State>>>,
    axum::extract::Extension(streamer): axum::extract::Extension<
        broadcast::Sender<serde_json::Value>,
    >,
    axum::extract::Json(op): axum::extract::Json<Operation>,
) -> axum::response::Response {
    let mut state = state.write().unwrap();

    // validate this operation
    let _ = match cassis::state::validate(&state, &op) {
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
                table.insert(&state.op_serial, &op)?;
            }
            txn.commit()?;
            Ok(())
        })
        .is_err()
    {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    // and then we apply the changes
    cassis::state::process(&mut state, &op);

    // dispatch to listeners
    let value = serde_json::to_value(op).unwrap();
    streamer
        .send(value.clone())
        .expect("failed to send through channel");

    StatusCode::OK.into_response()
}

#[derive(serde::Deserialize)]
struct GetLogParams {
    since: Option<i64>,
    pub live: Option<bool>,
}

async fn get_log(
    axum::extract::State(state): axum::extract::State<Arc<RwLock<cassis::State>>>,
    axum::extract::Extension(shared_listener): axum::extract::Extension<
        Arc<broadcast::Receiver<serde_json::Value>>,
    >,
    axum::extract::Query(mut qs): axum::extract::Query<GetLogParams>,
) -> axum::response::Response {
    let state = state.read().unwrap();

    // fetch from start to end, but limit to 50 results
    let start: u64 = match qs.since {
        Some(since) => {
            if since < 0 {
                state.op_serial + since.abs() as u64
            } else {
                since as u64
            }
        }
        None if state.op_serial > 50 => state.op_serial - 50,
        None => 0,
    };

    let end = if state.op_serial - start > 1000 {
        qs.live = Some(false);
        start + 500
    } else {
        state.op_serial
    };

    match DB.begin_read().map_err(|err| anyhow::Error::from(err)) {
        Ok(txn) => {
            let table = txn.open_table(db::LOG).unwrap();
            let past_stream = async_stream::stream! {
                for row in table.range(start..end).unwrap() {
                    let (_, v) = row.unwrap();
                    yield serde_json::to_value(v.value()).unwrap()
                }
            };

            if qs.live == Some(true) {
                let listener = shared_listener.resubscribe();
                let future_stream =
                    tokio_stream::wrappers::BroadcastStream::new(listener).map(|res| res.unwrap());

                axum_streams::StreamBodyAs::json_nl(past_stream.chain(future_stream))
                    .into_response()
            } else {
                axum_streams::StreamBodyAs::json_nl(past_stream).into_response()
            }
        }
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}

async fn get_key_id(
    axum::extract::State(state): axum::extract::State<Arc<RwLock<cassis::State>>>,
    axum::extract::Path(pubkey): axum::extract::Path<String>,
) -> axum::response::Response {
    let state = state.read().unwrap();

    let mut pk_slice = [0u8; 32];
    if hex::decode_to_slice(pubkey, &mut pk_slice).is_err() {
        return StatusCode::BAD_REQUEST.into_response();
    }

    match state.key_indexes.get(&pk_slice) {
        Some(idx_ref) => {
            let idx = *idx_ref;
            format!("{}", idx).into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn get_lines(
    axum::extract::State(state): axum::extract::State<Arc<RwLock<cassis::State>>>,
) -> axum::response::Response {
    let state = state.read().unwrap();
    Json(&state.lines).into_response()
}
