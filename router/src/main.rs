use axum::{
    http::status::StatusCode,
    response::{IntoResponse, Json},
    routing::{get, post},
};
use cassis::operation::Operation;
use db::DB;
use lazy_static::lazy_static;
use state::{process, validate, State};
use std::{
    cmp::min,
    env,
    sync::{Arc, RwLock},
};

mod db;
mod state;

#[tokio::main]
async fn main() {
    db::ensure_tables();

    let state = state::init().expect("failed to init state from db");
    let shared_state = Arc::new(state);

    let app = axum::Router::new().route("/", get(|| async { "cassis-router" }));

    println!("listening on http://localhost:7000",);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:6000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
