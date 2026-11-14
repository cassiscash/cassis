//! The admin interface over HTTP, as hyperb renderers speak it: the
//! `hello` is a POST answered with a session id, the page comes down a
//! server-sent event stream, and every later line is a POST signed with
//! the renderer's key. It listens on loopback only and lets anyone on
//! this machine in, but answers only requests addressed to a loopback
//! name, so that web pages cannot reach it by rebinding theirs.

use crate::{Access, Server, Session};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use futures::stream::{self, Stream};
use hypereffect::RendererMessage;
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::warn;

const KEY: &str = "hyperb-key";
const SESSION: &str = "hyperb-session";
const SIGNATURE: &str = "hyperb-signature";
/// How long a session waits for its event stream after the `hello`.
const STREAM_WAIT: Duration = Duration::from_secs(60);

#[derive(Clone)]
struct Http {
    server: Arc<Server>,
    sessions: Arc<Mutex<HashMap<String, Pending>>>,
}

/// A session by its id: the renderer's key, and the lines for the
/// event stream until it is opened.
struct Pending {
    key: iroh::PublicKey,
    session: Arc<Session>,
    lines: Option<mpsc::UnboundedReceiver<String>>,
}

/// Listen on `addr`, returning the address bound.
pub async fn serve(server: Arc<Server>, addr: SocketAddr) -> Result<SocketAddr, String> {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| format!("listen on {addr}: {e}"))?;
    let addr = listener.local_addr().map_err(|e| e.to_string())?;
    let http = Http {
        server,
        sessions: Default::default(),
    };
    let app = Router::new()
        .route("/", get(stream_events).post(post_line))
        .with_state(http);
    tokio::spawn(async move {
        if let Err(error) = axum::serve(listener, app).await {
            warn!("admin over HTTP stopped: {error}");
        }
    });
    Ok(addr)
}

fn refuse(status: StatusCode, why: &str) -> Response {
    (status, why.to_string()).into_response()
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name)?.to_str().ok()
}

fn is_loopback_host(headers: &HeaderMap) -> bool {
    let Some(host) = header(headers, "host") else {
        return false;
    };
    let name = match host.rsplit_once(':') {
        Some((name, port)) if !name.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => name,
        _ => host,
    };
    let name = name.trim_start_matches('[').trim_end_matches(']');
    name == "localhost"
        || name.ends_with(".localhost")
        || name
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

impl Http {
    /// The session a request is signed for.
    #[allow(clippy::result_large_err)]
    fn authenticate(&self, headers: &HeaderMap) -> Result<(String, Arc<Session>), Response> {
        let unauthorized = |why| Err(refuse(StatusCode::UNAUTHORIZED, why));
        let (Some(id), Some(signature)) = (header(headers, SESSION), header(headers, SIGNATURE))
        else {
            return unauthorized("missing session or signature");
        };
        let sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let Some(pending) = sessions.get(id) else {
            return unauthorized("unknown session");
        };
        let mut bytes = [0u8; 64];
        let signed = lowercase_hex::decode_to_slice(signature, &mut bytes).is_ok()
            && header(headers, KEY).and_then(|key| key.parse::<iroh::PublicKey>().ok())
                == Some(pending.key)
            && pending
                .key
                .verify(id.as_bytes(), &iroh::Signature::from_bytes(&bytes))
                .is_ok();
        if !signed {
            return unauthorized("bad signature");
        }
        Ok((id.to_string(), pending.session.clone()))
    }

    fn hello(&self, headers: &HeaderMap, line: &str) -> Response {
        let Some(key) = header(headers, KEY).and_then(|key| key.parse::<iroh::PublicKey>().ok())
        else {
            return refuse(StatusCode::UNAUTHORIZED, "missing or bad hyperb-key");
        };
        let Ok(RendererMessage::Hello { params }) = RendererMessage::parse(line.trim_end()) else {
            return refuse(StatusCode::BAD_REQUEST, "expected a hello");
        };
        let (out, lines) = mpsc::unbounded_channel();
        let session = self.server.open(Access::Local, &params, out);
        let id = crate::new_secret();
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                id.clone(),
                Pending {
                    key,
                    session,
                    lines: Some(lines),
                },
            );
        let http = self.clone();
        let waiting = id.clone();
        tokio::spawn(async move {
            tokio::time::sleep(STREAM_WAIT).await;
            let mut sessions = http.sessions.lock().unwrap_or_else(|e| e.into_inner());
            if sessions.get(&waiting).is_some_and(|p| p.lines.is_some()) {
                if let Some(pending) = sessions.remove(&waiting) {
                    http.server.close(&pending.session);
                }
            }
        });
        ([(SESSION, id)], "").into_response()
    }
}

async fn post_line(State(http): State<Http>, headers: HeaderMap, body: String) -> Response {
    if !is_loopback_host(&headers) {
        return refuse(StatusCode::FORBIDDEN, "not a loopback host");
    }
    if header(&headers, SESSION).is_none() {
        return http.hello(&headers, &body);
    }
    let (_, session) = match http.authenticate(&headers) {
        Ok(found) => found,
        Err(response) => return response,
    };
    for line in body.lines().filter(|line| !line.trim().is_empty()) {
        http.server.receive(&session, line);
    }
    StatusCode::OK.into_response()
}

/// Ends its session when the event stream is dropped.
struct Closer {
    http: Http,
    id: String,
}

impl Drop for Closer {
    fn drop(&mut self) {
        let removed = self
            .http
            .sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.id);
        if let Some(pending) = removed {
            self.http.server.close(&pending.session);
        }
    }
}

async fn stream_events(State(http): State<Http>, headers: HeaderMap) -> Response {
    if !is_loopback_host(&headers) {
        return refuse(StatusCode::FORBIDDEN, "not a loopback host");
    }
    let (id, _) = match http.authenticate(&headers) {
        Ok(found) => found,
        Err(response) => return response,
    };
    let lines = http
        .sessions
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get_mut(&id)
        .and_then(|pending| pending.lines.take());
    let Some(lines) = lines else {
        return refuse(StatusCode::CONFLICT, "the session already has its stream");
    };
    Sse::new(events(lines, Closer { http, id }))
        .keep_alive(KeepAlive::default())
        .into_response()
}

/// Each line `tag json` as an event named `tag` with the JSON as data.
fn events(
    lines: mpsc::UnboundedReceiver<String>,
    closer: Closer,
) -> impl Stream<Item = Result<Event, Infallible>> {
    let batches = stream::unfold((lines, closer), |(mut lines, closer)| async move {
        let batch = lines.recv().await?;
        Some((batch, (lines, closer)))
    });
    futures::StreamExt::flat_map(batches, |batch| {
        let events: Vec<Result<Event, Infallible>> = batch
            .lines()
            .filter_map(|line| line.split_once(' '))
            .map(|(tag, json)| Ok(Event::default().event(tag).data(json)))
            .collect();
        stream::iter(events)
    })
}
