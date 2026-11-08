//! The admin interface over iroh, as hyperb renderers speak it: one
//! bidirectional stream of hypereffect lines per connection, on the
//! ALPN `hyperb/0` (the root path). The renderer is who its connection
//! says it is, and is let in if it is one of `admin.peers` or brings
//! the pairing secret in its `hello`.

use crate::{Access, Server};
use hypereffect::RendererMessage;
use iroh::endpoint::presets;
use iroh::{Endpoint, SecretKey};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;
use tracing::{debug, warn};

const ALPN: &[u8] = b"hyperb/0";

/// Bind the admin endpoint and serve it, returning its id.
pub async fn serve(server: Arc<Server>, secret: [u8; 32]) -> Result<String, String> {
    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(SecretKey::from(secret))
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await
        .map_err(|e| format!("bind iroh endpoint: {e}"))?;
    let _ = tokio::time::timeout(Duration::from_secs(10), endpoint.online()).await;
    let id = endpoint.id().to_string();
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let server = server.clone();
            tokio::spawn(async move {
                if let Err(error) = session(server, incoming).await {
                    debug!("admin session over iroh ended: {error}");
                }
            });
        }
    });
    Ok(id)
}

async fn session(server: Arc<Server>, incoming: iroh::endpoint::Incoming) -> Result<(), String> {
    let connection = incoming.await.map_err(|e| e.to_string())?;
    let key = connection.remote_id().to_string();
    let (mut send, recv) = connection.accept_bi().await.map_err(|e| e.to_string())?;
    let mut lines = BufReader::new(recv).lines();
    let params = match lines.next_line().await.map_err(|e| e.to_string())? {
        Some(line) => match RendererMessage::parse(&line) {
            Ok(RendererMessage::Hello { params }) => params,
            _ => return Err("the session does not start with a hello".into()),
        },
        None => return Ok(()),
    };
    let (out, mut outgoing) = mpsc::unbounded_channel::<String>();
    let writer = tokio::spawn(async move {
        while let Some(batch) = outgoing.recv().await {
            if let Err(error) = send.write_all(batch.as_bytes()).await {
                warn!("admin over iroh: send: {error}");
                break;
            }
        }
    });
    let session = server.open(Access::Peer(key), &params, out);
    let ended = loop {
        match lines.next_line().await {
            Ok(Some(line)) if line.trim().is_empty() => {}
            Ok(Some(line)) => server.receive(&session, &line),
            Ok(None) => break Ok(()),
            Err(error) => break Err(error.to_string()),
        }
    };
    server.close(&session);
    drop(session);
    writer.abort();
    connection.close(0u32.into(), b"bye");
    ended
}
