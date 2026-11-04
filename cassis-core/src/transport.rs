//! Peer-to-peer transport over iroh: one bidirectional stream per
//! request, carrying one JSON [`Request`] and one JSON [`Response`].

use crate::protocol::{Request, Response, ALPN};
use futures::future::BoxFuture;
use iroh::endpoint::{presets, Connection};
use iroh::{Endpoint, EndpointAddr, PublicKey, RelayUrl, SecretKey};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, warn};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// Answers are quick (EXECUTE and COMMIT answer `Pending` rather than
/// wait), but PREPARE asks the wallets, which may be slow backends.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(180);
const MAX_MESSAGE_BYTES: usize = 1024 * 1024;

/// Where to reach a peer: its iroh endpoint id plus, optionally, its
/// home relay.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PeerAddr {
    pub id: String,
    pub relay: Option<String>,
}

impl PeerAddr {
    fn endpoint_addr(&self) -> Result<EndpointAddr, String> {
        let id = PublicKey::from_str(&self.id).map_err(|e| format!("peer id {}: {e}", self.id))?;
        let mut addr = EndpointAddr::new(id);
        if let Some(relay) = &self.relay {
            addr = addr.with_relay_url(
                RelayUrl::from_str(relay).map_err(|e| format!("relay {relay}: {e}"))?,
            );
        }
        Ok(addr)
    }
}

/// Answers one request; the second argument is the authenticated iroh
/// id of the peer that sent it.
pub type Handler = Arc<dyn Fn(Request, String) -> BoxFuture<'static, Response> + Send + Sync>;

#[derive(Clone)]
pub struct Transport {
    endpoint: Endpoint,
}

impl Transport {
    /// Bind an endpoint. With a `secret` it has the node's stable
    /// identity and accepts requests; without, it is an ephemeral
    /// client-only endpoint.
    pub async fn bind(secret: Option<[u8; 32]>) -> Result<Self, String> {
        let mut builder = Endpoint::builder(presets::N0);
        if let Some(secret) = secret {
            builder = builder
                .secret_key(SecretKey::from(secret))
                .alpns(vec![ALPN.to_vec()]);
        }
        let endpoint = builder
            .bind()
            .await
            .map_err(|e| format!("bind iroh endpoint: {e}"))?;
        Ok(Self { endpoint })
    }

    /// Bind a client-only endpoint with a stable identity, so the peers
    /// it talks to can tell who is asking.
    pub async fn bind_client(secret: [u8; 32]) -> Result<Self, String> {
        let endpoint = Endpoint::builder(presets::N0)
            .secret_key(SecretKey::from(secret))
            .bind()
            .await
            .map_err(|e| format!("bind iroh endpoint: {e}"))?;
        Ok(Self { endpoint })
    }

    pub fn peer_id(&self) -> String {
        self.endpoint.id().to_string()
    }

    /// The relay peers can reach this endpoint through, once known.
    pub async fn home_relay(&self) -> Option<String> {
        if tokio::time::timeout(Duration::from_secs(10), self.endpoint.online())
            .await
            .is_err()
        {
            warn!("iroh endpoint has no home relay after 10s");
            return None;
        }
        self.endpoint
            .addr()
            .relay_urls()
            .next()
            .map(|url| url.to_string())
    }

    pub async fn request(&self, peer: &PeerAddr, request: &Request) -> Result<Response, String> {
        let connection = tokio::time::timeout(
            CONNECT_TIMEOUT,
            self.endpoint.connect(peer.endpoint_addr()?, ALPN),
        )
        .await
        .map_err(|_| format!("connect to {} timed out", peer.id))?
        .map_err(|e| format!("connect to {}: {e:#}", peer.id))?;
        let (mut send, mut receive) = connection
            .open_bi()
            .await
            .map_err(|e| format!("open stream: {e}"))?;
        let bytes = serde_json::to_vec(request).map_err(|e| format!("encode request: {e}"))?;
        send.write_all(&bytes)
            .await
            .map_err(|e| format!("send request: {e}"))?;
        let _ = send.finish();
        let reply = tokio::time::timeout(RESPONSE_TIMEOUT, receive.read_to_end(MAX_MESSAGE_BYTES))
            .await
            .map_err(|_| format!("no response from {} in time", peer.id))?
            .map_err(|e| format!("read response: {e}"))?;
        connection.close(0u32.into(), b"done");
        serde_json::from_slice(&reply).map_err(|e| format!("decode response: {e}"))
    }

    /// Close the endpoint: open connections are dropped and peers can
    /// no longer reach it.
    pub async fn close(&self) {
        self.endpoint.close().await;
    }

    /// Accept requests until the endpoint closes, answering each with
    /// `handler`.
    pub async fn serve(&self, handler: Handler) {
        while let Some(incoming) = self.endpoint.accept().await {
            let handler = handler.clone();
            tokio::spawn(async move {
                match incoming.await {
                    Ok(connection) => {
                        if let Err(error) = answer(connection, handler).await {
                            debug!("request failed: {error}");
                        }
                    }
                    Err(error) => debug!("handshake failed: {error}"),
                }
            });
        }
    }
}

async fn answer(connection: Connection, handler: Handler) -> Result<(), String> {
    let peer = connection.remote_id().to_string();
    let (mut send, mut receive) = tokio::time::timeout(CONNECT_TIMEOUT, connection.accept_bi())
        .await
        .map_err(|_| "no stream opened".to_string())?
        .map_err(|e| format!("accept stream: {e}"))?;
    let bytes = tokio::time::timeout(CONNECT_TIMEOUT, receive.read_to_end(MAX_MESSAGE_BYTES))
        .await
        .map_err(|_| "request not received in time".to_string())?
        .map_err(|e| format!("read request: {e}"))?;
    let response = match serde_json::from_slice(&bytes) {
        Ok(request) => handler(request, peer).await,
        Err(error) => Response::Error(format!("malformed request: {error}")),
    };
    let bytes = serde_json::to_vec(&response).map_err(|e| format!("encode response: {e}"))?;
    send.write_all(&bytes)
        .await
        .map_err(|e| format!("send response: {e}"))?;
    let _ = send.finish();
    // Dropping the connection before the peer read everything would
    // reset the stream; wait for it to close its side.
    connection.closed().await;
    Ok(())
}
