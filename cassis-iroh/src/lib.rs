use cassis_core::{HopAck, HopInstruction, RouteAnnouncement};
use iroh::endpoint::Connection;
use iroh::{Endpoint, NodeAddr, SecretKey};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;

pub const ALPN_PROTOCOL: &[u8] = b"cassis-hop/1";

#[derive(thiserror::Error, Debug)]
pub enum IrohError {
    #[error("io error: {0}")]
    Io(String),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("connection closed")]
    Closed,
}

#[derive(Serialize, Deserialize)]
enum Frame {
    HopInstruction(HopInstruction),
    HopAck(HopAck),
}

/// Build a [`NodeAddr`] from a route announcement's iroh fields.
pub fn node_addr_from_announcement(ann: &RouteAnnouncement) -> Result<NodeAddr, IrohError> {
    let peer_id =
        iroh::PublicKey::from_str(&ann.iroh_peer_id).map_err(|e| IrohError::Io(e.to_string()))?;
    let mut addr = NodeAddr::new(peer_id);
    if let Some(relay_url) = &ann.iroh_relay {
        let relay = iroh::RelayUrl::from_str(relay_url).map_err(|e| IrohError::Io(e.to_string()))?;
        addr = addr.with_relay_url(relay);
    }
    Ok(addr)
}

/// Default iroh relay URL when the node has no home relay.
pub const DEFAULT_IROH_RELAY: &str = "https://euw1-1.relay.iroh.network";

#[derive(Clone, Debug)]
pub struct IrohClient {
    endpoint: Endpoint,
}

impl IrohClient {
    pub fn new(endpoint: Endpoint) -> Self {
        Self { endpoint }
    }

    /// Build a new client endpoint with the same defaults as the server.
    ///
    /// Use this instead of constructing an [`iroh::Endpoint`] by hand so that
    /// the TLS authentication mode matches the server's and QUIC handshakes
    /// over the relay don't time out.
    pub async fn bind() -> Result<Self, IrohError> {
        info!(target: "iroh_client", "binding endpoint with ALPN {:?}", ALPN_PROTOCOL);
        let endpoint = Endpoint::builder()
            .alpns(vec![ALPN_PROTOCOL.to_vec()])
            .tls_x509()
            .bind()
            .await
            .map_err(|e| IrohError::Io(e.to_string()))?;
        info!(target: "iroh_client", "bound peer_id={}", endpoint.node_id());
        Ok(Self::new(endpoint))
    }

    pub async fn send_instruction(
        &self,
        addr: NodeAddr,
        instruction: HopInstruction,
    ) -> Result<HopAck, IrohError> {
        info!(
            target: "iroh_client",
            "connecting to {} (relay={:?}, direct_addrs={})...",
            addr.node_id,
            addr.relay_url(),
            addr.direct_addresses().count()
        );
        let conn = match self.endpoint.connect(addr, ALPN_PROTOCOL).await {
            Ok(c) => c,
            Err(e) => {
                error!(target: "iroh_client", "connect error:");
                for cause in e.chain() {
                    error!(target: "iroh_client", "  caused by: {cause}");
                }
                return Err(IrohError::Io(format!("{e:#}")));
            }
        };
        debug!(target: "iroh_client", "connected, opening bi stream...");

        let (mut writer, mut reader) = conn
            .open_bi()
            .await
            .map_err(|e| IrohError::Io(e.to_string()))?;
        debug!(target: "iroh_client", "stream opened, writing frame...");

        let frame = Frame::HopInstruction(instruction.clone());
        let data = postcard::to_allocvec(&frame).map_err(|e| IrohError::Protocol(e.to_string()))?;
        debug!(
            target: "iroh_client",
            "sending HopInstruction(payment_hash={}, amount_msat={}, incoming={}, outgoing={}, recipient={})",
            lowercase_hex::encode(instruction.payment_hash),
            instruction.amount_msat,
            instruction.incoming_network.0,
            instruction.outgoing_network.0,
            instruction.recipient,
        );
        writer
            .write_all(&data)
            .await
            .map_err(|e| IrohError::Io(e.to_string()))?;
        let _ = writer.finish();
        debug!(target: "iroh_client", "wrote {} byte(s), awaiting response...", data.len());

        let buf = match reader.read_to_end(1024 * 1024).await {
            Ok(b) => b,
            Err(e) => {
                error!(target: "iroh_client", "read_to_end error: {e:?}");
                return Err(IrohError::Io(format!("read error: {e:?}")));
            }
        };
        debug!(target: "iroh_client", "got {} byte(s) of response", buf.len());

        let frame: Frame =
            postcard::from_bytes(&buf).map_err(|e| IrohError::Protocol(e.to_string()))?;
        match frame {
            Frame::HopAck(ack) => {
                info!(
                    target: "iroh_client",
                    "received HopAck(payment_hash={}, accepted={}, signature={:?})",
                    lowercase_hex::encode(ack.payment_hash),
                    ack.accepted,
                    ack.signature,
                );
                Ok(ack)
            }
            _ => Err(IrohError::Protocol("unexpected frame".into())),
        }
    }
}

pub struct IrohServer {
    endpoint: Endpoint,
    home_relay: Option<String>,
}

impl IrohServer {
    pub async fn new(secret_key: SecretKey) -> Result<(Self, SecretKey), IrohError> {
        info!(target: "iroh_server", "binding endpoint with ALPN {:?}", ALPN_PROTOCOL);
        let endpoint = Endpoint::builder()
            .secret_key(secret_key)
            .alpns(vec![ALPN_PROTOCOL.to_vec()])
            .tls_x509()
            .bind()
            .await
            .map_err(|e| IrohError::Io(e.to_string()))?;
        let key = endpoint.secret_key().clone();
        info!(
            target: "iroh_server",
            "bound peer_id={}, waiting for home relay...",
            endpoint.secret_key().public()
        );
        let home_relay = match tokio::time::timeout(
            std::time::Duration::from_secs(10),
            endpoint.home_relay().initialized(),
        )
        .await
        {
            Ok(Ok(url)) => {
                info!(target: "iroh_server", "home relay established: {url}");
                Some(url.to_string())
            }
            Ok(Err(e)) => {
                warn!(target: "iroh_server", "home_relay watcher error: {e}");
                None
            }
            Err(_) => {
                warn!(
                    target: "iroh_server",
                    "timed out waiting 10s for home relay to initialize; \
                     incoming relay connections will fail"
                );
                None
            }
        };
        Ok((Self { endpoint, home_relay }, key))
    }

    pub fn peer_id(&self) -> iroh::PublicKey {
        self.endpoint.secret_key().public()
    }

    pub fn home_relay(&self) -> Option<&str> {
        self.home_relay.as_deref()
    }

    pub async fn run(
        self,
        handler: Arc<
            dyn Fn(HopInstruction) -> Pin<Box<dyn Future<Output = Result<HopAck, String>> + Send>>
                + Send
                + Sync,
        >,
    ) -> Result<(), IrohError> {
        info!(target: "iroh_server", "entering accept loop");
        loop {
            debug!(target: "iroh_server", "waiting for incoming connection...");
            let connecting = match self.endpoint.accept().await {
                Some(c) => c,
                None => {
                    error!(target: "iroh_server", "accept() returned None, endpoint closed");
                    return Err(IrohError::Closed);
                }
            };
            debug!(target: "iroh_server", "got incoming connecting future, awaiting handshake...");
            let conn = match connecting.await {
                Ok(c) => {
                    info!(
                        target: "iroh_server",
                        "handshake complete from remote={:?}",
                        c.remote_node_id().ok()
                    );
                    c
                }
                Err(e) => {
                    warn!(target: "iroh_server", "handshake error: {e}");
                    continue;
                }
            };

            let handler = handler.clone();
            tokio::spawn(async move {
                debug!(target: "iroh_server", "handling new connection");
                if let Err(e) = handle_conn(conn, handler).await {
                    error!(target: "iroh_server", "handle error: {e}");
                } else {
                    info!(target: "iroh_server", "connection handled successfully");
                }
            });
        }
    }
}

async fn handle_conn(
    conn: Connection,
    handler: Arc<
        dyn Fn(HopInstruction) -> Pin<Box<dyn Future<Output = Result<HopAck, String>> + Send>>
            + Send
            + Sync,
    >,
) -> Result<(), IrohError> {
    debug!(target: "iroh_server", "accept_bi waiting for stream...");
    let (mut writer, mut reader) = conn
        .accept_bi()
        .await
        .map_err(|e| IrohError::Io(e.to_string()))?;
    debug!(target: "iroh_server", "stream opened, reading payload...");

    let buf = reader
        .read_to_end(1024 * 1024)
        .await
        .map_err(|e| IrohError::Io(e.to_string()))?;
    debug!(target: "iroh_server", "read {} byte(s) of payload", buf.len());

    let frame: Frame = postcard::from_bytes(&buf).map_err(|e| IrohError::Protocol(e.to_string()))?;
    debug!(target: "iroh_server", "decoded frame, dispatching to handler");
    let response = match frame {
        Frame::HopInstruction(inst) => {
            info!(
                target: "iroh_server",
                "received HopInstruction(payment_hash={}, amount_msat={}, incoming={}, outgoing={}, recipient={})",
                lowercase_hex::encode(inst.payment_hash),
                inst.amount_msat,
                inst.incoming_network.0,
                inst.outgoing_network.0,
                inst.recipient,
            );
            match handler(inst).await {
                Ok(ack) => {
                    info!(
                        target: "iroh_server",
                        "handler returned HopAck(payment_hash={}, accepted=true)",
                        lowercase_hex::encode(ack.payment_hash),
                    );
                    Frame::HopAck(ack)
                }
                Err(reason) => {
                    warn!(target: "iroh_server", "handler rejected: {reason}");
                    Frame::HopAck(HopAck {
                        payment_hash: [0u8; 32],
                        accepted: false,
                        signature: Some(reason),
                    })
                }
            }
        }
        _ => return Err(IrohError::Protocol("expected HopInstruction".into())),
    };

    let data =
        postcard::to_allocvec(&response).map_err(|e| IrohError::Protocol(e.to_string()))?;
    debug!(target: "iroh_server", "writing {} byte(s) of response", data.len());
    writer
        .write_all(&data)
        .await
        .map_err(|e| IrohError::Io(e.to_string()))?;
    let _ = writer.finish();
    debug!(target: "iroh_server", "response written and stream finished, waiting for peer to close...");

    // Keep the connection open until the peer (client) closes its side.
    // If we drop `conn` now, the client may see `ConnectionLost` instead
    // of a clean stream FIN.
    let close_reason = conn.closed().await;
    debug!(target: "iroh_server", "connection closed by peer: {close_reason}");

    Ok(())
}
