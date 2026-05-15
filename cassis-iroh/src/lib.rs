use cassis_core::{HopAck, HopInstruction, RouteAnnouncement};
use iroh::endpoint::Connection;
use iroh::{Endpoint, NodeAddr, SecretKey};
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
        eprintln!("iroh client: binding endpoint with ALPN {:?}", ALPN_PROTOCOL);
        let endpoint = Endpoint::builder()
            .alpns(vec![ALPN_PROTOCOL.to_vec()])
            .tls_x509()
            .bind()
            .await
            .map_err(|e| IrohError::Io(e.to_string()))?;
        eprintln!("iroh client: bound peer_id={}", endpoint.node_id());
        Ok(Self::new(endpoint))
    }

    pub async fn send_instruction(
        &self,
        addr: NodeAddr,
        instruction: HopInstruction,
    ) -> Result<HopAck, IrohError> {
        eprintln!(
            "iroh client: connecting to {} (relay={:?}, direct_addrs={})...",
            addr.node_id,
            addr.relay_url(),
            addr.direct_addresses().count()
        );
        let conn = match self.endpoint.connect(addr, ALPN_PROTOCOL).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("iroh client: connect error chain:");
                for cause in e.chain() {
                    eprintln!("  caused by: {cause}");
                }
                return Err(IrohError::Io(format!("{e:#}")));
            }
        };
        eprintln!("iroh client: connected, opening bi stream...");

        let (mut writer, mut reader) = conn
            .open_bi()
            .await
            .map_err(|e| IrohError::Io(e.to_string()))?;
        eprintln!("iroh client: stream opened, writing frame...");

        let frame = Frame::HopInstruction(instruction.clone());
        let data = postcard::to_allocvec(&frame).map_err(|e| IrohError::Protocol(e.to_string()))?;
        eprintln!(
            "iroh client: sending HopInstruction(payment_hash={}, amount_msat={}, incoming={}, outgoing={}, recipient={})",
            hex::encode(instruction.payment_hash),
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
        eprintln!("iroh client: wrote {} byte(s), awaiting response...", data.len());

        let buf = match reader.read_to_end(1024 * 1024).await {
            Ok(b) => b,
            Err(e) => {
                eprintln!("iroh client: read_to_end error: {e:?}");
                return Err(IrohError::Io(format!("read error: {e:?}")));
            }
        };
        eprintln!("iroh client: got {} byte(s) of response", buf.len());

        let frame: Frame =
            postcard::from_bytes(&buf).map_err(|e| IrohError::Protocol(e.to_string()))?;
        match frame {
            Frame::HopAck(ack) => {
                eprintln!(
                    "iroh client: received HopAck(payment_hash={}, accepted={}, signature={:?})",
                    hex::encode(ack.payment_hash),
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
        eprintln!("iroh server: binding endpoint with ALPN {:?}", ALPN_PROTOCOL);
        let endpoint = Endpoint::builder()
            .secret_key(secret_key)
            .alpns(vec![ALPN_PROTOCOL.to_vec()])
            .tls_x509()
            .bind()
            .await
            .map_err(|e| IrohError::Io(e.to_string()))?;
        let key = endpoint.secret_key().clone();
        eprintln!(
            "iroh server: bound peer_id={}, waiting for home relay...",
            endpoint.secret_key().public()
        );
        // Wait until the endpoint has selected a home relay so that incoming
        // connections through the relay can actually be delivered.
        let home_relay = match tokio::time::timeout(
            std::time::Duration::from_secs(10),
            endpoint.home_relay().initialized(),
        )
        .await
        {
            Ok(Ok(url)) => {
                eprintln!("iroh server: home relay established: {url}");
                Some(url.to_string())
            }
            Ok(Err(e)) => {
                eprintln!("iroh server: home_relay watcher error: {e}");
                None
            }
            Err(_) => {
                eprintln!(
                    "iroh server: WARNING timed out waiting 10s for home relay to initialize; \
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
        eprintln!("iroh server: entering accept loop");
        loop {
            eprintln!("iroh server: waiting for incoming connection...");
            let connecting = match self.endpoint.accept().await {
                Some(c) => c,
                None => {
                    eprintln!("iroh server: accept() returned None, endpoint closed");
                    return Err(IrohError::Closed);
                }
            };
            eprintln!("iroh server: got incoming connecting future, awaiting handshake...");
            let conn = match connecting.await {
                Ok(c) => {
                    eprintln!(
                        "iroh server: handshake complete from remote={:?}",
                        c.remote_node_id().ok()
                    );
                    c
                }
                Err(e) => {
                    eprintln!("iroh server: handshake error: {e}");
                    continue;
                }
            };

            let handler = handler.clone();
            tokio::spawn(async move {
                eprintln!("iroh server: handling new connection");
                if let Err(e) = handle_conn(conn, handler).await {
                    eprintln!("iroh handle error: {e}");
                } else {
                    eprintln!("iroh server: connection handled successfully");
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
    eprintln!("iroh server: accept_bi waiting for stream...");
    let (mut writer, mut reader) = conn
        .accept_bi()
        .await
        .map_err(|e| IrohError::Io(e.to_string()))?;
    eprintln!("iroh server: stream opened, reading payload...");

    let buf = reader
        .read_to_end(1024 * 1024)
        .await
        .map_err(|e| IrohError::Io(e.to_string()))?;
    eprintln!("iroh server: read {} byte(s) of payload", buf.len());

    let frame: Frame = postcard::from_bytes(&buf).map_err(|e| IrohError::Protocol(e.to_string()))?;
    eprintln!("iroh server: decoded frame, dispatching to handler");
    let response = match frame {
        Frame::HopInstruction(inst) => {
            eprintln!(
                "iroh server: received HopInstruction(payment_hash={}, amount_msat={}, incoming={}, outgoing={}, recipient={})",
                hex::encode(inst.payment_hash),
                inst.amount_msat,
                inst.incoming_network.0,
                inst.outgoing_network.0,
                inst.recipient,
            );
            match handler(inst).await {
                Ok(ack) => {
                    eprintln!(
                        "iroh server: handler returned HopAck(payment_hash={}, accepted=true)",
                        hex::encode(ack.payment_hash),
                    );
                    Frame::HopAck(ack)
                }
                Err(reason) => {
                    eprintln!("iroh server: handler rejected: {reason}");
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
    eprintln!("iroh server: writing {} byte(s) of response", data.len());
    writer
        .write_all(&data)
        .await
        .map_err(|e| IrohError::Io(e.to_string()))?;
    let _ = writer.finish();
    eprintln!("iroh server: response written and stream finished, waiting for peer to close...");

    // Keep the connection open until the peer (client) closes its side.
    // If we drop `conn` now, the client may see `ConnectionLost` instead
    // of a clean stream FIN.
    let close_reason = conn.closed().await;
    eprintln!("iroh server: connection closed by peer: {close_reason}");

    Ok(())
}
