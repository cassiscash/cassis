use cassis_core::{HopAck, HopInstruction, RouteAnnouncement};
use iroh::endpoint::Connection;
use iroh::{Endpoint, NodeAddr, SecretKey};
use serde::{Deserialize, Serialize};
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

    pub async fn send_instruction(
        &self,
        addr: NodeAddr,
        instruction: HopInstruction,
    ) -> Result<HopAck, IrohError> {
        let conn = self
            .endpoint
            .connect(addr, ALPN_PROTOCOL)
            .await
            .map_err(|e| IrohError::Io(e.to_string()))?;

        let (mut writer, mut reader) = conn
            .open_bi()
            .await
            .map_err(|e| IrohError::Io(e.to_string()))?;

        let frame = Frame::HopInstruction(instruction);
        let data = postcard::to_allocvec(&frame).map_err(|e| IrohError::Protocol(e.to_string()))?;
        writer
            .write_all(&data)
            .await
            .map_err(|e| IrohError::Io(e.to_string()))?;
        let _ = writer.finish();

        let buf = reader
            .read_to_end(1024 * 1024)
            .await
            .map_err(|e| IrohError::Io(e.to_string()))?;

        let frame: Frame =
            postcard::from_bytes(&buf).map_err(|e| IrohError::Protocol(e.to_string()))?;
        match frame {
            Frame::HopAck(ack) => Ok(ack),
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
        let endpoint = Endpoint::builder()
            .secret_key(secret_key)
            .alpns(vec![ALPN_PROTOCOL.to_vec()])
            .bind()
            .await
            .map_err(|e| IrohError::Io(e.to_string()))?;
        let key = endpoint.secret_key().clone();
        let home_relay = endpoint.home_relay().get().ok().flatten().map(|u| u.to_string());
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
        handler: Arc<dyn Fn(HopInstruction) -> Result<HopAck, String> + Send + Sync>,
    ) -> Result<(), IrohError> {
        loop {
            let connecting = self
                .endpoint
                .accept()
                .await
                .ok_or(IrohError::Closed)?;
            let conn = connecting
                .await
                .map_err(|e| IrohError::Io(e.to_string()))?;

            let handler = handler.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_conn(conn, handler).await {
                    eprintln!("iroh handle error: {e}");
                }
            });
        }
    }
}

async fn handle_conn(
    conn: Connection,
    handler: Arc<dyn Fn(HopInstruction) -> Result<HopAck, String> + Send + Sync>,
) -> Result<(), IrohError> {
    let (mut writer, mut reader) = conn
        .accept_bi()
        .await
        .map_err(|e| IrohError::Io(e.to_string()))?;

    let buf = reader
        .read_to_end(1024 * 1024)
        .await
        .map_err(|e| IrohError::Io(e.to_string()))?;

    let frame: Frame = postcard::from_bytes(&buf).map_err(|e| IrohError::Protocol(e.to_string()))?;
    let response = match frame {
        Frame::HopInstruction(inst) => match handler(inst) {
            Ok(ack) => Frame::HopAck(ack),
            Err(reason) => Frame::HopAck(HopAck {
                payment_hash: [0u8; 32],
                accepted: false,
                signature: Some(reason),
            }),
        },
        _ => return Err(IrohError::Protocol("expected HopInstruction".into())),
    };

    let data =
        postcard::to_allocvec(&response).map_err(|e| IrohError::Protocol(e.to_string()))?;
    writer
        .write_all(&data)
        .await
        .map_err(|e| IrohError::Io(e.to_string()))?;
    let _ = writer.finish();

    Ok(())
}
