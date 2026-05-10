use cassis_core::{HopAck, HopInstruction};
use iroh::endpoint::Connection;
use iroh::{Endpoint, NodeAddr, SecretKey};
use serde::{Deserialize, Serialize};
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
        peer_id: iroh::PublicKey,
        instruction: HopInstruction,
    ) -> Result<HopAck, IrohError> {
        let addr = NodeAddr::new(peer_id);
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
        Ok((Self { endpoint }, key))
    }

    pub fn peer_id(&self) -> iroh::PublicKey {
        self.endpoint.secret_key().public()
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
