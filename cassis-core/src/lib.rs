pub mod logging;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Bytes32(pub [u8; 32]);

impl fmt::Debug for Bytes32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", lowercase_hex::encode(self.0))
    }
}

impl fmt::Display for Bytes32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", lowercase_hex::encode(self.0))
    }
}

impl AsRef<[u8]> for Bytes32 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl serde::Serialize for Bytes32 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&lowercase_hex::encode(self.0))
    }
}

impl<'de> serde::Deserialize<'de> for Bytes32 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let mut bytes = [0u8; 32];
        lowercase_hex::decode_to_slice(&s, &mut bytes).map_err(serde::de::Error::custom)?;
        Ok(Bytes32(bytes))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NetworkId(pub String);

impl fmt::Display for NetworkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<&str> for NetworkId {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

/// A directed route offered by a node: receive on `from`, send on `to`.
/// Each announcement has its own fee schedule, parsed from kind-35515 event tags.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RouteAnnouncement {
    pub node_pubkey: ritualistic::PubKey,
    pub iroh_peer_id: String,
    pub iroh_relay: Option<String>,
    pub from: NetworkId,
    pub to: NetworkId,
    pub fee_base_msat: u64,
    pub fee_ppm: u64,
    pub expires_at: u64,
    pub relays: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Invoice {
    pub payment_hash: Bytes32,
    pub amount_msat: u64,
    pub payee: String,
    pub expires_at: u64,
    pub networks: Vec<NetworkId>,
    pub description: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HopInstruction {
    pub payment_hash: Bytes32,
    pub amount_msat: u64,
    pub incoming_network: NetworkId,
    pub outgoing_network: NetworkId,
    pub incoming_deadline: u64,
    pub outgoing_expiry: u64,
    pub recipient: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HopAck {
    pub payment_hash: Bytes32,
    pub accepted: bool,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HopReject {
    pub payment_hash: Bytes32,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IncomingHtlc {
    pub payment_hash: Bytes32,
    pub amount_msat: u64,
    pub expiry: u64,
    pub sender: String,
    pub network: NetworkId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutgoingHtlc {
    pub payment_hash: Bytes32,
    pub amount_msat: u64,
    pub expiry: u64,
    pub recipient: String,
    pub network: NetworkId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RouteHop {
    pub node: RouteAnnouncement,
    pub incoming: NetworkId,
    pub outgoing: NetworkId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PaymentStatus {
    Completed,
    Refunded,
    Failed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaymentResult {
    pub status: PaymentStatus,
    pub preimage: Option<Bytes32>,
}

#[derive(thiserror::Error, Debug)]
pub enum WatchError {
    #[error("deadline exceeded")]
    DeadlineExceeded,
    #[error("network error: {0}")]
    Network(String),
    #[error("unimplemented")]
    Unimplemented,
}

#[derive(thiserror::Error, Debug)]
pub enum HtlcError {
    #[error("invalid parameters: {0}")]
    InvalidParams(String),
    #[error("network error: {0}")]
    Network(String),
    #[error("unimplemented")]
    Unimplemented,
}

#[async_trait]
pub trait NetworkAdapter: Send + Sync {
    fn network_id(&self) -> NetworkId;

    async fn watch_incoming_htlc(
        &self,
        payment_hash: Bytes32,
        min_amount_msat: u64,
        deadline: u64,
    ) -> Result<IncomingHtlc, WatchError>;

    async fn create_outgoing_htlc(
        &self,
        payment_hash: Bytes32,
        amount_msat: u64,
        expiry: u64,
        recipient: &str,
    ) -> Result<OutgoingHtlc, HtlcError>;

    async fn claim_incoming(
        &self,
        htlc: &IncomingHtlc,
        preimage: Bytes32,
    ) -> Result<(), HtlcError>;

    async fn refund_outgoing(&self, htlc: &OutgoingHtlc) -> Result<(), HtlcError>;

    async fn watch_preimage(
        &self,
        htlc: &OutgoingHtlc,
        deadline: u64,
    ) -> Result<Bytes32, WatchError>;

    fn incoming_delta_secs(&self) -> u64;
}
