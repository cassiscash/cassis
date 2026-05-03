use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::fmt;

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

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct L2Tag(pub String);

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PeerTag(pub String);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeAnnouncement {
    pub node_pubkey: String,
    pub iroh_pubkey: String,
    pub networks: Vec<NetworkId>,
    /// Directed routes this node offers, e.g. `(A, B)` means
    /// "receive on A, send on B". Populated from kind-35515 `d` tags.
    #[serde(default)]
    pub routes: Vec<Route>,
    pub fee_base_msat: u64,
    pub fee_ppm: u64,
    pub expires_at: u64,
    pub relays: Vec<String>,
}

/// A directed route offered by a node: receive on `from`, send on `to`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Route {
    pub from: NetworkId,
    pub to: NetworkId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Invoice {
    pub payment_hash: [u8; 32],
    pub amount_msat: u64,
    pub destination_pubkey: String,
    pub expires_at: u64,
    pub route_hints: Vec<NetworkId>,
    pub description: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HopInstruction {
    pub payment_hash: [u8; 32],
    pub amount_msat: u64,
    pub incoming_network: NetworkId,
    pub outgoing_network: NetworkId,
    pub incoming_deadline: u64,
    pub outgoing_expiry: u64,
    pub recipient: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HopAck {
    pub payment_hash: [u8; 32],
    pub accepted: bool,
    pub signature: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HopReject {
    pub payment_hash: [u8; 32],
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IncomingHtlc {
    pub payment_hash: [u8; 32],
    pub amount_msat: u64,
    pub expiry: u64,
    pub sender: String,
    pub network: NetworkId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutgoingHtlc {
    pub payment_hash: [u8; 32],
    pub amount_msat: u64,
    pub expiry: u64,
    pub recipient: String,
    pub network: NetworkId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RouteHop {
    pub node: NodeAnnouncement,
    pub incoming: L2Tag,
    pub outgoing: L2Tag,
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
    pub preimage: Option<[u8; 32]>,
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
        payment_hash: [u8; 32],
        min_amount_msat: u64,
        deadline: u64,
    ) -> Result<IncomingHtlc, WatchError>;

    async fn create_outgoing_htlc(
        &self,
        payment_hash: [u8; 32],
        amount_msat: u64,
        expiry: u64,
        recipient: &str,
    ) -> Result<OutgoingHtlc, HtlcError>;

    async fn claim_incoming(
        &self,
        htlc: &IncomingHtlc,
        preimage: [u8; 32],
    ) -> Result<(), HtlcError>;

    async fn refund_outgoing(&self, htlc: &OutgoingHtlc) -> Result<(), HtlcError>;

    async fn watch_preimage(
        &self,
        htlc: &OutgoingHtlc,
        deadline: u64,
    ) -> Result<[u8; 32], WatchError>;

    fn incoming_delta_secs(&self) -> u64;
}
