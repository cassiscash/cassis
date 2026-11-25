//! Peer-to-peer transport over iroh: one bidirectional stream per
//! request, carrying one JSON [`Request`](crate::protocol::Request) and
//! one JSON [`Response`](crate::protocol::Response).
//!
//! [`PeerAddr`] is always available, so addresses can be parsed and
//! passed around without the node runtime; the endpoint itself
//! ([`Transport`], [`Handler`]) needs feature `node`.

use iroh_base::PublicKey;

#[cfg(feature = "node")]
mod endpoint;

#[cfg(feature = "node")]
pub use endpoint::{Handler, Transport};

/// Where to reach a peer: its iroh endpoint id plus, optionally, its
/// home relay.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PeerAddr {
    pub id: PublicKey,
    pub relay: Option<String>,
}
