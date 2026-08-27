//! Cassis core: everything shared by every Cassis component.
//!
//! * [`network`] — the [`Network`] trait each network crate implements,
//!   and the HTLC types it speaks.
//! * [`protocol`] — wire messages between payer, routers and payee.
//! * [`routing`] — route announcements, pathfinding, fee and timelock
//!   planning.
//! * [`keys`] — key derivation from the node's mnemonic.
//! * [`node`] (feature `node`, on by default) — the runtime that
//!   coordinates networks to pay, route and receive, with its iroh
//!   [`transport`] and its [`store`]. Without it the crate stays light
//!   enough for network crates and wasm.

pub mod keys;
pub mod logging;
pub mod network;
mod primitives;
pub mod protocol;
pub mod routing;

#[cfg(feature = "node")]
pub mod node;
#[cfg(feature = "node")]
pub mod store;
#[cfg(feature = "node")]
pub mod transport;

pub use network::{
    network_span, with_incoming_delta, with_max_incoming_lifetime, Htlc, HtlcDescriptor,
    HtlcTarget, Network, NetworkError, NetworkId, OutgoingState,
};
pub use primitives::{
    sats_for_msat, unix_now, Bytes32, OperationId, PubKey, XOnlyPubKey, MSAT_PER_SAT,
};
pub use protocol::Invoice;
