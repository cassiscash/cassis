//! Cassis core: everything shared by every Cassis component.
//!
//! * [`network`] — the [`Network`] trait each network crate implements,
//!   and the HTLC types it speaks.
//! * [`protocol`] — wire messages between payer, routers and payee.
//! * [`routing`] — route announcements, pathfinding, fee and timelock
//!   planning.
//! * [`keys`] — key derivation from the node's mnemonic.
//! * [`offline`] — receiving while offline: the payee's authorization
//!   of a gateway and a preimage server, and their signed statements.
//! * [`signing`] — the canonical bytes every signature covers.
//! * [`transport`] (feature `node`, on by default) — the iroh transport
//!   nodes talk over. Without it the crate stays light enough for
//!   network crates and wasm. Paying and receiving is `cassis-wallet`'s,
//!   routing `cassis-routerd`'s.

pub mod keys;
pub mod logging;
pub mod network;
pub mod offline;
mod primitives;
pub mod protocol;
pub mod routing;
pub mod signing;

#[cfg(feature = "node")]
pub mod transport;

pub use network::{
    network_span, with_incoming_delta, Htlc, HtlcDescriptor, HtlcTarget, Network, NetworkError,
    NetworkId, OutgoingState,
};
pub use primitives::{
    sats_for_msat, unix_now, Bytes32, OperationId, PubKey, XOnlyPubKey, MSAT_PER_SAT,
};
pub use protocol::{Invoice, InvoiceBody, InvoiceReceiver};
