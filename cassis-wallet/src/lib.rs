//! A Cassis wallet: pays and receives Cassis invoices on its networks,
//! living in a home directory (see [`home`]). `cassis-routerd` and
//! `cassis-gateway` keep their wallet the same way.
//!
//! * [`node`] — the payer and payee roles, and receiving offline through
//!   a gateway and a preimage server.
//! * [`db`] — what the wallet keeps of its payments, in
//!   `<home>/wallet.redb`; [`stored`] mirrors the wire types it stores.
//! * [`config`] — `<home>/config.toml`: its keys and its networks.

pub mod config;
pub mod db;
pub mod home;
pub mod node;
pub mod stored;

pub use home::{open_db, routine_checks, Home};
pub use node::{Node, NodeConfig};
