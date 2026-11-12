//! `<dir>/gateway.redb`: what a gateway keeps.
//!
//! * [`HandledDelegation`]s: the standing authorizations payees gave it,
//!   under which it issues invoices in their name.
//! * [`PayeeHtlc`]s: the HTLCs it paid payees on with, each presented to
//!   the payee's preimage server, with the payer's HTLC it claims once
//!   the preimage is released.
//!
//! It keeps no invoice: an invoice it issued carries its terms sealed
//! in its metadata, signed by the gateway (see
//! [`GatewayMetadata`](cassis_core::offline::GatewayMetadata)), which
//! payers hand back with PREPARE and COMMIT.

pub use db::*;

#[orangedb::schema]
pub mod db {
    use cassis_core::network::NetworkId;
    use cassis_wallet::stored::{StoredAuthorization, StoredHtlc};

    /// A standing authorization a payee gave this gateway.
    #[entity]
    #[derive(Clone, Debug, PartialEq)]
    pub struct HandledDelegation {
        /// Hex [`ReceiveAuthorization::id`](cassis_core::offline::ReceiveAuthorization::id).
        #[id(String)]
        pub authorization_id: HandledDelegationId,
        /// The payee's iroh key.
        #[index]
        pub payee: [u8; 32],
        pub authorization: StoredAuthorization,
        pub registered_at: u64,
    }

    /// What became of the HTLC to the payee.
    #[embed]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum PayeeOutcome {
        Claimed,
        Refunded,
    }

    /// An HTLC this gateway funds to a payee, from the moment it starts
    /// funding it, for the payer's HTLC it was paid with. The HTLC is
    /// presented to the preimage server, whose preimage claims the
    /// payer's HTLC; it is refunded only if no preimage came back.
    #[entity]
    #[derive(Clone, Debug, PartialEq)]
    #[index(open: bool = |r| r.htlc.is_some() && r.outcome.is_none())]
    pub struct PayeeHtlc {
        /// The payment hash.
        #[id([u8; 32])]
        pub payment_hash: PayeeHtlcHash,
        /// The payer's HTLC, to claim.
        #[fingerprint = "network_id"]
        pub incoming_network: NetworkId,
        pub incoming: StoredHtlc,
        /// The payer's HTLC must be claimed by then.
        pub claim_by: u64,
        /// The invoice's terms, from its metadata.
        pub authorization: StoredAuthorization,
        pub payee_metadata: Option<Vec<u8>>,
        /// The HTLC to the payee, once funded; while `None`, funding is
        /// under way, or was interrupted.
        #[fingerprint = "network_id"]
        pub network: NetworkId,
        pub htlc: Option<StoredHtlc>,
        pub outcome: Option<PayeeOutcome>,
        /// Released by the preimage server, or revealed by the payee.
        pub preimage: Option<[u8; 32]>,
        /// The payer's HTLC is claimed.
        #[index]
        pub settled: bool,
        /// Why the payer's HTLC will not be claimed, if so.
        pub failed: Option<String>,
        pub created_at: u64,
    }

    impl PayeeHtlc {
        /// Still needs its networks: to fund or claim, or to see the
        /// payee claim or refund.
        pub fn in_flight(&self) -> bool {
            let claiming = !self.settled && self.failed.is_none();
            claiming || (self.htlc.is_some() && self.outcome.is_none())
        }
    }
}
