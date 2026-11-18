//! `<data dir>/router.redb`: the hops the router routes, next to its
//! wallet's `wallet.redb` (see [`cassis_wallet::db`]).
//!
//! A [`Hop`] is journaled once EXECUTEd and kept for good: in flight
//! while its [`HopState`] is, then settled or failed.

pub use db_schema::*;

#[orangedb::schema]
pub mod db_schema {
    use cassis_wallet::stored::{StoredFailReason, StoredHtlc, StoredInvoiceTarget};

    /// Where a hop is.
    #[embed]
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum HopState {
        /// Waiting for the incoming HTLC to verify (to confirm, say).
        /// Nothing is funded yet.
        Verifying,
        /// Funding the outgoing HTLC.
        Funding,
        /// The outgoing HTLC is funded.
        Forwarded,
        /// The incoming HTLC is claimed.
        Settled,
        /// Over without the incoming HTLC claimed.
        Failed { reason: StoredFailReason },
    }

    impl HopState {
        pub fn in_flight(&self) -> bool {
            matches!(self, Self::Verifying | Self::Funding | Self::Forwarded)
        }
    }

    /// One hop, from its EXECUTE on.
    #[entity]
    #[derive(Clone, Debug, PartialEq)]
    #[index(in_flight: bool = |hop| matches!(
        hop.state,
        HopState::Verifying | HopState::Funding | HopState::Forwarded
    ))]
    pub struct Hop {
        #[id(String)]
        pub operation_id: HopId,
        /// Iroh id of the payer that prepared and executed the hop.
        pub owner: String,
        /// Hex.
        #[index]
        pub payment_hash: String,
        pub incoming_network: String,
        pub incoming: StoredHtlc,
        /// What the PREPARE asked to forward, and EXECUTE where to.
        pub outgoing_network: String,
        pub outgoing_amount_msat: u64,
        pub outgoing_expiry: u64,
        pub outgoing_target: StoredInvoiceTarget,
        /// The outgoing HTLC, funded in exchange for the incoming one.
        /// Known once [`HopState::Forwarded`], and already while
        /// [`HopState::Funding`] on networks that can tell it before
        /// funding (see `Network::outgoing_descriptor`).
        pub outgoing: Option<StoredHtlc>,
        /// Learned from downstream or the payer; claims the incoming
        /// HTLC.
        pub preimage: Option<[u8; 32]>,
        pub state: HopState,
        pub created_at: u64,
        /// When it settled or failed.
        pub ended_at: Option<u64>,
    }

    impl Hop {
        /// What a settled hop earned.
        pub fn fee_msat(&self) -> u64 {
            self.incoming
                .amount_msat
                .saturating_sub(self.outgoing_amount_msat)
        }
    }
}
