//! `<data dir>/router.redb`: the hops the router routes, next to its
//! wallet's `wallet.redb` (see [`cassis_wallet::db`]).
//!
//! A [`Hop`] is journaled once EXECUTEd and kept for good: in flight
//! while its [`HopState`] is, then settled or failed.

pub use db_schema::*;

#[orangedb::schema]
pub mod db_schema {
    use cassis_wallet::stored::{StoredHtlc, StoredInvoiceTarget};

    /// Where a hop is.
    #[embed]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
        Failed { reason: FailReason },
    }

    impl HopState {
        pub fn in_flight(self) -> bool {
            matches!(self, Self::Verifying | Self::Funding | Self::Forwarded)
        }
    }

    /// Why a hop failed.
    #[embed]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum FailReason {
        /// A network of the hop is not open.
        NetworkUnavailable,
        /// The incoming HTLC did not verify.
        IncomingRejected,
        /// The outgoing expiry passed before the incoming HTLC verified.
        ExpiredWhileVerifying,
        /// The outgoing HTLC could not be funded.
        FundingFailed,
        /// A restart interrupted funding the outgoing HTLC: whether it
        /// exists is unknown.
        InterruptedWhileFunding,
        /// The outgoing HTLC was refunded: no preimage came back.
        PreimageNotReceived,
        /// The incoming HTLC could not be claimed before it expired, so
        /// the outgoing one was paid for nothing.
        ClaimFailed,
    }

    impl FailReason {
        pub fn describe(self) -> &'static str {
            match self {
                FailReason::NetworkUnavailable => "a network of the hop is not open",
                FailReason::IncomingRejected => "the incoming HTLC was rejected",
                FailReason::ExpiredWhileVerifying => "the outgoing expiry passed while verifying",
                FailReason::FundingFailed => "the outgoing HTLC could not be funded",
                FailReason::InterruptedWhileFunding => "interrupted while funding",
                FailReason::PreimageNotReceived => "no preimage came back: refunded",
                FailReason::ClaimFailed => "the incoming HTLC could not be claimed in time",
            }
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
