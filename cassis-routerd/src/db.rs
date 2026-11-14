//! `<data dir>/router.redb`: the hops the router routes, next to its
//! wallet's `wallet.redb` (see [`cassis_wallet::db`]).
//!
//! A hop in flight is an [`Incoming`] HTLC, and once funded the
//! [`Outgoing`] one paid in exchange. When it ends both go, leaving a
//! [`Forward`] if the incoming HTLC was claimed, or a [`Fail`].

pub use db_schema::*;

#[orangedb::schema]
pub mod db_schema {
    use cassis_wallet::stored::{StoredHtlc, StoredInvoiceTarget};

    /// Where an incoming HTLC is.
    #[embed]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum IncomingState {
        /// Waiting to verify (to confirm, say). Nothing is funded yet.
        Verifying,
        /// Funding the outgoing HTLC.
        Funding,
        /// The outgoing HTLC is funded: see its [`Outgoing`].
        Forwarded,
    }

    /// The incoming HTLC of a hop in flight, from EXECUTE until it is
    /// claimed or the hop fails.
    #[entity]
    #[derive(Clone, Debug, PartialEq)]
    pub struct Incoming {
        #[id(String)]
        pub operation_id: HopId,
        /// Iroh id of the payer that prepared and executed the hop.
        pub owner: String,
        /// Hex.
        #[index]
        pub payment_hash: String,
        pub network: String,
        pub htlc: StoredHtlc,
        /// What the PREPARE asked to forward, and EXECUTE where to.
        pub outgoing_network: String,
        pub outgoing_amount_msat: u64,
        pub outgoing_expiry: u64,
        pub outgoing_target: StoredInvoiceTarget,
        pub state: IncomingState,
        pub created_at: u64,
    }

    /// The outgoing HTLC of a hop in flight, funded in exchange for its
    /// [`Incoming`] one.
    #[entity]
    #[derive(Clone, Debug, PartialEq)]
    pub struct Outgoing {
        #[id(String)]
        pub operation_id: OutgoingId,
        #[references(Incoming, on_delete = cascade)]
        pub incoming: HopId,
        pub network: String,
        pub htlc: StoredHtlc,
        /// Learned from downstream or the payer; claims the incoming
        /// HTLC.
        pub preimage: Option<[u8; 32]>,
        pub funded_at: u64,
    }

    /// A hop routed to its end: the incoming HTLC claimed.
    #[entity]
    #[derive(Clone, Debug, PartialEq)]
    pub struct Forward {
        #[id(String)]
        pub operation_id: ForwardId,
        pub owner: String,
        /// Hex.
        pub payment_hash: String,
        pub incoming_network: String,
        pub incoming_amount_msat: u64,
        pub outgoing_network: String,
        pub outgoing: StoredHtlc,
        #[index]
        pub settled_at: u64,
    }

    impl Forward {
        pub fn fee_msat(&self) -> u64 {
            self.incoming_amount_msat
                .saturating_sub(self.outgoing.amount_msat)
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

    /// A hop that ended without its incoming HTLC claimed.
    #[entity]
    #[derive(Clone, Debug, PartialEq)]
    pub struct Fail {
        #[id(String)]
        pub operation_id: FailId,
        pub owner: String,
        /// Hex.
        pub payment_hash: String,
        pub incoming_network: String,
        pub amount_msat: u64,
        pub outgoing_network: String,
        pub reason: FailReason,
        #[index]
        pub at: u64,
    }
}
