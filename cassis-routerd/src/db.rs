//! `<data dir>/router.redb`: the hops the router routes, next to its
//! wallet's `wallet.redb` (see [`cassis_wallet::db`]).
//!
//! A [`Hop`] is journaled once EXECUTEd and kept for good: in flight
//! while its [`HopState`] is, then settled or failed.

pub use db_schema::*;

#[orangedb::schema]
pub mod db_schema {
    use super::v1;
    use cassis_wallet::stored::{StoredFailReason, StoredHtlc, StoredInvoiceTarget};

    /// Hops, whose stored HTLCs and targets gained the variants of new
    /// networks.
    #[migrate]
    fn hop_from_v1(old: v1::Hop) -> orangedb::Result<Hop> {
        Ok(Hop {
            operation_id: HopId(old.operation_id.0),
            owner: old.owner,
            payment_hash: old.payment_hash,
            incoming_network: old.incoming_network,
            incoming: old.incoming.into(),
            outgoing_network: old.outgoing_network,
            outgoing_amount_msat: old.outgoing_amount_msat,
            outgoing_expiry: old.outgoing_expiry,
            outgoing_target: old.outgoing_target.into(),
            outgoing: old.outgoing.map(Into::into),
            preimage: old.preimage,
            state: match old.state {
                v1::HopState::Verifying => HopState::Verifying,
                v1::HopState::Funding => HopState::Funding,
                v1::HopState::Forwarded => HopState::Forwarded,
                v1::HopState::Settled => HopState::Settled,
                v1::HopState::Failed { reason } => HopState::Failed {
                    reason: reason.into(),
                },
            },
            created_at: old.created_at,
            ended_at: old.ended_at,
        })
    }

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
        #[id([u8; 16])]
        pub operation_id: HopId,
        /// Iroh key of the payer that prepared and executed the hop.
        pub owner: [u8; 32],
        #[index]
        pub payment_hash: [u8; 32],
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

/// The schema before Citrea, WBTC on Starknet and WBTC on Solana, whose
/// stored HTLCs and targets [`db_schema`] migrates from. Frozen: only
/// what decides how rows are stored, and the indexes orangedb needs.
#[orangedb::schema]
pub mod v1 {
    use cassis_wallet::stored::v1::{StoredFailReason, StoredHtlc, StoredInvoiceTarget};

    #[embed]
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum HopState {
        Verifying,
        Funding,
        Forwarded,
        Settled,
        Failed { reason: StoredFailReason },
    }

    #[entity]
    #[derive(Clone, Debug, PartialEq)]
    pub struct Hop {
        #[id([u8; 16])]
        pub operation_id: HopId,
        pub owner: [u8; 32],
        #[index]
        pub payment_hash: [u8; 32],
        pub incoming_network: String,
        pub incoming: StoredHtlc,
        pub outgoing_network: String,
        pub outgoing_amount_msat: u64,
        pub outgoing_expiry: u64,
        pub outgoing_target: StoredInvoiceTarget,
        pub outgoing: Option<StoredHtlc>,
        pub preimage: Option<[u8; 32]>,
        pub state: HopState,
        pub created_at: u64,
        pub ended_at: Option<u64>,
    }
}
