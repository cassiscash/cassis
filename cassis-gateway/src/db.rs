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

pub use db_schema::*;

#[orangedb::schema]
pub mod db_schema {
    use super::v1;
    use cassis_core::network::NetworkId;
    use cassis_wallet::stored::{StoredHtlc, StoredPayeeGatewayReceiveAuthorization};

    // Rows whose stored authorizations and HTLCs gained the variants of
    // new networks.

    #[migrate]
    fn handled_delegation_from_v1(
        old: v1::HandledDelegation,
    ) -> orangedb::Result<HandledDelegation> {
        Ok(HandledDelegation {
            authorization_id: HandledDelegationId(old.authorization_id.0),
            payee: old.payee,
            authorization: old.authorization.into(),
            preimage_server_relay: old.preimage_server_relay,
            registered_at: old.registered_at,
        })
    }

    #[migrate]
    fn payee_htlc_from_v1(old: v1::PayeeHtlc) -> orangedb::Result<PayeeHtlc> {
        Ok(PayeeHtlc {
            payment_hash: PayeeHtlcHash(old.payment_hash.0),
            incoming_network: old.incoming_network,
            incoming: old.incoming.into(),
            claim_by: old.claim_by,
            network: old.network,
            htlc: old.htlc.map(Into::into),
            outcome: old.outcome.map(|outcome| match outcome {
                v1::PayeeOutcome::Claimed => PayeeOutcome::Claimed,
                v1::PayeeOutcome::Refunded => PayeeOutcome::Refunded,
            }),
            preimage: old.preimage,
            settled: old.settled,
            failed: old.failed,
            created_at: old.created_at,
        })
    }

    /// A standing authorization a payee gave this gateway.
    #[entity]
    #[derive(Clone, Debug, PartialEq)]
    pub struct HandledDelegation {
        /// [`PayeeGatewayReceiveAuthorization::id`](cassis_core::offline::PayeeGatewayReceiveAuthorization::id).
        #[id([u8; 32])]
        pub authorization_id: HandledDelegationId,
        /// The payee's iroh key.
        #[index]
        pub payee: [u8; 32],
        pub authorization: StoredPayeeGatewayReceiveAuthorization,
        /// Iroh relay the payee gave for reaching the preimage server.
        pub preimage_server_relay: Option<String>,
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

/// The schema before Citrea, WBTC on Starknet and WBTC on Solana, whose
/// stored authorizations and HTLCs [`db_schema`] migrates from. Frozen:
/// only what decides how rows are stored, and the indexes orangedb
/// needs.
#[orangedb::schema]
pub mod v1 {
    use cassis_core::network::NetworkId;
    use cassis_wallet::stored::v1::{StoredHtlc, StoredPayeeGatewayReceiveAuthorization};

    #[entity]
    #[derive(Clone, Debug, PartialEq)]
    pub struct HandledDelegation {
        #[id([u8; 32])]
        pub authorization_id: HandledDelegationId,
        #[index]
        pub payee: [u8; 32],
        pub authorization: StoredPayeeGatewayReceiveAuthorization,
        pub preimage_server_relay: Option<String>,
        pub registered_at: u64,
    }

    #[embed]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum PayeeOutcome {
        Claimed,
        Refunded,
    }

    #[entity]
    #[derive(Clone, Debug, PartialEq)]
    pub struct PayeeHtlc {
        #[id([u8; 32])]
        pub payment_hash: PayeeHtlcHash,
        #[fingerprint = "network_id"]
        pub incoming_network: NetworkId,
        pub incoming: StoredHtlc,
        pub claim_by: u64,
        #[fingerprint = "network_id"]
        pub network: NetworkId,
        pub htlc: Option<StoredHtlc>,
        pub outcome: Option<PayeeOutcome>,
        pub preimage: Option<[u8; 32]>,
        #[index]
        pub settled: bool,
        pub failed: Option<String>,
        pub created_at: u64,
    }
}
