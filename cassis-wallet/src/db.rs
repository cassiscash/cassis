//! `<home>/wallet.redb`: what a wallet keeps of its payments.
//!
//! * [`Invoice`]s it issued, direct or delegated to a gateway and a
//!   preimage server, until settled or expired.
//! * [`Transaction`]s: money that moved in or out, by payment hash.
//! * [`PendingPayment`]s: HTLCs it funded that are neither claimed nor
//!   refunded yet.
//! * [`FullDelegation`]s: the gateways it lets issue invoices in its
//!   name, whose preimage servers it asks for payments to claim.

pub use db_schema::*;

#[orangedb::schema]
pub mod db_schema {
    use crate::stored::{StoredHtlc, StoredInvoiceNetwork, StoredReceiveAuthorization};

    /// Whether an invoice may still be paid.
    #[embed]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum InvoiceState {
        /// Live, waiting for its payment.
        Waiting,
        Settled,
        Expired,
    }

    /// The gateway an invoice is paid to in this wallet's place, and the
    /// preimage server that holds its preimage and logs the HTLC the
    /// gateway pays this wallet on with.
    #[embed]
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Delegation {
        /// Iroh key.
        pub gateway: [u8; 32],
        pub gateway_relay: Option<String>,
        /// Iroh key.
        pub preimage_server: [u8; 32],
        pub preimage_server_relay: Option<String>,
        pub authorization: StoredReceiveAuthorization,
    }

    /// An invoice this wallet issued.
    #[entity]
    #[derive(Clone, Debug, PartialEq)]
    #[index(to_check_on_preimage_server: [u8; 32] = |r| r.to_check_on_preimage_server())]
    #[index(waiting_until: u64 = |r| (r.state == InvoiceState::Waiting).then(|| r.expires_after()))]
    pub struct Invoice {
        #[id([u8; 32])]
        pub payment_hash: InvoiceHash,
        pub amount_msat: u64,
        pub expires_at: u64,
        pub networks: Vec<StoredInvoiceNetwork>,
        pub description: Option<String>,
        pub metadata: Option<Vec<u8>>,
        /// Known for a direct invoice; a delegated one's is with its
        /// preimage server.
        pub preimage: Option<[u8; 32]>,
        pub delegation: Option<Delegation>,
        pub state: InvoiceState,
        pub created_at: u64,
        pub settled_at: Option<u64>,
    }

    impl Invoice {
        /// The preimage server to ask for this invoice's payment: that
        /// of a delegated invoice still waiting for it.
        pub fn to_check_on_preimage_server(&self) -> Option<[u8; 32]> {
            let delegation = self.delegation.as_ref()?;
            (self.state == InvoiceState::Waiting).then_some(delegation.preimage_server)
        }

        /// When a waiting invoice expires: at its expiry, or for a
        /// delegated one, once the HTLC a gateway paid it on with before
        /// then may have been refunded, so its payment is looked for
        /// until it cannot be claimed anymore.
        pub fn expires_after(&self) -> u64 {
            match &self.delegation {
                Some(delegation) => self
                    .expires_at
                    .saturating_add(delegation.authorization.min_final_timeout_secs),
                None => self.expires_at,
            }
        }
    }

    /// Which way money moved.
    #[embed]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Direction {
        Incoming,
        Outgoing,
    }

    impl Direction {
        /// As an index key.
        pub fn key(self) -> u8 {
            match self {
                Direction::Incoming => 0,
                Direction::Outgoing => 1,
            }
        }
    }

    /// Money that moved: an HTLC this wallet claimed, or one it funded
    /// that was claimed. One per payment hash: a second one for the
    /// same hash is refused, as something went wrong.
    #[entity]
    #[derive(Clone, Debug, PartialEq)]
    #[index(direction: u8 = |r| r.direction.key())]
    pub struct Transaction {
        #[id([u8; 32])]
        pub payment_hash: TransactionHash,
        pub direction: Direction,
        pub amount_msat: u64,
        pub network: String,
        /// The proof of payment.
        pub preimage: [u8; 32],
        #[index]
        pub at: u64,
    }

    /// An HTLC this wallet funded to pay an invoice, until it is claimed
    /// (it becomes a [`Transaction`]) or refunded.
    #[entity]
    #[derive(Clone, Debug, PartialEq)]
    pub struct PendingPayment {
        #[id([u8; 32])]
        pub payment_hash: PendingPaymentHash,
        pub network: String,
        pub htlc: StoredHtlc,
        pub created_at: u64,
    }

    /// A gateway this wallet lets issue invoices in its name while it is
    /// offline, under a standing authorization. The preimage server of
    /// every one is asked for new payments to claim.
    #[entity]
    #[derive(Clone, Debug, PartialEq)]
    pub struct FullDelegation {
        /// [`ReceiveAuthorization::id`](cassis_core::offline::ReceiveAuthorization::id).
        #[id([u8; 32])]
        pub authorization_id: FullDelegationId,
        /// Iroh key.
        pub gateway: [u8; 32],
        pub gateway_relay: Option<String>,
        /// Iroh key.
        #[index]
        pub preimage_server: [u8; 32],
        pub preimage_server_relay: Option<String>,
        pub authorization: StoredReceiveAuthorization,
        pub created_at: u64,
    }
}
