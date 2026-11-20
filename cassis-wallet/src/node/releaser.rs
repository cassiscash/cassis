//! Receiving invoices the node keeps no record of.

use async_trait::async_trait;
use cassis_core::protocol::{Commit, PreparePayee};
use cassis_core::Bytes32;

/// What a [`PreimageReleaser`] lets a COMMIT claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Released {
    /// The preimage of the COMMIT's payment hash.
    pub preimage: Bytes32,
    /// What the invoice asked for: the HTLC must lock at least this.
    pub amount_msat: u64,
}

/// Answers PREPARE and COMMIT for invoices this node has no record of
/// (see `Node::set_preimage_releaser`), such as ones made with
/// `Node::build_invoice` whose terms and preimage are derived from what
/// the invoice's metadata carries back.
///
/// It is asked about the hashes the node has no stored invoice for; the
/// node still checks the HTLC and the time left to claim it, and
/// reveals the preimage only once the HTLC is claimed.
#[async_trait]
pub trait PreimageReleaser: Send + Sync {
    /// Whether to accept the payment `prepare` announces.
    async fn accept(&self, prepare: &PreparePayee) -> bool;

    /// The preimage to claim the HTLC of `commit` with, and what it
    /// must be worth, or `None` to refuse the payment.
    async fn release(&self, commit: &Commit) -> Option<Released>;
}
