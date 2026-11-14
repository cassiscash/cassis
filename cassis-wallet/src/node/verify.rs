//! Waiting for an incoming HTLC to verify.

use super::VERIFY_RETRY_INTERVAL;
use cassis_core::network::{Htlc, Network, NetworkError};
use cassis_core::unix_now;
use std::fmt;
use tracing::info;

/// Why an incoming HTLC did not verify.
#[derive(Debug)]
pub enum Unverified {
    /// The HTLC is wrong: waiting will not help.
    Rejected(String),
    /// Still not verified at the deadline, last for this reason.
    TimedOut(String),
}

impl fmt::Display for Unverified {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected(reason) => write!(f, "HTLC rejected: {reason}"),
            Self::TimedOut(reason) => write!(f, "HTLC not verified in time: {reason}"),
        }
    }
}

/// Verify `htlc` on `network`, again every [`VERIFY_RETRY_INTERVAL`]
/// until `deadline` (unix seconds) while it is not final yet or the
/// network cannot tell: nothing depends on it before it verifies, so
/// waiting costs nothing. `request` names what is waiting, in the logs.
pub async fn verify_incoming(
    network: &dyn Network,
    htlc: &Htlc,
    deadline: u64,
    request: &str,
) -> Result<(), Unverified> {
    let mut waiting = false;
    loop {
        match network.verify_incoming_htlc(htlc).await {
            Ok(()) => return Ok(()),
            Err(NetworkError::Invalid(reason)) => return Err(Unverified::Rejected(reason)),
            Err(error) if unix_now() < deadline => {
                if !waiting {
                    info!(
                        "{request} {}: waiting for the HTLC: {error}",
                        htlc.payment_hash.short()
                    );
                    waiting = true;
                }
                tokio::time::sleep(VERIFY_RETRY_INTERVAL).await;
            }
            Err(error) => return Err(Unverified::TimedOut(error.to_string())),
        }
    }
}
