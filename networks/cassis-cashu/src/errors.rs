use thiserror::Error;

pub type CashuResult<T> = std::result::Result<T, CashuError>;

#[derive(Debug, Error)]
pub enum CashuError {
    #[error("http error: {0}")]
    Http(String),
    #[error("deserialization error: {0}")]
    Deserialize(String),
    #[error("mint returned error: {0}")]
    Mint(String),
    #[error("mint has no active keyset")]
    NoKeyset,
    #[error("nuts error: {0}")]
    Nuts(String),
    #[error("proof verification failed")]
    VerifyProofs,
    #[error("amount mismatch: expected {expected}, got {actual}")]
    AmountMismatch { expected: u64, actual: u64 },
    #[error("proofs already spent")]
    ProofsSpent,
    #[error("htlc expired")]
    HtlcExpired,
}
