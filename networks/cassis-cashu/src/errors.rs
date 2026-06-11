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
    #[error("store error: {0}")]
    Store(String),
}

/// Map a `cdk::Error` (the error type used by the wallet HTTP
/// client and the protocol layer) into a [`CashuError`]. The
/// cdk error carries a human-readable message plus, for
/// HTTP-level failures, the status code; we surface the whole
/// thing so the router / wallet logs stay debuggable.
impl From<cdk::Error> for CashuError {
    fn from(e: cdk::Error) -> Self {
        match &e {
            cdk::Error::HttpError(Some(code), msg) => {
                CashuError::Http(format!("HTTP {code}: {msg}"))
            }
            _ => CashuError::Mint(e.to_string()),
        }
    }
}
