use super::{NetworkId, CASHU_NETWORK_ID_PREFIX};

/// Build the full mint URL for a cashu network id, choosing the
/// scheme from the host: `http` for loopback (`localhost`, `127.0.0.1`,
/// `::1`), `https` for everything else. Returns an error if the
/// network id is not a cashu id.
pub fn cashu_mint_url(network_id: &NetworkId) -> Result<String, String> {
    let host = network_id
        .0
        .strip_prefix(CASHU_NETWORK_ID_PREFIX)
        .ok_or_else(|| format!("network id {network_id} is not a cashu id"))?;
    if host.is_empty() {
        return Err(format!("network id {network_id} has no host"));
    }
    if host.contains("://") {
        return Err(format!("network id {network_id} must not contain a scheme"));
    }
    let scheme = if is_loopback_host(host) {
        "http"
    } else {
        "https"
    };
    Ok(format!("{scheme}://{host}"))
}

/// True if `host` is a loopback address (`localhost`, `127.0.0.1`,
/// `::1`, with or without a port and IPv6 brackets).
pub fn is_loopback_host(host: &str) -> bool {
    let host_part: &str = if let Some(rest) = host.strip_prefix('[') {
        match rest.find(']') {
            Some(end) => &rest[..end],
            None => host,
        }
    } else if host == "::1" || host.starts_with("::1:") {
        "::1"
    } else {
        host.split(':').next().unwrap_or(host)
    };
    matches!(host_part, "localhost" | "127.0.0.1" | "::1")
}
