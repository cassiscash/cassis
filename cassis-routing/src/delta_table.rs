use cassis_core::NetworkId;

/// Fallback per-hop transit slack (seconds): extra buffer the sender
/// adds to deadlines to absorb in-flight latency and clock skew between
/// sender and a hop. Used when a route announcement did not publish a
/// `transit_slack_secs` tag.
///
/// The default (60 s) is generous enough to absorb a round-trip plus
/// modest clock skew across typical WAN links, and is the same for
/// every network.
pub fn fallback_transit_slack(_network: &NetworkId) -> u64 {
    60
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_transit_slack_is_60_for_known_and_unknown_networks() {
        assert_eq!(fallback_transit_slack(&NetworkId("liquid".into())), 60);
        assert_eq!(fallback_transit_slack(&NetworkId("rootstock".into())), 60);
        assert_eq!(fallback_transit_slack(&NetworkId("mystery".into())), 60);
        assert_eq!(fallback_transit_slack(&NetworkId("".into())), 60);
    }
}
