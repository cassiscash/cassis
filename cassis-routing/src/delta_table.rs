use cassis_core::NetworkId;

/// Fallback per-hop incoming delta (seconds) for a given network, used when
/// a route announcement did not publish an `incoming_delta_secs` tag.
///
/// Values mirror the `incoming_delta_secs()` declared on each network
/// adapter (`cassisd` and the per-network crates):
///   - ark: 10
///   - fedimint: 30
///   - cashu: 30
///   - liquid: 300
///   - rootstock: 600
///
/// The default (30 s) matches the most common adapter and is used for
/// any network not in the table.
pub fn fallback_incoming_delta(network: &NetworkId) -> u64 {
    match network.0.as_str() {
        "ark" => 10,
        "fedimint" => 30,
        "cashu" => 30,
        "liquid" => 300,
        "rootstock" => 600,
        _ => 30,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_networks_return_documented_values() {
        assert_eq!(fallback_incoming_delta(&NetworkId("ark".into())), 10);
        assert_eq!(fallback_incoming_delta(&NetworkId("fedimint".into())), 30);
        assert_eq!(fallback_incoming_delta(&NetworkId("cashu".into())), 30);
        assert_eq!(fallback_incoming_delta(&NetworkId("liquid".into())), 300);
        assert_eq!(fallback_incoming_delta(&NetworkId("rootstock".into())), 600);
    }

    #[test]
    fn unknown_network_returns_default() {
        assert_eq!(fallback_incoming_delta(&NetworkId("mystery".into())), 30);
        assert_eq!(fallback_incoming_delta(&NetworkId("".into())), 30);
    }
}
