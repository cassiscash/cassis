//! Client for Blockstream's Liquid 0-conf observation service.
//!
//! <https://blog.blockstream.com/0-conf-for-elements-and-liquid-a-technical-explainer/>
//!
//! The service aggregates mempool visibility for Liquid transactions:
//! nodes across the network (grouped into observation tiers) report
//! when they have seen a txid, and the API exposes per-tier
//! `seen`/`total` counts. For a *non-RBF* transaction, wide
//! functionary coverage means the network has converged on one
//! version of the spend — Elements nodes keep the first-seen spend of
//! an input, so a later conflicting spend is ignored — which makes it
//! reasonable to act on the HTLC before it confirms.
//!
//! Two entry points, one acceptance policy ([`coverage_met`]: at
//! least 4/5 of the functionary tier):
//!
//! * [`wait_for_coverage`] — used by the node that *creates* an HTLC.
//!   Subscribes over the websocket endpoint and resolves only once
//!   coverage is reached, so no polling is involved.
//! * [`check_coverage`] — used by the node that *receives* an HTLC.
//!   A single REST lookup whose answer is treated as final: the
//!   sender only dispatches after waiting for coverage itself, so by
//!   the time the receiver asks, the coverage must already be there.

use futures::{SinkExt as _, StreamExt as _};
use serde::Deserialize;
use std::collections::HashMap;
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;

/// Hostname of the 0-conf observation service.
const HOST: &str = "0conf.dev.blockstream.com";
/// Observation tier whose coverage gates acceptance: the
/// functionaries that actually produce Liquid blocks.
const FUNCTIONARY_TIER: &str = "functionary";
/// Required functionary coverage as a fraction: at least
/// [`REQUIRED_NUM`]/[`REQUIRED_DEN`] of the configured functionaries
/// must have reported the transaction.
const REQUIRED_NUM: u64 = 4;
const REQUIRED_DEN: u64 = 5;
/// Sender-side budget for mempool propagation. Coverage normally
/// arrives within seconds of broadcast; one Liquid block interval of
/// slack is generous without stalling the DISPATCH round forever.
const WAIT_TIMEOUT: Duration = Duration::from_secs(60);
/// Delay before reconnecting after a websocket failure.
const RETRY_DELAY: Duration = Duration::from_secs(2);

/// `seen`/`total` counts of one observation tier.
#[derive(Debug, Deserialize)]
struct Tier {
    seen: u64,
    total: u64,
}

/// Tier name -> counts, as returned by both API flavors.
type Observations = HashMap<String, Tier>;

/// The acceptance policy: at least [`REQUIRED_NUM`]/[`REQUIRED_DEN`]
/// of the functionary tier has reported the transaction.
fn coverage_met(observations: &Observations) -> bool {
    observations
        .get(FUNCTIONARY_TIER)
        .is_some_and(|tier| tier.total > 0 && tier.seen * REQUIRED_DEN >= tier.total * REQUIRED_NUM)
}

fn coverage_shortfall(txid: &str, observations: &Observations) -> String {
    match observations.get(FUNCTIONARY_TIER) {
        Some(tier) => format!(
            "0-conf: tx {txid} seen by {}/{} functionaries, \
             need at least {REQUIRED_NUM}/{REQUIRED_DEN} of them",
            tier.seen, tier.total
        ),
        None => format!("0-conf: no functionary observations reported for tx {txid}"),
    }
}

/// One-shot REST check of `txid` (receiver side). The answer is
/// final: no retry, no polling — a shortfall (or an unknown txid)
/// rejects the HTLC.
pub(crate) async fn check_coverage(http: &reqwest::Client, txid: &str) -> Result<(), String> {
    #[derive(Deserialize)]
    struct Response {
        observations: Observations,
    }
    let url = format!("https://{HOST}/api/v1/zeroconf/{txid}");
    let response: Response = http
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("0-conf request: {e}"))?
        .error_for_status()
        .map_err(|e| format!("0-conf request: {e}"))?
        .json()
        .await
        .map_err(|e| format!("0-conf response: {e}"))?;
    if coverage_met(&response.observations) {
        Ok(())
    } else {
        Err(coverage_shortfall(txid, &response.observations))
    }
}

/// Watch `txid` over the websocket endpoint until functionary
/// coverage is met (sender side). Reconnects and re-subscribes on
/// dropped connections and expired subscriptions; gives up after
/// [`WAIT_TIMEOUT`].
pub(crate) async fn wait_for_coverage(span: &tracing::Span, txid: &str) -> Result<(), String> {
    tokio::time::timeout(WAIT_TIMEOUT, async {
        loop {
            match watch_once(txid).await {
                Ok(()) => return Ok(()),
                Err(Watch::Fatal(e)) => return Err(e),
                Err(Watch::Reconnect(e)) => {
                    span.in_scope(|| {
                        tracing::warn!(
                            target: "cassis_liquid",
                            "0-conf websocket for {txid}: {e}; reconnecting",
                        );
                    });
                    tokio::time::sleep(RETRY_DELAY).await;
                }
            }
        }
    })
    .await
    .map_err(|_| {
        format!(
            "0-conf: tx {txid} not seen by {REQUIRED_NUM}/{REQUIRED_DEN} \
             of functionaries within {}s",
            WAIT_TIMEOUT.as_secs()
        )
    })?
}

/// How a single websocket session ended short of coverage:
/// `Reconnect` failures are transient (dropped connection, expired
/// subscription), `Fatal` ones are protocol rejections a retry
/// cannot fix.
enum Watch {
    Reconnect(String),
    Fatal(String),
}

/// Server frames of the websocket protocol. Frames with unknown
/// actions (or shapes) are skipped by the caller.
#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "lowercase")]
enum ServerMessage {
    Subscribed {},
    Snapshot {
        txid: String,
        observations: Observations,
    },
    Expired {},
    Error {
        reason: String,
        message: String,
    },
}

/// One connection: subscribe to `txid`, then read snapshot frames
/// until coverage is met.
async fn watch_once(txid: &str) -> Result<(), Watch> {
    let url = format!("wss://{HOST}/ws/v1/zeroconf");
    let (mut ws, _) = tokio_tungstenite::connect_async(url)
        .await
        .map_err(|e| Watch::Reconnect(format!("connect: {e}")))?;
    let subscribe = serde_json::json!({ "action": "subscribe", "txid": txid });
    ws.send(Message::text(subscribe.to_string()))
        .await
        .map_err(|e| Watch::Reconnect(format!("subscribe: {e}")))?;
    while let Some(frame) = ws.next().await {
        let frame = frame.map_err(|e| Watch::Reconnect(format!("read: {e}")))?;
        let Message::Text(text) = frame else { continue };
        let Ok(message) = serde_json::from_str::<ServerMessage>(text.as_str()) else {
            continue;
        };
        match message {
            ServerMessage::Snapshot {
                txid: seen_txid,
                observations,
            } if seen_txid == txid && coverage_met(&observations) => {
                let _ = ws.close(None).await;
                return Ok(());
            }
            ServerMessage::Snapshot { .. } | ServerMessage::Subscribed {} => {}
            ServerMessage::Expired {} => {
                return Err(Watch::Reconnect("subscription expired".into()));
            }
            ServerMessage::Error { reason, message } => {
                return Err(Watch::Fatal(format!(
                    "0-conf service rejected watch: {reason}: {message}"
                )));
            }
        }
    }
    Err(Watch::Reconnect("connection closed".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn functionaries(seen: u64, total: u64) -> Observations {
        HashMap::from([(FUNCTIONARY_TIER.to_string(), Tier { seen, total })])
    }

    #[test]
    fn coverage_requires_four_fifths_of_functionaries() {
        assert!(coverage_met(&functionaries(12, 15)));
        assert!(!coverage_met(&functionaries(11, 15)));
        assert!(coverage_met(&functionaries(4, 5)));
        assert!(!coverage_met(&functionaries(3, 5)));
        assert!(coverage_met(&functionaries(5, 5)));
        // An empty tier (or a missing one) never counts as covered.
        assert!(!coverage_met(&functionaries(0, 0)));
        assert!(!coverage_met(&HashMap::new()));
    }

    #[test]
    fn parses_snapshot_frame() {
        let raw = r#"{"action":"snapshot","txid":"ab","observations":
            {"functionary":{"seen":12,"total":15},"bridge":{"seen":1,"total":2}}}"#;
        let ServerMessage::Snapshot { txid, observations } = serde_json::from_str(raw).unwrap()
        else {
            panic!("expected snapshot");
        };
        assert_eq!(txid, "ab");
        assert!(coverage_met(&observations));
    }

    #[test]
    fn parses_expired_and_error_frames() {
        let expired = r#"{"action":"expired","txid":"ab","message":"subscription expired"}"#;
        assert!(matches!(
            serde_json::from_str(expired).unwrap(),
            ServerMessage::Expired {}
        ));
        let error = r#"{"action":"error","reason":"bad_txid","message":"nope"}"#;
        assert!(matches!(
            serde_json::from_str(error).unwrap(),
            ServerMessage::Error { .. }
        ));
    }
}
