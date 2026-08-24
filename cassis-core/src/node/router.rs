//! Router role: PREPARE / EXECUTE / DISCARD / SETTLE handling and route
//! announcements.

use super::{HopRecord, HopState, Node, HOPS, INLINE_WAIT, VERIFY_RETRY_INTERVAL};
use crate::network::{Htlc, HtlcTarget, NetworkError};
use crate::primitives::{unix_now, OperationId};
use crate::protocol::{Discard, Execute, Prepare, Response, Settle};
use crate::routing::{self, RouteAnnouncement, DEFAULT_TRANSIT_SLACK_SECS};
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};

/// How long a PREPARE reservation waits for its EXECUTE.
const RESERVATION_TTL_SECS: u64 = 600;
/// Announcements are republished well within
/// [`routing::ANNOUNCEMENT_MAX_AGE_SECS`].
const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

/// Optional PREPARE veto: a rejection reason, or `None` to proceed.
pub type PrepareVeto = Arc<dyn Fn(&Prepare) -> Option<String> + Send + Sync>;

/// Terms this node routes under.
#[derive(Clone)]
pub struct RoutingPolicy {
    pub fee_base_msat: u64,
    pub fee_ppm: u64,
    pub transit_slack_secs: u64,
    pub nostr_relays: Vec<String>,
    /// Most PREPARE reservations held at once.
    pub max_reservations: usize,
    /// Runs after the built-in checks, before anything is reserved.
    pub prepare_veto: Option<PrepareVeto>,
}

impl Default for RoutingPolicy {
    fn default() -> Self {
        Self {
            fee_base_msat: 1000,
            fee_ppm: 500,
            transit_slack_secs: DEFAULT_TRANSIT_SLACK_SECS,
            nostr_relays: routing::DEFAULT_NOSTR_RELAYS
                .iter()
                .map(|relay| relay.to_string())
                .collect(),
            max_reservations: 100,
            prepare_veto: None,
        }
    }
}

/// A PREPARE waiting for its EXECUTE.
pub(super) struct Reservation {
    prepare: Prepare,
    owner: String,
    target: HtlcTarget,
    expires_at: u64,
}

impl Node {
    /// Start routing between every enabled network: accept PREPAREs and
    /// keep route announcements published.
    pub fn start_routing(&self, policy: RoutingPolicy) {
        *self.0.routing.write().unwrap_or_else(|e| e.into_inner()) = Some(policy);
        let node = self.clone();
        self.spawn(async move {
            loop {
                node.announce().await;
                tokio::time::sleep(ANNOUNCE_INTERVAL).await;
            }
        });
    }

    fn routing(&self) -> Option<RoutingPolicy> {
        self.0
            .routing
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    async fn announce(&self) {
        let Some(policy) = self.routing() else {
            return;
        };
        let networks = self.network_ids();
        let relay = self.0.transport.home_relay().await;
        let mut announcements = Vec::new();
        for from in &networks {
            let Ok(incoming) = self.network(from) else {
                continue;
            };
            for to in networks.iter().filter(|to| *to != from) {
                announcements.push(RouteAnnouncement {
                    node_pubkey: self.node_pubkey(),
                    iroh_peer_id: self.iroh_peer_id(),
                    iroh_relay: relay.clone(),
                    from: from.clone(),
                    to: to.clone(),
                    fee_base_msat: policy.fee_base_msat,
                    fee_ppm: policy.fee_ppm,
                    incoming_delta_secs: incoming.incoming_delta_secs(),
                    transit_slack_secs: policy.transit_slack_secs,
                });
            }
        }
        if announcements.is_empty() {
            warn!("routing needs at least two networks; nothing announced");
            return;
        }
        for (route, accepted) in
            routing::publish_announcements(&policy.nostr_relays, &self.0.keys.node, &announcements)
                .await
        {
            info!(
                "announced {route} to {accepted}/{} relay(s)",
                policy.nostr_relays.len()
            );
        }
    }

    pub(super) async fn prepare(
        &self,
        prepare: Prepare,
        peer: String,
    ) -> Result<HtlcTarget, String> {
        let result = self.reserve(&prepare, peer).await;
        match &result {
            Ok(_) => info!(
                "PREPARE {} accepted: {} msat {} -> {} msat {}",
                prepare.payment_hash.short(),
                prepare.amount_msat,
                prepare.incoming_network,
                prepare.outgoing_amount_msat,
                prepare.outgoing_network
            ),
            Err(reason) => warn!(
                "PREPARE {} rejected: {reason}",
                prepare.payment_hash.short()
            ),
        }
        result
    }

    async fn reserve(&self, prepare: &Prepare, peer: String) -> Result<HtlcTarget, String> {
        let policy = self.routing().ok_or("this node does not route")?;
        let incoming = self.network(&prepare.incoming_network)?;
        let outgoing = self.network(&prepare.outgoing_network)?;
        let now = unix_now();
        if !prepare.operation_id.is_valid() {
            return Err("operation id must be 32 hex characters".into());
        }
        if prepare.payment_hash.0 == [0; 32] {
            return Err("zero payment hash".into());
        }
        if prepare.incoming_network == prepare.outgoing_network {
            return Err("incoming and outgoing network are the same".into());
        }
        if prepare.outgoing_amount_msat == 0 || prepare.outgoing_amount_msat > prepare.amount_msat {
            return Err("outgoing amount must be positive and at most the incoming amount".into());
        }
        let fee = routing::fee_msat(
            policy.fee_base_msat,
            policy.fee_ppm,
            prepare.outgoing_amount_msat,
        );
        if prepare.amount_msat - prepare.outgoing_amount_msat < fee {
            return Err(format!("fee below the announced {fee} msat"));
        }
        if prepare.outgoing_expiry <= now {
            return Err("outgoing expiry is in the past".into());
        }
        // Worst case the downstream claims at the outgoing expiry; the
        // incoming network must still have time to take our claim.
        let delta = incoming.incoming_delta_secs();
        if prepare.incoming_expiry < prepare.outgoing_expiry.saturating_add(delta) {
            return Err(format!(
                "incoming expiry must be at least {delta}s after the outgoing expiry"
            ));
        }
        if let Some(reason) = policy.prepare_veto.as_ref().and_then(|veto| veto(prepare)) {
            return Err(reason);
        }

        let mut reservations = self.0.reservations.lock().await;
        if let Some(existing) = reservations.get(&prepare.operation_id) {
            return if existing.owner == peer && existing.prepare == *prepare {
                Ok(existing.target.clone())
            } else {
                Err("operation id already in use".into())
            };
        }
        if reservations.len() >= policy.max_reservations {
            return Err("too many pending reservations".into());
        }
        let hash_in_use = reservations
            .values()
            .any(|reservation| reservation.prepare.payment_hash == prepare.payment_hash)
            || self.hops()?.iter().any(|hop| {
                hop.prepare.payment_hash == prepare.payment_hash
                    && matches!(
                        hop.state,
                        HopState::Verifying | HopState::Funding | HopState::Forwarded
                    )
            });
        if hash_in_use {
            return Err("payment hash already has an active attempt here".into());
        }
        outgoing
            .can_send(prepare.outgoing_amount_msat)
            .await
            .map_err(|e| format!("cannot send on {}: {e}", prepare.outgoing_network))?;
        incoming
            .can_receive(prepare.amount_msat)
            .await
            .map_err(|e| format!("cannot receive on {}: {e}", prepare.incoming_network))?;
        let target = incoming
            .receive_target(
                prepare.payment_hash,
                prepare.amount_msat,
                prepare.incoming_expiry,
            )
            .await
            .map_err(|e| format!("cannot receive on {}: {e}", prepare.incoming_network))?;
        reservations.insert(
            prepare.operation_id.clone(),
            Reservation {
                prepare: prepare.clone(),
                owner: peer,
                target: target.clone(),
                expires_at: now + RESERVATION_TTL_SECS,
            },
        );
        Ok(target)
    }

    /// Start forwarding a prepared hop, or report on one already
    /// started: [`Response::Executed`] once the outgoing HTLC is funded,
    /// [`Response::Pending`] while the incoming one is not final yet.
    pub(super) async fn execute(&self, execute: Execute, peer: String) -> Response {
        if self.hop(&execute.operation_id).ok().flatten().is_none() {
            if let Err(error) = self.start_hop(execute.clone(), peer.clone()).await {
                return Response::Error(error);
            }
        }
        let report = || -> Response {
            match self.hop(&execute.operation_id) {
                Ok(Some(hop))
                    if hop.owner != peer || hop.prepare.payment_hash != execute.payment_hash =>
                {
                    Response::Error("operation belongs to another payment".into())
                }
                Ok(Some(hop)) => match (hop.state, hop.outgoing) {
                    (HopState::Failed(reason), _) => Response::Error(reason),
                    (_, Some(outgoing)) => Response::Executed(outgoing.descriptor),
                    _ => Response::Pending,
                },
                Ok(None) => Response::Error("no matching PREPARE".into()),
                Err(error) => Response::Error(error),
            }
        };
        // Answer right away when forwarding is quick.
        let deadline = tokio::time::Instant::now() + INLINE_WAIT;
        loop {
            let response = report();
            if !matches!(response, Response::Pending) || tokio::time::Instant::now() >= deadline {
                return response;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Turn the reservation of `execute` into a journaled hop and
    /// forward it in the background.
    async fn start_hop(&self, execute: Execute, peer: String) -> Result<(), String> {
        let reservation = {
            let mut reservations = self.0.reservations.lock().await;
            match reservations.get(&execute.operation_id) {
                Some(reservation)
                    if reservation.owner == peer
                        && reservation.prepare.payment_hash == execute.payment_hash => {}
                _ => return Err("no matching PREPARE".into()),
            }
            reservations
                .remove(&execute.operation_id)
                .expect("checked above")
        };
        let prepare = reservation.prepare;
        if prepare.outgoing_expiry <= unix_now() {
            return Err("outgoing expiry passed before EXECUTE".into());
        }
        let hop = HopRecord {
            operation_id: execute.operation_id,
            owner: peer,
            incoming: Htlc {
                payment_hash: prepare.payment_hash,
                amount_msat: prepare.amount_msat,
                expiry: prepare.incoming_expiry,
                target: reservation.target,
                descriptor: execute.incoming_descriptor,
            },
            prepare,
            outgoing_target: execute.outgoing_target,
            outgoing: None,
            state: HopState::Verifying,
            preimage: None,
        };
        self.save_hop(&hop)?;
        self.spawn(self.clone().forward(hop));
        Ok(())
    }

    /// Wait for the incoming HTLC of `hop` to verify, then fund its
    /// outgoing HTLC.
    async fn forward(self, mut hop: HopRecord) {
        let Some(_busy) = self.busy(format!("hop:{}", hop.operation_id)) else {
            return;
        };
        let prepare = hop.prepare.clone();
        let (incoming, outgoing) = match (
            self.network(&prepare.incoming_network),
            self.network(&prepare.outgoing_network),
        ) {
            (Ok(incoming), Ok(outgoing)) => (incoming, outgoing),
            (Err(error), _) | (_, Err(error)) => return self.fail_hop(hop, error).await,
        };
        let mut waiting = false;
        loop {
            match incoming.verify_incoming_htlc(&hop.incoming).await {
                Ok(()) => break,
                Err(NetworkError::NotYet(reason)) if unix_now() < prepare.outgoing_expiry => {
                    if !waiting {
                        info!(
                            "EXECUTE {}: waiting for the incoming HTLC: {reason}",
                            prepare.payment_hash.short()
                        );
                        waiting = true;
                    }
                    tokio::time::sleep(VERIFY_RETRY_INTERVAL).await;
                }
                Err(error) => {
                    let reason = format!("incoming HTLC rejected: {error}");
                    return self.fail_hop(hop, reason).await;
                }
            }
        }
        if prepare.outgoing_expiry <= unix_now() {
            let reason = "outgoing expiry passed while verifying".to_string();
            return self.fail_hop(hop, reason).await;
        }

        hop.state = HopState::Funding;
        if let Err(error) = self.save_hop(&hop) {
            return self.fail_hop(hop, error).await;
        }
        let funded = outgoing
            .create_outgoing_htlc(
                prepare.payment_hash,
                prepare.outgoing_amount_msat,
                prepare.outgoing_expiry,
                &hop.outgoing_target,
            )
            .await;
        match funded {
            Ok(descriptor) => {
                hop.outgoing = Some(Htlc {
                    payment_hash: prepare.payment_hash,
                    amount_msat: prepare.outgoing_amount_msat,
                    expiry: prepare.outgoing_expiry,
                    target: hop.outgoing_target.clone(),
                    descriptor,
                });
                hop.state = HopState::Forwarded;
                if let Err(error) = self.save_hop(&hop) {
                    error!("journaling forwarded hop {}: {error}", hop.operation_id);
                }
                info!(
                    "EXECUTE {}: forwarded {} msat {} -> {}",
                    prepare.payment_hash.short(),
                    prepare.outgoing_amount_msat,
                    prepare.incoming_network,
                    prepare.outgoing_network
                );
            }
            Err(error) => {
                hop.state = HopState::Failed(format!(
                    "cannot fund on {}: {error}",
                    prepare.outgoing_network
                ));
                if let Err(error) = self.save_hop(&hop) {
                    error!("journaling failed hop {}: {error}", hop.operation_id);
                }
            }
        }
    }

    /// End a hop that never funded its outgoing HTLC.
    async fn fail_hop(&self, mut hop: HopRecord, reason: String) {
        warn!(
            "EXECUTE {} failed: {reason}",
            hop.prepare.payment_hash.short()
        );
        self.release(&hop.prepare).await;
        hop.state = HopState::Failed(reason);
        if let Err(error) = self.save_hop(&hop) {
            error!("journaling failed hop {}: {error}", hop.operation_id);
        }
    }

    pub(super) async fn discard(&self, discard: Discard, peer: String) {
        let reservation = {
            let mut reservations = self.0.reservations.lock().await;
            match reservations.get(&discard.operation_id) {
                Some(reservation)
                    if reservation.owner == peer
                        && reservation.prepare.payment_hash == discard.payment_hash =>
                {
                    reservations.remove(&discard.operation_id)
                }
                _ => None,
            }
        };
        if let Some(reservation) = reservation {
            self.release(&reservation.prepare).await;
        }
    }

    /// The payer reveals the preimage of an executed hop.
    pub(super) async fn settle_hop(&self, settle: Settle, peer: String) {
        let Some(_busy) = self.busy(format!("hop:{}", settle.operation_id)) else {
            return;
        };
        let Ok(Some(mut hop)) = self.hop(&settle.operation_id) else {
            return;
        };
        if hop.owner != peer
            || hop.state != HopState::Forwarded
            || !hop.prepare.payment_hash.matches_preimage(&settle.preimage)
        {
            return;
        }
        hop.preimage = Some(settle.preimage);
        self.claim_hop(&mut hop).await;
    }

    /// Drop reservations whose EXECUTE never came.
    pub(super) async fn expire_reservations(&self) {
        let now = unix_now();
        let expired: Vec<Reservation> = {
            let mut reservations = self.0.reservations.lock().await;
            let ids: Vec<OperationId> = reservations
                .iter()
                .filter(|(_, reservation)| reservation.expires_at <= now)
                .map(|(id, _)| id.clone())
                .collect();
            ids.iter()
                .filter_map(|id| reservations.remove(id))
                .collect()
        };
        for reservation in expired {
            self.release(&reservation.prepare).await;
        }
    }

    /// Release what the incoming network set up to receive `prepare`.
    async fn release(&self, prepare: &Prepare) {
        if let Ok(network) = self.network(&prepare.incoming_network) {
            if let Err(error) = network.cancel_receive(prepare.payment_hash).await {
                warn!(
                    "releasing reservation {} on {}: {error}",
                    prepare.payment_hash.short(),
                    prepare.incoming_network
                );
            }
        }
    }

    /// Hops this node routed, in any state.
    pub fn hops(&self) -> Result<Vec<HopRecord>, String> {
        self.store().list(HOPS)
    }

    pub(super) fn hop(&self, operation_id: &OperationId) -> Result<Option<HopRecord>, String> {
        self.store().get(HOPS, operation_id.as_str())
    }

    pub(super) fn save_hop(&self, hop: &HopRecord) -> Result<(), String> {
        self.store().put(HOPS, hop.operation_id.as_str(), hop)
    }

    /// After a restart: go on waiting for hops still verifying, and
    /// fail hops left mid-funding, which cannot be resumed: whether
    /// their outgoing HTLC exists is unknown, and funding it again could
    /// pay twice.
    pub(super) fn resume_hops(&self) -> Result<(), String> {
        for mut hop in self.hops()? {
            match hop.state {
                HopState::Verifying => {
                    self.spawn(self.clone().forward(hop));
                }
                HopState::Funding => {
                    error!(
                        "hop {} was interrupted while funding its outgoing HTLC on {}; \
                         check that wallet for a lock to {:?}",
                        hop.prepare.payment_hash, hop.prepare.outgoing_network, hop.prepare,
                    );
                    hop.state = HopState::Failed("interrupted while funding".into());
                    self.save_hop(&hop)?;
                }
                _ => {}
            }
        }
        Ok(())
    }
}
