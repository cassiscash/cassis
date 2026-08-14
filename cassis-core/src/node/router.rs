//! Router role: PREPARE / EXECUTE / DISCARD / SETTLE handling and route
//! announcements.

use super::{HopRecord, HopState, Node, HOPS};
use crate::network::{Htlc, HtlcDescriptor, HtlcTarget};
use crate::primitives::{unix_now, OperationId};
use crate::protocol::{Discard, Execute, Prepare, Settle};
use crate::routing::{self, RouteAnnouncement, DEFAULT_TRANSIT_SLACK_SECS};
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn, Instrument};

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
        tokio::spawn(
            async move {
                loop {
                    node.announce().await;
                    tokio::time::sleep(ANNOUNCE_INTERVAL).await;
                }
            }
            .instrument(self.span()),
        );
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
                    && matches!(hop.state, HopState::Funding | HopState::Forwarded)
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

    pub(super) async fn execute(
        &self,
        execute: Execute,
        peer: String,
    ) -> Result<HtlcDescriptor, String> {
        let _busy = self
            .busy(format!("hop:{}", execute.operation_id))
            .ok_or("this operation is already being executed")?;
        // A retried EXECUTE gets the answer of the first one.
        if let Some(hop) = self.hop(&execute.operation_id)? {
            if hop.owner != peer || hop.prepare.payment_hash != execute.payment_hash {
                return Err("operation belongs to another payment".into());
            }
            return hop
                .outgoing
                .map(|htlc| htlc.descriptor)
                .ok_or_else(|| format!("this operation failed earlier: {:?}", hop.state));
        }
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
        let prepare = reservation.prepare.clone();
        let incoming_network = self.network(&prepare.incoming_network)?;
        let outgoing_network = self.network(&prepare.outgoing_network)?;
        if prepare.outgoing_expiry <= unix_now() {
            return Err("outgoing expiry passed before EXECUTE".into());
        }
        let incoming = Htlc {
            payment_hash: prepare.payment_hash,
            amount_msat: prepare.amount_msat,
            expiry: prepare.incoming_expiry,
            target: reservation.target.clone(),
            descriptor: execute.incoming_descriptor,
        };
        if let Err(error) = incoming_network.verify_incoming_htlc(&incoming).await {
            // Leave the reservation for a corrected retry.
            self.0
                .reservations
                .lock()
                .await
                .insert(execute.operation_id, reservation);
            return Err(format!("incoming HTLC rejected: {error}"));
        }

        let mut hop = HopRecord {
            operation_id: execute.operation_id.clone(),
            owner: peer,
            prepare: prepare.clone(),
            incoming,
            outgoing: None,
            state: HopState::Funding,
            preimage: None,
        };
        self.save_hop(&hop)?;
        let funded = outgoing_network
            .create_outgoing_htlc(
                prepare.payment_hash,
                prepare.outgoing_amount_msat,
                prepare.outgoing_expiry,
                &execute.outgoing_target,
            )
            .await;
        match funded {
            Ok(descriptor) => {
                hop.outgoing = Some(Htlc {
                    payment_hash: prepare.payment_hash,
                    amount_msat: prepare.outgoing_amount_msat,
                    expiry: prepare.outgoing_expiry,
                    target: execute.outgoing_target,
                    descriptor: descriptor.clone(),
                });
                hop.state = HopState::Forwarded;
                self.save_hop(&hop)?;
                info!(
                    "EXECUTE {}: forwarded {} msat {} -> {}",
                    prepare.payment_hash.short(),
                    prepare.outgoing_amount_msat,
                    prepare.incoming_network,
                    prepare.outgoing_network
                );
                Ok(descriptor)
            }
            Err(error) => {
                hop.state = HopState::Failed(format!("funding the outgoing HTLC: {error}"));
                self.save_hop(&hop)?;
                Err(format!(
                    "cannot fund on {}: {error}",
                    prepare.outgoing_network
                ))
            }
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
            self.release(reservation).await;
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
            self.release(reservation).await;
        }
    }

    async fn release(&self, reservation: Reservation) {
        let prepare = &reservation.prepare;
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

    pub(super) fn hops(&self) -> Result<Vec<HopRecord>, String> {
        self.store().list(HOPS)
    }

    fn hop(&self, operation_id: &OperationId) -> Result<Option<HopRecord>, String> {
        self.store().get(HOPS, operation_id.as_str())
    }

    pub(super) fn save_hop(&self, hop: &HopRecord) -> Result<(), String> {
        self.store().put(HOPS, hop.operation_id.as_str(), hop)
    }

    /// Hops left mid-funding by a crash cannot be resumed: whether the
    /// outgoing HTLC exists is unknown, and funding it again could pay
    /// twice.
    pub(super) fn fail_interrupted_hops(&self) -> Result<(), String> {
        for mut hop in self.hops()? {
            if hop.state == HopState::Funding {
                error!(
                    "hop {} was interrupted while funding its outgoing HTLC on {}; \
                     check that wallet for a lock to {:?}",
                    hop.prepare.payment_hash, hop.prepare.outgoing_network, hop.prepare,
                );
                hop.state = HopState::Failed("interrupted while funding".into());
                self.save_hop(&hop)?;
            }
        }
        Ok(())
    }
}
