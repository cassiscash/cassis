//! Router role: PREPARE / EXECUTE / DISCARD / SETTLE handling and route
//! announcements, on the networks and endpoint of a wallet
//! [`Node`](cassis_wallet::Node).
//!
//! Every hop is journaled in the router's [`Db`] once EXECUTEd, and a
//! settlement loop drives each to its end: claim the incoming HTLC once
//! the preimage shows up downstream, refund the outgoing one once it
//! expires.

use crate::db::{Db, Hop, HopId, HopState};
use cassis_core::network::{Htlc, InvoiceTarget, Network, NetworkId};
use cassis_core::protocol::{Discard, Execute, FailReason, Prepare, Request, Response, Settle};
use cassis_core::routing::{self, RouteAnnouncement};
use cassis_core::transport::Handler;
use cassis_core::{unix_now, Bytes32, OperationId};
use cassis_wallet::node::{settle_outgoing, verify_incoming, Outcome, Unverified, INLINE_WAIT};
use cassis_wallet::stored::StoredFailReason;
use cassis_wallet::Node;
use iroh_base::PublicKey;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tracing::{error, info, warn};

/// How long a PREPARE reservation waits for its EXECUTE.
const RESERVATION_TTL_SECS: u64 = 600;
/// Announcements are republished well within
/// [`routing::ANNOUNCEMENT_MAX_AGE_SECS`].
const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(3 * 60 * 60);
const SETTLE_INTERVAL: Duration = Duration::from_secs(10);

/// Optional PREPARE veto: a rejection reason, or `None` to proceed.
pub type PrepareVeto = Arc<dyn Fn(&Prepare) -> Option<String> + Send + Sync>;

/// One directed hop this node offers: receive on `from`, send on `to`,
/// under its own terms and announced on its own relays.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteOffer {
    pub from: NetworkId,
    pub to: NetworkId,
    pub fee_base_msat: u64,
    pub fee_ppm: u64,
    /// Seconds the hop requires and announces between its outgoing and
    /// its incoming expiry, instead of [`RouteOffer::incoming_delta_secs`]'s
    /// default.
    pub incoming_delta_secs: Option<u64>,
    pub nostr_relays: Vec<String>,
    /// Mark the announcement as test money ([`routing::TEST_MONEY_TAG`]).
    pub test_money: bool,
}

impl RouteOffer {
    /// The incoming delta the hop requires and announces: the configured
    /// one, else what `incoming` and `to` need (see [`hop_delta_secs`]).
    fn incoming_delta_secs(&self, incoming: &dyn Network) -> u64 {
        self.incoming_delta_secs
            .unwrap_or_else(|| hop_delta_secs(incoming, &self.to))
    }

    /// `from -> to` at the default fees, on the default relays.
    pub fn new(from: NetworkId, to: NetworkId) -> Self {
        Self {
            fee_base_msat: from.default_base_fee_msat(),
            from,
            to,
            fee_ppm: 500,
            incoming_delta_secs: None,
            nostr_relays: routing::DEFAULT_NOSTR_RELAYS
                .iter()
                .map(|relay| relay.to_string())
                .collect(),
            test_money: false,
        }
    }
}

/// Terms this node routes under.
#[derive(Clone)]
pub struct RoutingPolicy {
    /// The only hops this node forwards and announces.
    pub routes: Vec<RouteOffer>,
    /// Relays to delete this node's announcements from when they are not
    /// offered there (anymore), on top of every route's relays.
    pub cleanup_relays: Vec<String>,
    /// Most PREPARE reservations held at once.
    pub max_reservations: usize,
    /// Longest an incoming HTLC may run from its PREPARE: how long a
    /// hop that never settles can keep this node's funds locked.
    pub max_htlc_secs: u64,
    /// Runs after the built-in checks, before anything is reserved.
    pub prepare_veto: Option<PrepareVeto>,
}

impl Default for RoutingPolicy {
    fn default() -> Self {
        Self {
            routes: Vec::new(),
            cleanup_relays: Vec::new(),
            max_reservations: 100,
            max_htlc_secs: 3 * 24 * 60 * 60,
            prepare_veto: None,
        }
    }
}

impl RoutingPolicy {
    fn route(&self, from: &NetworkId, to: &NetworkId) -> Option<&RouteOffer> {
        self.routes
            .iter()
            .find(|route| route.from == *from && route.to == *to)
    }
}

/// Seconds a hop needs between its outgoing and its incoming expiry: the
/// outgoing HTLC can still be claimed for a while after its expiry (see
/// [`NetworkId::outgoing_lag_secs`]), and the incoming one must then
/// still take the claim.
fn hop_delta_secs(incoming: &dyn Network, outgoing: &NetworkId) -> u64 {
    incoming
        .incoming_delta_secs()
        .saturating_add(outgoing.outgoing_lag_secs())
}

/// A PREPARE waiting for its EXECUTE.
struct Reservation {
    prepare: Prepare,
    owner: PublicKey,
    /// What the payer locks to; `None` while the networks are asked.
    target: Option<InvoiceTarget>,
    expires_at: u64,
}

/// Handle to a router. Cheap to clone.
#[derive(Clone)]
pub struct Router(Arc<Inner>);

struct Inner {
    node: Node,
    db: Arc<Db>,
    routing: RwLock<Option<RoutingPolicy>>,
    reservations: tokio::sync::Mutex<HashMap<OperationId, Reservation>>,
}

impl Router {
    /// Route on `node`, which must serve: answer its hop requests, resume
    /// the hops journaled in `db`, and settle them in the background.
    pub fn start(node: Node, db: Arc<Db>) -> Result<Self, String> {
        let router = Self(Arc::new(Inner {
            node,
            db,
            routing: RwLock::new(None),
            reservations: Default::default(),
        }));
        router.resume()?;
        let handling = router.clone();
        let handler: Handler = Arc::new(move |request, peer| {
            let router = handling.clone();
            Box::pin(async move { router.handle(request, peer).await })
        });
        router.node().route_with(handler);
        router.node().spawn(router.clone().settle_loop());
        Ok(router)
    }

    pub fn node(&self) -> &Node {
        &self.0.node
    }

    pub fn db(&self) -> &Db {
        &self.0.db
    }

    async fn handle(&self, request: Request, peer: PublicKey) -> Response {
        match request {
            Request::Prepare(prepare) => Response::Prepared(self.prepare(prepare, peer).await),
            Request::Execute(execute) => self.execute(execute, peer).await,
            Request::Discard(discard) => {
                self.discard(discard, peer).await;
                Response::Discarded
            }
            Request::Settle(settle) => {
                self.settle_hop(settle, peer).await;
                Response::Settled
            }
            _ => Response::Error("not a hop request".into()),
        }
    }

    /// Start routing the hops `policy` offers: accept PREPAREs for them,
    /// keep their announcements published, and delete this node's
    /// announcements of anything else.
    pub fn start_routing(&self, policy: RoutingPolicy) {
        self.set_routing(policy);
        let router = self.clone();
        self.node().spawn(async move {
            loop {
                router.announce().await;
                tokio::time::sleep(ANNOUNCE_INTERVAL).await;
            }
        });
    }

    /// Replace the policy routed under since [`Router::start_routing`],
    /// announced at the next interval or [`Router::announce`].
    pub fn set_routing(&self, policy: RoutingPolicy) {
        *self.0.routing.write().unwrap_or_else(|e| e.into_inner()) = Some(policy);
    }

    /// Publish `name` as this node's profile on `relays`: see
    /// [`routing::publish_name`].
    pub async fn publish_name(&self, relays: &[String], name: Option<&str>) -> usize {
        routing::publish_name(relays, &self.node().keys().node, name).await
    }

    fn routing(&self) -> Option<RoutingPolicy> {
        self.0
            .routing
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Publish the announcements of the hops routed now, and delete
    /// this node's others from every relay that has them, as
    /// [`Router::start_routing`] does every interval.
    pub async fn announce(&self) {
        let Some(policy) = self.routing() else {
            return;
        };
        let node = self.node();
        let relay = node.transport().home_relay().await;
        // What each relay should keep from this node, by `d` tag.
        let mut wanted: HashMap<String, HashSet<String>> = policy
            .cleanup_relays
            .iter()
            .map(|relay| (relay.clone(), HashSet::new()))
            .collect();
        for route in &policy.routes {
            let d_tag = routing::route_d_tag(&route.from, &route.to);
            for nostr_relay in &route.nostr_relays {
                wanted
                    .entry(nostr_relay.clone())
                    .or_default()
                    .insert(d_tag.clone());
            }
            let (Ok(incoming), Ok(outgoing)) = (node.network(&route.from), node.network(&route.to))
            else {
                warn!(
                    "not announcing {d_tag}: {} or {} is not open",
                    route.from, route.to
                );
                continue;
            };
            let announcement = RouteAnnouncement {
                node_pubkey: node.node_pubkey(),
                iroh_peer_id: node.iroh_peer_id(),
                iroh_relay: relay.clone(),
                from: route.from.clone(),
                to: route.to.clone(),
                fee_base_msat: route.fee_base_msat,
                fee_ppm: route.fee_ppm,
                incoming_delta_secs: route.incoming_delta_secs(incoming.as_ref()),
                min_htlc_msat: incoming.min_htlc_msat().max(outgoing.min_htlc_msat()),
                test_money: route.test_money,
            };
            for (d_tag, accepted) in routing::publish_announcements(
                &route.nostr_relays,
                &node.keys().node,
                &[announcement],
            )
            .await
            {
                info!(
                    "announced {d_tag} to {accepted}/{} relay(s)",
                    route.nostr_relays.len()
                );
            }
        }
        for (nostr_relay, keep) in &wanted {
            let stale: Vec<String> =
                match routing::fetch_own_routes(nostr_relay, node.node_pubkey()).await {
                    Ok(found) => found.into_iter().filter(|d| !keep.contains(d)).collect(),
                    Err(error) => {
                        warn!("listing own announcements: {error}");
                        continue;
                    }
                };
            if stale.is_empty() {
                continue;
            }
            let accepted = routing::delete_announcements(
                std::slice::from_ref(nostr_relay),
                &node.keys().node,
                &stale,
            )
            .await;
            if accepted > 0 {
                info!("deleted {} from {nostr_relay}", stale.join(", "));
            } else {
                warn!("{nostr_relay} refused to delete {}", stale.join(", "));
            }
        }
    }

    async fn prepare(&self, prepare: Prepare, peer: PublicKey) -> Result<InvoiceTarget, String> {
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

    async fn reserve(&self, prepare: &Prepare, peer: PublicKey) -> Result<InvoiceTarget, String> {
        let policy = self.routing().ok_or("this node does not route")?;
        let incoming = self.node().network(&prepare.incoming_network)?;
        let outgoing = self.node().network(&prepare.outgoing_network)?;
        let now = unix_now();
        if prepare.payment_hash.0 == [0; 32] {
            return Err("zero payment hash".into());
        }
        if prepare.incoming_network == prepare.outgoing_network {
            return Err("incoming and outgoing network are the same".into());
        }
        if prepare.outgoing_amount_msat == 0 || prepare.outgoing_amount_msat > prepare.amount_msat {
            return Err("outgoing amount must be positive and at most the incoming amount".into());
        }
        let route = policy
            .route(&prepare.incoming_network, &prepare.outgoing_network)
            .ok_or_else(|| {
                format!(
                    "this node does not route {} -> {}",
                    prepare.incoming_network, prepare.outgoing_network
                )
            })?;
        let fee = routing::fee_msat(
            route.fee_base_msat,
            route.fee_ppm,
            prepare.outgoing_amount_msat,
        );
        if prepare.amount_msat - prepare.outgoing_amount_msat < fee {
            return Err(format!("fee below the announced {fee} msat"));
        }
        if prepare.outgoing_expiry <= now {
            return Err("outgoing expiry is in the past".into());
        }
        // Worst case the downstream claims as late as the outgoing
        // network lets it; the incoming network must still have time to
        // take our claim.
        let delta = route.incoming_delta_secs(incoming.as_ref());
        if prepare.incoming_expiry < prepare.outgoing_expiry.saturating_add(delta) {
            return Err(format!(
                "incoming expiry must be at least {delta}s after the outgoing expiry"
            ));
        }
        if prepare.incoming_expiry > now.saturating_add(policy.max_htlc_secs) {
            return Err(format!(
                "incoming expiry must be within {}s",
                policy.max_htlc_secs
            ));
        }
        if let Some(reason) = policy.prepare_veto.as_ref().and_then(|veto| veto(prepare)) {
            return Err(reason);
        }

        // Reserve first, then ask the networks without holding up the
        // other hops.
        let promised = {
            let mut reservations = self.0.reservations.lock().await;
            if let Some(existing) = reservations.get(&prepare.operation_id) {
                return match &existing.target {
                    Some(target) if existing.owner == peer && existing.prepare == *prepare => {
                        Ok(target.clone())
                    }
                    None if existing.owner == peer && existing.prepare == *prepare => {
                        Err("still preparing: ask again".into())
                    }
                    _ => Err("operation id already in use".into()),
                };
            }
            if reservations.len() >= policy.max_reservations {
                return Err("too many pending reservations".into());
            }
            let in_flight = self.db().hops().by_in_flight(true).map_err(db_error)?;
            let hash_in_use = reservations
                .values()
                .any(|reservation| reservation.prepare.payment_hash == prepare.payment_hash)
                || in_flight
                    .iter()
                    .any(|hop| hop.payment_hash == prepare.payment_hash.0);
            if hash_in_use {
                return Err("payment hash already has an active attempt here".into());
            }
            // What other hops are about to send on the outgoing network.
            let promised: u64 = reservations
                .values()
                .filter(|reservation| {
                    reservation.prepare.outgoing_network == prepare.outgoing_network
                })
                .map(|reservation| reservation.prepare.outgoing_amount_msat)
                .chain(
                    in_flight
                        .iter()
                        .filter(|hop| {
                            matches!(hop.state, HopState::Verifying | HopState::Funding)
                                && hop.outgoing_network == prepare.outgoing_network.0
                        })
                        .map(|hop| hop.outgoing_amount_msat),
                )
                .fold(0, u64::saturating_add);
            reservations.insert(
                prepare.operation_id,
                Reservation {
                    prepare: prepare.clone(),
                    owner: peer,
                    target: None,
                    expires_at: now + RESERVATION_TTL_SECS,
                },
            );
            promised
        };
        let asked = async {
            outgoing
                .check_htlc_amount(prepare.outgoing_amount_msat)
                .map_err(|e| format!("cannot send on {}: {e}", prepare.outgoing_network))?;
            incoming
                .check_htlc_amount(prepare.amount_msat)
                .map_err(|e| format!("cannot receive on {}: {e}", prepare.incoming_network))?;
            outgoing
                .can_send(prepare.outgoing_amount_msat.saturating_add(promised))
                .await
                .map_err(|e| format!("cannot send on {}: {e}", prepare.outgoing_network))?;
            incoming
                .can_receive(prepare.amount_msat)
                .await
                .map_err(|e| format!("cannot receive on {}: {e}", prepare.incoming_network))?;
            incoming
                .receive_target(
                    prepare.payment_hash,
                    prepare.amount_msat,
                    prepare.incoming_expiry,
                )
                .await
                .map_err(|e| format!("cannot receive on {}: {e}", prepare.incoming_network))
        }
        .await;
        let mut reservations = self.0.reservations.lock().await;
        match asked {
            Ok(target) => match reservations.get_mut(&prepare.operation_id) {
                Some(reservation) => {
                    reservation.target = Some(target.clone());
                    Ok(target)
                }
                // Discarded meanwhile.
                None => {
                    drop(reservations);
                    self.release(&prepare.incoming_network, prepare.payment_hash)
                        .await;
                    Err("discarded while preparing".into())
                }
            },
            Err(error) => {
                reservations.remove(&prepare.operation_id);
                Err(error)
            }
        }
    }

    /// Start forwarding a prepared hop, or report on one already
    /// started: [`Response::Executed`] once the outgoing HTLC is funded,
    /// [`Response::Pending`] while the incoming one is not final yet.
    async fn execute(&self, execute: Execute, peer: PublicKey) -> Response {
        let known = match self.hop(&execute.operation_id) {
            Ok(hop) => hop.is_some(),
            Err(error) => return Response::Error(error),
        };
        if !known {
            if let Err(error) = self.start_hop(execute.clone(), peer).await {
                return Response::Error(error);
            }
        }
        // Answer right away when forwarding is quick.
        let deadline = tokio::time::Instant::now() + INLINE_WAIT;
        loop {
            let response = match self.hop(&execute.operation_id) {
                Ok(Some(hop))
                    if hop.owner != *peer.as_bytes()
                        || hop.payment_hash != execute.payment_hash.0 =>
                {
                    Response::Error("operation belongs to another payment".into())
                }
                Ok(Some(hop)) => report(&hop),
                Ok(None) => Response::Error("no matching PREPARE".into()),
                Err(error) => Response::Error(error),
            };
            if !matches!(response, Response::Pending) || tokio::time::Instant::now() >= deadline {
                return response;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    fn hop(&self, operation_id: &OperationId) -> Result<Option<Hop>, String> {
        self.db()
            .hops()
            .get(HopId(operation_id.0))
            .map_err(db_error)
    }

    /// Turn the reservation of `execute` into a journaled hop and
    /// forward it in the background.
    async fn start_hop(&self, execute: Execute, peer: PublicKey) -> Result<(), String> {
        let (prepare, target) = {
            let mut reservations = self.0.reservations.lock().await;
            match reservations.get(&execute.operation_id) {
                Some(reservation)
                    if reservation.owner == peer
                        && reservation.prepare.payment_hash == execute.payment_hash
                        && reservation.target.is_some() => {}
                _ => return Err("no matching PREPARE".into()),
            }
            let reservation = reservations
                .remove(&execute.operation_id)
                .expect("checked above");
            (
                reservation.prepare,
                reservation.target.expect("checked above"),
            )
        };
        let checked = if prepare.outgoing_expiry <= unix_now() {
            Err("outgoing expiry passed before EXECUTE")
        } else if !execute.incoming_descriptor.pays(&target) {
            Err("the incoming HTLC does not pay the PREPARE answer")
        } else if *execute.outgoing_target.network() != prepare.outgoing_network {
            Err("EXECUTE pays on another network than its PREPARE")
        } else {
            Ok(())
        };
        if let Err(error) = checked {
            self.release(&prepare.incoming_network, prepare.payment_hash)
                .await;
            return Err(error.into());
        }
        let hop = Hop {
            operation_id: HopId(execute.operation_id.0),
            owner: *peer.as_bytes(),
            payment_hash: prepare.payment_hash.0,
            incoming_network: prepare.incoming_network.0.clone(),
            incoming: (&Htlc {
                payment_hash: prepare.payment_hash,
                amount_msat: prepare.amount_msat,
                expiry: prepare.incoming_expiry,
                descriptor: execute.incoming_descriptor,
            })
                .into(),
            outgoing_network: prepare.outgoing_network.0.clone(),
            outgoing_amount_msat: prepare.outgoing_amount_msat,
            outgoing_expiry: prepare.outgoing_expiry,
            outgoing_target: (&execute.outgoing_target).into(),
            outgoing: None,
            preimage: None,
            state: HopState::Verifying,
            created_at: unix_now(),
            ended_at: None,
        };
        self.db().hops().insert(&hop).map_err(db_error)?;
        self.node().spawn(self.clone().forward(hop));
        Ok(())
    }

    /// Wait for the incoming HTLC of a hop to verify, then fund its
    /// outgoing HTLC.
    async fn forward(self, mut hop: Hop) {
        let Some(_busy) = self
            .node()
            .busy(format!("hop:{}", OperationId(hop.operation_id.0)))
        else {
            return;
        };
        let hash = short(&hop.payment_hash);
        let (incoming, outgoing) = match (
            self.node()
                .network(&NetworkId(hop.incoming_network.clone())),
            self.node()
                .network(&NetworkId(hop.outgoing_network.clone())),
        ) {
            (Ok(incoming), Ok(outgoing)) => (incoming, outgoing),
            (Err(error), _) | (_, Err(error)) => {
                warn!("EXECUTE {hash} failed: {error}");
                return self.fail(&hop, FailReason::NetworkUnavailable, true).await;
            }
        };
        let htlc = match Htlc::try_from(&hop.incoming) {
            Ok(htlc) => htlc,
            Err(error) => {
                error!("hop {}: {error}", OperationId(hop.operation_id.0));
                return;
            }
        };
        if let Err(error) =
            verify_incoming(incoming.as_ref(), &htlc, hop.outgoing_expiry, "EXECUTE").await
        {
            warn!("EXECUTE {hash} failed: {error}");
            let reason = match error {
                Unverified::Rejected(_) => FailReason::IncomingRejected,
                Unverified::TimedOut(_) => FailReason::ExpiredWhileVerifying,
            };
            return self.fail(&hop, reason, true).await;
        }
        if hop.outgoing_expiry <= unix_now() {
            warn!("EXECUTE {hash} failed: outgoing expiry passed while verifying");
            return self
                .fail(&hop, FailReason::ExpiredWhileVerifying, true)
                .await;
        }

        let network = outgoing.id();
        let target = match InvoiceTarget::try_from(&hop.outgoing_target) {
            Ok(target) => target,
            Err(error) => {
                error!("hop {}: {error}", OperationId(hop.operation_id.0));
                return self
                    .fail(&hop, FailReason::InvalidOutgoingTarget, true)
                    .await;
            }
        };
        let sent = |descriptor| Htlc {
            payment_hash: htlc.payment_hash,
            amount_msat: hop.outgoing_amount_msat,
            expiry: hop.outgoing_expiry,
            descriptor,
        };
        // Where the network can tell the HTLC before funding it, it is
        // journaled first: a restart then finds it (see `resume`).
        hop.outgoing = outgoing
            .outgoing_descriptor(
                htlc.payment_hash,
                hop.outgoing_amount_msat,
                hop.outgoing_expiry,
                &target,
            )
            .map(|descriptor| (&sent(descriptor)).into());
        hop.state = HopState::Funding;
        if let Err(error) = self.db().hops().update(&hop) {
            warn!("EXECUTE {hash} failed: journaling: {error}");
            return self.fail(&hop, FailReason::JournalingFailed, true).await;
        }
        let funded = outgoing
            .create_outgoing_htlc(
                htlc.payment_hash,
                hop.outgoing_amount_msat,
                hop.outgoing_expiry,
                &target,
            )
            .await;
        match funded {
            Ok(descriptor) => {
                let sent = sent(descriptor);
                hop.outgoing = Some((&sent).into());
                hop.state = HopState::Forwarded;
                if let Err(error) = self.db().hops().update(&hop) {
                    error!(
                        "journaling forwarded hop {}: {error}; check {network} for a lock to \
                         {sent:?}",
                        OperationId(hop.operation_id.0)
                    );
                }
                info!(
                    "EXECUTE {hash}: forwarded {} msat {} -> {network}",
                    hop.outgoing_amount_msat, hop.incoming_network
                );
            }
            Err(error) => {
                warn!("EXECUTE {hash}: cannot fund on {network}: {error}");
                self.fail(
                    &hop,
                    FailReason::OutgoingFundingRefused(error.to_string()),
                    false,
                )
                .await;
            }
        }
    }

    /// End `hop` with `reason`, releasing what its incoming network set
    /// up to receive it if `release`.
    async fn fail(&self, hop: &Hop, reason: FailReason, release: bool) {
        if release {
            self.release(
                &NetworkId(hop.incoming_network.clone()),
                Bytes32(hop.payment_hash),
            )
            .await;
        }
        self.end(
            hop,
            HopState::Failed {
                reason: (&reason).into(),
            },
        );
    }

    /// Journal `hop` as over, in `state`.
    fn end(&self, hop: &Hop, state: HopState) {
        let ended = Hop {
            state,
            ended_at: Some(unix_now()),
            ..hop.clone()
        };
        if let Err(error) = self.db().hops().update(&ended) {
            error!(
                "journaling ended hop {}: {error}",
                OperationId(hop.operation_id.0)
            );
        }
    }

    async fn discard(&self, discard: Discard, peer: PublicKey) {
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
            let prepare = reservation.prepare;
            self.release(&prepare.incoming_network, prepare.payment_hash)
                .await;
        }
    }

    /// The payer reveals the preimage of an executed hop.
    async fn settle_hop(&self, settle: Settle, peer: PublicKey) {
        let id = settle.operation_id;
        let Some(_busy) = self.node().busy(format!("hop:{id}")) else {
            return;
        };
        let Ok(Some(mut hop)) = self.hop(&settle.operation_id) else {
            return;
        };
        let matches = Bytes32(hop.payment_hash).matches_preimage(&settle.preimage);
        if hop.state != HopState::Forwarded || hop.owner != *peer.as_bytes() || !matches {
            return;
        }
        hop.preimage = Some(settle.preimage.0);
        if let Err(error) = self.db().hops().update(&hop) {
            warn!("saving hop {id}: {error}");
        }
        self.claim(&hop).await;
    }

    /// Drop reservations whose EXECUTE never came.
    async fn expire_reservations(&self) {
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
            let prepare = reservation.prepare;
            self.release(&prepare.incoming_network, prepare.payment_hash)
                .await;
        }
    }

    /// Release what `network` set up to receive `payment_hash`.
    async fn release(&self, network: &NetworkId, payment_hash: Bytes32) {
        if let Ok(opened) = self.node().network(network) {
            if let Err(error) = opened.cancel_receive(payment_hash).await {
                warn!(
                    "releasing reservation {} on {network}: {error}",
                    payment_hash.short()
                );
            }
        }
    }

    /// The hops in flight through `id`, which need it to settle.
    pub fn in_flight(&self, id: &NetworkId) -> usize {
        match self.db().hops().by_in_flight(true) {
            Ok(hops) => hops
                .iter()
                .filter(|hop| hop.incoming_network == id.0 || hop.outgoing_network == id.0)
                .count(),
            // Unable to tell: do not let go of the network.
            Err(_) => 1,
        }
    }

    /// After a restart: go on waiting for hops still verifying, and
    /// settle those interrupted while funding an outgoing HTLC that was
    /// journaled first, as if it was funded: it refunds like one that
    /// was. The others left mid-funding cannot be resumed, and fail:
    /// whether their outgoing HTLC exists is unknown, and funding it
    /// again could pay twice.
    fn resume(&self) -> Result<(), String> {
        for mut hop in self.db().hops().by_in_flight(true).map_err(db_error)? {
            match hop.state {
                HopState::Verifying => self.node().spawn(self.clone().forward(hop)),
                HopState::Funding if hop.outgoing.is_some() => {
                    warn!(
                        "hop {} was interrupted while funding its outgoing HTLC on {}: \
                         settling it as funded",
                        OperationId(hop.operation_id.0),
                        hop.outgoing_network,
                    );
                    hop.state = HopState::Forwarded;
                    self.db().hops().update(&hop).map_err(db_error)?;
                }
                HopState::Funding => {
                    error!(
                        "hop {} was interrupted while funding its outgoing HTLC on {}; check \
                         that wallet for a lock of {} msat for {} until {}",
                        OperationId(hop.operation_id.0),
                        hop.outgoing_network,
                        hop.outgoing_amount_msat,
                        Bytes32(hop.payment_hash),
                        hop.outgoing_expiry,
                    );
                    self.end(
                        &hop,
                        HopState::Failed {
                            reason: StoredFailReason::InterruptedWhileFunding,
                        },
                    );
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Every tick, each forwarded hop advances in a task of its own: one
    /// stuck on its network does not hold up the others, and is skipped
    /// while it is.
    async fn settle_loop(self) {
        let mut ticker = tokio::time::interval(SETTLE_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            self.expire_reservations().await;
            for id in self.forwarded() {
                let router = self.clone();
                self.node().spawn(async move { router.advance(id).await });
            }
        }
    }

    /// One pass over the hops in flight: expired reservations, and
    /// forwarded hops whose outgoing HTLC may be claimed or refundable.
    pub async fn settle_once(&self) {
        self.expire_reservations().await;
        futures::future::join_all(self.forwarded().into_iter().map(|id| self.advance(id))).await;
    }

    /// The hops whose outgoing HTLC is funded.
    fn forwarded(&self) -> Vec<HopId> {
        match self.db().hops().by_in_flight(true) {
            Ok(hops) => hops
                .into_iter()
                .filter(|hop| hop.state == HopState::Forwarded)
                .map(|hop| hop.operation_id)
                .collect(),
            Err(error) => {
                warn!("listing hops: {error}");
                Vec::new()
            }
        }
    }

    async fn advance(&self, id: HopId) {
        let Some(_busy) = self.node().busy(format!("hop:{}", OperationId(id.0))) else {
            return;
        };
        // The listing may be stale: a SETTLE could have ended it since.
        let Ok(Some(mut hop)) = self.db().hops().get(id.clone()) else {
            return;
        };
        if hop.state != HopState::Forwarded {
            return;
        }
        let (Ok(network), Some(Ok(htlc))) = (
            self.node()
                .network(&NetworkId(hop.outgoing_network.clone())),
            hop.outgoing.as_ref().map(Htlc::try_from),
        ) else {
            return;
        };
        if hop.preimage.is_none() {
            match settle_outgoing(network.as_ref(), &htlc).await {
                Outcome::Pending => return,
                Outcome::Claimed(preimage) => {
                    info!(
                        "{} claimed downstream on {}",
                        short(&hop.payment_hash),
                        hop.outgoing_network
                    );
                    hop.preimage = Some(preimage.0);
                    if let Err(error) = self.db().hops().update(&hop) {
                        warn!("saving hop {}: {error}", OperationId(id.0));
                    }
                }
                Outcome::Refunded => {
                    return self.fail(&hop, FailReason::PreimageNotReceived, true).await
                }
            }
        }
        self.claim(&hop).await;
    }

    /// Claim the incoming HTLC of a hop whose preimage is known.
    async fn claim(&self, hop: &Hop) {
        let Some(preimage) = hop.preimage.map(Bytes32) else {
            return;
        };
        let hash = short(&hop.payment_hash);
        let (Ok(network), Ok(htlc)) = (
            self.node()
                .network(&NetworkId(hop.incoming_network.clone())),
            Htlc::try_from(&hop.incoming),
        ) else {
            return;
        };
        match network.claim_incoming_htlc(&htlc, preimage).await {
            Ok(()) => {
                info!("{hash} settled: earned {} msat", hop.fee_msat());
                self.end(hop, HopState::Settled);
            }
            Err(claim_error) if unix_now() >= htlc.expiry => {
                error!(
                    "{hash} could not be claimed on {} before it expired: {claim_error}",
                    hop.incoming_network
                );
                self.fail(hop, FailReason::ClaimFailed, false).await;
            }
            Err(claim_error) => warn!(
                "claiming {hash} on {}: {claim_error}; retrying",
                hop.incoming_network
            ),
        }
    }
}

/// What EXECUTE answers about `hop`.
fn report(hop: &Hop) -> Response {
    match &hop.state {
        HopState::Verifying | HopState::Funding => Response::Pending,
        HopState::Forwarded | HopState::Settled => match &hop.outgoing {
            Some(outgoing) => Htlc::try_from(outgoing)
                .map(|htlc| Response::Executed(htlc.descriptor))
                .unwrap_or_else(Response::Error),
            None => Response::Error("the forwarded HTLC is missing".into()),
        },
        HopState::Failed { reason } => Response::HopFailed(FailReason::from(reason)),
    }
}

fn short(hash: &[u8; 32]) -> String {
    Bytes32(*hash).short()
}

fn db_error(error: orangedb::Error) -> String {
    format!("database: {error}")
}
