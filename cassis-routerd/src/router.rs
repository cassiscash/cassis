//! Router role: PREPARE / EXECUTE / DISCARD / SETTLE handling and route
//! announcements, on the networks and endpoint of a wallet
//! [`Node`](cassis_wallet::Node).
//!
//! Every hop is journaled in the router's [`Db`] once EXECUTEd, and a
//! settlement loop drives each to its end: claim the incoming HTLC once
//! the preimage shows up downstream, refund the outgoing one once it
//! expires.

use crate::db::{
    Db, Fail, FailId, FailReason, Forward, ForwardId, HopId, Incoming, IncomingState, Outgoing,
    OutgoingId,
};
use cassis_core::network::{Htlc, InvoiceTarget, NetworkError, NetworkId};
use cassis_core::protocol::{Discard, Execute, Prepare, Request, Response, Settle};
use cassis_core::routing::{self, RouteAnnouncement, DEFAULT_TRANSIT_SLACK_SECS};
use cassis_core::transport::Handler;
use cassis_core::{unix_now, Bytes32, OperationId};
use cassis_wallet::node::{settle_outgoing, Outcome, INLINE_WAIT, VERIFY_RETRY_INTERVAL};
use cassis_wallet::Node;
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
    pub transit_slack_secs: u64,
    pub nostr_relays: Vec<String>,
    /// Mark the announcement as test money ([`routing::TEST_MONEY_TAG`]).
    pub test_money: bool,
}

impl RouteOffer {
    /// `from -> to` at the default fees, on the default relays.
    pub fn new(from: NetworkId, to: NetworkId) -> Self {
        Self {
            from,
            to,
            fee_base_msat: 1000,
            fee_ppm: 500,
            transit_slack_secs: DEFAULT_TRANSIT_SLACK_SECS,
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
    /// Runs after the built-in checks, before anything is reserved.
    pub prepare_veto: Option<PrepareVeto>,
}

impl Default for RoutingPolicy {
    fn default() -> Self {
        Self {
            routes: Vec::new(),
            cleanup_relays: Vec::new(),
            max_reservations: 100,
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

/// A PREPARE waiting for its EXECUTE.
struct Reservation {
    prepare: Prepare,
    owner: String,
    target: InvoiceTarget,
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

    async fn handle(&self, request: Request, peer: String) -> Response {
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
            let (Ok(incoming), Ok(_)) = (node.network(&route.from), node.network(&route.to)) else {
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
                incoming_delta_secs: incoming.incoming_delta_secs(),
                transit_slack_secs: route.transit_slack_secs,
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

    async fn prepare(&self, prepare: Prepare, peer: String) -> Result<InvoiceTarget, String> {
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

    async fn reserve(&self, prepare: &Prepare, peer: String) -> Result<InvoiceTarget, String> {
        let policy = self.routing().ok_or("this node does not route")?;
        let incoming = self.node().network(&prepare.incoming_network)?;
        let outgoing = self.node().network(&prepare.outgoing_network)?;
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
            || !self
                .db()
                .incomings()
                .ids_by_payment_hash(prepare.payment_hash.to_string())
                .map_err(db_error)?
                .is_empty();
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
    async fn execute(&self, execute: Execute, peer: String) -> Response {
        let known = match self.hop(&execute.operation_id) {
            Ok(hop) => hop.is_some(),
            Err(error) => return Response::Error(error),
        };
        if !known {
            if let Err(error) = self.start_hop(execute.clone(), peer.clone()).await {
                return Response::Error(error);
            }
        }
        // Answer right away when forwarding is quick.
        let deadline = tokio::time::Instant::now() + INLINE_WAIT;
        loop {
            let response = match self.hop(&execute.operation_id) {
                Ok(Some(hop)) if hop.owner != peer || hop.payment_hash != execute.payment_hash => {
                    Response::Error("operation belongs to another payment".into())
                }
                Ok(Some(hop)) => hop.response,
                Ok(None) => Response::Error("no matching PREPARE".into()),
                Err(error) => Response::Error(error),
            };
            if !matches!(response, Response::Pending) || tokio::time::Instant::now() >= deadline {
                return response;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// What EXECUTE answers about the hop `operation_id`, wherever it is.
    fn hop(&self, operation_id: &OperationId) -> Result<Option<HopReport>, String> {
        let id = operation_id.as_str().to_string();
        let found = self
            .db()
            .read(|tx| {
                if let Some(incoming) = tx.incomings().get(HopId(id.clone()))? {
                    let outgoing = tx.outgoings().get(OutgoingId(id.clone()))?;
                    return Ok(Some((
                        incoming.owner,
                        incoming.payment_hash,
                        Found::InFlight(outgoing.map(|outgoing| outgoing.htlc)),
                    )));
                }
                if let Some(forward) = tx.forwards().get(ForwardId(id.clone()))? {
                    return Ok(Some((
                        forward.owner,
                        forward.payment_hash,
                        Found::Forwarded(forward.outgoing),
                    )));
                }
                let fail = tx.fails().get(FailId(id.clone()))?;
                Ok::<_, orangedb::Error>(
                    fail.map(|fail| (fail.owner, fail.payment_hash, Found::Failed(fail.reason))),
                )
            })
            .map_err(db_error)?;
        let Some((owner, payment_hash, found)) = found else {
            return Ok(None);
        };
        let response = match found {
            Found::InFlight(None) => Response::Pending,
            Found::InFlight(Some(htlc)) | Found::Forwarded(htlc) => Htlc::try_from(&htlc)
                .map(|htlc| Response::Executed(htlc.descriptor))
                .unwrap_or_else(Response::Error),
            Found::Failed(reason) => Response::Error(reason.describe().into()),
        };
        Ok(Some(HopReport {
            owner,
            payment_hash: payment_hash
                .parse()
                .map_err(|_| "stored payment hash is invalid".to_string())?,
            response,
        }))
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
        if !execute.incoming_descriptor.pays(&reservation.target) {
            return Err("the incoming HTLC does not pay the PREPARE answer".into());
        }
        if *execute.outgoing_target.network() != prepare.outgoing_network {
            return Err("EXECUTE pays on another network than its PREPARE".into());
        }
        let incoming = Incoming {
            operation_id: HopId(execute.operation_id.as_str().to_string()),
            owner: peer,
            payment_hash: prepare.payment_hash.to_string(),
            network: prepare.incoming_network.0.clone(),
            htlc: (&Htlc {
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
            state: IncomingState::Verifying,
            created_at: unix_now(),
        };
        self.db().incomings().insert(&incoming).map_err(db_error)?;
        self.node().spawn(self.clone().forward(incoming));
        Ok(())
    }

    /// Wait for the incoming HTLC of a hop to verify, then fund its
    /// outgoing HTLC.
    async fn forward(self, mut hop: Incoming) {
        let Some(_busy) = self.node().busy(format!("hop:{}", hop.operation_id.0)) else {
            return;
        };
        let hash = short(&hop.payment_hash);
        let (incoming, outgoing) = match (
            self.node().network(&NetworkId(hop.network.clone())),
            self.node()
                .network(&NetworkId(hop.outgoing_network.clone())),
        ) {
            (Ok(incoming), Ok(outgoing)) => (incoming, outgoing),
            (Err(error), _) | (_, Err(error)) => {
                warn!("EXECUTE {hash} failed: {error}");
                return self.fail(&hop, FailReason::NetworkUnavailable, true).await;
            }
        };
        let htlc = match Htlc::try_from(&hop.htlc) {
            Ok(htlc) => htlc,
            Err(error) => {
                error!("hop {}: {error}", hop.operation_id.0);
                return;
            }
        };
        let mut waiting = false;
        loop {
            match incoming.verify_incoming_htlc(&htlc).await {
                Ok(()) => break,
                Err(NetworkError::NotYet(reason)) if unix_now() < hop.outgoing_expiry => {
                    if !waiting {
                        info!("EXECUTE {hash}: waiting for the incoming HTLC: {reason}");
                        waiting = true;
                    }
                    tokio::time::sleep(VERIFY_RETRY_INTERVAL).await;
                }
                Err(error) => {
                    warn!("EXECUTE {hash} failed: incoming HTLC rejected: {error}");
                    return self.fail(&hop, FailReason::IncomingRejected, true).await;
                }
            }
        }
        if hop.outgoing_expiry <= unix_now() {
            warn!("EXECUTE {hash} failed: outgoing expiry passed while verifying");
            return self
                .fail(&hop, FailReason::ExpiredWhileVerifying, true)
                .await;
        }

        hop.state = IncomingState::Funding;
        if let Err(error) = self.db().incomings().update(&hop) {
            warn!("EXECUTE {hash} failed: journaling: {error}");
            return self.fail(&hop, FailReason::FundingFailed, true).await;
        }
        let network = outgoing.id();
        let target = match InvoiceTarget::try_from(&hop.outgoing_target) {
            Ok(target) => target,
            Err(error) => {
                error!("hop {}: {error}", hop.operation_id.0);
                return self.fail(&hop, FailReason::FundingFailed, true).await;
            }
        };
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
                let sent = Htlc {
                    payment_hash: htlc.payment_hash,
                    amount_msat: hop.outgoing_amount_msat,
                    expiry: hop.outgoing_expiry,
                    descriptor,
                };
                let forwarded = Incoming {
                    state: IncomingState::Forwarded,
                    ..hop.clone()
                };
                let journaled = self.db().write(|tx| {
                    tx.incomings().update(&forwarded)?;
                    tx.outgoings().insert(&Outgoing {
                        operation_id: OutgoingId(hop.operation_id.0.clone()),
                        incoming: hop.operation_id.clone(),
                        network: network.0.clone(),
                        htlc: (&sent).into(),
                        preimage: None,
                        funded_at: unix_now(),
                    })
                });
                if let Err(error) = journaled {
                    error!(
                        "journaling forwarded hop {}: {error}; check {network} for a lock to \
                         {sent:?}",
                        hop.operation_id.0
                    );
                }
                info!(
                    "EXECUTE {hash}: forwarded {} msat {} -> {network}",
                    hop.outgoing_amount_msat, hop.network
                );
            }
            Err(error) => {
                warn!("EXECUTE {hash}: cannot fund on {network}: {error}");
                self.fail(&hop, FailReason::FundingFailed, false).await;
            }
        }
    }

    /// End `hop` with `reason`, releasing what its incoming network set
    /// up to receive it if `release`.
    async fn fail(&self, hop: &Incoming, reason: FailReason, release: bool) {
        if release {
            if let Ok(hash) = hop.payment_hash.parse() {
                self.release(&NetworkId(hop.network.clone()), hash).await;
            }
        }
        let ended = self.db().write(|tx| {
            tx.incomings().delete(hop.operation_id.clone())?;
            tx.fails().insert(&Fail {
                operation_id: FailId(hop.operation_id.0.clone()),
                owner: hop.owner.clone(),
                payment_hash: hop.payment_hash.clone(),
                incoming_network: hop.network.clone(),
                amount_msat: hop.htlc.amount_msat,
                outgoing_network: hop.outgoing_network.clone(),
                reason,
                at: unix_now(),
            })
        });
        if let Err(error) = ended {
            error!("journaling failed hop {}: {error}", hop.operation_id.0);
        }
    }

    async fn discard(&self, discard: Discard, peer: String) {
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
    async fn settle_hop(&self, settle: Settle, peer: String) {
        let id = settle.operation_id.as_str().to_string();
        let Some(_busy) = self.node().busy(format!("hop:{id}")) else {
            return;
        };
        let Ok((Some(incoming), Some(outgoing))) = self.db().read(|tx| {
            Ok::<_, orangedb::Error>((
                tx.incomings().get(HopId(id.clone()))?,
                tx.outgoings().get(OutgoingId(id.clone()))?,
            ))
        }) else {
            return;
        };
        let matches = incoming
            .payment_hash
            .parse::<Bytes32>()
            .is_ok_and(|hash| hash.matches_preimage(&settle.preimage));
        if incoming.owner != peer || !matches {
            return;
        }
        let outgoing = Outgoing {
            preimage: Some(settle.preimage.0),
            ..outgoing
        };
        if let Err(error) = self.db().outgoings().update(&outgoing) {
            warn!("saving hop {id}: {error}");
        }
        self.claim(&incoming, &outgoing).await;
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
        match self.db().incomings().all() {
            Ok(hops) => hops
                .iter()
                .filter(|hop| hop.network == id.0 || hop.outgoing_network == id.0)
                .count(),
            // Unable to tell: do not let go of the network.
            Err(_) => 1,
        }
    }

    /// After a restart: go on waiting for hops still verifying, and
    /// fail hops left mid-funding, which cannot be resumed: whether
    /// their outgoing HTLC exists is unknown, and funding it again could
    /// pay twice.
    fn resume(&self) -> Result<(), String> {
        for hop in self.db().incomings().all().map_err(db_error)? {
            match hop.state {
                IncomingState::Verifying => self.node().spawn(self.clone().forward(hop)),
                IncomingState::Funding => {
                    error!(
                        "hop {} was interrupted while funding its outgoing HTLC on {}; check \
                         that wallet for a lock of {} msat for {} until {}",
                        hop.operation_id.0,
                        hop.outgoing_network,
                        hop.outgoing_amount_msat,
                        hop.payment_hash,
                        hop.outgoing_expiry,
                    );
                    let router = self.clone();
                    self.node().spawn(async move {
                        router
                            .fail(&hop, FailReason::InterruptedWhileFunding, false)
                            .await
                    });
                }
                IncomingState::Forwarded => {}
            }
        }
        Ok(())
    }

    async fn settle_loop(self) {
        let mut ticker = tokio::time::interval(SETTLE_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            self.settle_once().await;
        }
    }

    /// One pass over the hops in flight: expired reservations, and
    /// forwarded hops whose outgoing HTLC may be claimed or refundable.
    pub async fn settle_once(&self) {
        self.expire_reservations().await;
        match self.db().outgoings().all() {
            Ok(outgoings) => {
                for outgoing in outgoings {
                    self.advance(outgoing).await;
                }
            }
            Err(error) => warn!("listing hops: {error}"),
        }
    }

    async fn advance(&self, outgoing: Outgoing) {
        let id = outgoing.operation_id.0.clone();
        let Some(_busy) = self.node().busy(format!("hop:{id}")) else {
            return;
        };
        // The listing may be stale: a SETTLE could have ended it since.
        let Ok((Some(incoming), Some(mut outgoing))) = self.db().read(|tx| {
            Ok::<_, orangedb::Error>((
                tx.incomings().get(HopId(id.clone()))?,
                tx.outgoings().get(OutgoingId(id.clone()))?,
            ))
        }) else {
            return;
        };
        let (Ok(network), Ok(htlc)) = (
            self.node().network(&NetworkId(outgoing.network.clone())),
            Htlc::try_from(&outgoing.htlc),
        ) else {
            return;
        };
        if outgoing.preimage.is_none() {
            match settle_outgoing(network.as_ref(), &htlc).await {
                Outcome::Pending => return,
                Outcome::Claimed(preimage) => {
                    info!(
                        "{} claimed downstream on {}",
                        short(&incoming.payment_hash),
                        outgoing.network
                    );
                    outgoing.preimage = Some(preimage.0);
                    if let Err(error) = self.db().outgoings().update(&outgoing) {
                        warn!("saving hop {id}: {error}");
                    }
                }
                Outcome::Refunded => {
                    return self
                        .fail(&incoming, FailReason::PreimageNotReceived, true)
                        .await
                }
            }
        }
        self.claim(&incoming, &outgoing).await;
    }

    /// Claim the incoming HTLC of a hop whose preimage is known.
    async fn claim(&self, incoming: &Incoming, outgoing: &Outgoing) {
        let Some(preimage) = outgoing.preimage.map(Bytes32) else {
            return;
        };
        let hash = short(&incoming.payment_hash);
        let (Ok(network), Ok(htlc)) = (
            self.node().network(&NetworkId(incoming.network.clone())),
            Htlc::try_from(&incoming.htlc),
        ) else {
            return;
        };
        match network.claim_incoming_htlc(&htlc, preimage).await {
            Ok(()) => {
                let forward = Forward {
                    operation_id: ForwardId(incoming.operation_id.0.clone()),
                    owner: incoming.owner.clone(),
                    payment_hash: incoming.payment_hash.clone(),
                    incoming_network: incoming.network.clone(),
                    incoming_amount_msat: htlc.amount_msat,
                    outgoing_network: outgoing.network.clone(),
                    outgoing: outgoing.htlc.clone(),
                    settled_at: unix_now(),
                };
                info!("{hash} settled: earned {} msat", forward.fee_msat());
                let ended = self.db().write(|tx| {
                    tx.incomings().delete(incoming.operation_id.clone())?;
                    tx.forwards().insert(&forward)
                });
                if let Err(error) = ended {
                    error!(
                        "journaling settled hop {}: {error}",
                        incoming.operation_id.0
                    );
                }
            }
            Err(claim_error) if unix_now() >= htlc.expiry => {
                error!(
                    "{hash} could not be claimed on {} before it expired: {claim_error}",
                    incoming.network
                );
                self.fail(incoming, FailReason::ClaimFailed, false).await;
            }
            Err(claim_error) => warn!(
                "claiming {hash} on {}: {claim_error}; retrying",
                incoming.network
            ),
        }
    }
}

/// Where a hop is.
enum Found {
    /// In flight, with its outgoing HTLC once funded.
    InFlight(Option<cassis_wallet::stored::StoredHtlc>),
    Forwarded(cassis_wallet::stored::StoredHtlc),
    Failed(FailReason),
}

/// What EXECUTE answers about a hop, and who it belongs to.
struct HopReport {
    owner: String,
    payment_hash: Bytes32,
    response: Response,
}

fn short(hash: &str) -> String {
    hash.parse::<Bytes32>()
        .map(|hash| hash.short())
        .unwrap_or_else(|_| hash.to_string())
}

fn db_error(error: orangedb::Error) -> String {
    format!("database: {error}")
}
