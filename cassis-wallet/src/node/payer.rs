//! Payer role: route, PREPARE, fund, EXECUTE, COMMIT.

use super::{Node, db_error};
use crate::db::{Direction, PendingPayment, PendingPaymentHash, Transaction, TransactionHash};
use cassis_core::network::{Htlc, HtlcRequest, NetworkId};
use cassis_core::offline::endpoint_public_key;
use cassis_core::protocol::{
    Commit, Discard, Execute, FailReason, Invoice, Prepare, PreparePayee, Request, Response, Settle,
};
use cassis_core::routing::{self, HopId, RouteAnnouncement, RoutePlan};
use cassis_core::transport::PeerAddr;
use cassis_core::{Bytes32, OperationId, XOnlyPubKey, unix_now};
use futures::future::join_all;
use std::collections::HashSet;
use std::time::Duration;
use tracing::{info, warn};

/// How often a pending EXECUTE or COMMIT is asked again.
const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Routes [`Node::pay_retrying`] tries by default.
pub const DEFAULT_MAX_ROUTES: usize = 3;

/// What came of an attempt to [`Node::pay`] an invoice.
#[derive(Clone, Debug)]
pub struct PayReport {
    /// The route attempted: empty when the payment was direct or was
    /// already paid.
    pub route: Vec<RouteAnnouncement>,
    /// The preimage, or what went wrong.
    pub outcome: Result<Bytes32, PayFailure>,
}

/// Why a payment attempt failed, once it had a route.
#[derive(Clone, Debug)]
pub struct PayFailure {
    /// The step of the attempt that failed.
    pub phase: PayPhase,
    /// What happened, with a note on what stays locked, if anything.
    pub message: String,
    /// The hop the attempt failed at, when a hop is to blame.
    pub hop: Option<FailedHop>,
}

/// The steps of a payment attempt, in order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PayPhase {
    /// Hops and the payee were asked to reserve: nothing is funded
    /// yet, so another route can be tried.
    Prepare,
    /// Funding the first HTLC failed: nothing stays locked.
    Fund,
    /// A hop failed to forward: the HTLCs up to it stay locked, and
    /// claimable with the preimage, until they expire.
    Execute,
    /// The payee did not claim: every HTLC stays locked until it
    /// expires.
    Commit,
}

/// A hop of the route that failed the payment.
#[derive(Clone, Debug)]
pub struct FailedHop {
    /// Position in the route, from 0.
    pub index: usize,
    /// Router to skip to route around the hop (see [`Node::pay`]).
    pub node: XOnlyPubKey,
    pub error: HopError,
}

/// How a hop failed.
#[derive(Clone, Debug)]
pub enum HopError {
    /// The hop did not accept PREPARE.
    PrepareRefused(String),
    /// The hop did not answer, or not as expected.
    Unresponsive(String),
    /// The hop gave up forwarding.
    Failed(FailReason),
}

impl std::fmt::Display for HopError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PrepareRefused(reason) => write!(f, "refused: {reason}"),
            Self::Unresponsive(error) => f.write_str(error),
            Self::Failed(reason) => reason.fmt(f),
        }
    }
}

impl PayReport {
    /// The preimage, or the failure's message.
    pub fn into_result(self) -> Result<Bytes32, String> {
        self.outcome.map_err(|failure| failure.message)
    }

    fn paid(route: Vec<RouteAnnouncement>, preimage: Bytes32) -> Self {
        Self {
            route,
            outcome: Ok(preimage),
        }
    }

    fn failed(
        phase: PayPhase,
        route: Vec<RouteAnnouncement>,
        message: String,
        hop: Option<FailedHop>,
    ) -> Self {
        Self {
            route,
            outcome: Err(PayFailure {
                phase,
                message,
                hop,
            }),
        }
    }
}

/// A way to pay an invoice, as [`Node::find_routes`] finds them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayRoute {
    /// The hops to the payee's network: none when it is paid directly.
    pub hops: Vec<RouteAnnouncement>,
    /// The network of the invoice the route ends at.
    pub network: NetworkId,
    /// The amounts and expiries of its legs, planned when it was found.
    pub plan: RoutePlan,
}

impl PayRoute {
    /// What paying over the route costs, fees included.
    pub fn cost_msat(&self) -> u64 {
        self.plan.amounts[0]
    }

    /// Whether the route pays `invoice` from `from`.
    fn check(&self, invoice: &Invoice, from: &NetworkId) -> Result<(), String> {
        if invoice.target_for(&self.network).is_none() {
            return Err(format!("the invoice does not accept {}", self.network));
        }
        let mut at = from;
        for hop in &self.hops {
            if hop.from != *at {
                return Err(format!(
                    "the route does not lead from {from} to {}",
                    self.network
                ));
            }
            at = &hop.to;
        }
        if *at != self.network {
            return Err(format!(
                "the route does not lead from {from} to {}",
                self.network
            ));
        }
        let routers: HashSet<_> = self.hops.iter().map(|hop| hop.node_pubkey).collect();
        if routers.len() != self.hops.len() {
            // A router can only hold one hop per payment hash.
            return Err("the route passes the same router twice".into());
        }
        Ok(())
    }
}

/// The direct way to pay `invoice`, when it accepts `from`.
fn direct_route(invoice: &Invoice, from: &NetworkId) -> Result<Option<PayRoute>, String> {
    if invoice.target_for(from).is_none() {
        return Ok(None);
    }
    let plan = routing::plan_route(
        &[],
        invoice.body.amount_msat,
        invoice.incoming_delta_for(from),
        unix_now(),
    )?;
    Ok(Some(PayRoute {
        hops: Vec::new(),
        network: from.clone(),
        plan,
    }))
}

/// The `n` cheapest routes over `announcements` from `from` to any
/// network of `invoice`, cheapest first. `Err` when there is none.
fn invoice_routes(
    invoice: &Invoice,
    from: &NetworkId,
    announcements: &[RouteAnnouncement],
    n: usize,
    skip_hops: &HashSet<HopId>,
    skip_routers: &HashSet<XOnlyPubKey>,
) -> Result<Vec<PayRoute>, String> {
    let amount_msat = invoice.body.amount_msat;
    let mut routes = Vec::new();
    // Why no route was found to each network, or could not be planned.
    let mut errors = Vec::new();
    for entry in &invoice.body.networks {
        let network = entry.target.network();
        let found = match routing::find_routes(
            announcements,
            from,
            network,
            amount_msat,
            n,
            skip_hops,
            skip_routers,
        ) {
            Ok(found) => found,
            Err(error) => {
                errors.push(error);
                continue;
            }
        };
        for hops in found {
            let delta = invoice.incoming_delta_for(network);
            match routing::plan_route(&hops, amount_msat, delta, unix_now()) {
                Ok(plan) => routes.push(PayRoute {
                    hops,
                    network: network.clone(),
                    plan,
                }),
                Err(error) => errors.push(format!("route to {network}: {error}")),
            }
        }
    }
    routes.sort_by_key(PayRoute::cost_msat);
    routes.truncate(n);
    if routes.is_empty() && n > 0 {
        return Err(match errors.as_slice() {
            [error] => error.clone(),
            _ => format!("no route from {from} to any network of the invoice"),
        });
    }
    Ok(routes)
}

impl Node {
    /// [`Node::pay`] over up to `max_routes` routes: when an attempt
    /// fails at PREPARE because of a hop, the next one routes around
    /// that hop's router. A failure after PREPARE ends the payment: its
    /// HTLCs stay locked, and claimable with the preimage, so paying
    /// again under the same payment hash could pay twice.
    ///
    /// The report is the last attempt's.
    pub async fn pay_retrying(
        &self,
        invoice: &Invoice,
        from: &NetworkId,
        relays: &[String],
        max_routes: usize,
    ) -> Result<PayReport, String> {
        if let Some(paid) = self.check_payable(invoice)? {
            return Ok(paid);
        }
        if let Some(direct) = direct_route(invoice, from)? {
            return self.pay_with_route(invoice, from, &direct).await;
        }
        // Every attempt routes over the same announcements.
        let announcements = routing::fetch_announcements(relays).await?;
        let mut skip = HashSet::new();
        let mut last: Option<PayReport> = None;
        for attempt in 1..=max_routes.max(1) {
            let report =
                match invoice_routes(invoice, from, &announcements, 1, &HashSet::new(), &skip) {
                    Ok(routes) => self.pay_with_route(invoice, from, &routes[0]).await,
                    Err(error) => Err(error),
                };
            let report = match report {
                Ok(report) => report,
                // Typically no route is left once failed hops are
                // skipped: the last failure says more.
                Err(error) => {
                    return match last {
                        Some(report) => {
                            warn!("attempt {attempt} could not start: {error}");
                            Ok(report)
                        }
                        None => Err(error),
                    };
                }
            };
            let node = match &report.outcome {
                Err(PayFailure {
                    phase: PayPhase::Prepare,
                    hop: Some(hop),
                    message,
                }) => {
                    warn!(
                        "attempt {attempt} failed: {message}; routing around {}",
                        hop.node.to_hex()
                    );
                    hop.node
                }
                _ => return Ok(report),
            };
            skip.insert(node);
            last = Some(report);
        }
        Ok(last.expect("at least one attempt ran"))
    }

    /// Pay `invoice` from this node's `from` network over the cheapest
    /// of [`Node::find_routes`], skipping the routers in `skip`: a
    /// caller whose attempt failed at a hop retries with that hop's
    /// [`FailedHop::node`] added. See [`Node::pay_with_route`].
    pub async fn pay(
        &self,
        invoice: &Invoice,
        from: &NetworkId,
        relays: &[String],
        skip: &HashSet<XOnlyPubKey>,
    ) -> Result<PayReport, String> {
        if let Some(paid) = self.check_payable(invoice)? {
            return Ok(paid);
        }
        let routes = self
            .find_routes(invoice, from, relays, 1, &HashSet::new(), skip)
            .await?;
        self.pay_with_route(invoice, from, &routes[0]).await
    }

    /// The `n` cheapest ways to pay `invoice` from this node's `from`
    /// network, cheapest first: the direct one alone when the invoice
    /// accepts `from`, else routes through the routers announced on
    /// `relays` to any network it accepts. Hops in `skip_hops` and every
    /// hop of the routers in `skip_routers` are left out (see
    /// [`routing::find_routes`]).
    ///
    /// `Err` when there is none, saying why.
    pub async fn find_routes(
        &self,
        invoice: &Invoice,
        from: &NetworkId,
        relays: &[String],
        n: usize,
        skip_hops: &HashSet<HopId>,
        skip_routers: &HashSet<XOnlyPubKey>,
    ) -> Result<Vec<PayRoute>, String> {
        if let Some(direct) = direct_route(invoice, from)? {
            return Ok(vec![direct]);
        }
        let announcements = routing::fetch_announcements(relays).await?;
        invoice_routes(invoice, from, &announcements, n, skip_hops, skip_routers)
    }

    /// Pay `invoice` from this node's `from` network over `route`, as
    /// [`Node::find_routes`] found it. Its legs are planned again from
    /// now, so the route can be paid a while after it was found.
    ///
    /// `Err` is a payment that could not start. Otherwise the report
    /// holds the route attempted and the preimage, or what failed.
    ///
    /// Once the first HTLC is funded the payment is journaled as a
    /// [`PendingPayment`]: if the payment fails afterwards, a serving
    /// node refunds it after its expiry. Once claimed it is an outgoing
    /// [`Transaction`].
    ///
    /// Hops and the payee may wait for their incoming HTLC to become
    /// final (to confirm, on Bitcoin), so this can take as long as the
    /// route's timelocks allow.
    pub async fn pay_with_route(
        &self,
        invoice: &Invoice,
        from: &NetworkId,
        route: &PayRoute,
    ) -> Result<PayReport, String> {
        let hash = invoice.body.payment_hash;
        let _busy = self
            .busy(format!("pay:{hash}"))
            .ok_or("this invoice is already being paid")?;
        if let Some(paid) = self.check_payable(invoice)? {
            return Ok(paid);
        }
        route.check(invoice, from)?;
        let funder = self.funder(from);
        let sender = match funder {
            Some(_) => None,
            None => Some(self.network(from)?),
        };
        let (route, payee_network) = (route.hops.clone(), route.network.clone());
        let payee_target = invoice
            .target_for(&payee_network)
            .cloned()
            .ok_or("invoice has no target for the chosen network")?;
        // PREPARE and COMMIT go to the gateway when there is one: it is
        // paid in the payee's place.
        let endpoint = invoice.receiver.iroh_peer_id();
        let payee = PeerAddr {
            id: *endpoint,
            relay: invoice.body.iroh_relay.clone(),
        };
        let plan = routing::plan_route(
            &route,
            invoice.body.amount_msat,
            invoice.incoming_delta_for(&payee_network),
            unix_now(),
        )?;
        // Routers and the payee check the other legs at PREPARE.
        if let Some(sender) = &sender {
            sender
                .check_htlc_amount(plan.amounts[0])
                .map_err(|e| format!("cannot send on {from}: {e}"))?;
        }
        // Hop `i` of the route, as the report names it.
        let failed_hop = |i: usize, error: HopError| FailedHop {
            index: i,
            node: route[i].node_pubkey,
            error,
        };
        let hops: Vec<Hop> = route
            .iter()
            .enumerate()
            .map(|(i, announcement)| {
                let id = announcement.iroh_peer_id.trim().parse().map_err(|e| {
                    format!("hop {} peer id {}: {e}", i + 1, announcement.iroh_peer_id)
                })?;
                Ok(Hop {
                    peer: PeerAddr {
                        id,
                        relay: announcement.iroh_relay.clone(),
                    },
                    prepare: Prepare {
                        payment_hash: hash,
                        operation_id: OperationId::random(),
                        amount_msat: plan.amounts[i],
                        outgoing_amount_msat: plan.amounts[i + 1],
                        incoming_network: announcement.from.clone(),
                        outgoing_network: announcement.to.clone(),
                        incoming_expiry: plan.expiries[i],
                        outgoing_expiry: plan.expiries[i + 1],
                    },
                })
            })
            .collect::<Result<_, String>>()?;
        info!(
            "paying {} msat ({} msat with fees) from {from} to {payee_network} over {} hop(s)",
            invoice.body.amount_msat,
            plan.amounts[0],
            hops.len()
        );

        // PREPARE every hop, and the payee, at once. All replies are
        // awaited, so every hop that might hold a reservation is known
        // when aborting.
        let payee_prepare = Request::PreparePayee(PreparePayee {
            payment_hash: hash,
            network: payee_network.clone(),
            expiry: plan.expiries[hops.len()],
            metadata: invoice.body.metadata.clone(),
        });
        let (replies, payee_reply) = futures::join!(
            join_all(hops.iter().map(|hop| async move {
                let prepare = Request::Prepare(hop.prepare.clone());
                self.0.transport.request(&hop.peer, &prepare).await
            })),
            self.0.transport.request(&payee, &payee_prepare),
        );
        let mut targets = Vec::with_capacity(hops.len() + 1);
        for (i, reply) in replies.into_iter().enumerate() {
            match reply {
                Ok(Response::Prepared(Ok(target))) => targets.push(target),
                Ok(Response::Prepared(Err(reason))) => {
                    self.discard_hops(&hops).await;
                    return Ok(PayReport::failed(
                        PayPhase::Prepare,
                        route.clone(),
                        format!("hop {} refused: {reason}", i + 1),
                        Some(failed_hop(i, HopError::PrepareRefused(reason))),
                    ));
                }
                other => {
                    self.discard_hops(&hops).await;
                    let error = unexpected(other);
                    return Ok(PayReport::failed(
                        PayPhase::Prepare,
                        route.clone(),
                        format!("hop {}: {error}", i + 1),
                        Some(failed_hop(i, HopError::Unresponsive(error))),
                    ));
                }
            }
        }
        match payee_reply {
            Ok(Response::PayeePrepared(Ok(()))) => {}
            Ok(Response::PayeePrepared(Err(reason))) => {
                self.discard_hops(&hops).await;
                return Ok(PayReport::failed(
                    PayPhase::Prepare,
                    route,
                    format!("payee refused: {reason}"),
                    None,
                ));
            }
            other => {
                self.discard_hops(&hops).await;
                return Ok(PayReport::failed(
                    PayPhase::Prepare,
                    route,
                    format!("payee: {}", unexpected(other)),
                    None,
                ));
            }
        }
        targets.push(payee_target);

        let funded = match (&funder, &sender) {
            (Some(funder), _) => {
                funder
                    .fund(&HtlcRequest {
                        payment_hash: hash,
                        amount_msat: plan.amounts[0],
                        expiry: plan.expiries[0],
                        target: targets[0].clone(),
                    })
                    .await
            }
            (None, Some(sender)) => {
                sender
                    .create_outgoing_htlc(hash, plan.amounts[0], plan.expiries[0], &targets[0])
                    .await
            }
            (None, None) => unreachable!("a network or a funder was chosen"),
        };
        let first = match funded {
            Ok(descriptor) => Htlc {
                payment_hash: hash,
                amount_msat: plan.amounts[0],
                expiry: plan.expiries[0],
                descriptor,
            },
            Err(error) => {
                self.discard_hops(&hops).await;
                return Ok(PayReport::failed(
                    PayPhase::Fund,
                    route,
                    format!("cannot fund the first HTLC on {from}: {error}"),
                    None,
                ));
            }
        };
        self.db()
            .pending_payments()
            .insert(&PendingPayment {
                payment_hash: PendingPaymentHash(hash.0),
                network: from.0.clone(),
                htlc: (&first).into(),
                created_at: unix_now(),
            })
            .map_err(db_error)?;
        let locked = |reason: String| {
            format!(
                "{reason}; {} msat stay locked on {from} until {} and are refunded by a \
                 serving node after that",
                first.amount_msat, first.expiry
            )
        };

        let mut descriptor = first.descriptor.clone();
        for (i, hop) in hops.iter().enumerate() {
            let execute = Execute {
                payment_hash: hash,
                operation_id: hop.prepare.operation_id,
                incoming_descriptor: descriptor,
                outgoing_target: targets[i + 1].clone(),
            };
            descriptor = match self
                .request_until_done(
                    &hop.peer,
                    &Request::Execute(execute),
                    hop.prepare.outgoing_expiry,
                )
                .await
            {
                Ok(Response::Executed(next)) => next,
                other => {
                    self.discard_hops(&hops[i..]).await;
                    let error = match other {
                        Ok(Response::HopFailed(reason)) => HopError::Failed(reason),
                        other => HopError::Unresponsive(unexpected(other)),
                    };
                    return Ok(PayReport::failed(
                        PayPhase::Execute,
                        route.clone(),
                        locked(format!("hop {} failed: {error}", i + 1)),
                        Some(failed_hop(i, error)),
                    ));
                }
            };
        }

        let commit = Commit {
            payment_hash: hash,
            network: payee_network,
            expiry: plan.expiries[hops.len()],
            descriptor,
            metadata: invoice.body.metadata.clone(),
        };
        let deadline = commit.expiry;
        let preimage = match self
            .request_until_done(&payee, &Request::Commit(commit), deadline)
            .await
        {
            Ok(Response::Committed(preimage)) if hash.matches_preimage(&preimage) => preimage,
            Ok(Response::Committed(_)) => {
                return Ok(PayReport::failed(
                    PayPhase::Commit,
                    route,
                    locked("payee answered with a wrong preimage".into()),
                    None,
                ));
            }
            other => {
                return Ok(PayReport::failed(
                    PayPhase::Commit,
                    route,
                    locked(format!("payee did not claim: {}", unexpected(other))),
                    None,
                ));
            }
        };
        self.complete_payment(hash, from, &first, preimage)?;
        info!("paid {}: preimage {preimage}", hash.short());

        // Let every hop claim right away instead of waiting to observe
        // the preimage downstream.
        join_all(hops.iter().map(|hop| {
            let settle = Request::Settle(Settle {
                operation_id: hop.prepare.operation_id,
                preimage,
            });
            async move {
                if let Err(error) = self.0.transport.request(&hop.peer, &settle).await {
                    warn!("could not tell a hop the preimage: {error}");
                }
            }
        }))
        .await;
        Ok(PayReport::paid(route, preimage))
    }

    /// Turn the pending payment of `htlc` on `network` into an outgoing
    /// transaction: the payee claimed it with `preimage`.
    pub(super) fn complete_payment(
        &self,
        hash: Bytes32,
        network: &NetworkId,
        htlc: &Htlc,
        preimage: Bytes32,
    ) -> Result<(), String> {
        self.db()
            .write(|tx| {
                tx.pending_payments().delete(PendingPaymentHash(hash.0))?;
                tx.transactions().insert(&Transaction {
                    payment_hash: TransactionHash(hash.0),
                    direction: Direction::Outgoing,
                    amount_msat: htlc.amount_msat,
                    network: network.0.clone(),
                    preimage: preimage.0,
                    at: unix_now(),
                })
            })
            .map_err(db_error)
    }

    /// Whether `invoice` can be paid by this wallet: `Some` report when
    /// it already paid it.
    fn check_payable(&self, invoice: &Invoice) -> Result<Option<PayReport>, String> {
        let hash = invoice.body.payment_hash;
        invoice.verify()?;
        // The payee and payer journals both key on the payment hash, so
        // a wallet cannot be both ends of one payment: claiming would
        // record the incoming transaction only after the outgoing one was
        // already journaled, or the other way around.
        if invoice.receiver.payee() == &endpoint_public_key(&self.keys().iroh) {
            return Err("this wallet issued the invoice and cannot pay itself".into());
        }
        if invoice.body.amount_msat == 0 {
            return Err("invoice amount is zero".into());
        }
        if invoice.body.expires_at <= unix_now() {
            return Err("invoice expired".into());
        }
        if let Some(previous) = self
            .db()
            .transactions()
            .get(TransactionHash(hash.0))
            .map_err(db_error)?
        {
            return match previous.direction {
                Direction::Outgoing => Ok(Some(PayReport::paid(
                    Vec::new(),
                    Bytes32(previous.preimage),
                ))),
                Direction::Incoming => Err("this wallet was paid this invoice".into()),
            };
        }
        if let Some(previous) = self
            .db()
            .pending_payments()
            .get(PendingPaymentHash(hash.0))
            .map_err(db_error)?
        {
            return Err(format!(
                "an earlier attempt is still locked until {}",
                previous.htlc.expiry
            ));
        }
        Ok(None)
    }

    /// Send `request` to `peer` again and again while it answers
    /// [`Response::Pending`], until `deadline` (unix seconds). Once the
    /// peer has accepted the request, connection failures are retried
    /// too: the work goes on without us.
    async fn request_until_done(
        &self,
        peer: &PeerAddr,
        request: &Request,
        deadline: u64,
    ) -> Result<Response, String> {
        let mut accepted = false;
        loop {
            match self.0.transport.request(peer, request).await {
                Ok(Response::Pending) => accepted = true,
                Err(error) if accepted => warn!("asking {} again: {error}", peer.id),
                other => return other,
            }
            if unix_now() >= deadline {
                return Err("still pending at its deadline".into());
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }

    async fn discard_hops(&self, hops: &[Hop]) {
        join_all(hops.iter().map(|hop| {
            let discard = Request::Discard(Discard {
                payment_hash: hop.prepare.payment_hash,
                operation_id: hop.prepare.operation_id,
            });
            async move {
                let _ = self.0.transport.request(&hop.peer, &discard).await;
            }
        }))
        .await;
    }
}

struct Hop {
    peer: PeerAddr,
    prepare: Prepare,
}

/// Human-readable account of a reply that was not the expected one.
fn unexpected(reply: Result<Response, String>) -> String {
    match reply {
        Ok(Response::Error(error)) | Err(error) => error,
        Ok(other) => format!("unexpected answer {other:?}"),
    }
}
