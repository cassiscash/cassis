//! Payer role: route, PREPARE, fund, EXECUTE, COMMIT.

use super::{Node, PaymentRecord, PaymentStatus, PAYMENTS};
use crate::network::{Htlc, NetworkId};
use crate::primitives::{unix_now, Bytes32, OperationId};
use crate::protocol::{Commit, Discard, Execute, Invoice, Prepare, Request, Response, Settle};
use crate::routing::{self, RouteAnnouncement};
use crate::transport::PeerAddr;
use futures::future::join_all;
use std::time::Duration;
use tracing::{info, warn};

/// How often a pending EXECUTE or COMMIT is asked again.
const POLL_INTERVAL: Duration = Duration::from_secs(5);

impl Node {
    /// Pay `invoice` from this node's `from` network, routing through
    /// routers announced on `relays` when the invoice is not payable on
    /// `from` directly. Returns the preimage.
    ///
    /// Once the first HTLC is funded the payment is journaled: if the
    /// payment fails afterwards, a serving node refunds it after its
    /// expiry.
    ///
    /// Hops and the payee may wait for their incoming HTLC to become
    /// final (to confirm, on Bitcoin), so this can take as long as the
    /// route's timelocks allow.
    pub async fn pay(
        &self,
        invoice: &Invoice,
        from: &NetworkId,
        relays: &[String],
    ) -> Result<Bytes32, String> {
        let hash = invoice.payment_hash;
        let _busy = self
            .busy(format!("pay:{hash}"))
            .ok_or("this invoice is already being paid")?;
        if invoice.amount_msat == 0 {
            return Err("invoice amount is zero".into());
        }
        if invoice.expires_at <= unix_now() {
            return Err("invoice expired".into());
        }
        if let Some(previous) = self
            .store()
            .get::<PaymentRecord>(PAYMENTS, &hash.to_string())?
        {
            match previous.status {
                PaymentStatus::Completed => {
                    return previous
                        .preimage
                        .ok_or("completed payment without preimage".into())
                }
                PaymentStatus::Pending => {
                    return Err(format!(
                        "an earlier attempt is still locked until {}",
                        previous.htlc.expiry
                    ))
                }
                PaymentStatus::Refunded => {}
            }
        }
        let sender = self.network(from)?;
        let (route, payee_network) = self.choose_route(invoice, from, relays).await?;
        let payee_target = invoice
            .target_for(&payee_network)
            .cloned()
            .ok_or("invoice has no target for the chosen network")?;
        let payee = PeerAddr {
            id: invoice
                .iroh_peer_id
                .clone()
                .ok_or("invoice does not name the payee's endpoint")?,
            relay: invoice.iroh_relay.clone(),
        };
        let plan = routing::plan_route(
            &route,
            invoice.amount_msat,
            invoice.incoming_delta_for(&payee_network),
            unix_now(),
        )?;
        let hops: Vec<Hop> = route
            .iter()
            .enumerate()
            .map(|(i, announcement)| Hop {
                peer: PeerAddr {
                    id: announcement.iroh_peer_id.clone(),
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
            .collect();
        info!(
            "paying {} msat ({} msat with fees) from {from} to {payee_network} over {} hop(s)",
            invoice.amount_msat,
            plan.amounts[0],
            hops.len()
        );

        // PREPARE every hop at once. All replies are awaited, so every
        // hop that might hold a reservation is known when aborting.
        let replies = join_all(hops.iter().map(|hop| async move {
            let prepare = Request::Prepare(hop.prepare.clone());
            self.0.transport.request(&hop.peer, &prepare).await
        }))
        .await;
        let mut targets = Vec::with_capacity(hops.len() + 1);
        for (i, reply) in replies.into_iter().enumerate() {
            match reply {
                Ok(Response::Prepared(Ok(target))) => targets.push(target),
                Ok(Response::Prepared(Err(reason))) => {
                    self.discard_hops(&hops).await;
                    return Err(format!("hop {} refused: {reason}", i + 1));
                }
                other => {
                    self.discard_hops(&hops).await;
                    return Err(format!("hop {}: {}", i + 1, unexpected(other)));
                }
            }
        }
        targets.push(payee_target);

        let first = match sender
            .create_outgoing_htlc(hash, plan.amounts[0], plan.expiries[0], &targets[0])
            .await
        {
            Ok(descriptor) => Htlc {
                payment_hash: hash,
                amount_msat: plan.amounts[0],
                expiry: plan.expiries[0],
                target: targets[0].clone(),
                descriptor,
            },
            Err(error) => {
                self.discard_hops(&hops).await;
                return Err(format!("cannot fund the first HTLC on {from}: {error}"));
            }
        };
        let mut record = PaymentRecord {
            invoice: invoice.clone(),
            network: from.clone(),
            htlc: first.clone(),
            status: PaymentStatus::Pending,
            preimage: None,
            created_at: unix_now(),
        };
        self.store().put(PAYMENTS, &hash.to_string(), &record)?;
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
                operation_id: hop.prepare.operation_id.clone(),
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
                    return Err(locked(format!(
                        "hop {} failed: {}",
                        i + 1,
                        unexpected(other)
                    )));
                }
            };
        }

        let commit = Commit {
            payment_hash: hash,
            network: payee_network,
            expiry: plan.expiries[hops.len()],
            descriptor,
        };
        let deadline = commit.expiry;
        let preimage = match self
            .request_until_done(&payee, &Request::Commit(commit), deadline)
            .await
        {
            Ok(Response::Committed(preimage)) if hash.matches_preimage(&preimage) => preimage,
            Ok(Response::Committed(_)) => {
                return Err(locked("payee answered with a wrong preimage".into()))
            }
            other => {
                return Err(locked(format!(
                    "payee did not claim: {}",
                    unexpected(other)
                )))
            }
        };
        record.status = PaymentStatus::Completed;
        record.preimage = Some(preimage);
        self.store().put(PAYMENTS, &hash.to_string(), &record)?;
        info!("paid {}: preimage {preimage}", hash.short());

        // Let every hop claim right away instead of waiting to observe
        // the preimage downstream.
        join_all(hops.iter().map(|hop| {
            let settle = Request::Settle(Settle {
                operation_id: hop.prepare.operation_id.clone(),
                preimage,
            });
            async move {
                if let Err(error) = self.0.transport.request(&hop.peer, &settle).await {
                    warn!("could not tell a hop the preimage: {error}");
                }
            }
        }))
        .await;
        Ok(preimage)
    }

    /// The invoice network to pay and the route there: direct when the
    /// invoice accepts `from`, else the cheapest announced route to any
    /// network it accepts.
    async fn choose_route(
        &self,
        invoice: &Invoice,
        from: &NetworkId,
        relays: &[String],
    ) -> Result<(Vec<RouteAnnouncement>, NetworkId), String> {
        if invoice.target_for(from).is_some() {
            return Ok((Vec::new(), from.clone()));
        }
        let announcements = routing::fetch_announcements(relays).await?;
        invoice
            .networks
            .iter()
            .filter_map(|entry| {
                let route =
                    routing::find_route(&announcements, from, &entry.network, invoice.amount_msat)
                        .ok()?;
                let cost = routing::plan_route(&route, invoice.amount_msat, 0, 0)
                    .ok()?
                    .amounts[0];
                Some((cost, route, entry.network.clone()))
            })
            .min_by_key(|(cost, _, _)| *cost)
            .map(|(_, route, network)| (route, network))
            .ok_or_else(|| format!("no route from {from} to any network of the invoice"))
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
                operation_id: hop.prepare.operation_id.clone(),
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
