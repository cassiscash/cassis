//! Payer role: route, PREPARE, fund, EXECUTE, COMMIT.

use super::{db_error, Node};
use crate::db::{Direction, PendingPayment, PendingPaymentHash, Transaction, TransactionHash};
use cassis_core::network::{Htlc, NetworkId};
use cassis_core::protocol::{
    Commit, Discard, Execute, Invoice, Prepare, PreparePayee, Request, Response, Settle,
};
use cassis_core::routing::{self, RouteAnnouncement};
use cassis_core::transport::PeerAddr;
use cassis_core::{unix_now, Bytes32, OperationId};
use futures::future::join_all;
use std::collections::HashSet;
use std::time::Duration;
use tracing::{info, warn};

/// How often a pending EXECUTE or COMMIT is asked again.
const POLL_INTERVAL: Duration = Duration::from_secs(5);

impl Node {
    /// Pay `invoice` from this node's `from` network, routing through
    /// routers announced on `relays` when the invoice is not payable on
    /// `from` directly. Returns the preimage.
    ///
    /// Once the first HTLC is funded the payment is journaled as a
    /// [`PendingPayment`]: if the payment fails afterwards, a serving
    /// node refunds it after its expiry. Once claimed it is an outgoing
    /// [`Transaction`].
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
        let hash = invoice.body.payment_hash;
        let _busy = self
            .busy(format!("pay:{hash}"))
            .ok_or("this invoice is already being paid")?;
        invoice.verify()?;
        if invoice.body.amount_msat == 0 {
            return Err("invoice amount is zero".into());
        }
        if invoice.body.expires_at <= unix_now() {
            return Err("invoice expired".into());
        }
        let key = hash.to_string();
        if let Some(previous) = self
            .db()
            .transactions()
            .get(TransactionHash(key.clone()))
            .map_err(db_error)?
        {
            return match previous.direction {
                Direction::Outgoing => Ok(Bytes32(previous.preimage)),
                Direction::Incoming => Err("this wallet was paid this invoice".into()),
            };
        }
        if let Some(previous) = self
            .db()
            .pending_payments()
            .get(PendingPaymentHash(key.clone()))
            .map_err(db_error)?
        {
            return Err(format!(
                "an earlier attempt is still locked until {}",
                previous.htlc.expiry
            ));
        }
        let sender = self.network(from)?;
        let (route, payee_network) = self.choose_route(invoice, from, relays).await?;
        let payee_target = invoice
            .target_for(&payee_network)
            .cloned()
            .ok_or("invoice has no target for the chosen network")?;
        // PREPARE and COMMIT go to the gateway when there is one: it is
        // paid in the payee's place.
        let endpoint = invoice.receiver.iroh_peer_id();
        let payee = PeerAddr {
            id: endpoint.to_string(),
            relay: invoice.body.iroh_relay.clone(),
        };
        let plan = routing::plan_route(
            &route,
            invoice.body.amount_msat,
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
                    return Err(format!("hop {} refused: {reason}", i + 1));
                }
                other => {
                    self.discard_hops(&hops).await;
                    return Err(format!("hop {}: {}", i + 1, unexpected(other)));
                }
            }
        }
        match payee_reply {
            Ok(Response::PayeePrepared(Ok(()))) => {}
            Ok(Response::PayeePrepared(Err(reason))) => {
                self.discard_hops(&hops).await;
                return Err(format!("payee refused: {reason}"));
            }
            other => {
                self.discard_hops(&hops).await;
                return Err(format!("payee: {}", unexpected(other)));
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
                descriptor,
            },
            Err(error) => {
                self.discard_hops(&hops).await;
                return Err(format!("cannot fund the first HTLC on {from}: {error}"));
            }
        };
        self.db()
            .pending_payments()
            .insert(&PendingPayment {
                payment_hash: PendingPaymentHash(key.clone()),
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
            metadata: invoice.body.metadata.clone(),
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
        self.complete_payment(&key, from, &first, preimage)?;
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

    /// Turn the pending payment of `htlc` on `network` into an outgoing
    /// transaction: the payee claimed it with `preimage`.
    pub(super) fn complete_payment(
        &self,
        key: &str,
        network: &NetworkId,
        htlc: &Htlc,
        preimage: Bytes32,
    ) -> Result<(), String> {
        self.db()
            .write(|tx| {
                tx.pending_payments()
                    .delete(PendingPaymentHash(key.to_string()))?;
                tx.transactions().insert(&Transaction {
                    payment_hash: TransactionHash(key.to_string()),
                    direction: Direction::Outgoing,
                    amount_msat: htlc.amount_msat,
                    network: network.0.clone(),
                    preimage: preimage.0,
                    at: unix_now(),
                    invoice: None,
                })
            })
            .map_err(db_error)
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
        // Why the last route found could not be planned, if any was.
        let mut unplannable = None;
        invoice
            .body
            .networks
            .iter()
            .filter_map(|entry| {
                let route = routing::find_route(
                    &announcements,
                    from,
                    entry.target.network(),
                    invoice.body.amount_msat,
                    &HashSet::new(),
                )
                .ok()?;
                // Fails when a leg runs longer than its receiver accepts.
                let plan = routing::plan_route(
                    &route,
                    invoice.body.amount_msat,
                    invoice.incoming_delta_for(entry.target.network()),
                    unix_now(),
                )
                .map_err(|error| {
                    unplannable = Some(format!("route to {}: {error}", entry.target.network()))
                })
                .ok()?;
                Some((plan.amounts[0], route, entry.target.network().clone()))
            })
            .min_by_key(|(cost, _, _)| *cost)
            .map(|(_, route, network)| (route, network))
            .ok_or_else(|| {
                unplannable.unwrap_or_else(|| {
                    format!("no route from {from} to any network of the invoice")
                })
            })
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
