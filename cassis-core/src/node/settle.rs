//! Settlement: drive every journaled HTLC to its end.

use super::{
    HopRecord, HopState, InvoiceRecord, InvoiceStatus, Node, PaymentRecord, PaymentStatus,
    INVOICES, PAYMENTS,
};
use crate::network::{Htlc, Network, OutgoingState};
use crate::primitives::unix_now;
use std::time::Duration;
use tracing::{error, info, warn};

const SETTLE_INTERVAL: Duration = Duration::from_secs(10);

/// What became of an outgoing HTLC this round.
enum Outcome {
    Pending,
    Claimed(crate::primitives::Bytes32),
    Refunded,
}

impl Node {
    pub(super) async fn settle_loop(self) {
        let mut ticker = tokio::time::interval(SETTLE_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            self.settle_once().await;
        }
    }

    /// One pass over everything in flight: expired reservations,
    /// forwarded hops, own payments and expired invoices.
    pub async fn settle_once(&self) {
        self.expire_reservations().await;
        match self.hops() {
            Ok(hops) => {
                for hop in hops {
                    if hop.state == HopState::Forwarded {
                        self.advance_hop(hop).await;
                    }
                }
            }
            Err(error) => warn!("listing hops: {error}"),
        }
        match self.store().list::<PaymentRecord>(PAYMENTS) {
            Ok(payments) => {
                for payment in payments {
                    if payment.status == PaymentStatus::Pending {
                        self.advance_payment(payment).await;
                    }
                }
            }
            Err(error) => warn!("listing payments: {error}"),
        }
        match self.store().list::<InvoiceRecord>(INVOICES) {
            Ok(invoices) => {
                for mut record in invoices {
                    if record.status == InvoiceStatus::Pending
                        && record.invoice.expires_at <= unix_now()
                    {
                        record.status = InvoiceStatus::Expired;
                        self.cancel_targets(&record, None).await;
                        let key = record.invoice.payment_hash.to_string();
                        if let Err(error) = self.store().put(INVOICES, &key, &record) {
                            warn!("expiring invoice {key}: {error}");
                        }
                    }
                }
            }
            Err(error) => warn!("listing invoices: {error}"),
        }
    }

    async fn advance_hop(&self, hop: HopRecord) {
        let Some(_busy) = self.busy(format!("hop:{}", hop.operation_id)) else {
            return;
        };
        let (Some(outgoing), Ok(network)) = (
            hop.outgoing.clone(),
            self.network(&hop.prepare.outgoing_network),
        ) else {
            return;
        };
        let mut hop = hop;
        if hop.preimage.is_none() {
            match settle_outgoing(network.as_ref(), &outgoing).await {
                Outcome::Pending => return,
                Outcome::Claimed(preimage) => {
                    info!(
                        "{} claimed downstream on {}",
                        hop.prepare.payment_hash.short(),
                        hop.prepare.outgoing_network
                    );
                    hop.preimage = Some(preimage);
                }
                Outcome::Refunded => {
                    hop.state = HopState::Refunded;
                    if let Err(error) = self.save_hop(&hop) {
                        warn!("saving hop: {error}");
                    }
                    return;
                }
            }
        }
        self.claim_hop(&mut hop).await;
    }

    /// Claim the incoming HTLC of a hop whose preimage is known.
    pub(super) async fn claim_hop(&self, hop: &mut HopRecord) {
        let Some(preimage) = hop.preimage else {
            return;
        };
        let Ok(network) = self.network(&hop.prepare.incoming_network) else {
            return;
        };
        match network.claim_incoming_htlc(&hop.incoming, preimage).await {
            Ok(()) => {
                hop.state = HopState::Settled;
                info!(
                    "{} settled: earned {} msat",
                    hop.prepare.payment_hash.short(),
                    hop.prepare.amount_msat - hop.prepare.outgoing_amount_msat
                );
            }
            Err(claim_error) if unix_now() >= hop.incoming.expiry => {
                error!(
                    "{} could not be claimed on {} before it expired: {claim_error}",
                    hop.prepare.payment_hash.short(),
                    hop.prepare.incoming_network
                );
                hop.state = HopState::Failed(format!("claim failed: {claim_error}"));
            }
            Err(claim_error) => warn!(
                "claiming {} on {}: {claim_error}; retrying",
                hop.prepare.payment_hash.short(),
                hop.prepare.incoming_network
            ),
        }
        if let Err(error) = self.save_hop(hop) {
            warn!("saving hop: {error}");
        }
    }

    async fn advance_payment(&self, mut payment: PaymentRecord) {
        let key = payment.invoice.payment_hash.to_string();
        let Some(_busy) = self.busy(format!("pay:{key}")) else {
            return;
        };
        let Ok(network) = self.network(&payment.network) else {
            return;
        };
        match settle_outgoing(network.as_ref(), &payment.htlc).await {
            Outcome::Pending => return,
            Outcome::Claimed(preimage) => {
                payment.status = PaymentStatus::Completed;
                payment.preimage = Some(preimage);
            }
            Outcome::Refunded => payment.status = PaymentStatus::Refunded,
        }
        if let Err(error) = self.store().put(PAYMENTS, &key, &payment) {
            warn!("saving payment {key}: {error}");
        }
    }
}

/// Look at an outgoing HTLC and refund it once expired.
async fn settle_outgoing(network: &dyn Network, htlc: &Htlc) -> Outcome {
    match network.check_outgoing_htlc(htlc).await {
        Ok(OutgoingState::Claimed(preimage)) if htlc.payment_hash.matches_preimage(&preimage) => {
            return Outcome::Claimed(preimage)
        }
        Ok(OutgoingState::Claimed(_)) => {
            warn!("{} reported a wrong preimage", network.id());
            return Outcome::Pending;
        }
        Ok(OutgoingState::Refunded) => return Outcome::Refunded,
        Ok(OutgoingState::Pending) => {}
        Err(error) => {
            warn!(
                "checking {} on {}: {error}",
                htlc.payment_hash.short(),
                network.id()
            );
            return Outcome::Pending;
        }
    }
    if unix_now() < htlc.expiry {
        return Outcome::Pending;
    }
    match network.refund_outgoing_htlc(htlc).await {
        Ok(()) => {
            info!("{} refunded on {}", htlc.payment_hash.short(), network.id());
            Outcome::Refunded
        }
        Err(error) => {
            warn!(
                "refunding {} on {}: {error}; retrying",
                htlc.payment_hash.short(),
                network.id()
            );
            Outcome::Pending
        }
    }
}
