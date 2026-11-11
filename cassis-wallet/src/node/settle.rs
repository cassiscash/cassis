//! Settlement: drive every journaled HTLC to its end.

use super::{db_error, Node};
use crate::db::{Invoice, InvoiceState, PendingPayment, PendingPaymentHash};
use cassis_core::network::{Htlc, Network, OutgoingState};
use cassis_core::{unix_now, Bytes32, NetworkId};
use std::time::Duration;
use tracing::{info, warn};

const SETTLE_INTERVAL: Duration = Duration::from_secs(10);

/// What became of an outgoing HTLC this round.
pub enum Outcome {
    Pending,
    Claimed(Bytes32),
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

    /// One pass over everything in flight: own payments and expired
    /// invoices.
    pub async fn settle_once(&self) {
        match self.db().pending_payments().all() {
            Ok(payments) => {
                for payment in payments {
                    self.advance_payment(payment).await;
                }
            }
            Err(error) => warn!("listing payments: {error}"),
        }
        match self.db().invoices().range_by_waiting_until(..=unix_now()) {
            Ok(invoices) => {
                for invoice in invoices {
                    self.expire_invoice(invoice).await;
                }
            }
            Err(error) => warn!("listing invoices: {error}"),
        }
    }

    async fn expire_invoice(&self, invoice: Invoice) {
        let key = invoice.payment_hash.0.clone();
        let Some(_busy) = self.busy(format!("invoice:{key}")) else {
            return;
        };
        let expired = Invoice {
            state: InvoiceState::Expired,
            ..invoice.clone()
        };
        if let Err(error) = self.db().invoices().update(&expired) {
            warn!("expiring invoice {key}: {error}");
            return;
        }
        if invoice.delegation.is_none() {
            self.cancel_targets(&invoice, None).await;
        }
    }

    async fn advance_payment(&self, payment: PendingPayment) {
        let key = payment.payment_hash.0.clone();
        let Some(_busy) = self.busy(format!("pay:{key}")) else {
            return;
        };
        let network_id = NetworkId(payment.network.clone());
        let (Ok(network), Ok(htlc)) = (self.network(&network_id), Htlc::try_from(&payment.htlc))
        else {
            return;
        };
        let saved = match settle_outgoing(network.as_ref(), &htlc).await {
            Outcome::Pending => return,
            Outcome::Claimed(preimage) => self.complete_payment(&key, &network_id, &htlc, preimage),
            Outcome::Refunded => self
                .db()
                .pending_payments()
                .delete(PendingPaymentHash(key.clone()))
                .map(|_| ())
                .map_err(db_error),
        };
        if let Err(error) = saved {
            warn!("saving payment {key}: {error}");
        }
    }
}

/// Look at an outgoing HTLC and refund it once expired.
pub async fn settle_outgoing(network: &dyn Network, htlc: &Htlc) -> Outcome {
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
