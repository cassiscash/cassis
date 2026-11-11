//! Payee role: issue invoices, vet PREPARE, claim on COMMIT.

use super::{db_error, Node, INLINE_WAIT, VERIFY_RETRY_INTERVAL};
use crate::db::{
    Db, Direction, Invoice as StoredInvoice, InvoiceHash, InvoiceState, Transaction,
    TransactionHash,
};
use crate::stored::stored_metadata;
use cassis_core::keys::NodeKeys;
use cassis_core::network::{Htlc, HtlcTarget, Network, NetworkError, NetworkId};
use cassis_core::protocol::{
    Commit, Invoice, InvoiceBody, InvoiceNetwork, Metadata, PreparePayee, Response,
};
use cassis_core::{unix_now, Bytes32};
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

/// A claim started by COMMIT.
pub(super) enum CommitState {
    Claiming,
    /// Kept until a repeated COMMIT reports it.
    Failed(String),
}

/// Create and record an invoice payable on each of `networks`, carrying
/// `metadata` back to this node with every PREPARE and COMMIT.
///
/// Needs no running node: the payee endpoint is derived from `keys`, so
/// an invoice can be issued while the node that will claim it is
/// offline. `iroh_relay` is that node's home relay, if known.
pub async fn create_invoice(
    db: &Db,
    keys: &NodeKeys,
    iroh_relay: Option<String>,
    networks: &[Arc<dyn Network>],
    amount_msat: u64,
    expires_at: u64,
    description: Option<String>,
    metadata: Option<Metadata>,
) -> Result<Invoice, String> {
    if amount_msat == 0 {
        return Err("invoice amount must be positive".into());
    }
    if expires_at <= unix_now() {
        return Err("invoice expiry must be in the future".into());
    }
    if networks.is_empty() {
        return Err("an invoice needs at least one network".into());
    }
    let preimage = Bytes32::random();
    let payment_hash = preimage.sha256();
    let mut targets = Vec::with_capacity(networks.len());
    for network in networks {
        let target = network
            .receive_target(payment_hash, amount_msat, expires_at)
            .await
            .map_err(|e| format!("cannot receive on {}: {e}", network.id()))?;
        targets.push(InvoiceNetwork {
            network: network.id(),
            target,
            incoming_delta_secs: Some(network.incoming_delta_secs()),
        });
    }
    let invoice = Invoice::direct(
        InvoiceBody {
            payment_hash,
            amount_msat,
            expires_at,
            networks: targets,
            description,
            metadata,
            iroh_relay,
        },
        &keys.iroh,
    );
    db.invoices()
        .insert(&StoredInvoice {
            payment_hash: InvoiceHash(payment_hash.to_string()),
            amount_msat,
            expires_at,
            networks: invoice.body.networks.iter().map(Into::into).collect(),
            description: invoice.body.description.clone(),
            metadata: stored_metadata(&invoice.body.metadata),
            preimage: Some(preimage.0),
            delegation: None,
            state: InvoiceState::Waiting,
            created_at: unix_now(),
            settled_at: None,
        })
        .map_err(db_error)?;
    Ok(invoice)
}

impl Node {
    /// [`create_invoice`] on networks of this node, reachable through
    /// this node's endpoint.
    pub async fn create_invoice(
        &self,
        networks: &[NetworkId],
        amount_msat: u64,
        expires_at: u64,
        description: Option<String>,
        metadata: Option<Metadata>,
    ) -> Result<Invoice, String> {
        let networks = networks
            .iter()
            .map(|id| self.network(id))
            .collect::<Result<Vec<_>, _>>()?;
        let relay = self.0.transport.home_relay().await;
        create_invoice(
            self.db(),
            &self.0.keys,
            relay,
            &networks,
            amount_msat,
            expires_at,
            description,
            metadata,
        )
        .await
    }

    /// Whether this node expects the HTLC `prepare` announces. Nothing
    /// is reserved: COMMIT checks everything again.
    pub(super) fn prepare_payee(&self, prepare: PreparePayee) -> Result<(), String> {
        let hash = prepare.payment_hash;
        let result = self.check_prepare_payee(&prepare);
        match &result {
            Ok(()) => info!(
                "PREPARE {} accepted as payee on {}",
                hash.short(),
                prepare.network
            ),
            Err(reason) => warn!("PREPARE {} rejected as payee: {reason}", hash.short()),
        }
        result
    }

    fn check_prepare_payee(&self, prepare: &PreparePayee) -> Result<(), String> {
        let record = self.invoice(&prepare.payment_hash)?;
        if record.state == InvoiceState::Settled {
            return Err("invoice already paid".into());
        }
        self.payable_on(&record, &prepare.network, prepare.expiry)
            .map(|_| ())
    }

    /// What paying `record` with an HTLC on `network` expiring at
    /// `expiry` needs: the invoice's target there, the network, and the
    /// time by which the claim must start. Fails when the invoice or
    /// the HTLC would not allow claiming.
    fn payable_on(
        &self,
        record: &StoredInvoice,
        network: &NetworkId,
        expiry: u64,
    ) -> Result<(HtlcTarget, Arc<dyn Network>, u64), String> {
        if record.state == InvoiceState::Expired || record.expires_at <= unix_now() {
            return Err("invoice expired".into());
        }
        let entry = record
            .networks
            .iter()
            .find(|entry| entry.network == network.0)
            .ok_or_else(|| format!("invoice is not payable on {network}"))?;
        let target = HtlcTarget::try_from(&entry.target)?;
        let network = self.network(network)?;
        // The claim itself must land before the HTLC expires.
        let claim_by = expiry.saturating_sub(network.incoming_delta_secs());
        if claim_by <= unix_now() {
            return Err("HTLC expires too soon to claim it".into());
        }
        Ok((target, network, claim_by))
    }

    /// Start claiming the HTLC of `commit`, or report on a claim
    /// already started: [`Response::Committed`] once claimed,
    /// [`Response::Pending`] while the HTLC is not final yet.
    pub(super) async fn commit(&self, commit: Commit) -> Response {
        let hash = commit.payment_hash;
        let start = {
            let mut commits = self.0.commits.lock().unwrap_or_else(|e| e.into_inner());
            match commits.get(&hash) {
                Some(CommitState::Claiming) => false,
                Some(CommitState::Failed(_)) => false,
                None => {
                    commits.insert(hash, CommitState::Claiming);
                    true
                }
            }
        };
        if start {
            self.spawn(self.clone().claim(commit));
        }
        // Answer right away when claiming is quick.
        let deadline = tokio::time::Instant::now() + INLINE_WAIT;
        loop {
            let preimage = self
                .invoice(&hash)
                .ok()
                .filter(|record| record.state == InvoiceState::Settled)
                .and_then(|record| record.preimage);
            if let Some(preimage) = preimage {
                return Response::Committed(Bytes32(preimage));
            }
            {
                let mut commits = self.0.commits.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(CommitState::Failed(reason)) = commits.get(&hash) {
                    // Reported once; a corrected COMMIT may start over.
                    let reason = reason.clone();
                    commits.remove(&hash);
                    return Response::Error(reason);
                }
            }
            if tokio::time::Instant::now() >= deadline {
                return Response::Pending;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Verify the HTLC of `commit`, waiting while it is not final yet,
    /// and claim it.
    async fn claim(self, commit: Commit) {
        let hash = commit.payment_hash;
        let outcome = self.try_claim(commit).await;
        let mut commits = self.0.commits.lock().unwrap_or_else(|e| e.into_inner());
        match outcome {
            Ok(()) => {
                commits.remove(&hash);
            }
            Err(reason) => {
                warn!("COMMIT {} failed: {reason}", hash.short());
                commits.insert(hash, CommitState::Failed(reason));
            }
        }
    }

    async fn try_claim(&self, commit: Commit) -> Result<(), String> {
        let key = commit.payment_hash.to_string();
        let _busy = self
            .busy(format!("invoice:{key}"))
            .ok_or("this invoice is already being claimed")?;
        let record = self.invoice(&commit.payment_hash)?;
        if record.state == InvoiceState::Settled {
            return Ok(());
        }
        let preimage = Bytes32(
            record
                .preimage
                .ok_or("the invoice's preimage is not here")?,
        );
        let (target, network, claim_by) =
            self.payable_on(&record, &commit.network, commit.expiry)?;
        let htlc = Htlc {
            payment_hash: commit.payment_hash,
            amount_msat: record.amount_msat,
            expiry: commit.expiry,
            target,
            descriptor: commit.descriptor,
        };
        let mut waiting = false;
        loop {
            match network.verify_incoming_htlc(&htlc).await {
                Ok(()) => break,
                Err(NetworkError::NotYet(reason)) if unix_now() < claim_by => {
                    if !waiting {
                        info!(
                            "COMMIT {}: waiting for the HTLC: {reason}",
                            htlc.payment_hash.short()
                        );
                        waiting = true;
                    }
                    tokio::time::sleep(VERIFY_RETRY_INTERVAL).await;
                }
                Err(error) => return Err(format!("HTLC rejected: {error}")),
            }
        }
        info!(
            "claiming {} msat for invoice {} on {}",
            htlc.amount_msat, key, commit.network
        );
        network
            .claim_incoming_htlc(&htlc, preimage)
            .await
            .map_err(|e| format!("claim failed: {e}"))?;
        self.settle_invoice(&record, &commit.network, htlc.amount_msat, preimage)?;
        self.cancel_targets(&record, Some(&commit.network)).await;
        Ok(())
    }

    /// The invoice `hash` names.
    pub(super) fn invoice(&self, hash: &Bytes32) -> Result<StoredInvoice, String> {
        self.db()
            .invoices()
            .get(InvoiceHash(hash.to_string()))
            .map_err(db_error)?
            .ok_or_else(|| "unknown invoice".to_string())
    }

    /// Record that `record` was paid `amount_msat` on `network`.
    pub(super) fn settle_invoice(
        &self,
        record: &StoredInvoice,
        network: &NetworkId,
        amount_msat: u64,
        preimage: Bytes32,
    ) -> Result<(), String> {
        settle_invoice(self.db(), record, network, amount_msat, preimage)
    }

    /// Release what the invoice's networks, except `claimed_on`, set up
    /// to receive it.
    pub(super) async fn cancel_targets(
        &self,
        record: &StoredInvoice,
        claimed_on: Option<&NetworkId>,
    ) {
        let Ok(hash) = record.payment_hash.0.parse::<Bytes32>() else {
            return;
        };
        for entry in &record.networks {
            let id = NetworkId(entry.network.clone());
            if Some(&id) == claimed_on {
                continue;
            }
            let Ok(network) = self.network(&id) else {
                continue;
            };
            if let Err(error) = network.cancel_receive(hash).await {
                warn!("releasing invoice target on {id}: {error}");
            }
        }
    }
}

/// Record, at once, that `record` was paid `amount_msat` on `network`
/// and the incoming transaction that paid it.
pub(super) fn settle_invoice(
    db: &Db,
    record: &StoredInvoice,
    network: &NetworkId,
    amount_msat: u64,
    preimage: Bytes32,
) -> Result<(), String> {
    let now = unix_now();
    db.write(|tx| {
        tx.invoices().update(&StoredInvoice {
            state: InvoiceState::Settled,
            settled_at: Some(now),
            ..record.clone()
        })?;
        tx.transactions().insert(&Transaction {
            payment_hash: TransactionHash(record.payment_hash.0.clone()),
            direction: Direction::Incoming,
            amount_msat,
            network: network.0.clone(),
            preimage: preimage.0,
            at: now,
            invoice: Some(record.payment_hash.clone()),
        })
    })
    .map_err(db_error)
}
