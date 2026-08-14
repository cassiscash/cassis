//! Payee role: issue invoices, claim on COMMIT.

use super::{InvoiceRecord, InvoiceStatus, Node, INVOICES};
use crate::keys::NodeKeys;
use crate::network::{Htlc, Network};
use crate::primitives::{unix_now, Bytes32};
use crate::protocol::{Commit, Invoice, InvoiceNetwork};
use crate::store::Store;
use std::sync::Arc;
use tracing::{info, warn};

/// Create and record an invoice payable on each of `networks`.
///
/// Needs no running node: the payee endpoint is derived from `keys`, so
/// an invoice can be issued while the node that will claim it is
/// offline. `iroh_relay` is that node's home relay, if known.
pub async fn create_invoice(
    store: &Store,
    keys: &NodeKeys,
    iroh_relay: Option<String>,
    networks: &[Arc<dyn Network>],
    amount_msat: u64,
    expires_at: u64,
    description: Option<String>,
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
        });
    }
    let invoice = Invoice {
        payment_hash,
        amount_msat,
        payee: keys.node.pubkey(),
        expires_at,
        networks: targets,
        description,
        autocommit: false,
        iroh_peer_id: Some(iroh::SecretKey::from(keys.iroh).public().to_string()),
        iroh_relay,
    };
    store.put(
        INVOICES,
        &payment_hash.to_string(),
        &InvoiceRecord {
            invoice: invoice.clone(),
            preimage,
            status: InvoiceStatus::Pending,
            created_at: unix_now(),
            settled_at: None,
        },
    )?;
    Ok(invoice)
}

impl Node {
    /// [`create_invoice`] on networks of this node, reachable through
    /// this node's endpoint.
    pub async fn create_invoice(
        &self,
        networks: &[crate::network::NetworkId],
        amount_msat: u64,
        expires_at: u64,
        description: Option<String>,
    ) -> Result<Invoice, String> {
        let networks = networks
            .iter()
            .map(|id| self.network(id))
            .collect::<Result<Vec<_>, _>>()?;
        let relay = self.0.transport.home_relay().await;
        create_invoice(
            self.store(),
            &self.0.keys,
            relay,
            &networks,
            amount_msat,
            expires_at,
            description,
        )
        .await
    }

    pub(super) async fn commit(&self, commit: Commit) -> Result<Bytes32, String> {
        let key = commit.payment_hash.to_string();
        let _busy = self
            .busy(format!("invoice:{key}"))
            .ok_or("this invoice is already being claimed")?;
        let mut record: InvoiceRecord =
            self.store().get(INVOICES, &key)?.ok_or("unknown invoice")?;
        match record.status {
            // The preimage is public once claimed.
            InvoiceStatus::Claimed => return Ok(record.preimage),
            InvoiceStatus::Expired => return Err("invoice expired".into()),
            InvoiceStatus::Pending => {}
        }
        let now = unix_now();
        if record.invoice.expires_at <= now {
            return Err("invoice expired".into());
        }
        let target = record
            .invoice
            .target_for(&commit.network)
            .cloned()
            .ok_or_else(|| format!("invoice is not payable on {}", commit.network))?;
        let network = self.network(&commit.network)?;
        if commit.expiry < now.saturating_add(network.incoming_delta_secs()) {
            return Err("HTLC expires too soon to claim it".into());
        }
        let htlc = Htlc {
            payment_hash: commit.payment_hash,
            amount_msat: record.invoice.amount_msat,
            expiry: commit.expiry,
            target,
            descriptor: commit.descriptor,
        };
        network
            .verify_incoming_htlc(&htlc)
            .await
            .map_err(|e| format!("HTLC rejected: {e}"))?;
        info!(
            "claiming {} msat for invoice {} on {}",
            htlc.amount_msat, key, commit.network
        );
        network
            .claim_incoming_htlc(&htlc, record.preimage)
            .await
            .map_err(|e| format!("claim failed: {e}"))?;
        record.status = InvoiceStatus::Claimed;
        record.settled_at = Some(unix_now());
        self.store().put(INVOICES, &key, &record)?;
        self.cancel_targets(&record, Some(&commit.network)).await;
        Ok(record.preimage)
    }

    /// Release what the invoice's networks, except `claimed_on`, set up
    /// to receive it.
    pub(super) async fn cancel_targets(
        &self,
        record: &InvoiceRecord,
        claimed_on: Option<&crate::network::NetworkId>,
    ) {
        for entry in &record.invoice.networks {
            if Some(&entry.network) == claimed_on {
                continue;
            }
            let Ok(network) = self.network(&entry.network) else {
                continue;
            };
            if let Err(error) = network.cancel_receive(record.invoice.payment_hash).await {
                warn!("releasing invoice target on {}: {error}", entry.network);
            }
        }
    }
}
