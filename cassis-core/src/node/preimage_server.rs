//! Receiving through a preimage server: an always-online iroh node that
//! answers PREPARE and COMMIT for this payee, so the payee can go
//! offline.
//!
//! The server picks each invoice's preimage and reveals it on COMMIT.
//! HTLCs stay locked to this node's targets, so the server cannot claim
//! them: it logs what each COMMIT named, and [`redeem_preimage_server_payments`]
//! later claims those HTLCs with the preimages it logged. That must
//! happen before they expire, or the payer can refund them.

use super::InvoiceStatus;
use crate::keys::NodeKeys;
use crate::network::{Htlc, Network, NetworkError, NetworkId};
use crate::primitives::{unix_now, Bytes32};
use crate::protocol::{
    Invoice, InvoiceNetwork, PreimageInvoice, PreimageInvoiceTerms, ReceivedPayment, Request,
    Response,
};
use crate::store::Store;
use crate::transport::{PeerAddr, Transport};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{info, warn};

/// Table of invoices issued through a preimage server.
pub const PREIMAGE_SERVER_INVOICES: &str = "preimage_server_invoices";

/// An invoice issued through a preimage server. Unlike
/// [`super::InvoiceRecord`] it keeps no preimage: the server holds it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreimageServerInvoiceRecord {
    pub invoice: Invoice,
    pub server: PeerAddr,
    pub status: InvoiceStatus,
    pub created_at: u64,
    pub settled_at: Option<u64>,
}

/// Create and record an invoice whose PREPAREs and COMMITs go to
/// `server`, payable on each of `networks`.
///
/// The server chooses the payment hash and the metadata, and signs the
/// invoice, which names its endpoint. The preimage it also sends is
/// only checked against the hash.
pub async fn create_preimage_server_invoice(
    store: &Store,
    keys: &NodeKeys,
    server: PeerAddr,
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
    let transport = Transport::bind_client(keys.preimage_server_client_secret()).await?;
    let result = issue(
        &transport,
        keys,
        &server,
        networks,
        amount_msat,
        expires_at,
        description,
    )
    .await;
    transport.close().await;
    let invoice = result?;
    store.put(
        PREIMAGE_SERVER_INVOICES,
        &invoice.payment_hash.to_string(),
        &PreimageServerInvoiceRecord {
            invoice: invoice.clone(),
            server,
            status: InvoiceStatus::Pending,
            created_at: unix_now(),
            settled_at: None,
        },
    )?;
    Ok(invoice)
}

async fn issue(
    transport: &Transport,
    keys: &NodeKeys,
    server: &PeerAddr,
    networks: &[Arc<dyn Network>],
    amount_msat: u64,
    expires_at: u64,
    description: Option<String>,
) -> Result<Invoice, String> {
    let request = Request::PreimageInvoice(PreimageInvoice {
        amount_msat,
        expires_at,
        description: description.clone(),
    });
    let terms: PreimageInvoiceTerms = match transport.request(server, &request).await? {
        Response::PreimageInvoice(Ok(terms)) => terms,
        Response::PreimageInvoice(Err(reason)) | Response::Error(reason) => {
            return Err(format!("preimage server refused the invoice: {reason}"))
        }
        other => return Err(format!("unexpected answer from preimage server: {other:?}")),
    };
    // The preimage is only checked: the server reveals it, we don't.
    if !terms.payment_hash.matches_preimage(&terms.preimage) {
        return Err("preimage server sent a preimage that does not match its hash".into());
    }
    let payment_hash = terms.payment_hash;
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
            max_incoming_lifetime_secs: network.max_incoming_lifetime_secs(),
        });
    }
    let mut invoice = Invoice {
        payment_hash,
        amount_msat,
        payee: keys.node.pubkey(),
        expires_at,
        networks: targets,
        description,
        metadata: terms.metadata,
        iroh_peer_id: Some(server.id.clone()),
        iroh_relay: server.relay.clone(),
        signature: None,
    };
    let signed = transport
        .request(server, &Request::PreimageSign(invoice.clone()))
        .await;
    let signature = match signed {
        Ok(Response::PreimageSigned(Ok(signature))) => Ok(signature),
        Ok(Response::PreimageSigned(Err(reason)) | Response::Error(reason)) => Err(format!(
            "preimage server refused to sign the invoice: {reason}"
        )),
        Ok(other) => Err(format!("unexpected answer from preimage server: {other:?}")),
        Err(error) => Err(error),
    };
    let signature = match signature {
        Ok(signature) => signature,
        Err(error) => {
            release_targets(networks, payment_hash, None).await;
            return Err(error);
        }
    };
    invoice.signature = Some(signature);
    if let Err(error) = invoice.verify_signature() {
        release_targets(networks, payment_hash, None).await;
        return Err(format!("preimage server signature: {error}"));
    }
    Ok(invoice)
}

/// What [`redeem_preimage_server_payments`] did.
#[derive(Clone, Debug, Default)]
pub struct RedeemReport {
    /// Claimed now: payment hash, network, amount.
    pub claimed: Vec<(Bytes32, NetworkId, u64)>,
    /// Logged as received but not claimed yet (an HTLC not final, a
    /// backend down); a later call tries again.
    pub pending: Vec<(Bytes32, String)>,
    /// Failed payments the server logged, and HTLCs that could not be
    /// claimed.
    pub failed: Vec<(Bytes32, String)>,
}

/// Fetch from `server` the payments it logged since `since` (unix
/// seconds) and claim, on `networks`, the HTLCs of the ones received for
/// invoices this node issued through it.
pub async fn redeem_preimage_server_payments(
    store: &Store,
    keys: &NodeKeys,
    server: &PeerAddr,
    networks: &[Arc<dyn Network>],
    since: u64,
) -> Result<RedeemReport, String> {
    let transport = Transport::bind_client(keys.preimage_server_client_secret()).await?;
    let answer = transport
        .request(server, &Request::PreimagePayments { since })
        .await;
    transport.close().await;
    let payments = match answer? {
        Response::PreimagePayments(Ok(payments)) => payments,
        Response::PreimagePayments(Err(reason)) | Response::Error(reason) => {
            return Err(format!("preimage server: {reason}"))
        }
        other => return Err(format!("unexpected answer from preimage server: {other:?}")),
    };
    let mut report = RedeemReport::default();
    for payment in payments {
        match payment {
            ReceivedPayment::Failed {
                payment_hash,
                reason,
                ..
            } => report.failed.push((payment_hash, reason)),
            ReceivedPayment::Received {
                payment_hash,
                network,
                expiry,
                descriptor,
                preimage,
                ..
            } => {
                let Some(mut record) = store.get::<PreimageServerInvoiceRecord>(
                    PREIMAGE_SERVER_INVOICES,
                    &payment_hash.to_string(),
                )?
                else {
                    warn!(
                        "preimage server logged {}, which is not ours",
                        payment_hash.short()
                    );
                    continue;
                };
                if record.status == InvoiceStatus::Claimed {
                    continue;
                }
                match redeem(&record, networks, &network, expiry, descriptor, preimage).await {
                    Ok(()) => {
                        record.status = InvoiceStatus::Claimed;
                        record.settled_at = Some(unix_now());
                        store.put(PREIMAGE_SERVER_INVOICES, &payment_hash.to_string(), &record)?;
                        release_targets(networks, payment_hash, Some(&network)).await;
                        report
                            .claimed
                            .push((payment_hash, network, record.invoice.amount_msat));
                    }
                    Err(NetworkError::NotYet(reason) | NetworkError::Network(reason)) => {
                        report.pending.push((payment_hash, reason))
                    }
                    Err(error) => report.failed.push((payment_hash, error.to_string())),
                }
            }
        }
    }
    Ok(report)
}

async fn redeem(
    record: &PreimageServerInvoiceRecord,
    networks: &[Arc<dyn Network>],
    network_id: &NetworkId,
    expiry: u64,
    descriptor: crate::network::HtlcDescriptor,
    preimage: Bytes32,
) -> Result<(), NetworkError> {
    let invoice = &record.invoice;
    if !invoice.payment_hash.matches_preimage(&preimage) {
        return Err(NetworkError::invalid(
            "preimage server logged a wrong preimage",
        ));
    }
    let target = invoice
        .target_for(network_id)
        .cloned()
        .ok_or_else(|| NetworkError::invalid(format!("invoice is not payable on {network_id}")))?;
    let network = networks
        .iter()
        .find(|network| network.id() == *network_id)
        .ok_or_else(|| NetworkError::invalid(format!("network {network_id} is not open")))?;
    let htlc = Htlc {
        payment_hash: invoice.payment_hash,
        amount_msat: invoice.amount_msat,
        expiry,
        target,
        descriptor,
    };
    network.verify_incoming_htlc(&htlc).await?;
    info!(
        "claiming {} msat for invoice {} on {network_id}",
        htlc.amount_msat, invoice.payment_hash
    );
    network.claim_incoming_htlc(&htlc, preimage).await
}

/// Release what `networks`, except `claimed_on`, set up to receive
/// `payment_hash`.
async fn release_targets(
    networks: &[Arc<dyn Network>],
    payment_hash: Bytes32,
    claimed_on: Option<&NetworkId>,
) {
    for network in networks {
        if Some(&network.id()) == claimed_on {
            continue;
        }
        if let Err(error) = network.cancel_receive(payment_hash).await {
            warn!("releasing invoice target on {}: {error}", network.id());
        }
    }
}
