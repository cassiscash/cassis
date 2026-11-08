//! Receiving offline, the payee's side (see [`crate::offline`]): issue
//! invoices through a gateway and a preimage server, or let the gateway
//! issue them alone, and later claim what the preimage server logged.
//!
//! None of this needs a running node: the payee talks to both servers
//! from the endpoint of [`NodeKeys::offline_payee_secret`], the key its
//! authorizations are signed with and its payments are logged under.

use super::InvoiceStatus;
use crate::keys::NodeKeys;
use crate::network::{Htlc, Network, NetworkError, NetworkId};
use crate::offline::{
    AuthorizationKind, Destination, EndpointKey, PreimageIssuance, ReceiveAuthorization,
};
use crate::primitives::{unix_now, Bytes32};
use crate::protocol::{
    GatewayInvoiceRequest, Invoice, InvoiceKind, Metadata, ReceivedPayment, Request, Response,
};
use crate::store::Store;
use crate::transport::{PeerAddr, Transport};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{info, warn};

/// Table of invoices issued through a gateway, one at a time.
pub const GATEWAY_INVOICES: &str = "gateway_invoices";
/// Table of standing authorizations given to gateways, by id.
pub const STANDING_AUTHORIZATIONS: &str = "standing_authorizations";
/// Table of HTLCs claimed from preimage server logs, by payment hash.
pub const OFFLINE_CLAIMS: &str = "offline_claims";

/// The gateway and preimage server a payee receives through.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OfflineEndpoints {
    pub gateway: PeerAddr,
    pub preimage_server: PeerAddr,
}

/// An invoice issued through a gateway. It keeps no preimage: the
/// preimage server holds it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GatewayInvoiceRecord {
    pub invoice: Invoice,
    pub authorization: ReceiveAuthorization,
    pub endpoints: OfflineEndpoints,
    pub status: InvoiceStatus,
    pub created_at: u64,
    pub settled_at: Option<u64>,
}

/// A standing authorization this node gave a gateway.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StandingAuthorizationRecord {
    pub authorization: ReceiveAuthorization,
    pub endpoints: OfflineEndpoints,
    pub created_at: u64,
}

/// An HTLC claimed from a preimage server's log.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OfflineClaim {
    pub payment_hash: Bytes32,
    pub network: NetworkId,
    pub amount_msat: u64,
    pub claimed_at: u64,
}

/// Where the gateway may pay this node: its claim key on each of
/// `networks`, which must let HTLCs run for `min_final_timeout_secs`
/// and more. Lightning is refused: its hold invoices need this node
/// online.
async fn destinations(
    networks: &[Arc<dyn Network>],
    min_final_timeout_secs: u64,
) -> Result<Vec<Destination>, String> {
    if networks.is_empty() {
        return Err("receiving offline needs at least one network".into());
    }
    let mut destinations = Vec::with_capacity(networks.len());
    for network in networks {
        let id = network.id();
        if id.kind() == "lightning" {
            return Err(format!(
                "{id} cannot be paid to an offline payee: its hold invoices need it online"
            ));
        }
        let lifetime = min_final_timeout_secs.saturating_add(network.incoming_delta_secs());
        if let Some(max) = network
            .max_incoming_lifetime_secs()
            .filter(|max| *max <= lifetime)
        {
            return Err(format!(
                "{id} takes HTLCs running at most {max}s, too short for a final timeout of \
                 {min_final_timeout_secs}s"
            ));
        }
        // Claim-key networks give the same target whatever the hash.
        let target = network
            .receive_target(Bytes32([0; 32]), 0, 0)
            .await
            .map_err(|e| format!("cannot receive on {id}: {e}"))?;
        destinations.push(Destination {
            network: id,
            target,
        });
    }
    Ok(destinations)
}

fn endpoint_key(peer: &PeerAddr) -> Result<EndpointKey, String> {
    peer.id.parse()
}

/// Create and record an invoice that payers pay to `endpoints.gateway`,
/// for a hash `endpoints.preimage_server` issues, signed by both the
/// gateway and this node.
///
/// The gateway forwards each payment as an HTLC to this node on one of
/// `networks`, refundable no earlier than `min_final_timeout_secs`
/// after the preimage server releases the preimage: how long this node
/// may stay offline before [`redeem_offline_payments`]. Payers lock no
/// longer than for a direct payment: only the gateway's HTLC runs that
/// long.
#[allow(clippy::too_many_arguments)]
pub async fn create_gateway_invoice(
    store: &Store,
    keys: &NodeKeys,
    endpoints: OfflineEndpoints,
    networks: &[Arc<dyn Network>],
    amount_msat: u64,
    expires_at: u64,
    description: Option<String>,
    metadata: Option<Metadata>,
    min_final_timeout_secs: u64,
) -> Result<Invoice, String> {
    let now = unix_now();
    if amount_msat == 0 {
        return Err("invoice amount must be positive".into());
    }
    if expires_at <= now {
        return Err("invoice expiry must be in the future".into());
    }
    let secret = keys.offline_payee_secret();
    let authorization = ReceiveAuthorization::sign(
        &secret,
        AuthorizationKind::Single,
        endpoint_key(&endpoints.gateway)?,
        endpoint_key(&endpoints.preimage_server)?,
        now,
        expires_at,
        amount_msat,
        amount_msat,
        min_final_timeout_secs,
        destinations(networks, min_final_timeout_secs).await?,
    )?;
    let transport = Transport::bind_client(secret).await?;
    let result = issue(
        &transport,
        &endpoints,
        &authorization,
        expires_at,
        description,
        metadata,
    )
    .await;
    transport.close().await;
    let mut invoice = result?;
    invoice.sign_as_payee(&secret)?;
    if invoice.verify()? != InvoiceKind::Gateway {
        return Err("the gateway's invoice is not a gateway invoice".into());
    }
    store.put(
        GATEWAY_INVOICES,
        &invoice.payment_hash.to_string(),
        &GatewayInvoiceRecord {
            invoice: invoice.clone(),
            authorization,
            endpoints,
            status: InvoiceStatus::Pending,
            created_at: now,
            settled_at: None,
        },
    )?;
    Ok(invoice)
}

/// Get a hash from the preimage server and the gateway's invoice for
/// it, checked to be exactly what was asked for.
async fn issue(
    transport: &Transport,
    endpoints: &OfflineEndpoints,
    authorization: &ReceiveAuthorization,
    expires_at: u64,
    description: Option<String>,
    metadata: Option<Metadata>,
) -> Result<Invoice, String> {
    let amount_msat = authorization.min_amount_msat;
    let request = Request::PreimageIssue {
        authorization: authorization.clone(),
        amount_msat,
    };
    let issuance: PreimageIssuance = match transport
        .request(&endpoints.preimage_server, &request)
        .await?
    {
        Response::PreimageIssued(Ok(issuance)) => issuance,
        Response::PreimageIssued(Err(reason)) | Response::Error(reason) => {
            return Err(format!("preimage server refused: {reason}"))
        }
        other => return Err(format!("unexpected answer from preimage server: {other:?}")),
    };
    issuance.verify(&authorization.preimage_server, authorization)?;
    if issuance.amount_msat != amount_msat {
        return Err("preimage server issued the hash for another amount".into());
    }
    let request = Request::GatewayInvoice(GatewayInvoiceRequest {
        authorization: authorization.clone(),
        issuance: issuance.clone(),
        expires_at,
        description: description.clone(),
        metadata: metadata.clone(),
        preimage_server_relay: endpoints.preimage_server.relay.clone(),
    });
    let invoice = match transport.request(&endpoints.gateway, &request).await? {
        Response::GatewayInvoice(Ok(invoice)) => invoice,
        Response::GatewayInvoice(Err(reason)) | Response::Error(reason) => {
            return Err(format!("gateway refused: {reason}"))
        }
        other => return Err(format!("unexpected answer from gateway: {other:?}")),
    };
    let asked = invoice.payment_hash == issuance.payment_hash
        && invoice.amount_msat == amount_msat
        && invoice.expires_at == expires_at
        && invoice.description == description
        && invoice.metadata == metadata
        && invoice.gateway == Some(authorization.gateway)
        && invoice.payee.is_none()
        && invoice.payee_signature.is_none()
        && invoice.preimage_server.is_none()
        && invoice.preimage_server_issuance.is_none()
        && invoice.payee_authorization.is_none()
        && !invoice.networks.is_empty();
    if !asked {
        return Err("the gateway's invoice is not the one asked for".into());
    }
    Ok(invoice)
}

/// Let `endpoints.gateway` issue invoices in this node's name while it
/// is offline: between `valid_from` and `valid_until`, for amounts
/// between `min_amount_msat` and `max_amount_msat`, paid on to this
/// node on one of `networks` as for [`create_gateway_invoice`]. The
/// gateway may refuse the terms. Records the authorization, so
/// [`redeem_offline_payments`] knows where to look.
#[allow(clippy::too_many_arguments)]
pub async fn authorize_gateway(
    store: &Store,
    keys: &NodeKeys,
    endpoints: OfflineEndpoints,
    networks: &[Arc<dyn Network>],
    valid_from: u64,
    valid_until: u64,
    min_amount_msat: u64,
    max_amount_msat: u64,
    min_final_timeout_secs: u64,
) -> Result<ReceiveAuthorization, String> {
    if valid_until <= unix_now() {
        return Err("the authorization must end in the future".into());
    }
    let secret = keys.offline_payee_secret();
    let authorization = ReceiveAuthorization::sign(
        &secret,
        AuthorizationKind::Standing,
        endpoint_key(&endpoints.gateway)?,
        endpoint_key(&endpoints.preimage_server)?,
        valid_from,
        valid_until,
        min_amount_msat,
        max_amount_msat,
        min_final_timeout_secs,
        destinations(networks, min_final_timeout_secs).await?,
    )?;
    let transport = Transport::bind_client(secret).await?;
    let answer = transport
        .request(
            &endpoints.gateway,
            &Request::GatewayAuthorize {
                authorization: authorization.clone(),
                preimage_server_relay: endpoints.preimage_server.relay.clone(),
            },
        )
        .await;
    transport.close().await;
    match answer? {
        Response::GatewayAuthorized(Ok(())) => {}
        Response::GatewayAuthorized(Err(reason)) | Response::Error(reason) => {
            return Err(format!("gateway refused: {reason}"))
        }
        other => return Err(format!("unexpected answer from gateway: {other:?}")),
    }
    store.put(
        STANDING_AUTHORIZATIONS,
        &authorization.id()?.to_string(),
        &StandingAuthorizationRecord {
            authorization: authorization.clone(),
            endpoints,
            created_at: unix_now(),
        },
    )?;
    Ok(authorization)
}

/// What [`redeem_offline_payments`] did.
#[derive(Clone, Debug, Default)]
pub struct RedeemReport {
    /// Claimed now: payment hash, network, amount.
    pub claimed: Vec<(Bytes32, NetworkId, u64)>,
    /// Logged but not claimed yet (an HTLC not final, a backend down);
    /// a later call tries again.
    pub pending: Vec<(Bytes32, String)>,
    /// Failed payments the server logged, and HTLCs that could not be
    /// claimed.
    pub failed: Vec<(Bytes32, String)>,
}

/// Fetch from `preimage_server` the HTLCs gateways funded to this node
/// since `since` (unix seconds) and claim them on `networks`, before
/// they expire.
pub async fn redeem_offline_payments(
    store: &Store,
    keys: &NodeKeys,
    preimage_server: &PeerAddr,
    networks: &[Arc<dyn Network>],
    since: u64,
) -> Result<RedeemReport, String> {
    let transport = Transport::bind_client(keys.offline_payee_secret()).await?;
    let answer = transport
        .request(preimage_server, &Request::PreimagePayments { since })
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
        let (payment_hash, network, htlc, preimage) = match payment {
            ReceivedPayment::Failed {
                payment_hash,
                reason,
                ..
            } => {
                report.failed.push((payment_hash, reason));
                continue;
            }
            ReceivedPayment::Received {
                payment_hash,
                network,
                amount_msat,
                expiry,
                target,
                descriptor,
                preimage,
                ..
            } => (
                payment_hash,
                network,
                Htlc {
                    payment_hash,
                    amount_msat,
                    expiry,
                    target,
                    descriptor,
                },
                preimage,
            ),
        };
        let key = payment_hash.to_string();
        if store.get::<OfflineClaim>(OFFLINE_CLAIMS, &key)?.is_some() {
            continue;
        }
        match redeem(networks, &network, &htlc, preimage).await {
            Ok(()) => {
                store.put(
                    OFFLINE_CLAIMS,
                    &key,
                    &OfflineClaim {
                        payment_hash,
                        network: network.clone(),
                        amount_msat: htlc.amount_msat,
                        claimed_at: unix_now(),
                    },
                )?;
                if let Some(mut record) =
                    store.get::<GatewayInvoiceRecord>(GATEWAY_INVOICES, &key)?
                {
                    record.status = InvoiceStatus::Claimed;
                    record.settled_at = Some(unix_now());
                    store.put(GATEWAY_INVOICES, &key, &record)?;
                }
                report
                    .claimed
                    .push((payment_hash, network, htlc.amount_msat));
            }
            Err(NetworkError::NotYet(reason) | NetworkError::Network(reason)) => {
                report.pending.push((payment_hash, reason))
            }
            Err(error) => report.failed.push((payment_hash, error.to_string())),
        }
    }
    Ok(report)
}

/// Verify `htlc` pays this node on `network_id` and claim it.
async fn redeem(
    networks: &[Arc<dyn Network>],
    network_id: &NetworkId,
    htlc: &Htlc,
    preimage: Bytes32,
) -> Result<(), NetworkError> {
    if !htlc.payment_hash.matches_preimage(&preimage) {
        return Err(NetworkError::invalid(
            "preimage server logged a wrong preimage",
        ));
    }
    let network = networks
        .iter()
        .find(|network| network.id() == *network_id)
        .ok_or_else(|| NetworkError::invalid(format!("network {network_id} is not open")))?;
    if let Err(error) = network.verify_incoming_htlc(htlc).await {
        warn!(
            "{} logged on {network_id} does not verify: {error}",
            htlc.payment_hash.short()
        );
        return Err(error);
    }
    info!(
        "claiming {} msat for {} on {network_id}",
        htlc.amount_msat, htlc.payment_hash
    );
    network.claim_incoming_htlc(htlc, preimage).await
}
