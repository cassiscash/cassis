//! Receiving offline, the payee's side (see [`cassis_core::offline`]): issue
//! invoices through a gateway and a preimage server, or let the gateway
//! issue them alone, and later claim what the preimage server logged.
//!
//! None of this needs a running node, only an endpoint with the node's
//! identity, [`NodeKeys::iroh`]: the key its invoices and authorizations
//! are signed with and its payments are logged under, which the servers
//! check the payee talks from. A serving node passes its own
//! ([`super::Node::transport`]); otherwise bind a client one with
//! [`Transport::bind_client`].

use super::db_error;
use super::payee::settle_invoice;
use crate::db::{
    Db, Delegation, Direction, FullDelegation, FullDelegationId, Invoice as StoredInvoice,
    InvoiceHash, InvoiceState, Transaction, TransactionHash,
};
use crate::stored::stored_metadata;
use cassis_core::keys::NodeKeys;
use cassis_core::network::{Htlc, Network, NetworkError, NetworkId};
use cassis_core::offline::{
    endpoint_public_key, AuthorizationKind, GatewayDestination, PreimageIssuance,
    ReceiveAuthorization,
};
use cassis_core::protocol::{
    GatewayInvoiceRequest, Invoice, InvoiceReceiver, Metadata, ReceivedPayment, Request, Response,
};
use cassis_core::transport::{PeerAddr, Transport};
use cassis_core::{unix_now, Bytes32};
use iroh_base::PublicKey;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{info, warn};

/// The gateway and preimage server a payee receives through.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OfflineEndpoints {
    pub gateway: PeerAddr,
    pub preimage_server: PeerAddr,
}

/// Where the gateway may pay this node: its claim key on each of
/// `networks`. Lightning is refused: its hold invoices need this node
/// online.
async fn destinations(networks: &[Arc<dyn Network>]) -> Result<Vec<GatewayDestination>, String> {
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
        // Claim-key networks give the same target whatever the hash.
        let target = network
            .receive_target(Bytes32([0; 32]), 0, 0)
            .await
            .map_err(|e| format!("cannot receive on {id}: {e}"))?;
        destinations.push(target.destination().map_err(|(id, _)| {
            format!("{id} cannot be paid to an offline payee: its hold invoices need it online")
        })?);
    }
    Ok(destinations)
}

fn endpoint_key(peer: &PeerAddr) -> Result<PublicKey, String> {
    peer.id
        .trim()
        .parse()
        .map_err(|e| format!("endpoint key {}: {e}", peer.id))
}

/// Check `transport` speaks as this node, whose payee key is the
/// identity the servers expect, and return that key's secret.
fn payee_secret(keys: &NodeKeys, transport: &Transport) -> Result<[u8; 32], String> {
    if transport.peer_id() != endpoint_public_key(&keys.iroh).to_string() {
        return Err("the endpoint does not have this node's identity".into());
    }
    Ok(keys.iroh)
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
    db: &Db,
    keys: &NodeKeys,
    transport: &Transport,
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
    let secret = payee_secret(keys, transport)?;
    let authorization = ReceiveAuthorization::sign(
        &secret,
        AuthorizationKind::Single,
        endpoint_key(&endpoints.gateway)?,
        endpoint_key(&endpoints.preimage_server)?,
        endpoints.preimage_server.relay.clone(),
        description.clone(),
        now,
        expires_at,
        amount_msat,
        amount_msat,
        min_final_timeout_secs,
        destinations(networks).await?,
    )?;
    let mut invoice = issue(
        transport,
        &endpoints,
        &authorization,
        expires_at,
        description,
        metadata,
    )
    .await?;
    invoice.sign_as_payee(&secret)?;
    invoice.verify()?;
    if !matches!(invoice.receiver, InvoiceReceiver::Gateway(_)) {
        return Err("the gateway's invoice is not a gateway invoice".into());
    }
    db.invoices()
        .insert(&StoredInvoice {
            payment_hash: InvoiceHash(invoice.body.payment_hash.to_string()),
            amount_msat,
            expires_at,
            networks: invoice.body.networks.iter().map(Into::into).collect(),
            description: invoice.body.description.clone(),
            metadata: stored_metadata(&invoice.body.metadata),
            preimage: None,
            delegation: Some(Delegation {
                gateway: endpoints.gateway.id.clone(),
                gateway_relay: endpoints.gateway.relay.clone(),
                preimage_server: endpoints.preimage_server.id.clone(),
                authorization: (&authorization).into(),
            }),
            state: InvoiceState::Waiting,
            created_at: now,
            settled_at: None,
        })
        .map_err(db_error)?;
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
        metadata: metadata.clone(),
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
    if issuance.amount_msat != amount_msat || !issuance.matches_metadata(metadata.as_ref()) {
        return Err("preimage server issued the hash for another payment".into());
    }
    let request = Request::GatewayInvoice(GatewayInvoiceRequest {
        authorization: authorization.clone(),
        issuance: issuance.clone(),
        expires_at,
        description: description.clone(),
        metadata: metadata.clone(),
    });
    let invoice = match transport.request(&endpoints.gateway, &request).await? {
        Response::GatewayInvoice(Ok(invoice)) => invoice,
        Response::GatewayInvoice(Err(reason)) | Response::Error(reason) => {
            return Err(format!("gateway refused: {reason}"))
        }
        other => return Err(format!("unexpected answer from gateway: {other:?}")),
    };
    // The gateway's metadata is opaque to the payee: the invoice's
    // signatures cover it, and the preimage server checks what the hash
    // was issued for when it releases.
    let asked = match &invoice {
        Invoice {
            body,
            receiver: InvoiceReceiver::Gateway(receiver),
        } => {
            body.payment_hash == issuance.payment_hash
                && body.amount_msat == amount_msat
                && body.expires_at == expires_at
                && body.description == description
                && body.metadata.is_some()
                && receiver.gateway == authorization.gateway
                && receiver.payee == authorization.payee
                && receiver.gateway_signature.is_some()
                && receiver.payee_signature.is_none()
                && !body.networks.is_empty()
        }
        _ => false,
    };
    if !asked {
        return Err("the gateway's invoice is not the one asked for".into());
    }
    Ok(invoice)
}

/// Let `endpoints.gateway` issue invoices in this node's name while it
/// is offline: between `valid_from` and `valid_until`, for amounts
/// between `min_amount_msat` and `max_amount_msat`, paid on to this
/// node on one of `networks` as for [`create_gateway_invoice`]. With a
/// `description`, every invoice it issues must say exactly that. The
/// gateway may refuse the terms. Records the authorization, so
/// [`redeem_offline_payments`] knows where to look.
#[allow(clippy::too_many_arguments)]
pub async fn authorize_gateway(
    db: &Db,
    keys: &NodeKeys,
    transport: &Transport,
    endpoints: OfflineEndpoints,
    networks: &[Arc<dyn Network>],
    valid_from: u64,
    valid_until: u64,
    min_amount_msat: u64,
    max_amount_msat: u64,
    min_final_timeout_secs: u64,
    description: Option<String>,
) -> Result<ReceiveAuthorization, String> {
    if valid_until <= unix_now() {
        return Err("the authorization must end in the future".into());
    }
    let secret = payee_secret(keys, transport)?;
    let authorization = ReceiveAuthorization::sign(
        &secret,
        AuthorizationKind::Standing,
        endpoint_key(&endpoints.gateway)?,
        endpoint_key(&endpoints.preimage_server)?,
        endpoints.preimage_server.relay.clone(),
        description,
        valid_from,
        valid_until,
        min_amount_msat,
        max_amount_msat,
        min_final_timeout_secs,
        destinations(networks).await?,
    )?;
    let answer = transport
        .request(
            &endpoints.gateway,
            &Request::GatewayAuthorize {
                authorization: authorization.clone(),
            },
        )
        .await?;
    match answer {
        Response::GatewayAuthorized(Ok(())) => {}
        Response::GatewayAuthorized(Err(reason)) | Response::Error(reason) => {
            return Err(format!("gateway refused: {reason}"))
        }
        other => return Err(format!("unexpected answer from gateway: {other:?}")),
    }
    db.full_delegations()
        .upsert(&FullDelegation {
            authorization_id: FullDelegationId(authorization.id()?.to_string()),
            gateway: endpoints.gateway.id,
            gateway_relay: endpoints.gateway.relay,
            preimage_server: endpoints.preimage_server.id,
            authorization: (&authorization).into(),
            created_at: unix_now(),
        })
        .map_err(db_error)?;
    Ok(authorization)
}

/// What [`redeem_offline_payments`] did.
#[derive(Clone, Debug, Default)]
pub struct RedeemReport {
    /// Claimed now: payment hash, network, amount.
    pub claimed: Vec<(Bytes32, NetworkId, u64)>,
    /// Metadata of the invoices claimed now, by payment hash: how an
    /// offline payee learns what a gateway's invoice was for.
    pub metadata: Vec<(Bytes32, Metadata)>,
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
    db: &Db,
    keys: &NodeKeys,
    transport: &Transport,
    preimage_server: &PeerAddr,
    networks: &[Arc<dyn Network>],
    since: u64,
) -> Result<RedeemReport, String> {
    payee_secret(keys, transport)?;
    let answer = transport
        .request(preimage_server, &Request::PreimagePayments { since })
        .await?;
    let payments = match answer {
        Response::PreimagePayments(Ok(payments)) => payments,
        Response::PreimagePayments(Err(reason)) | Response::Error(reason) => {
            return Err(format!("preimage server: {reason}"))
        }
        other => return Err(format!("unexpected answer from preimage server: {other:?}")),
    };
    let mut report = RedeemReport::default();
    for payment in payments {
        let (payment_hash, network, htlc, preimage, metadata) = match payment {
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
                descriptor,
                preimage,
                metadata,
                ..
            } => (
                payment_hash,
                network,
                Htlc {
                    payment_hash,
                    amount_msat,
                    expiry,
                    descriptor,
                },
                preimage,
                metadata,
            ),
        };
        let key = payment_hash.to_string();
        if db
            .transactions()
            .contains(TransactionHash(key.clone()))
            .map_err(db_error)?
        {
            continue;
        }
        match redeem(networks, &network, &htlc, preimage).await {
            Ok(()) => {
                match db
                    .invoices()
                    .get(InvoiceHash(key.clone()))
                    .map_err(db_error)?
                {
                    Some(invoice) => {
                        settle_invoice(db, &invoice, &network, htlc.amount_msat, preimage)?
                    }
                    None => db
                        .transactions()
                        .insert(&Transaction {
                            payment_hash: TransactionHash(key.clone()),
                            direction: Direction::Incoming,
                            amount_msat: htlc.amount_msat,
                            network: network.0.clone(),
                            preimage: preimage.0,
                            at: unix_now(),
                            invoice: None,
                        })
                        .map_err(db_error)?,
                }
                report
                    .claimed
                    .push((payment_hash, network, htlc.amount_msat));
                if let Some(metadata) = metadata {
                    report.metadata.push((payment_hash, metadata));
                }
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
