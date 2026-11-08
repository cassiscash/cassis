//! Wire messages exchanged between payer, routers and payee.
//!
//! A payment over a route of `n` routers runs:
//!
//! 1. **PREPARE** every router concurrently. Each checks the terms and
//!    its liquidity, and answers with the [`HtlcTarget`] its incoming
//!    HTLC must be locked to. The payee gets a [`PreparePayee`] at the
//!    same time, announcing the HTLC it will be COMMITted, and may
//!    refuse the payment before anything is funded.
//! 2. The payer funds the first HTLC, then **EXECUTE**s the routers in
//!    order: each verifies its incoming HTLC, funds its outgoing one to
//!    the next target and returns that HTLC's descriptor.
//! 3. **COMMIT** to the payee with the last descriptor: the payee
//!    verifies and claims its HTLC and returns the preimage.
//! 4. **SETTLE** fans the preimage out to the routers so each can claim
//!    its incoming HTLC immediately (they also watch for it on-chain).
//!
//! **DISCARD** releases PREPARE reservations of an aborted attempt.
//!
//! Every request is one JSON message on its own stream, answered by
//! exactly one [`Response`]. EXECUTE and COMMIT may have to wait for
//! their incoming HTLC to become final (a confirmation, say): they then
//! answer [`Response::Pending`] and keep working, and the payer repeats
//! the same request until it gets the outcome.

use crate::network::{Htlc, HtlcDescriptor, HtlcTarget, NetworkId};
use crate::offline::{
    AuthorizationKind, EndpointKey, PreimageIssuance, ReceiveAuthorization, Signature,
};
use crate::primitives::{Bytes32, OperationId};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

/// Protocol identifier negotiated on every connection.
pub const ALPN: &[u8] = b"cassis-hop/6";

/// Most bytes [`Metadata`] may hold.
pub const MAX_METADATA_BYTES: usize = 128 * 1024;

/// Arbitrary payload the payee attaches to an invoice, handed back to it
/// with PREPARE and COMMIT. Base64 on the wire; at most
/// [`MAX_METADATA_BYTES`], checked when decoding too.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Metadata(Vec<u8>);

impl Metadata {
    pub fn new(bytes: Vec<u8>) -> Result<Self, String> {
        if bytes.len() > MAX_METADATA_BYTES {
            return Err(format!(
                "metadata is {} bytes, at most {MAX_METADATA_BYTES} allowed",
                bytes.len()
            ));
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Serialize for Metadata {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&BASE64.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for Metadata {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        // Refuse oversized payloads before decoding them.
        if encoded.len() > MAX_METADATA_BYTES.div_ceil(3) * 4 {
            return Err(serde::de::Error::custom(format!(
                "metadata exceeds {MAX_METADATA_BYTES} bytes"
            )));
        }
        let bytes = BASE64
            .decode(encoded)
            .map_err(|e| serde::de::Error::custom(format!("metadata: {e}")))?;
        Self::new(bytes).map_err(serde::de::Error::custom)
    }
}

/// Prefix of the message a payee signs an invoice with (see
/// [`Invoice::sign_as_payee`]), so it cannot be mistaken for a
/// signature over anything else.
const PAYEE_SIGNATURE_DOMAIN: &[u8] = b"cassis-invoice/v2/payee\0";
/// Same for a gateway (see [`Invoice::sign_as_gateway`]).
const GATEWAY_SIGNATURE_DOMAIN: &[u8] = b"cassis-invoice/v2/gateway\0";

/// A payment request. Who issued it, and so which signatures it
/// carries, is its [`InvoiceKind`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Invoice {
    pub payment_hash: Bytes32,
    pub amount_msat: u64,
    pub expires_at: u64,
    /// Networks this invoice can be paid on, each with the target the
    /// payer must lock to there.
    pub networks: Vec<InvoiceNetwork>,
    pub description: Option<String>,
    /// Handed back to the endpoint with PREPARE and COMMIT.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Metadata>,
    /// Iroh endpoint PREPARE and COMMIT are sent to: the payee's, or
    /// the gateway's when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iroh_peer_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iroh_relay: Option<String>,
    /// Key of the final payee.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payee: Option<EndpointKey>,
    /// By `payee`, over everything else.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payee_signature: Option<Signature>,
    /// Key of the gateway that is paid in the payee's place.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<EndpointKey>,
    /// By `gateway`, over everything but `payee` and the signatures.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_signature: Option<Signature>,
    /// Key of the preimage server that issued `payment_hash`, on
    /// invoices the gateway issued alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preimage_server: Option<EndpointKey>,
    /// `preimage_server`'s word that it issued `payment_hash` under
    /// `payee_authorization`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preimage_server_issuance: Option<PreimageIssuance>,
    /// The payee's leave for the gateway to issue this invoice, in
    /// place of a payee signature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payee_authorization: Option<ReceiveAuthorization>,
}

/// The three kinds of invoices, by who issued them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvoiceKind {
    /// Issued and signed by the payee, which is paid directly at its
    /// own endpoint.
    Direct,
    /// Issued by a gateway that is paid in the payee's place, for a
    /// hash the payee got from a preimage server, and signed by both.
    Gateway,
    /// Issued by a gateway alone while the payee is offline, under the
    /// payee's standing [`ReceiveAuthorization`] and for a hash its
    /// preimage server vouches for.
    Delegated,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InvoiceNetwork {
    pub network: NetworkId,
    pub target: HtlcTarget,
    /// The receiver's safety margin on this network (see
    /// [`crate::Network::incoming_delta_secs`]): its HTLC must expire at
    /// least this long after COMMIT. The network's default when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub incoming_delta_secs: Option<u64>,
    /// Longest the receiver lets its HTLC on this network run (see
    /// [`crate::Network::max_incoming_lifetime_secs`]); no limit when
    /// absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_incoming_lifetime_secs: Option<u64>,
}

impl Invoice {
    /// Sign as the payee whose secret is `secret`, naming it as `payee`.
    /// A direct invoice must name that same key as its endpoint; on a
    /// gateway's invoice the signature covers the gateway's.
    pub fn sign_as_payee(&mut self, secret: &[u8; 32]) -> Result<(), String> {
        let payee = EndpointKey::from_secret(secret);
        if self.gateway.is_none() && self.endpoint_key()? != payee {
            return Err("invoice names another endpoint than the signing key's".into());
        }
        self.payee = Some(payee);
        self.payee_signature = Some(Signature::sign(secret, &self.payee_message()));
        Ok(())
    }

    /// Sign as the gateway whose secret is `secret`, naming it as
    /// `gateway` and as the endpoint.
    pub fn sign_as_gateway(&mut self, secret: &[u8; 32]) -> Result<(), String> {
        let gateway = EndpointKey::from_secret(secret);
        if self.endpoint_key()? != gateway {
            return Err("invoice names another endpoint than the gateway's".into());
        }
        self.gateway = Some(gateway);
        self.gateway_signature = Some(Signature::sign(secret, &self.gateway_message()));
        Ok(())
    }

    /// Check the invoice is signed as its kind requires, and return that
    /// kind:
    ///
    /// * [`InvoiceKind::Direct`]: no gateway; `payee` is the endpoint
    ///   and signed.
    /// * [`InvoiceKind::Gateway`]: `gateway` is the endpoint and
    ///   signed; `payee` signed too, over the gateway's signature.
    /// * [`InvoiceKind::Delegated`]: `gateway` is the endpoint and
    ///   signed; `payee` signed no invoice but a standing authorization
    ///   naming this gateway and `preimage_server`, whose terms the
    ///   invoice meets, and `preimage_server` vouches for its hash.
    ///
    /// Decoding drops unknown fields, so an invoice carrying fields this
    /// version does not know fails to verify.
    pub fn verify(&self) -> Result<InvoiceKind, String> {
        let endpoint = self.endpoint_key()?;
        let payee = self.payee.ok_or("invoice names no payee")?;
        let Some(gateway) = self.gateway else {
            if self.gateway_signature.is_some()
                || self.preimage_server.is_some()
                || self.preimage_server_issuance.is_some()
                || self.payee_authorization.is_some()
            {
                return Err("an invoice without a gateway carries gateway fields".into());
            }
            if endpoint != payee {
                return Err("invoice names another endpoint than its payee".into());
            }
            self.verify_payee_signature(&payee)?;
            return Ok(InvoiceKind::Direct);
        };
        if endpoint != gateway {
            return Err("invoice names another endpoint than its gateway".into());
        }
        if gateway == payee {
            return Err("the payee cannot be its own gateway".into());
        }
        let signature = self
            .gateway_signature
            .ok_or("invoice is not signed by its gateway")?;
        gateway
            .verify(&self.gateway_message(), &signature)
            .map_err(|_| "invalid invoice signature by the gateway".to_string())?;
        let Some(authorization) = &self.payee_authorization else {
            if self.preimage_server.is_some() || self.preimage_server_issuance.is_some() {
                return Err("a payee-signed gateway invoice carries preimage server fields".into());
            }
            self.verify_payee_signature(&payee)?;
            return Ok(InvoiceKind::Gateway);
        };
        if self.payee_signature.is_some() {
            return Err("an invoice under a payee authorization carries a payee signature".into());
        }
        authorization.verify()?;
        if authorization.kind != AuthorizationKind::Standing {
            return Err("the payee's authorization does not let the gateway issue invoices".into());
        }
        if authorization.payee != payee {
            return Err("the payee's authorization is another payee's".into());
        }
        if authorization.gateway != gateway {
            return Err("the payee's authorization names another gateway".into());
        }
        let preimage_server = self
            .preimage_server
            .ok_or("invoice names no preimage server")?;
        if authorization.preimage_server != preimage_server {
            return Err("the payee's authorization names another preimage server".into());
        }
        if !authorization.allows_amount(self.amount_msat) {
            return Err("the payee did not authorize this amount".into());
        }
        if self.expires_at > authorization.valid_until
            || self.expires_at <= authorization.valid_from
        {
            return Err("invoice expires outside the payee's authorization".into());
        }
        let issuance = self
            .preimage_server_issuance
            .as_ref()
            .ok_or("invoice carries no issuance of its payment hash")?;
        issuance.verify(&preimage_server, authorization)?;
        if issuance.payment_hash != self.payment_hash || issuance.amount_msat != self.amount_msat {
            return Err("the preimage server issued the hash for another payment".into());
        }
        Ok(InvoiceKind::Delegated)
    }

    fn verify_payee_signature(&self, payee: &EndpointKey) -> Result<(), String> {
        let signature = self
            .payee_signature
            .ok_or("invoice is not signed by its payee")?;
        payee
            .verify(&self.payee_message(), &signature)
            .map_err(|_| "invalid invoice signature by the payee".to_string())
    }

    fn endpoint_key(&self) -> Result<EndpointKey, String> {
        self.iroh_peer_id
            .as_deref()
            .ok_or("invoice does not name an endpoint")?
            .parse()
    }

    /// What the payee signs: the invoice without its payee signature, as
    /// JSON.
    fn payee_message(&self) -> Vec<u8> {
        let unsigned = Invoice {
            payee_signature: None,
            ..self.clone()
        };
        let mut message = PAYEE_SIGNATURE_DOMAIN.to_vec();
        message.extend(serde_json::to_vec(&unsigned).expect("invoices serialize"));
        message
    }

    /// What the gateway signs: the invoice without `payee` and the
    /// signatures, as JSON. The payee is added after the gateway signed,
    /// or is bound by the payee's authorization.
    fn gateway_message(&self) -> Vec<u8> {
        let unsigned = Invoice {
            payee: None,
            payee_signature: None,
            gateway_signature: None,
            ..self.clone()
        };
        let mut message = GATEWAY_SIGNATURE_DOMAIN.to_vec();
        message.extend(serde_json::to_vec(&unsigned).expect("invoices serialize"));
        message
    }

    /// Target the payer must lock to when paying on `network`.
    pub fn target_for(&self, network: &NetworkId) -> Option<&HtlcTarget> {
        self.networks
            .iter()
            .find(|entry| entry.network == *network)
            .map(|entry| &entry.target)
    }

    /// The receiver's safety margin when paid on `network`.
    pub fn incoming_delta_for(&self, network: &NetworkId) -> u64 {
        self.networks
            .iter()
            .find(|entry| entry.network == *network)
            .and_then(|entry| entry.incoming_delta_secs)
            .unwrap_or_else(|| network.default_incoming_delta())
    }

    /// Longest the receiver lets its HTLC on `network` run.
    pub fn max_incoming_lifetime_for(&self, network: &NetworkId) -> Option<u64> {
        self.networks
            .iter()
            .find(|entry| entry.network == *network)
            .and_then(|entry| entry.max_incoming_lifetime_secs)
    }
}

/// Ask a router to reserve a hop: receive `amount_msat` on
/// `incoming_network` locked until `incoming_expiry`, forward
/// `outgoing_amount_msat` on `outgoing_network` locked until
/// `outgoing_expiry`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Prepare {
    pub payment_hash: Bytes32,
    pub operation_id: OperationId,
    pub amount_msat: u64,
    pub outgoing_amount_msat: u64,
    pub incoming_network: NetworkId,
    pub outgoing_network: NetworkId,
    pub incoming_expiry: u64,
    pub outgoing_expiry: u64,
}

/// The incoming HTLC of a prepared hop is funded: verify it and fund
/// the outgoing HTLC to `outgoing_target` (the next hop's PREPARE
/// answer, or the payee's invoice target).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Execute {
    pub payment_hash: Bytes32,
    pub operation_id: OperationId,
    pub incoming_descriptor: HtlcDescriptor,
    pub outgoing_target: HtlcTarget,
}

/// Release the reservation of a PREPARE that will not be executed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Discard {
    pub payment_hash: Bytes32,
    pub operation_id: OperationId,
}

/// Payer to payee, once a route reaching it is planned and before
/// anything is funded: its HTLC will be on `network`, expiring at
/// `expiry`. Informative: nothing is reserved, but the payee may refuse
/// the payment.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreparePayee {
    pub payment_hash: Bytes32,
    pub network: NetworkId,
    pub expiry: u64,
    /// The invoice's [`Invoice::metadata`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Metadata>,
    /// The whole invoice.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invoice: Option<Invoice>,
}

/// Payer to payee: the final HTLC is funded on `network`; claim it and
/// reveal the preimage.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Commit {
    pub payment_hash: Bytes32,
    pub network: NetworkId,
    pub expiry: u64,
    pub descriptor: HtlcDescriptor,
    /// The invoice's [`Invoice::metadata`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Metadata>,
    /// The whole invoice.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invoice: Option<Invoice>,
}

/// Payer to router: the preimage of an executed hop, so the router can
/// claim its incoming HTLC without waiting to observe it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Settle {
    pub operation_id: OperationId,
    pub preimage: Bytes32,
}

/// Gateway to preimage server: the HTLC it funded to the payee for
/// an invoice it is paid for. Answered with the preimage once the HTLC
/// checks out, [`Response::Pending`] while it is not final yet.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreimageRelease {
    pub authorization: ReceiveAuthorization,
    pub issuance: PreimageIssuance,
    pub network: NetworkId,
    pub htlc: Htlc,
}

/// Payee to gateway: issue an invoice for the hash the preimage server
/// issued it under `authorization`, which the payee then signs too.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GatewayInvoiceRequest {
    /// A [`AuthorizationKind::Single`] authorization.
    pub authorization: ReceiveAuthorization,
    pub issuance: PreimageIssuance,
    pub expires_at: u64,
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Metadata>,
    /// Where the gateway reaches the preimage server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preimage_server_relay: Option<String>,
}

/// Anyone to gateway: an invoice paying `payee`, issued under one of
/// its standing authorizations.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GatewayInvoiceFor {
    pub payee: EndpointKey,
    pub amount_msat: u64,
    /// The gateway's default, capped by the authorization, when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Metadata>,
}

/// What the preimage server logged for one of the payee's invoices.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ReceivedPayment {
    /// An HTLC a gateway funded to the payee and the server verified
    /// before releasing its preimage: still to be claimed by the payee
    /// with `preimage`. `descriptor` is the network-specific part
    /// (cashu proofs, a lockup output, ...).
    Received {
        payment_hash: Bytes32,
        network: NetworkId,
        amount_msat: u64,
        expiry: u64,
        target: HtlcTarget,
        descriptor: HtlcDescriptor,
        preimage: Bytes32,
        at: u64,
    },
    /// A payment the server refused or could not verify. Servers may
    /// not log these.
    Failed {
        payment_hash: Bytes32,
        reason: String,
        at: u64,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Request {
    Prepare(Prepare),
    PreparePayee(PreparePayee),
    Execute(Execute),
    Discard(Discard),
    Commit(Commit),
    Settle(Settle),
    /// Payee (single authorization) or gateway (standing) to preimage
    /// server: a payment hash for an invoice of `amount_msat`.
    PreimageIssue {
        authorization: ReceiveAuthorization,
        amount_msat: u64,
    },
    PreimageRelease(PreimageRelease),
    /// Payee to preimage server: what it logged since unix time `since`.
    PreimagePayments {
        since: u64,
    },
    GatewayInvoice(GatewayInvoiceRequest),
    /// Payee to gateway: let it issue invoices under this standing
    /// authorization.
    GatewayAuthorize {
        authorization: ReceiveAuthorization,
        /// Where the gateway reaches the preimage server.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        preimage_server_relay: Option<String>,
    },
    GatewayInvoiceFor(GatewayInvoiceFor),
}

// One per request, so the size of its largest variant does not matter.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Response {
    /// Target to lock the hop's incoming HTLC to, or why the hop
    /// refuses.
    Prepared(Result<HtlcTarget, String>),
    /// The payee expects the announced HTLC, or why it refuses.
    PayeePrepared(Result<(), String>),
    /// Descriptor of the hop's freshly funded outgoing HTLC.
    Executed(HtlcDescriptor),
    Discarded,
    /// The preimage the payee claimed with.
    Committed(Bytes32),
    Settled,
    /// EXECUTE or COMMIT accepted and still in progress: repeat the
    /// request to learn its outcome.
    Pending,
    Error(String),
    PreimageIssued(Result<PreimageIssuance, String>),
    PreimageReleased(Result<Bytes32, String>),
    PreimagePayments(Result<Vec<ReceivedPayment>, String>),
    /// An invoice the gateway issued and signed, or why it refuses.
    GatewayInvoice(Result<Invoice, String>),
    GatewayAuthorized(Result<(), String>),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_round_trip_through_json() {
        let request = Request::Execute(Execute {
            payment_hash: Bytes32([0x42; 32]),
            operation_id: OperationId::random(),
            incoming_descriptor: HtlcDescriptor::Cashu {
                proofs_b64: vec!["eyJhbW91bnQiOjF9".into()],
            },
            outgoing_target: HtlcTarget::LightningInvoice("lnbc...".into()),
        });
        let bytes = serde_json::to_vec(&request).unwrap();
        let Request::Execute(decoded) = serde_json::from_slice(&bytes).unwrap() else {
            panic!("expected execute");
        };
        assert_eq!(
            decoded.outgoing_target,
            HtlcTarget::LightningInvoice("lnbc...".into())
        );
        let response = Response::Prepared(Err("no liquidity".into()));
        let bytes = serde_json::to_vec(&response).unwrap();
        assert!(matches!(
            serde_json::from_slice(&bytes).unwrap(),
            Response::Prepared(Err(reason)) if reason == "no liquidity"
        ));
    }

    #[test]
    fn invoice_decodes_without_optional_fields() {
        let decoded: Invoice = serde_json::from_str(
            r#"{
                "payment_hash": "0000000000000000000000000000000000000000000000000000000000000001",
                "amount_msat": 1000,
                "expires_at": 3000,
                "networks": [{
                    "network": "cashu::localhost",
                    "target": {"XOnlyPubKey": "17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917"}
                }],
                "description": null
            }"#,
        )
        .unwrap();
        assert!(decoded
            .target_for(&NetworkId("cashu::localhost".into()))
            .is_some());
        assert!(decoded.metadata.is_none());
    }

    fn endpoint(secret: &[u8; 32]) -> String {
        EndpointKey::from_secret(secret).to_string()
    }

    fn unsigned_invoice(endpoint_secret: &[u8; 32]) -> Invoice {
        Invoice {
            payment_hash: Bytes32([1; 32]),
            amount_msat: 1000,
            expires_at: 3000,
            networks: vec![InvoiceNetwork {
                network: NetworkId("cashu::localhost".into()),
                target: HtlcTarget::XOnlyPubKey(
                    ritualistic::SecretKey::from_bytes([3; 32])
                        .unwrap()
                        .pubkey(),
                ),
                incoming_delta_secs: None,
                max_incoming_lifetime_secs: None,
            }],
            description: Some("coffee".into()),
            metadata: Some(Metadata::new(b"order 42".to_vec()).unwrap()),
            iroh_peer_id: Some(endpoint(endpoint_secret)),
            iroh_relay: None,
            payee: None,
            payee_signature: None,
            gateway: None,
            gateway_signature: None,
            preimage_server: None,
            preimage_server_issuance: None,
            payee_authorization: None,
        }
    }

    fn signed_invoice(secret: &[u8; 32]) -> Invoice {
        let mut invoice = unsigned_invoice(secret);
        invoice.sign_as_payee(secret).unwrap();
        invoice
    }

    const PAYEE: [u8; 32] = [7; 32];
    const GATEWAY: [u8; 32] = [8; 32];
    const PREIMAGE_SERVER: [u8; 32] = [9; 32];

    fn authorization(kind: AuthorizationKind) -> ReceiveAuthorization {
        ReceiveAuthorization::sign(
            &PAYEE,
            kind,
            EndpointKey::from_secret(&GATEWAY),
            EndpointKey::from_secret(&PREIMAGE_SERVER),
            1000,
            5000,
            1000,
            1000,
            crate::offline::DEFAULT_MIN_FINAL_TIMEOUT_SECS,
            vec![crate::offline::Destination {
                network: NetworkId("cashu::localhost".into()),
                target: HtlcTarget::XOnlyPubKey(
                    ritualistic::SecretKey::from_bytes([4; 32])
                        .unwrap()
                        .pubkey(),
                ),
            }],
        )
        .unwrap()
    }

    fn issuance(authorization: &ReceiveAuthorization) -> PreimageIssuance {
        let mut issuance = PreimageIssuance {
            payment_hash: Bytes32([1; 32]),
            amount_msat: 1000,
            authorization: authorization.id().unwrap(),
            nonce: Bytes32([0; 32]),
            signature: Signature([0; 64]),
        };
        issuance.sign(&PREIMAGE_SERVER);
        issuance
    }

    /// Issued by the gateway, then signed by the payee.
    fn gateway_invoice() -> Invoice {
        let mut invoice = unsigned_invoice(&GATEWAY);
        invoice.sign_as_gateway(&GATEWAY).unwrap();
        assert!(invoice.payee.is_none());
        invoice.sign_as_payee(&PAYEE).unwrap();
        invoice
    }

    /// Issued by the gateway alone.
    fn delegated_invoice() -> Invoice {
        let authorization = authorization(AuthorizationKind::Standing);
        let mut invoice = unsigned_invoice(&GATEWAY);
        invoice.payee = Some(authorization.payee);
        invoice.preimage_server = Some(authorization.preimage_server);
        invoice.preimage_server_issuance = Some(issuance(&authorization));
        invoice.payee_authorization = Some(authorization);
        invoice.sign_as_gateway(&GATEWAY).unwrap();
        invoice
    }

    #[test]
    fn invoice_signature_covers_every_field() {
        let invoice = signed_invoice(&PAYEE);
        assert_eq!(invoice.verify().unwrap(), InvoiceKind::Direct);
        let decoded: Invoice =
            serde_json::from_str(&serde_json::to_string(&invoice).unwrap()).unwrap();
        decoded.verify().unwrap();

        let mut tampered = invoice.clone();
        tampered.amount_msat += 1;
        assert!(tampered.verify().is_err());
        let mut tampered = invoice.clone();
        tampered.metadata = None;
        assert!(tampered.verify().is_err());
        // Pointing the invoice at another endpoint breaks it, and that
        // endpoint's key cannot sign for the first one.
        let mut redirected = invoice.clone();
        redirected.iroh_peer_id = Some(endpoint(&[8; 32]));
        assert!(redirected.verify().is_err());
        assert!(invoice.clone().sign_as_payee(&[8; 32]).is_err());
        let mut unsigned = invoice;
        unsigned.payee_signature = None;
        assert!(unsigned.verify().is_err());
    }

    #[test]
    fn gateway_invoices_need_both_signatures() {
        let invoice = gateway_invoice();
        assert_eq!(invoice.verify().unwrap(), InvoiceKind::Gateway);
        let decoded: Invoice =
            serde_json::from_str(&serde_json::to_string(&invoice).unwrap()).unwrap();
        assert_eq!(decoded.verify().unwrap(), InvoiceKind::Gateway);

        let mut unsigned = invoice.clone();
        unsigned.payee_signature = None;
        assert!(unsigned.verify().is_err());
        // The payee signed over the gateway: another one cannot step in.
        let mut swapped = invoice.clone();
        swapped.gateway = Some(EndpointKey::from_secret(&[10; 32]));
        swapped.iroh_peer_id = Some(endpoint(&[10; 32]));
        swapped.sign_as_gateway(&[10; 32]).unwrap();
        assert!(swapped.verify().is_err());
        // The gateway's signature leaves the payee out, but the payee's
        // covers it.
        let mut other_payee = invoice.clone();
        other_payee.payee = Some(EndpointKey::from_secret(&[11; 32]));
        assert!(other_payee.verify().is_err());
        let mut tampered = invoice;
        tampered.amount_msat += 1;
        assert!(tampered.verify().is_err());
    }

    #[test]
    fn delegated_invoices_follow_the_authorization() {
        let invoice = delegated_invoice();
        assert_eq!(invoice.verify().unwrap(), InvoiceKind::Delegated);
        let decoded: Invoice =
            serde_json::from_str(&serde_json::to_string(&invoice).unwrap()).unwrap();
        assert_eq!(decoded.verify().unwrap(), InvoiceKind::Delegated);

        // Outside the authorized amounts, even signed by the gateway.
        let mut more = invoice.clone();
        more.amount_msat = 2000;
        more.sign_as_gateway(&GATEWAY).unwrap();
        assert!(more.verify().is_err());
        // Expiring after the authorization does.
        let mut later = invoice.clone();
        later.expires_at = 6000;
        later.sign_as_gateway(&GATEWAY).unwrap();
        assert!(later.verify().unwrap_err().contains("outside"));
        // Another payee's name.
        let mut renamed = invoice.clone();
        renamed.payee = Some(EndpointKey::from_secret(&[11; 32]));
        assert!(renamed.verify().is_err());
        // A hash the gateway made up.
        let mut made_up = invoice.clone();
        made_up.payment_hash = Bytes32([2; 32]);
        made_up.sign_as_gateway(&GATEWAY).unwrap();
        assert!(made_up.verify().is_err());
        // A single authorization does not let the gateway issue alone.
        let single = authorization(AuthorizationKind::Single);
        let mut unauthorized = invoice.clone();
        unauthorized.preimage_server_issuance = Some(issuance(&single));
        unauthorized.payee_authorization = Some(single);
        unauthorized.sign_as_gateway(&GATEWAY).unwrap();
        assert!(unauthorized.verify().unwrap_err().contains("does not let"));
        // Another gateway cannot reuse the authorization.
        let mut stolen = invoice;
        stolen.gateway = None;
        stolen.iroh_peer_id = Some(endpoint(&[10; 32]));
        stolen.sign_as_gateway(&[10; 32]).unwrap();
        assert!(stolen.verify().unwrap_err().contains("another gateway"));
    }

    #[test]
    fn metadata_is_base64_and_bounded() {
        let metadata = Metadata::new(b"order 42".to_vec()).unwrap();
        let json = serde_json::to_string(&metadata).unwrap();
        assert_eq!(json, r#""b3JkZXIgNDI=""#);
        assert_eq!(serde_json::from_str::<Metadata>(&json).unwrap(), metadata);

        assert!(Metadata::new(vec![0; MAX_METADATA_BYTES]).is_ok());
        assert!(Metadata::new(vec![0; MAX_METADATA_BYTES + 1]).is_err());
        let oversized = format!(r#""{}""#, BASE64.encode(vec![0; MAX_METADATA_BYTES + 1]));
        assert!(serde_json::from_str::<Metadata>(&oversized).is_err());
    }
}
