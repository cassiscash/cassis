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

use crate::network::{HtlcDescriptor, HtlcTarget, NetworkId};
use crate::primitives::{Bytes32, OperationId, XOnlyPubKey};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

/// Protocol identifier negotiated on every connection.
pub const ALPN: &[u8] = b"cassis-hop/5";

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

/// A payment request created by the payee.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Invoice {
    pub payment_hash: Bytes32,
    pub amount_msat: u64,
    /// Node key of the payee.
    pub payee: XOnlyPubKey,
    pub expires_at: u64,
    /// Networks this invoice can be paid on, each with the target the
    /// payer must lock to there.
    pub networks: Vec<InvoiceNetwork>,
    pub description: Option<String>,
    /// Handed back to the payee's endpoint with PREPARE and COMMIT.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Metadata>,
    /// Iroh endpoint of the payee, where PREPARE and COMMIT are sent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iroh_peer_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iroh_relay: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InvoiceNetwork {
    pub network: NetworkId,
    pub target: HtlcTarget,
    /// The payee's safety margin on this network (see
    /// [`crate::Network::incoming_delta_secs`]): its HTLC must expire at
    /// least this long after COMMIT. The network's default when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub incoming_delta_secs: Option<u64>,
    /// Longest the payee lets its HTLC on this network run (see
    /// [`crate::Network::max_incoming_lifetime_secs`]); no limit when
    /// absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_incoming_lifetime_secs: Option<u64>,
}

impl Invoice {
    /// Target the payer must lock to when paying on `network`.
    pub fn target_for(&self, network: &NetworkId) -> Option<&HtlcTarget> {
        self.networks
            .iter()
            .find(|entry| entry.network == *network)
            .map(|entry| &entry.target)
    }

    /// The payee's safety margin when paid on `network`.
    pub fn incoming_delta_for(&self, network: &NetworkId) -> u64 {
        self.networks
            .iter()
            .find(|entry| entry.network == *network)
            .and_then(|entry| entry.incoming_delta_secs)
            .unwrap_or_else(|| network.default_incoming_delta())
    }

    /// Longest the payee lets its HTLC on `network` run.
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
}

/// Payer to router: the preimage of an executed hop, so the router can
/// claim its incoming HTLC without waiting to observe it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Settle {
    pub operation_id: OperationId,
    pub preimage: Bytes32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Request {
    Prepare(Prepare),
    PreparePayee(PreparePayee),
    Execute(Execute),
    Discard(Discard),
    Commit(Commit),
    Settle(Settle),
}

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
                "payee": "17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917",
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
