//! Wire messages exchanged between payer, routers and payee.
//!
//! A payment over a route of `n` routers runs:
//!
//! 1. **PREPARE** every router concurrently. Each checks the terms and
//!    its liquidity, and answers with the [`InvoiceTarget`] its incoming
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

use crate::network::{Htlc, HtlcDescriptor, InvoiceTarget, NetworkId};
use crate::offline::{
    endpoint_public_key, AuthorizationKind, PreimageIssuance, ReceiveAuthorization, Signature,
};
use crate::primitives::{Bytes32, OperationId};
use crate::signing::SigningMessage;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use iroh_base::PublicKey;
use serde::ser::SerializeStruct;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeMap;
use std::fmt;

/// Protocol identifier negotiated on every connection.
pub const ALPN: &[u8] = b"cassis-hop/9";

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

    /// SHA-256 of the bytes: what a [`PreimageIssuance`] commits to.
    pub fn hash(&self) -> Bytes32 {
        use sha2::{Digest, Sha256};
        Bytes32(Sha256::digest(&self.0).into())
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

/// Domain of the message a payee signs an invoice with (see
/// [`Invoice::sign_as_payee`]), so it cannot be mistaken for a
/// signature over anything else.
const PAYEE_SIGNATURE_DOMAIN: &str = "cassis/invoice/payee/v3";
/// Same for a gateway (see [`Invoice::sign_as_gateway`]).
const GATEWAY_SIGNATURE_DOMAIN: &str = "cassis/invoice/gateway/v3";

/// A payment request: the payment terms every invoice carries, plus the
/// [`InvoiceReceiver`] that issued it and carries its signatures.
#[derive(Clone, Debug)]
pub struct Invoice {
    pub body: InvoiceBody,
    pub receiver: InvoiceReceiver,
}

/// The payment terms every invoice carries, whatever its receiver.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InvoiceBody {
    pub payment_hash: Bytes32,
    pub amount_msat: u64,
    pub expires_at: u64,
    /// Networks this invoice can be paid on, each with the target the
    /// payer must lock to there.
    pub networks: Vec<InvoiceNetwork>,
    pub description: Option<String>,
    /// Handed back to the endpoint with PREPARE and COMMIT.
    pub metadata: Option<Metadata>,
    /// Relay the payer reaches the invoice's endpoint through, if known.
    pub iroh_relay: Option<String>,
}

/// The three kinds of invoices, by who issued them and how the payer
/// reaches the payee.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
pub enum InvoiceReceiver {
    /// Issued and signed by the payee, which is paid directly at its
    /// own endpoint.
    Direct(DirectReceiver),
    /// Issued by a gateway that is paid in the payee's place, for a
    /// hash the payee got from a preimage server, and signed by both.
    Gateway(GatewayReceiver),
    /// Issued by a gateway alone while the payee is offline, under the
    /// payee's standing [`ReceiveAuthorization`] and for a hash its
    /// preimage server vouches for.
    Delegated(DelegatedReceiver),
}

/// A direct invoice's receiver: the payee itself.
#[derive(Clone, Debug)]
pub struct DirectReceiver {
    /// Key of the final payee, which is also the endpoint the payer
    /// talks to.
    pub payee: PublicKey,
    /// By `payee`, over everything else.
    pub payee_signature: Option<Signature>,
}

/// A gateway invoice's receiver: the gateway the payer talks to, and
/// the payee behind it. The payee signs after the gateway, so its
/// signature is absent until it does.
#[derive(Clone, Debug)]
pub struct GatewayReceiver {
    /// Key of the final payee.
    pub payee: PublicKey,
    /// Key of the gateway that is paid in the payee's place, and the
    /// endpoint the payer talks to.
    pub gateway: PublicKey,
    /// By `gateway`, over everything but the signatures.
    pub gateway_signature: Option<Signature>,
    /// By `payee`, over everything but its own signature.
    pub payee_signature: Option<Signature>,
}

/// A delegated invoice's receiver: a gateway issuing alone under the
/// payee's standing authorization.
#[derive(Clone, Debug)]
pub struct DelegatedReceiver {
    /// Key of the final payee.
    pub payee: PublicKey,
    /// Key of the gateway that is paid in the payee's place, and the
    /// endpoint the payer talks to.
    pub gateway: PublicKey,
    /// By `gateway`, over everything but the signatures.
    pub gateway_signature: Option<Signature>,
    /// Key of the preimage server that issued `payment_hash`.
    pub preimage_server: PublicKey,
    /// `preimage_server`'s word that it issued `payment_hash` under
    /// `payee_authorization`.
    pub preimage_server_issuance: PreimageIssuance,
    /// The payee's leave for the gateway to issue this invoice, in
    /// place of a payee signature.
    pub payee_authorization: ReceiveAuthorization,
}

impl InvoiceReceiver {
    /// The iroh endpoint PREPARE and COMMIT are sent to: the payee's, or
    /// the gateway's when there is one.
    pub fn iroh_peer_id(&self) -> &PublicKey {
        match self {
            Self::Direct(receiver) => &receiver.payee,
            Self::Gateway(receiver) => &receiver.gateway,
            Self::Delegated(receiver) => &receiver.gateway,
        }
    }

    /// Key of the final payee, whoever the payer talks to.
    pub fn payee(&self) -> &PublicKey {
        match self {
            Self::Direct(receiver) => &receiver.payee,
            Self::Gateway(receiver) => &receiver.payee,
            Self::Delegated(receiver) => &receiver.payee,
        }
    }

    /// Key of the gateway paid in the payee's place, if any.
    pub fn gateway(&self) -> Option<&PublicKey> {
        match self {
            Self::Direct(_) => None,
            Self::Gateway(receiver) => Some(&receiver.gateway),
            Self::Delegated(receiver) => Some(&receiver.gateway),
        }
    }
}

/// One network an invoice can be paid on.
///
/// Crosses the wire as its [`InvoiceTarget`], plus
/// `incoming_delta_secs` when set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvoiceNetwork {
    pub target: InvoiceTarget,
    /// The receiver's safety margin on this network (see
    /// [`crate::Network::incoming_delta_secs`]): its HTLC must expire at
    /// least this long after COMMIT. The network's default when absent.
    pub incoming_delta_secs: Option<u64>,
}

impl Serialize for InvoiceNetwork {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut entry = serializer.serialize_struct("InvoiceNetwork", 3)?;
        entry.serialize_field("network", self.target.network())?;
        entry.serialize_field("target", &BTreeMap::from(self.target.tagged_target()))?;
        optional_field(&mut entry, "incoming_delta_secs", &self.incoming_delta_secs)?;
        entry.end()
    }
}

impl<'de> Deserialize<'de> for InvoiceNetwork {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = InvoiceNetwork;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a network an invoice can be paid on")
            }

            fn visit_map<A: de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut network = None;
                let mut target = None;
                let mut incoming_delta_secs = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "network" => network = Some(map.next_value()?),
                        "target" => target = Some(map.next_value()?),
                        "incoming_delta_secs" => incoming_delta_secs = map.next_value()?,
                        _ => {
                            map.next_value::<de::IgnoredAny>()?;
                        }
                    }
                }
                let network = network.ok_or_else(|| de::Error::missing_field("network"))?;
                let target = target.ok_or_else(|| de::Error::missing_field("target"))?;
                Ok(InvoiceNetwork {
                    target: InvoiceTarget::from_tagged(network, target)
                        .map_err(de::Error::custom)?,
                    incoming_delta_secs,
                })
            }
        }

        deserializer.deserialize_struct(
            "InvoiceNetwork",
            &["network", "target", "incoming_delta_secs"],
            Visitor,
        )
    }
}

/// Serialize `value` as field `key` of a struct, or skip it when absent.
fn optional_field<S: SerializeStruct, T: Serialize>(
    serializer: &mut S,
    key: &'static str,
    value: &Option<T>,
) -> Result<(), S::Error> {
    match value {
        Some(value) => serializer.serialize_field(key, value),
        None => serializer.skip_field(key),
    }
}

impl Invoice {
    /// A direct invoice: `body`, signed by `secret` as its payee and
    /// endpoint.
    pub fn direct(body: InvoiceBody, secret: &[u8; 32]) -> Self {
        let payee = endpoint_public_key(secret);
        let mut invoice = Self {
            body,
            receiver: InvoiceReceiver::Direct(DirectReceiver {
                payee,
                payee_signature: None,
            }),
        };
        invoice
            .sign_as_payee(secret)
            .expect("a direct invoice signs for its own payee");
        invoice
    }

    /// A gateway invoice for `payee`, signed by `secret` as the
    /// gateway. The payee signs it later.
    pub fn gateway_invoice(body: InvoiceBody, payee: PublicKey, secret: &[u8; 32]) -> Self {
        let gateway = endpoint_public_key(secret);
        let mut invoice = Self {
            body,
            receiver: InvoiceReceiver::Gateway(GatewayReceiver {
                payee,
                gateway,
                gateway_signature: None,
                payee_signature: None,
            }),
        };
        invoice
            .sign_as_gateway(secret)
            .expect("a gateway invoice signs for its own gateway");
        invoice
    }

    /// A delegated invoice for `payee`, issued and signed by `secret` as
    /// the gateway under `payee_authorization`.
    pub fn delegated(
        body: InvoiceBody,
        payee: PublicKey,
        secret: &[u8; 32],
        preimage_server: PublicKey,
        preimage_server_issuance: PreimageIssuance,
        payee_authorization: ReceiveAuthorization,
    ) -> Self {
        let gateway = endpoint_public_key(secret);
        let mut invoice = Self {
            body,
            receiver: InvoiceReceiver::Delegated(DelegatedReceiver {
                payee,
                gateway,
                gateway_signature: None,
                preimage_server,
                preimage_server_issuance,
                payee_authorization,
            }),
        };
        invoice
            .sign_as_gateway(secret)
            .expect("a delegated invoice signs for its own gateway");
        invoice
    }

    /// Sign as the payee whose secret is `secret`. A direct invoice must
    /// name that same key as its payee; a gateway's invoice must already
    /// name it as its payee, and the signature covers the gateway's.
    /// Delegated invoices carry no payee signature.
    pub fn sign_as_payee(&mut self, secret: &[u8; 32]) -> Result<(), String> {
        let payee = endpoint_public_key(secret);
        match &self.receiver {
            InvoiceReceiver::Direct(receiver) if receiver.payee != payee => {
                return Err("invoice names another payee than the signing key's".into());
            }
            InvoiceReceiver::Gateway(receiver) if receiver.payee != payee => {
                return Err("the gateway issued the invoice for another payee".into());
            }
            InvoiceReceiver::Delegated(_) => {
                return Err("a delegated invoice carries no payee signature".into());
            }
            _ => {}
        }
        let signature = Signature::sign(secret, &self.payee_message());
        match &mut self.receiver {
            InvoiceReceiver::Direct(receiver) => receiver.payee_signature = Some(signature),
            InvoiceReceiver::Gateway(receiver) => receiver.payee_signature = Some(signature),
            InvoiceReceiver::Delegated(_) => unreachable!(),
        }
        Ok(())
    }

    /// Sign as the gateway whose secret is `secret`. The invoice must
    /// already name that key as its gateway; the signature covers the
    /// payee too.
    pub fn sign_as_gateway(&mut self, secret: &[u8; 32]) -> Result<(), String> {
        let gateway = endpoint_public_key(secret);
        match &self.receiver {
            InvoiceReceiver::Direct(_) => {
                return Err("a direct invoice has no gateway".into());
            }
            InvoiceReceiver::Gateway(receiver) if receiver.gateway != gateway => {
                return Err("invoice names another gateway than the signing key's".into());
            }
            InvoiceReceiver::Delegated(receiver) if receiver.gateway != gateway => {
                return Err("invoice names another gateway than the signing key's".into());
            }
            _ => {}
        }
        let signature = Signature::sign(secret, &self.gateway_message());
        match &mut self.receiver {
            InvoiceReceiver::Direct(_) => unreachable!(),
            InvoiceReceiver::Gateway(receiver) => receiver.gateway_signature = Some(signature),
            InvoiceReceiver::Delegated(receiver) => receiver.gateway_signature = Some(signature),
        }
        Ok(())
    }

    /// Check the invoice is signed as its receiver requires:
    ///
    /// * [`InvoiceReceiver::Direct`]: signed by the payee.
    /// * [`InvoiceReceiver::Gateway`]: signed by the gateway (over the
    ///   payee too) and by the payee (over the gateway's signature).
    /// * [`InvoiceReceiver::Delegated`]: signed by the gateway; the
    ///   payee signed no invoice but a standing authorization naming
    ///   this gateway and preimage server, whose terms the invoice
    ///   meets, and the preimage server vouches for its hash, amount
    ///   and metadata.
    ///
    /// Decoding drops unknown fields, and the signatures cover every
    /// field of a version that knew them, so an invoice carrying fields
    /// this version does not know fails to verify.
    pub fn verify(&self) -> Result<(), String> {
        match &self.receiver {
            InvoiceReceiver::Direct(receiver) => {
                let signature = receiver
                    .payee_signature
                    .ok_or("invoice is not signed by its payee")?;
                signature
                    .verify(&receiver.payee, &self.payee_message())
                    .map_err(|_| "invalid invoice signature by the payee".to_string())
            }
            InvoiceReceiver::Gateway(receiver) => {
                if receiver.payee == receiver.gateway {
                    return Err("the payee cannot be its own gateway".into());
                }
                let signature = receiver
                    .gateway_signature
                    .ok_or("invoice is not signed by its gateway")?;
                signature
                    .verify(&receiver.gateway, &self.gateway_message())
                    .map_err(|_| "invalid invoice signature by the gateway".to_string())?;
                let signature = receiver
                    .payee_signature
                    .ok_or("invoice is not signed by its payee")?;
                signature
                    .verify(&receiver.payee, &self.payee_message())
                    .map_err(|_| "invalid invoice signature by the payee".to_string())
            }
            InvoiceReceiver::Delegated(receiver) => {
                if receiver.payee == receiver.gateway {
                    return Err("the payee cannot be its own gateway".into());
                }
                let signature = receiver
                    .gateway_signature
                    .ok_or("invoice is not signed by its gateway")?;
                signature
                    .verify(&receiver.gateway, &self.gateway_message())
                    .map_err(|_| "invalid invoice signature by the gateway".to_string())?;
                let authorization = &receiver.payee_authorization;
                authorization.verify()?;
                if authorization.kind != AuthorizationKind::Standing {
                    return Err(
                        "the payee's authorization does not let the gateway issue invoices".into(),
                    );
                }
                if authorization.payee != receiver.payee {
                    return Err("the payee's authorization is another payee's".into());
                }
                if authorization.gateway != receiver.gateway {
                    return Err("the payee's authorization names another gateway".into());
                }
                if authorization.preimage_server != receiver.preimage_server {
                    return Err("the payee's authorization names another preimage server".into());
                }
                if !authorization.allows_amount(self.body.amount_msat) {
                    return Err("the payee did not authorize this amount".into());
                }
                if !authorization.allows_description(self.body.description.as_deref()) {
                    return Err(
                        "the invoice does not carry the description the payee authorized".into(),
                    );
                }
                if self.body.expires_at > authorization.valid_until
                    || self.body.expires_at <= authorization.valid_from
                {
                    return Err("invoice expires outside the payee's authorization".into());
                }
                let issuance = &receiver.preimage_server_issuance;
                issuance.verify(&receiver.preimage_server, authorization)?;
                // The metadata is for the gateway (or the payee): the
                // payer only carries it back, unread.
                if issuance.payment_hash != self.body.payment_hash
                    || issuance.amount_msat != self.body.amount_msat
                {
                    return Err("the preimage server issued the hash for another payment".into());
                }
                Ok(())
            }
        }
    }

    /// What the payee signs: the invoice's terms and, on a gateway
    /// invoice, the gateway's signature (as an option: the payee signs
    /// after the gateway). See [`Invoice::write_terms`].
    fn payee_message(&self) -> Vec<u8> {
        let mut message = SigningMessage::new(PAYEE_SIGNATURE_DOMAIN);
        self.write_terms(&mut message);
        if let InvoiceReceiver::Gateway(receiver) = &self.receiver {
            message.option(receiver.gateway_signature.as_ref(), |message, signature| {
                message.raw(&signature.0)
            });
        }
        message.into_bytes()
    }

    /// What the gateway signs: the invoice's terms. See
    /// [`Invoice::write_terms`].
    fn gateway_message(&self) -> Vec<u8> {
        let mut message = SigningMessage::new(GATEWAY_SIGNATURE_DOMAIN);
        self.write_terms(&mut message);
        message.into_bytes()
    }

    /// Every field but the signatures, in [`crate::signing`]'s encoding:
    ///
    /// ```text
    /// bytes32 payment hash
    /// u64     amount msat
    /// u64     expires at (unix seconds)
    /// count   networks, each:
    ///   str     network id
    ///   target  what the payer locks to there
    ///   option  u64  incoming delta secs
    /// option  str    description
    /// option  bytes  metadata
    /// option  str    iroh relay
    /// u8      receiver: 0 direct, 1 gateway, 2 delegated
    /// key     payee
    /// -- gateway and delegated:
    /// key     gateway
    /// -- delegated:
    /// key     preimage server
    /// bytes32 payee authorization id
    /// sig     payee authorization signature
    /// bytes32 issuance payment hash
    /// u64     issuance amount msat
    /// option  bytes32  issuance metadata hash
    /// bytes32 issuance authorization id
    /// bytes32 issuance nonce
    /// sig     issuance signature
    /// ```
    fn write_terms(&self, message: &mut SigningMessage) {
        let body = &self.body;
        message
            .bytes32(&body.payment_hash)
            .u64(body.amount_msat)
            .u64(body.expires_at)
            .count(body.networks.len());
        for entry in &body.networks {
            message
                .invoice_target(&entry.target)
                .option(entry.incoming_delta_secs, SigningMessage::u64);
        }
        message
            .option(body.description.as_deref(), SigningMessage::str)
            .option(
                body.metadata.as_ref().map(Metadata::as_bytes),
                SigningMessage::bytes,
            )
            .option(body.iroh_relay.as_deref(), SigningMessage::str);
        match &self.receiver {
            InvoiceReceiver::Direct(receiver) => {
                message.u8(0).key(&receiver.payee);
            }
            InvoiceReceiver::Gateway(receiver) => {
                message.u8(1).key(&receiver.payee).key(&receiver.gateway);
            }
            InvoiceReceiver::Delegated(receiver) => {
                let authorization = &receiver.payee_authorization;
                let issuance = &receiver.preimage_server_issuance;
                message
                    .u8(2)
                    .key(&receiver.payee)
                    .key(&receiver.gateway)
                    .key(&receiver.preimage_server)
                    .bytes32(&authorization.digest())
                    .raw(&authorization.signature.0)
                    .bytes32(&issuance.payment_hash)
                    .u64(issuance.amount_msat)
                    .option(issuance.metadata_hash.as_ref(), SigningMessage::bytes32)
                    .bytes32(&issuance.authorization)
                    .bytes32(&issuance.nonce)
                    .raw(&issuance.signature.0);
            }
        }
    }

    /// Target the payer must lock to when paying on `network`.
    pub fn target_for(&self, network: &NetworkId) -> Option<&InvoiceTarget> {
        self.body
            .networks
            .iter()
            .find(|entry| entry.target.network() == network)
            .map(|entry| &entry.target)
    }

    /// The receiver's safety margin when paid on `network`.
    pub fn incoming_delta_for(&self, network: &NetworkId) -> u64 {
        self.body
            .networks
            .iter()
            .find(|entry| entry.target.network() == network)
            .and_then(|entry| entry.incoming_delta_secs)
            .unwrap_or_else(|| network.default_incoming_delta())
    }
}

/// An [`Invoice`] crosses the wire as flat JSON, so its bytes do not
/// depend on how the Rust model is nested: the body's fields, then
/// `iroh_peer_id` (derived from the receiver, kept for compatibility)
/// and the receiver's fields, each present only when its kind has it.
impl Serialize for Invoice {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let body = &self.body;
        let (
            payee,
            payee_signature,
            gateway,
            gateway_signature,
            preimage_server,
            preimage_server_issuance,
            payee_authorization,
        ) = match &self.receiver {
            InvoiceReceiver::Direct(receiver) => (
                &receiver.payee,
                &receiver.payee_signature,
                None,
                &None,
                None,
                None,
                None,
            ),
            InvoiceReceiver::Gateway(receiver) => (
                &receiver.payee,
                &receiver.payee_signature,
                Some(&receiver.gateway),
                &receiver.gateway_signature,
                None,
                None,
                None,
            ),
            InvoiceReceiver::Delegated(receiver) => (
                &receiver.payee,
                &None,
                Some(&receiver.gateway),
                &receiver.gateway_signature,
                Some(&receiver.preimage_server),
                Some(&receiver.preimage_server_issuance),
                Some(&receiver.payee_authorization),
            ),
        };
        let mut invoice = serializer.serialize_struct("Invoice", 15)?;
        invoice.serialize_field("payment_hash", &body.payment_hash)?;
        invoice.serialize_field("amount_msat", &body.amount_msat)?;
        invoice.serialize_field("expires_at", &body.expires_at)?;
        invoice.serialize_field("networks", &body.networks)?;
        invoice.serialize_field("description", &body.description)?;
        optional_field(&mut invoice, "metadata", &body.metadata)?;
        invoice.serialize_field("iroh_peer_id", &self.receiver.iroh_peer_id().to_string())?;
        optional_field(&mut invoice, "iroh_relay", &body.iroh_relay)?;
        invoice.serialize_field("payee", payee)?;
        optional_field(&mut invoice, "payee_signature", payee_signature)?;
        optional_field(&mut invoice, "gateway", &gateway)?;
        optional_field(&mut invoice, "gateway_signature", gateway_signature)?;
        optional_field(&mut invoice, "preimage_server", &preimage_server)?;
        optional_field(
            &mut invoice,
            "preimage_server_issuance",
            &preimage_server_issuance,
        )?;
        optional_field(&mut invoice, "payee_authorization", &payee_authorization)?;
        invoice.end()
    }
}

/// Reads what [`Invoice`]'s `Serialize` writes, classifying the receiver
/// by the fields present.
impl<'de> Deserialize<'de> for Invoice {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        const FIELDS: &[&str] = &[
            "payment_hash",
            "amount_msat",
            "expires_at",
            "networks",
            "description",
            "metadata",
            "iroh_peer_id",
            "iroh_relay",
            "payee",
            "payee_signature",
            "gateway",
            "gateway_signature",
            "preimage_server",
            "preimage_server_issuance",
            "payee_authorization",
        ];

        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = Invoice;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("an invoice")
            }

            fn visit_map<A: de::MapAccess<'de>>(self, mut map: A) -> Result<Invoice, A::Error> {
                let mut payment_hash = None;
                let mut amount_msat = None;
                let mut expires_at = None;
                let mut networks = None;
                let mut description = None;
                let mut metadata = None;
                let mut iroh_peer_id: Option<String> = None;
                let mut iroh_relay = None;
                let mut payee: Option<PublicKey> = None;
                let mut payee_signature = None;
                let mut gateway: Option<PublicKey> = None;
                let mut gateway_signature = None;
                let mut preimage_server = None;
                let mut preimage_server_issuance = None;
                let mut payee_authorization = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "payment_hash" => payment_hash = Some(map.next_value()?),
                        "amount_msat" => amount_msat = Some(map.next_value()?),
                        "expires_at" => expires_at = Some(map.next_value()?),
                        "networks" => networks = Some(map.next_value()?),
                        "description" => description = map.next_value()?,
                        "metadata" => metadata = map.next_value()?,
                        "iroh_peer_id" => iroh_peer_id = map.next_value()?,
                        "iroh_relay" => iroh_relay = map.next_value()?,
                        "payee" => payee = map.next_value()?,
                        "payee_signature" => payee_signature = map.next_value()?,
                        "gateway" => gateway = map.next_value()?,
                        "gateway_signature" => gateway_signature = map.next_value()?,
                        "preimage_server" => preimage_server = map.next_value()?,
                        "preimage_server_issuance" => {
                            preimage_server_issuance = map.next_value()?
                        }
                        "payee_authorization" => payee_authorization = map.next_value()?,
                        _ => {
                            map.next_value::<de::IgnoredAny>()?;
                        }
                    }
                }
                let invalid = |reason: &str| de::Error::custom(reason);
                let body = InvoiceBody {
                    payment_hash: payment_hash
                        .ok_or_else(|| de::Error::missing_field("payment_hash"))?,
                    amount_msat: amount_msat
                        .ok_or_else(|| de::Error::missing_field("amount_msat"))?,
                    expires_at: expires_at.ok_or_else(|| de::Error::missing_field("expires_at"))?,
                    networks: networks.ok_or_else(|| de::Error::missing_field("networks"))?,
                    description,
                    metadata,
                    iroh_relay,
                };
                let payee = payee.ok_or_else(|| invalid("invoice names no payee"))?;
                let named = iroh_peer_id
                    .map(|named| {
                        named
                            .parse::<PublicKey>()
                            .map_err(|e| de::Error::custom(format!("invoice endpoint: {e}")))
                    })
                    .transpose()?;
                let receiver = if let Some(gateway) = gateway {
                    if gateway == payee {
                        return Err(invalid("the payee cannot be its own gateway"));
                    }
                    if named.is_some_and(|named| named != gateway) {
                        return Err(invalid("invoice names another endpoint than its gateway"));
                    }
                    if let Some(authorization) = payee_authorization {
                        if payee_signature.is_some() {
                            return Err(invalid(
                                "an invoice under a payee authorization carries a payee signature",
                            ));
                        }
                        InvoiceReceiver::Delegated(DelegatedReceiver {
                            payee,
                            gateway,
                            gateway_signature,
                            preimage_server: preimage_server
                                .ok_or_else(|| invalid("invoice names no preimage server"))?,
                            preimage_server_issuance: preimage_server_issuance.ok_or_else(
                                || invalid("invoice carries no issuance of its payment hash"),
                            )?,
                            payee_authorization: authorization,
                        })
                    } else {
                        if preimage_server.is_some() || preimage_server_issuance.is_some() {
                            return Err(invalid(
                                "a payee-signed gateway invoice carries preimage server fields",
                            ));
                        }
                        InvoiceReceiver::Gateway(GatewayReceiver {
                            payee,
                            gateway,
                            gateway_signature,
                            payee_signature,
                        })
                    }
                } else {
                    if gateway_signature.is_some()
                        || preimage_server.is_some()
                        || preimage_server_issuance.is_some()
                        || payee_authorization.is_some()
                    {
                        return Err(invalid(
                            "an invoice without a gateway carries gateway fields",
                        ));
                    }
                    if named.is_some_and(|named| named != payee) {
                        return Err(invalid("invoice names another endpoint than its payee"));
                    }
                    InvoiceReceiver::Direct(DirectReceiver {
                        payee,
                        payee_signature,
                    })
                };
                Ok(Invoice { body, receiver })
            }
        }

        deserializer.deserialize_struct("Invoice", FIELDS, Visitor)
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
    pub outgoing_target: InvoiceTarget,
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
    /// The invoice's [`InvoiceBody::metadata`].
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
    /// The invoice's [`InvoiceBody::metadata`].
    pub metadata: Option<Metadata>,
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
    /// The preimage server's opaque metadata for the hash, as carried
    /// in the invoice.
    pub preimage_metadata: Metadata,
    /// The invoice's metadata, which the issuance commits to; logged
    /// for the payee.
    pub metadata: Option<Metadata>,
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
    pub metadata: Option<Metadata>,
}

/// Anyone to gateway: an invoice paying `payee`, issued under one of
/// its standing authorizations.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GatewayInvoiceFor {
    pub payee: PublicKey,
    pub amount_msat: u64,
    /// The gateway's default, capped by the authorization, when absent.
    pub expires_at: Option<u64>,
    /// Unless the payee's authorization pins a description: then the
    /// invoice says that, and this asks for it or names none.
    pub description: Option<String>,
    pub metadata: Option<Metadata>,
}

/// What the preimage server logged for one of the payee's invoices.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ReceivedPayment {
    /// An HTLC a gateway funded to the payee and the server verified
    /// before releasing its preimage: still to be claimed by the payee
    /// with `preimage`. `descriptor` is the network-specific part
    /// (its target, cashu proofs, a lockup output, ...).
    Received {
        payment_hash: Bytes32,
        network: NetworkId,
        amount_msat: u64,
        expiry: u64,
        descriptor: HtlcDescriptor,
        preimage: Bytes32,
        /// The paid invoice's metadata.
        metadata: Option<Metadata>,
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
    /// server: a payment hash for an invoice of `amount_msat` carrying
    /// `metadata`.
    PreimageIssue {
        authorization: ReceiveAuthorization,
        amount_msat: u64,
        metadata: Option<Metadata>,
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
    },
    GatewayInvoiceFor(GatewayInvoiceFor),
}

// One per request, so the size of its largest variant does not matter.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Response {
    /// Target to lock the hop's incoming HTLC to, or why the hop
    /// refuses.
    Prepared(Result<InvoiceTarget, String>),
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
    use crate::offline::{GatewayMetadata, GatewayTerms};

    #[test]
    fn requests_round_trip_through_json() {
        let request = Request::Execute(Execute {
            payment_hash: Bytes32([0x42; 32]),
            operation_id: OperationId::random(),
            incoming_descriptor: HtlcDescriptor::Cashu {
                proofs_b64: vec!["eyJhbW91bnQiOjF9".into()],
                target: ritualistic::SecretKey::from_bytes([3; 32])
                    .unwrap()
                    .pubkey(),
            },
            outgoing_target: InvoiceTarget::Lightning {
                network: NetworkId("lightning".into()),
                invoice: "lnbc...".into(),
            },
        });
        let bytes = serde_json::to_vec(&request).unwrap();
        let Request::Execute(decoded) = serde_json::from_slice(&bytes).unwrap() else {
            panic!("expected execute");
        };
        assert_eq!(
            decoded.outgoing_target,
            InvoiceTarget::Lightning {
                network: NetworkId("lightning".into()),
                invoice: "lnbc...".into(),
            }
        );
        let response = Response::Prepared(Err("no liquidity".into()));
        let bytes = serde_json::to_vec(&response).unwrap();
        assert!(matches!(
            serde_json::from_slice(&bytes).unwrap(),
            Response::Prepared(Err(reason)) if reason == "no liquidity"
        ));
    }

    #[test]
    fn invoice_networks_keep_their_wire_bytes() {
        let mut entry = body().networks.remove(0);
        let key = ritualistic::SecretKey::from_bytes([3; 32])
            .unwrap()
            .pubkey();
        assert_eq!(
            serde_json::to_string(&entry).unwrap(),
            format!(
                r#"{{"network":"cashu::localhost","target":{{"XOnlyPubKey":"{}"}}}}"#,
                key.to_hex()
            )
        );
        entry.incoming_delta_secs = Some(60);
        assert_eq!(
            serde_json::to_string(&entry).unwrap(),
            format!(
                r#"{{"network":"cashu::localhost","target":{{"XOnlyPubKey":"{}"}},"incoming_delta_secs":60}}"#,
                key.to_hex()
            )
        );
        let lightning = r#"{"network":"lightning","target":{"LightningInvoice":"lnbc1"}}"#;
        let decoded: InvoiceNetwork = serde_json::from_str(lightning).unwrap();
        assert_eq!(
            decoded.target,
            InvoiceTarget::Lightning {
                network: NetworkId("lightning".into()),
                invoice: "lnbc1".into(),
            }
        );
        assert_eq!(serde_json::to_string(&decoded).unwrap(), lightning);
        let mismatched = r#"{"network":"cashu::localhost","target":{"LightningInvoice":"lnbc1"}}"#;
        assert!(serde_json::from_str::<InvoiceNetwork>(mismatched).is_err());
        let mismatched = format!(
            r#"{{"network":"lightning","target":{{"XOnlyPubKey":"{}"}}}}"#,
            key.to_hex()
        );
        assert!(serde_json::from_str::<InvoiceNetwork>(&mismatched).is_err());
    }

    #[test]
    fn invoice_decodes_without_optional_fields() {
        let payee = endpoint_public_key(&[1; 32]);
        let decoded: Invoice = serde_json::from_str(&format!(
            r#"{{
                "payment_hash": "0000000000000000000000000000000000000000000000000000000000000001",
                "amount_msat": 1000,
                "expires_at": 3000,
                "networks": [{{
                    "network": "cashu::localhost",
                    "target": {{"XOnlyPubKey": "17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917"}}
                }}],
                "description": null,
                "payee": "{payee}"
            }}"#
        ))
        .unwrap();
        assert!(decoded
            .target_for(&NetworkId("cashu::localhost".into()))
            .is_some());
        assert!(decoded.body.metadata.is_none());
        assert!(decoded.body.iroh_relay.is_none());
        assert!(matches!(decoded.receiver, InvoiceReceiver::Direct(_)));
    }

    fn body() -> InvoiceBody {
        InvoiceBody {
            payment_hash: Bytes32([1; 32]),
            amount_msat: 1000,
            expires_at: 3000,
            networks: vec![InvoiceNetwork {
                target: InvoiceTarget::Cashu {
                    network: NetworkId("cashu::localhost".into()),
                    target: ritualistic::SecretKey::from_bytes([3; 32])
                        .unwrap()
                        .pubkey(),
                },
                incoming_delta_secs: None,
            }],
            description: Some("coffee".into()),
            metadata: Some(Metadata::new(b"order 42".to_vec()).unwrap()),
            iroh_relay: None,
        }
    }

    fn signed_invoice(secret: &[u8; 32]) -> Invoice {
        Invoice::direct(body(), secret)
    }

    const PAYEE: [u8; 32] = [7; 32];
    const GATEWAY: [u8; 32] = [8; 32];
    const PREIMAGE_SERVER: [u8; 32] = [9; 32];

    fn authorization(kind: AuthorizationKind) -> ReceiveAuthorization {
        ReceiveAuthorization::sign(
            &PAYEE,
            kind,
            endpoint_public_key(&GATEWAY),
            endpoint_public_key(&PREIMAGE_SERVER),
            None,
            None,
            1000,
            5000,
            1000,
            1000,
            crate::offline::DEFAULT_MIN_FINAL_TIMEOUT_SECS,
            vec![crate::offline::GatewayDestination::Cashu {
                network: NetworkId("cashu::localhost".into()),
                target: ritualistic::SecretKey::from_bytes([4; 32])
                    .unwrap()
                    .pubkey(),
            }],
        )
        .unwrap()
    }

    fn issuance(authorization: &ReceiveAuthorization) -> PreimageIssuance {
        let mut issuance = PreimageIssuance {
            payment_hash: Bytes32([1; 32]),
            amount_msat: 1000,
            metadata_hash: Some(Metadata::new(b"order 42".to_vec()).unwrap().hash()),
            authorization: authorization.id().unwrap(),
            nonce: Bytes32([0; 32]),
            signature: Signature([0; 64]),
        };
        issuance.sign(&PREIMAGE_SERVER);
        issuance
    }

    /// Issued by the gateway, then signed by the payee.
    fn gateway_invoice() -> Invoice {
        let mut invoice = Invoice::gateway_invoice(body(), endpoint_public_key(&PAYEE), &GATEWAY);
        assert!(invoice.clone().sign_as_payee(&[11; 32]).is_err());
        invoice.sign_as_payee(&PAYEE).unwrap();
        invoice
    }

    /// Issued by the gateway alone.
    fn delegated_invoice() -> Invoice {
        delegated_with(authorization(AuthorizationKind::Standing))
    }

    /// A standing authorization the payee pinned a description on,
    /// signed again over the changed terms.
    fn described_authorization(description: &str) -> ReceiveAuthorization {
        let mut authorization = authorization(AuthorizationKind::Standing);
        authorization.description = Some(description.into());
        let message = authorization.message().unwrap();
        authorization.signature = Signature::sign(&PAYEE, &message);
        authorization
    }

    fn delegated_with(authorization: ReceiveAuthorization) -> Invoice {
        let mut body = body();
        let preimage_issuance = issuance(&authorization);
        let carried = GatewayMetadata::sign(
            &GATEWAY,
            preimage_issuance.to_metadata().unwrap(),
            GatewayTerms {
                payment_hash: body.payment_hash,
                amount_msat: body.amount_msat,
                authorization: authorization.clone(),
                expires_at: body.expires_at,
                payee_metadata: body.metadata.take(),
            },
        )
        .unwrap();
        body.metadata = Some(carried.to_metadata().unwrap());
        Invoice::delegated(
            body,
            authorization.payee,
            &GATEWAY,
            authorization.preimage_server,
            issuance(&authorization),
            authorization,
        )
    }

    #[test]
    fn invoice_serializes_flat_and_derives_iroh_peer_id() {
        let payee = endpoint_public_key(&PAYEE).to_string();
        let gateway = endpoint_public_key(&GATEWAY).to_string();

        let json = serde_json::to_value(signed_invoice(&PAYEE)).unwrap();
        assert!(json.get("body").is_none() && json.get("receiver").is_none());
        assert_eq!(json["payee"].as_str(), Some(payee.as_str()));
        assert_eq!(json["iroh_peer_id"].as_str(), Some(payee.as_str()));
        assert!(json.get("gateway").is_none());

        let json = serde_json::to_value(gateway_invoice()).unwrap();
        assert_eq!(json["payee"].as_str(), Some(payee.as_str()));
        assert_eq!(json["gateway"].as_str(), Some(gateway.as_str()));
        assert_eq!(json["iroh_peer_id"].as_str(), Some(gateway.as_str()));
    }

    #[test]
    fn invoice_signature_covers_every_field() {
        let invoice = signed_invoice(&PAYEE);
        assert!(matches!(invoice.receiver, InvoiceReceiver::Direct(_)));
        invoice.verify().unwrap();
        let decoded: Invoice =
            serde_json::from_str(&serde_json::to_string(&invoice).unwrap()).unwrap();
        decoded.verify().unwrap();

        let mut tampered = invoice.clone();
        tampered.body.amount_msat += 1;
        assert!(tampered.verify().is_err());
        let mut tampered = invoice.clone();
        tampered.body.metadata = None;
        assert!(tampered.verify().is_err());
        // Changing the payee breaks the signature, and that key cannot
        // sign for the first one.
        let mut redirected = invoice.clone();
        if let InvoiceReceiver::Direct(receiver) = &mut redirected.receiver {
            receiver.payee = endpoint_public_key(&[8; 32]);
        }
        assert!(redirected.verify().is_err());
        assert!(invoice.clone().sign_as_payee(&[8; 32]).is_err());
        let mut unsigned = invoice;
        if let InvoiceReceiver::Direct(receiver) = &mut unsigned.receiver {
            receiver.payee_signature = None;
        }
        assert!(unsigned.verify().is_err());
        // A direct invoice has no gateway to sign as.
        let mut direct = signed_invoice(&PAYEE);
        assert!(direct.sign_as_gateway(&GATEWAY).is_err());
    }

    #[test]
    fn gateway_invoices_need_both_signatures() {
        let invoice = gateway_invoice();
        assert!(matches!(invoice.receiver, InvoiceReceiver::Gateway(_)));
        invoice.verify().unwrap();
        let decoded: Invoice =
            serde_json::from_str(&serde_json::to_string(&invoice).unwrap()).unwrap();
        assert!(matches!(decoded.receiver, InvoiceReceiver::Gateway(_)));
        decoded.verify().unwrap();

        let mut unsigned = invoice.clone();
        if let InvoiceReceiver::Gateway(receiver) = &mut unsigned.receiver {
            receiver.payee_signature = None;
        }
        assert!(unsigned.verify().is_err());
        // The payee signed over the gateway: another one cannot step in.
        let mut swapped = invoice.clone();
        if let InvoiceReceiver::Gateway(receiver) = &mut swapped.receiver {
            receiver.gateway = endpoint_public_key(&[10; 32]);
        }
        swapped.sign_as_gateway(&[10; 32]).unwrap();
        assert!(swapped.verify().is_err());
        // Both signatures cover the payee: a new payee cannot sign the
        // gateway's invoice over.
        let mut other_payee = invoice.clone();
        if let InvoiceReceiver::Gateway(receiver) = &mut other_payee.receiver {
            receiver.payee = endpoint_public_key(&[11; 32]);
        }
        assert!(other_payee.verify().is_err());
        other_payee.sign_as_payee(&[11; 32]).unwrap();
        assert!(other_payee
            .verify()
            .unwrap_err()
            .contains("signature by the gateway"));
        let mut tampered = invoice;
        tampered.body.amount_msat += 1;
        assert!(tampered.verify().is_err());
    }

    #[test]
    fn delegated_invoices_follow_the_authorization() {
        let invoice = delegated_invoice();
        assert!(matches!(invoice.receiver, InvoiceReceiver::Delegated(_)));
        invoice.verify().unwrap();
        let decoded: Invoice =
            serde_json::from_str(&serde_json::to_string(&invoice).unwrap()).unwrap();
        assert!(matches!(decoded.receiver, InvoiceReceiver::Delegated(_)));
        decoded.verify().unwrap();

        // Outside the authorized amounts, even signed by the gateway.
        let mut more = invoice.clone();
        more.body.amount_msat = 2000;
        more.sign_as_gateway(&GATEWAY).unwrap();
        assert!(more.verify().is_err());
        // Expiring after the authorization does.
        let mut later = invoice.clone();
        later.body.expires_at = 6000;
        later.sign_as_gateway(&GATEWAY).unwrap();
        assert!(later.verify().unwrap_err().contains("outside"));
        // A description the payee pinned, which the invoice must say.
        delegated_with(described_authorization("coffee"))
            .verify()
            .unwrap();
        let misdescribed = delegated_with(described_authorization("tea"));
        assert!(misdescribed.verify().unwrap_err().contains("description"));
        // Another payee's name.
        let mut renamed = invoice.clone();
        if let InvoiceReceiver::Delegated(receiver) = &mut renamed.receiver {
            receiver.payee = endpoint_public_key(&[11; 32]);
        }
        assert!(renamed.verify().is_err());
        // Metadata is the receiver's: the payer carries it back without
        // reading it, so another payload under the gateway's signature
        // still passes here (the gateway itself rejects it on COMMIT).
        let mut relabeled = invoice.clone();
        let carried =
            GatewayMetadata::from_metadata(relabeled.body.metadata.as_ref().unwrap()).unwrap();
        let mut terms = carried
            .open(&GATEWAY, &relabeled.body.payment_hash)
            .unwrap();
        terms.payee_metadata = Some(Metadata::new(b"order 43".to_vec()).unwrap());
        let carried =
            GatewayMetadata::sign(&GATEWAY, carried.preimage_metadata.clone(), terms).unwrap();
        relabeled.body.metadata = Some(carried.to_metadata().unwrap());
        relabeled.sign_as_gateway(&GATEWAY).unwrap();
        relabeled.verify().unwrap();
        let mut opaque = invoice.clone();
        opaque.body.metadata = Some(Metadata::new(b"order 42".to_vec()).unwrap());
        opaque.sign_as_gateway(&GATEWAY).unwrap();
        opaque.verify().unwrap();
        // A hash the gateway made up.
        let mut made_up = invoice.clone();
        made_up.body.payment_hash = Bytes32([2; 32]);
        made_up.sign_as_gateway(&GATEWAY).unwrap();
        assert!(made_up.verify().is_err());
        // A single authorization does not let the gateway issue alone.
        let single = authorization(AuthorizationKind::Single);
        let mut unauthorized = invoice.clone();
        if let InvoiceReceiver::Delegated(receiver) = &mut unauthorized.receiver {
            receiver.preimage_server_issuance = issuance(&single);
            receiver.payee_authorization = single;
        }
        unauthorized.sign_as_gateway(&GATEWAY).unwrap();
        assert!(unauthorized.verify().unwrap_err().contains("does not let"));
        // Another gateway cannot reuse the authorization.
        let mut stolen = invoice;
        if let InvoiceReceiver::Delegated(receiver) = &mut stolen.receiver {
            receiver.gateway = endpoint_public_key(&[10; 32]);
        }
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
