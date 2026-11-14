//! Receiving while offline, through a gateway and a preimage server.
//!
//! The final payee picks a **preimage server**, which chooses payment
//! hashes and keeps their preimages, and a **gateway**, another party,
//! which is paid by payers in its place. Payers lock to the gateway;
//! once the gateway locked an HTLC to the payee on a network the payee
//! named, with at least the timeout the payee asked for, the preimage
//! server checks that HTLC, logs it for the payee and gives the gateway
//! the preimage to settle the incoming payment with. When it comes back
//! online the payee fetches the log from the preimage server and claims
//! every HTLC on its networks. Neither server can take the payment
//! alone: the gateway does not know the preimage before paying the
//! payee, and the preimage server holds no funds.
//!
//! Everything here is signed by Ed25519 keys, the iroh keys each party
//! talks to the others with:
//!
//! * [`ReceiveAuthorization`]: the payee lets a gateway and a preimage
//!   server act for it, within limits.
//! * [`PreimageIssuance`]: the preimage server vouches that it issued a
//!   payment hash under an authorization.
//! * [`GatewayMetadata`]: the gateway carries the preimage server's
//!   opaque metadata and its own sealed terms in the invoice metadata,
//!   signed, so payers hand it back with PREPARE and COMMIT and the
//!   gateway stores no invoice.
//!
//! Each signature covers the statement's canonical bytes, written as
//! [`crate::signing`] and `SPEC.md` lay out, never its JSON.
//!
//! Invoices come in three [`InvoiceReceiver`](crate::protocol::InvoiceReceiver)s
//! with their own signature rules (see
//! [`Invoice::verify`](crate::protocol::Invoice::verify)).

use crate::network::InvoiceTarget;
use crate::network::NetworkId;
use crate::primitives::Bytes32;
use crate::protocol::Metadata;
use crate::signing::SigningMessage;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::{ChaCha20, Key as ChachaKey, Nonce as ChachaNonce};
use hmac::{Hmac, Mac};
use iroh_base::PublicKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::convert::Infallible;
use std::fmt;

/// Default of [`ReceiveAuthorization::min_final_timeout_secs`]: how
/// long the payee may stay offline after a payment before it claims.
pub const DEFAULT_MIN_FINAL_TIMEOUT_SECS: u64 = 7 * 24 * 3600;

/// Domain of [`ReceiveAuthorization::message`].
const AUTHORIZATION_DOMAIN: &str = "cassis/receive-authorization/v2";
/// Domain of [`PreimageIssuance::message`].
const ISSUANCE_DOMAIN: &str = "cassis/preimage-issuance/v2";
/// Domain of [`GatewayMetadata::message`].
const GATEWAY_METADATA_DOMAIN: &str = "cassis/gateway-metadata/v2";
/// Prefix of the key a gateway seals its [`GatewayTerms`] with.
const GATEWAY_METADATA_KEY_DOMAIN: &[u8] = b"cassis-gateway-metadata-key/v1\0";

/// The public key of the iroh endpoint whose secret is `secret`.
pub fn endpoint_public_key(secret: &[u8; 32]) -> PublicKey {
    iroh_base::SecretKey::from_bytes(secret).public()
}

/// Ed25519 signature by a [`PublicKey`]. Hex on the wire.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature(pub [u8; 64]);

impl Signature {
    pub fn sign(secret: &[u8; 32], message: &[u8]) -> Self {
        Self(
            iroh_base::SecretKey::from_bytes(secret)
                .sign(message)
                .to_bytes(),
        )
    }

    /// Check this signature over `message` by `key`.
    pub fn verify(&self, key: &PublicKey, message: &[u8]) -> Result<(), String> {
        key.verify(message, &iroh_base::Signature::from_bytes(&self.0))
            .map_err(|_| format!("invalid signature by {key}"))
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", lowercase_hex::encode(self.0))
    }
}

impl Serialize for Signature {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&lowercase_hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut bytes = [0u8; 64];
        lowercase_hex::decode_to_slice(String::deserialize(deserializer)?, &mut bytes)
            .map_err(|e| serde::de::Error::custom(format!("signature: {e}")))?;
        Ok(Self(bytes))
    }
}

/// What a [`ReceiveAuthorization`] lets its gateway do.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthorizationKind {
    /// One invoice the payee builds and signs itself: the preimage
    /// server issues hashes under it to the payee only, and the gateway
    /// cannot issue invoices with it.
    Single,
    /// Invoices the gateway issues in the payee's name while the payee
    /// is offline, with hashes the preimage server issues to the
    /// gateway.
    Standing,
}

impl AuthorizationKind {
    /// Its tag in [`ReceiveAuthorization::message`].
    fn tag(&self) -> u8 {
        match self {
            Self::Single => 0,
            Self::Standing => 1,
        }
    }
}

/// Where the gateway pays the payee: an [`InvoiceTarget`] without a
/// Lightning one, whose hold invoices need the payee online.
pub type GatewayDestination = InvoiceTarget<Infallible>;

/// The payee's signed statement: "I, `payee`, authorize `gateway` and
/// `preimage_server` to create invoices in my name, valid between
/// `valid_from` and `valid_until`, for amounts between
/// `min_amount_msat` and `max_amount_msat`; the gateway pays each one
/// with an HTLC to one of my `destinations` that cannot be refunded
/// before `min_final_timeout_secs` after the preimage server releases
/// its preimage, and the invoices it issues say the `description` I
/// pinned, if I pinned one."
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiveAuthorization {
    pub kind: AuthorizationKind,
    pub payee: PublicKey,
    pub gateway: PublicKey,
    pub preimage_server: PublicKey,
    /// Where the gateway reaches the preimage server.
    #[serde(default)]
    pub preimage_server_relay: Option<String>,
    /// What every invoice issued under this authorization must say, if set.
    pub description: Option<String>,
    /// Unix seconds.
    pub valid_from: u64,
    /// Unix seconds; invoices made under it expire by then.
    pub valid_until: u64,
    pub min_amount_msat: u64,
    pub max_amount_msat: u64,
    pub min_final_timeout_secs: u64,
    pub destinations: Vec<GatewayDestination>,
    /// By `payee`, over [`ReceiveAuthorization::message`].
    pub signature: Signature,
}

impl ReceiveAuthorization {
    /// Sign the terms as `payee`, whose secret is `payee_secret`.
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        payee_secret: &[u8; 32],
        kind: AuthorizationKind,
        gateway: PublicKey,
        preimage_server: PublicKey,
        preimage_server_relay: Option<String>,
        description: Option<String>,
        valid_from: u64,
        valid_until: u64,
        min_amount_msat: u64,
        max_amount_msat: u64,
        min_final_timeout_secs: u64,
        destinations: Vec<GatewayDestination>,
    ) -> Result<Self, String> {
        let mut authorization = Self {
            kind,
            payee: endpoint_public_key(payee_secret),
            gateway,
            preimage_server,
            preimage_server_relay,
            description,
            valid_from,
            valid_until,
            min_amount_msat,
            max_amount_msat,
            min_final_timeout_secs,
            destinations,
            signature: Signature([0; 64]),
        };
        let message = authorization.message()?;
        authorization.signature = Signature::sign(payee_secret, &message);
        Ok(authorization)
    }

    /// The bytes the payee signs, in [`crate::signing`]'s encoding:
    ///
    /// ```text
    /// str     "cassis/receive-authorization/v2"
    /// u8      kind: 0 single, 1 standing
    /// key     payee
    /// key     gateway
    /// key     preimage server
    /// option  str  preimage server relay
    /// option  str  description
    /// u64     valid from (unix seconds)
    /// u64     valid until (unix seconds)
    /// u64     min amount msat
    /// u64     max amount msat
    /// u64     min final timeout secs
    /// count   destinations, each:
    ///   str     network id
    ///   target  claim key
    /// ```
    ///
    /// Fails on terms that make no sense (see
    /// [`ReceiveAuthorization::check_terms`]).
    pub fn message(&self) -> Result<Vec<u8>, String> {
        self.check_terms()?;
        Ok(self.encode())
    }

    /// [`ReceiveAuthorization::message`], whatever the terms.
    fn encode(&self) -> Vec<u8> {
        let mut message = SigningMessage::new(AUTHORIZATION_DOMAIN);
        message
            .u8(self.kind.tag())
            .key(&self.payee)
            .key(&self.gateway)
            .key(&self.preimage_server)
            .option(self.preimage_server_relay.as_deref(), SigningMessage::str)
            .option(self.description.as_deref(), SigningMessage::str)
            .u64(self.valid_from)
            .u64(self.valid_until)
            .u64(self.min_amount_msat)
            .u64(self.max_amount_msat)
            .u64(self.min_final_timeout_secs)
            .count(self.destinations.len());
        for destination in &self.destinations {
            message.invoice_target(destination);
        }
        message.into_bytes()
    }

    /// Terms every authorization must meet: three distinct parties, a
    /// window, an amount range, a timeout and a destination.
    pub fn check_terms(&self) -> Result<(), String> {
        if self.payee == self.gateway
            || self.payee == self.preimage_server
            || self.gateway == self.preimage_server
        {
            return Err("payee, gateway and preimage server must be three different keys".into());
        }
        if self.valid_from >= self.valid_until {
            return Err("authorization ends before it starts".into());
        }
        if self.min_amount_msat == 0 || self.min_amount_msat > self.max_amount_msat {
            return Err("authorized amounts must be positive and min at most max".into());
        }
        if self.min_final_timeout_secs == 0 {
            return Err("the final HTLC needs a timeout".into());
        }
        if self.destinations.is_empty() {
            return Err("authorization names no destination".into());
        }
        Ok(())
    }

    /// Check the terms and that `payee` signed them.
    pub fn verify(&self) -> Result<(), String> {
        let message = self.message()?;
        self.signature
            .verify(&self.payee, &message)
            .map_err(|_| "invalid payee signature on the receive authorization".to_string())
    }

    /// SHA-256 of [`ReceiveAuthorization::message`]: what a
    /// [`PreimageIssuance`] refers to it by.
    pub fn id(&self) -> Result<Bytes32, String> {
        self.check_terms()?;
        Ok(self.digest())
    }

    /// [`ReceiveAuthorization::id`], whatever the terms: what an invoice
    /// signature covers it by.
    pub(crate) fn digest(&self) -> Bytes32 {
        Bytes32(Sha256::digest(self.encode()).into())
    }

    /// The destination on `network`, if any.
    pub fn destination(&self, network: &NetworkId) -> Option<&GatewayDestination> {
        self.destinations
            .iter()
            .find(|destination| destination.network() == network)
    }

    /// Whether `now` is inside the authorization's window.
    pub fn is_valid_at(&self, now: u64) -> bool {
        self.valid_from <= now && now < self.valid_until
    }

    pub fn allows_amount(&self, amount_msat: u64) -> bool {
        (self.min_amount_msat..=self.max_amount_msat).contains(&amount_msat)
    }

    /// Whether an invoice with `description` is one this authorization
    /// allows: if it names a description, the invoice must carry it.
    pub fn allows_description(&self, description: Option<&str>) -> bool {
        self.description
            .as_deref()
            .is_none_or(|required| description == Some(required))
    }
}

/// A preimage server's statement: "I issued `payment_hash`, for
/// `amount_msat` and the invoice metadata hashing to `metadata_hash`,
/// under the receive authorization `authorization`", and the `nonce` it
/// derived the preimage from. It releases the preimage only to the
/// authorization's gateway, against an HTLC paying the payee at least
/// `amount_msat`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreimageIssuance {
    pub payment_hash: Bytes32,
    pub amount_msat: u64,
    /// [`Metadata::hash`] of the metadata of the invoice the hash is
    /// for; `None` for an invoice without.
    pub metadata_hash: Option<Bytes32>,
    /// [`ReceiveAuthorization::id`].
    pub authorization: Bytes32,
    /// Not signed: the server derives the preimage from it, so a wrong
    /// one only fails to match the hash.
    pub nonce: Bytes32,
    /// By the preimage server, over [`PreimageIssuance::message`].
    pub signature: Signature,
}

impl PreimageIssuance {
    /// The bytes the preimage server signs, in [`crate::signing`]'s
    /// encoding:
    ///
    /// ```text
    /// str     "cassis/preimage-issuance/v2"
    /// key     preimage server
    /// bytes32 authorization id
    /// bytes32 payment hash
    /// u64     amount msat
    /// option  bytes32  metadata hash
    /// ```
    pub fn message(&self, preimage_server: &PublicKey) -> Vec<u8> {
        let mut message = SigningMessage::new(ISSUANCE_DOMAIN);
        message
            .key(preimage_server)
            .bytes32(&self.authorization)
            .bytes32(&self.payment_hash)
            .u64(self.amount_msat)
            .option(self.metadata_hash.as_ref(), SigningMessage::bytes32);
        message.into_bytes()
    }

    /// Whether the hash was issued for an invoice carrying `metadata`.
    pub fn matches_metadata(&self, metadata: Option<&Metadata>) -> bool {
        self.metadata_hash == metadata.map(Metadata::hash)
    }

    /// Sign as the preimage server whose secret is `secret`.
    pub fn sign(&mut self, secret: &[u8; 32]) {
        let message = self.message(&endpoint_public_key(secret));
        self.signature = Signature::sign(secret, &message);
    }

    /// Check that `preimage_server` issued this under `authorization`.
    pub fn verify(
        &self,
        preimage_server: &PublicKey,
        authorization: &ReceiveAuthorization,
    ) -> Result<(), String> {
        if authorization.preimage_server != *preimage_server {
            return Err("the authorization names another preimage server".into());
        }
        if self.authorization != authorization.id()? {
            return Err("the hash was issued under another authorization".into());
        }
        self.signature
            .verify(preimage_server, &self.message(preimage_server))
            .map_err(|_| "invalid preimage server signature on the payment hash".to_string())
    }

    /// As opaque metadata a gateway can carry for this server: Postcard
    /// of the tuple of its fields, with the signature raw.
    pub fn to_metadata(&self) -> Result<Metadata, String> {
        let fields = (
            self.payment_hash.0,
            self.amount_msat,
            self.metadata_hash.map(|hash| hash.0),
            self.authorization.0,
            self.nonce.0,
            self.signature.0.as_slice(),
        );
        let bytes =
            postcard::to_allocvec(&fields).map_err(|e| format!("encoding issuance: {e}"))?;
        Metadata::new(bytes)
    }

    /// Read what [`PreimageIssuance::to_metadata`] wrote.
    pub fn from_metadata(metadata: &Metadata) -> Result<Self, String> {
        type Fields = ([u8; 32], u64, Option<[u8; 32]>, [u8; 32], [u8; 32], Vec<u8>);
        let ((payment_hash, amount_msat, metadata_hash, authorization, nonce, signature), rest) =
            postcard::take_from_bytes::<Fields>(metadata.as_bytes())
                .map_err(|e| format!("not a preimage server's issuance: {e}"))?;
        if !rest.is_empty() {
            return Err("not a preimage server's issuance: trailing bytes".into());
        }
        Ok(Self {
            payment_hash: Bytes32(payment_hash),
            amount_msat,
            metadata_hash: metadata_hash.map(Bytes32),
            authorization: Bytes32(authorization),
            nonce: Bytes32(nonce),
            signature: Signature(
                signature
                    .try_into()
                    .map_err(|_| "not a preimage server's issuance: bad signature".to_string())?,
            ),
        })
    }
}

/// The [`Metadata`] of every invoice a gateway issues: the preimage
/// server's opaque metadata, the gateway's sealed terms, and the
/// gateway's signature. Payers hand it back with PREPARE and COMMIT,
/// and only the gateway can open the terms.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatewayMetadata {
    /// What the preimage server needs to release the preimage (or what
    /// the payee handed the gateway for its own invoice), raw.
    pub preimage_metadata: Metadata,
    /// The gateway's terms, sealed with a key from its secret.
    sealed: Vec<u8>,
    /// By the gateway, over [`GatewayMetadata::message`].
    pub gateway_signature: Signature,
}

/// The terms a gateway seals into the metadata of its invoices.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayTerms {
    pub payment_hash: Bytes32,
    pub amount_msat: u64,
    pub authorization: ReceiveAuthorization,
    pub expires_at: u64,
    /// The payee's metadata, which the issuance commits to.
    pub payee_metadata: Option<Metadata>,
}

/// The key a gateway seals its terms with, derived from its signing
/// secret so the signing key itself is not reused as a cipher key.
fn metadata_key(secret: &[u8; 32]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("hmac accepts any key length");
    mac.update(GATEWAY_METADATA_KEY_DOMAIN);
    mac.finalize().into_bytes().into()
}

/// The ChaCha20 nonce for an invoice: its payment hash is unique.
fn metadata_nonce(payment_hash: &Bytes32) -> [u8; 12] {
    payment_hash.0[..12]
        .try_into()
        .expect("payment hashes are 32 bytes")
}

impl GatewayMetadata {
    /// Seal `terms` and sign the result as the gateway whose secret is
    /// `gateway_secret`.
    pub fn sign(
        gateway_secret: &[u8; 32],
        preimage_metadata: Metadata,
        terms: GatewayTerms,
    ) -> Result<Self, String> {
        let key = metadata_key(gateway_secret);
        let nonce = metadata_nonce(&terms.payment_hash);
        let mut sealed =
            postcard::to_allocvec(&terms).map_err(|e| format!("encoding gateway terms: {e}"))?;
        let mut cipher =
            ChaCha20::new(ChachaKey::from_slice(&key), ChachaNonce::from_slice(&nonce));
        cipher.apply_keystream(&mut sealed);
        let mut metadata = Self {
            preimage_metadata,
            sealed,
            gateway_signature: Signature([0; 64]),
        };
        metadata.gateway_signature = Signature::sign(gateway_secret, &metadata.message());
        Ok(metadata)
    }

    /// The bytes the gateway signs, in [`crate::signing`]'s encoding:
    ///
    /// ```text
    /// str     "cassis/gateway-metadata/v2"
    /// bytes   preimage metadata
    /// bytes   sealed terms
    /// ```
    pub fn message(&self) -> Vec<u8> {
        let mut message = SigningMessage::new(GATEWAY_METADATA_DOMAIN);
        message
            .bytes(self.preimage_metadata.as_bytes())
            .bytes(&self.sealed);
        message.into_bytes()
    }

    /// Check that `gateway` signed this.
    pub fn verify(&self, gateway: &PublicKey) -> Result<(), String> {
        self.gateway_signature
            .verify(gateway, &self.message())
            .map_err(|_| "the invoice metadata is not signed by this gateway".to_string())
    }

    /// Open the terms for the invoice whose payment hash is
    /// `payment_hash`, as the gateway whose secret is `gateway_secret`.
    pub fn open(
        &self,
        gateway_secret: &[u8; 32],
        payment_hash: &Bytes32,
    ) -> Result<GatewayTerms, String> {
        self.verify(&endpoint_public_key(gateway_secret))?;
        let key = metadata_key(gateway_secret);
        let nonce = metadata_nonce(payment_hash);
        let mut plaintext = self.sealed.clone();
        let mut cipher =
            ChaCha20::new(ChachaKey::from_slice(&key), ChachaNonce::from_slice(&nonce));
        cipher.apply_keystream(&mut plaintext);
        let (terms, rest) = postcard::take_from_bytes::<GatewayTerms>(&plaintext)
            .map_err(|e| format!("not a gateway's invoice metadata: {e}"))?;
        if !rest.is_empty() {
            return Err("not a gateway's invoice metadata: trailing bytes".into());
        }
        if terms.payment_hash != *payment_hash {
            return Err("the gateway's metadata is for another payment".into());
        }
        Ok(terms)
    }

    /// As invoice metadata: Postcard of the preimage metadata, the
    /// sealed terms and the signature, as raw bytes.
    pub fn to_metadata(&self) -> Result<Metadata, String> {
        let fields = (
            self.preimage_metadata.as_bytes(),
            self.sealed.as_slice(),
            self.gateway_signature.0.as_slice(),
        );
        let bytes =
            postcard::to_allocvec(&fields).map_err(|e| format!("encoding metadata: {e}"))?;
        Metadata::new(bytes)
    }

    /// Read it from the metadata of a gateway's invoice.
    pub fn from_metadata(metadata: &Metadata) -> Result<Self, String> {
        let ((preimage_metadata, sealed, gateway_signature), rest) =
            postcard::take_from_bytes::<(Vec<u8>, Vec<u8>, Vec<u8>)>(metadata.as_bytes())
                .map_err(|e| format!("not a gateway's invoice metadata: {e}"))?;
        if !rest.is_empty() {
            return Err("not a gateway's invoice metadata: trailing bytes".into());
        }
        Ok(Self {
            preimage_metadata: Metadata::new(preimage_metadata)?,
            sealed,
            gateway_signature: Signature(
                gateway_signature
                    .try_into()
                    .map_err(|_| "not a gateway's invoice metadata: bad signature".to_string())?,
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> PublicKey {
        endpoint_public_key(&[byte; 32])
    }

    fn authorization(kind: AuthorizationKind) -> ReceiveAuthorization {
        signed(kind, None)
    }

    fn signed(kind: AuthorizationKind, description: Option<&str>) -> ReceiveAuthorization {
        ReceiveAuthorization::sign(
            &[1; 32],
            kind,
            key(2),
            key(3),
            Some("https://relay.example".into()),
            description.map(Into::into),
            1000,
            2000,
            1,
            50_000,
            DEFAULT_MIN_FINAL_TIMEOUT_SECS,
            vec![GatewayDestination::Cashu {
                network: NetworkId("cashu::localhost".into()),
                target: ritualistic::SecretKey::from_bytes([4; 32])
                    .unwrap()
                    .pubkey(),
            }],
        )
        .unwrap()
    }

    #[test]
    fn authorization_message_is_canonical() {
        let authorization = authorization(AuthorizationKind::Standing);
        let mut expected = Vec::new();
        expected.extend(31u32.to_be_bytes());
        expected.extend(b"cassis/receive-authorization/v2");
        expected.push(1);
        expected.extend(key(1).as_bytes());
        expected.extend(key(2).as_bytes());
        expected.extend(key(3).as_bytes());
        expected.push(1);
        expected.extend(21u32.to_be_bytes());
        expected.extend(b"https://relay.example");
        expected.push(0);
        for value in [1000u64, 2000, 1, 50_000, DEFAULT_MIN_FINAL_TIMEOUT_SECS] {
            expected.extend(value.to_be_bytes());
        }
        expected.extend(1u32.to_be_bytes());
        expected.extend(16u32.to_be_bytes());
        expected.extend(b"cashu::localhost");
        expected.push(0);
        expected.extend(
            ritualistic::SecretKey::from_bytes([4; 32])
                .unwrap()
                .pubkey()
                .0,
        );
        assert_eq!(authorization.message().unwrap(), expected);
        authorization.verify().unwrap();
    }

    #[test]
    fn authorization_description_is_a_signed_term() {
        let authorization = signed(
            AuthorizationKind::Standing,
            Some("a \"quoted\"\ndescription"),
        );
        authorization.verify().unwrap();
        assert!(authorization.allows_description(Some("a \"quoted\"\ndescription")));
        assert!(!authorization.allows_description(None));
        assert!(!authorization.allows_description(Some("coffee")));
        let mut tampered = authorization.clone();
        tampered.description = Some("coffee".into());
        assert!(tampered.verify().is_err());
        // Without one, any description does.
        assert!(signed(AuthorizationKind::Single, None).allows_description(None));
        assert!(signed(AuthorizationKind::Single, None).allows_description(Some("coffee")));
    }

    #[test]
    fn authorization_signature_covers_every_term() {
        let authorization = authorization(AuthorizationKind::Single);
        let mut tampered = authorization.clone();
        tampered.max_amount_msat += 1;
        assert!(tampered.verify().is_err());
        let mut tampered = authorization.clone();
        tampered.kind = AuthorizationKind::Standing;
        assert!(tampered.verify().is_err());
        let mut tampered = authorization.clone();
        tampered.gateway = key(9);
        assert!(tampered.verify().is_err());
        let mut tampered = authorization.clone();
        tampered.preimage_server_relay = None;
        assert!(tampered.verify().is_err());
        let mut tampered = authorization;
        tampered.destinations[0] = GatewayDestination::parse(
            NetworkId("cashu::elsewhere".into()),
            &tampered.destinations[0].target_string(),
        )
        .unwrap();
        assert!(tampered.verify().is_err());
    }

    #[test]
    fn authorization_refuses_absurd_terms() {
        let mut same = authorization(AuthorizationKind::Standing);
        same.gateway = same.preimage_server;
        assert!(same.message().is_err());
        let mut nowhere = authorization(AuthorizationKind::Standing);
        nowhere.destinations.clear();
        assert!(nowhere.message().is_err());
    }

    #[test]
    fn destinations_fit_their_network() {
        let key = ritualistic::SecretKey::from_bytes([4; 32])
            .unwrap()
            .pubkey();
        assert!(GatewayDestination::parse(NetworkId("lightning".into()), "lnbc").is_err());
        let liquid = NetworkId("liquid".into());
        assert!(GatewayDestination::parse(liquid.clone(), &key.to_hex()).is_err());
        let full = crate::PubKey::from_x_only(&key).unwrap();
        let destination = GatewayDestination::parse(liquid.clone(), &full.to_hex()).unwrap();
        assert_eq!(
            destination,
            GatewayDestination::Liquid {
                network: liquid,
                target: full
            }
        );
        let json = serde_json::to_string(&destination).unwrap();
        assert_eq!(
            serde_json::from_str::<GatewayDestination>(&json).unwrap(),
            destination
        );
        let mismatched = json.replace("\"liquid\"", "\"bitcoin\"");
        assert!(serde_json::from_str::<GatewayDestination>(&mismatched).is_err());
        let mistagged = json.replace("\"PubKey\"", "\"XOnlyPubKey\"");
        assert!(serde_json::from_str::<GatewayDestination>(&mistagged).is_err());
    }

    #[test]
    fn issuance_is_bound_to_server_and_authorization() {
        let authorization = authorization(AuthorizationKind::Standing);
        let metadata = Metadata::new(b"order 42".to_vec()).unwrap();
        let mut issuance = PreimageIssuance {
            payment_hash: Bytes32([5; 32]),
            amount_msat: 1000,
            metadata_hash: Some(metadata.hash()),
            authorization: authorization.id().unwrap(),
            nonce: Bytes32([6; 32]),
            signature: Signature([0; 64]),
        };
        issuance.sign(&[3; 32]);
        issuance.verify(&key(3), &authorization).unwrap();
        assert!(issuance.matches_metadata(Some(&metadata)));
        assert!(!issuance.matches_metadata(None));
        assert!(issuance.verify(&key(2), &authorization).is_err());
        let mut other = issuance.clone();
        other.amount_msat = 2000;
        assert!(other.verify(&key(3), &authorization).is_err());
        let mut other = issuance.clone();
        other.metadata_hash = None;
        assert!(other.verify(&key(3), &authorization).is_err());
        let mut elsewhere = authorization;
        elsewhere.max_amount_msat += 1;
        assert!(issuance.verify(&key(3), &elsewhere).is_err());
    }

    #[test]
    fn issuance_metadata_round_trips() {
        let authorization = authorization(AuthorizationKind::Standing);
        let mut issuance = PreimageIssuance {
            payment_hash: Bytes32([5; 32]),
            amount_msat: 1000,
            metadata_hash: Some(Metadata::new(b"order 42".to_vec()).unwrap().hash()),
            authorization: authorization.id().unwrap(),
            nonce: Bytes32([6; 32]),
            signature: Signature([0; 64]),
        };
        issuance.sign(&[3; 32]);
        let metadata = issuance.to_metadata().unwrap();
        assert_eq!(
            PreimageIssuance::from_metadata(&metadata).unwrap(),
            issuance
        );
        let mut trailing = metadata.as_bytes().to_vec();
        trailing.push(0);
        assert!(PreimageIssuance::from_metadata(&Metadata::new(trailing).unwrap()).is_err());
    }

    #[test]
    fn gateway_metadata_is_signed_by_the_gateway() {
        let authorization = authorization(AuthorizationKind::Standing);
        let payee_metadata = Metadata::new(b"order 42".to_vec()).unwrap();
        let mut issuance = PreimageIssuance {
            payment_hash: Bytes32([5; 32]),
            amount_msat: 1000,
            metadata_hash: Some(payee_metadata.hash()),
            authorization: authorization.id().unwrap(),
            nonce: Bytes32([6; 32]),
            signature: Signature([0; 64]),
        };
        issuance.sign(&[3; 32]);
        let terms = GatewayTerms {
            payment_hash: issuance.payment_hash,
            amount_msat: issuance.amount_msat,
            authorization,
            expires_at: 1500,
            payee_metadata: Some(payee_metadata),
        };
        let carried =
            GatewayMetadata::sign(&[2; 32], issuance.to_metadata().unwrap(), terms.clone())
                .unwrap();
        let metadata = carried.to_metadata().unwrap();
        let read = GatewayMetadata::from_metadata(&metadata).unwrap();
        assert_eq!(read, carried);
        read.verify(&key(2)).unwrap();
        assert_eq!(read.open(&[2; 32], &Bytes32([5; 32])).unwrap(), terms);
        // Another gateway's key, a different payment, or anything
        // changed, does not open.
        assert!(read.open(&[3; 32], &Bytes32([5; 32])).is_err());
        assert!(read.open(&[2; 32], &Bytes32([6; 32])).is_err());
        let mut changed = read.clone();
        changed.sealed[0] ^= 1;
        assert!(changed.verify(&key(2)).is_err());
        let mut changed = read;
        changed.preimage_metadata = Metadata::new(b"other".to_vec()).unwrap();
        assert!(changed.verify(&key(2)).is_err());
        assert!(
            GatewayMetadata::from_metadata(&Metadata::new(b"order 42".to_vec()).unwrap()).is_err()
        );
    }
}
