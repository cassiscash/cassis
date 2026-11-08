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
//!   server act for it, within limits. Its signed message is a fixed
//!   text ([`ReceiveAuthorization::message`]), so anyone can check it
//!   without knowing Cassis' JSON.
//! * [`PreimageIssuance`]: the preimage server vouches that it issued a
//!   payment hash under an authorization.
//!
//! Invoices come in three [`InvoiceReceiver`](crate::protocol::InvoiceReceiver)s
//! with their own signature rules (see
//! [`Invoice::verify`](crate::protocol::Invoice::verify)).

use crate::network::{HtlcTarget, NetworkId};
use crate::primitives::Bytes32;
use crate::protocol::Metadata;
use iroh_base::PublicKey;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Default of [`ReceiveAuthorization::min_final_timeout_secs`]: how
/// long the payee may stay offline after a payment before it claims.
pub const DEFAULT_MIN_FINAL_TIMEOUT_SECS: u64 = 7 * 24 * 3600;

/// First line of [`ReceiveAuthorization::message`].
const AUTHORIZATION_HEADER: &str = "Cassis receive authorization v1";
/// First line of [`PreimageIssuance::message`].
const ISSUANCE_HEADER: &str = "Cassis preimage issuance v1";

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
    fn as_str(&self) -> &'static str {
        match self {
            Self::Single => "single",
            Self::Standing => "standing",
        }
    }
}

/// Where the gateway pays the payee: an HTLC on `network` locked to
/// `target`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Destination {
    pub network: NetworkId,
    pub target: HtlcTarget,
}

/// The payee's signed statement: "I, `payee`, authorize `gateway` and
/// `preimage_server` to create invoices in my name, valid between
/// `valid_from` and `valid_until`, for amounts between
/// `min_amount_msat` and `max_amount_msat`; the gateway pays each one
/// with an HTLC to one of my `destinations` that cannot be refunded
/// before `min_final_timeout_secs` after the preimage server releases
/// its preimage."
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiveAuthorization {
    pub kind: AuthorizationKind,
    pub payee: PublicKey,
    pub gateway: PublicKey,
    pub preimage_server: PublicKey,
    /// Unix seconds.
    pub valid_from: u64,
    /// Unix seconds; invoices made under it expire by then.
    pub valid_until: u64,
    pub min_amount_msat: u64,
    pub max_amount_msat: u64,
    pub min_final_timeout_secs: u64,
    pub destinations: Vec<Destination>,
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
        valid_from: u64,
        valid_until: u64,
        min_amount_msat: u64,
        max_amount_msat: u64,
        min_final_timeout_secs: u64,
        destinations: Vec<Destination>,
    ) -> Result<Self, String> {
        let mut authorization = Self {
            kind,
            payee: endpoint_public_key(payee_secret),
            gateway,
            preimage_server,
            valid_from,
            valid_until,
            min_amount_msat,
            max_amount_msat,
            min_final_timeout_secs,
            destinations,
            signature: Signature([0; 64]),
        };
        let message = authorization.message()?;
        authorization.signature = Signature::sign(payee_secret, message.as_bytes());
        Ok(authorization)
    }

    /// The text the payee signs, one `name: value` line per term:
    ///
    /// ```text
    /// Cassis receive authorization v1
    /// kind: standing
    /// payee: <hex key>
    /// gateway: <hex key>
    /// preimage server: <hex key>
    /// valid from: <unix seconds>
    /// valid until: <unix seconds>
    /// min amount msat: <n>
    /// max amount msat: <n>
    /// min final timeout secs: <n>
    /// destination: <network id> <xonly|pubkey>:<hex key>
    /// ```
    ///
    /// with one `destination` line per destination, in order, and a
    /// final newline. Fails on terms that cannot be written this way
    /// unambiguously, or that make no sense (see
    /// [`ReceiveAuthorization::check_terms`]).
    pub fn message(&self) -> Result<String, String> {
        self.check_terms()?;
        let mut message = format!(
            "{AUTHORIZATION_HEADER}\n\
             kind: {}\n\
             payee: {}\n\
             gateway: {}\n\
             preimage server: {}\n\
             valid from: {}\n\
             valid until: {}\n\
             min amount msat: {}\n\
             max amount msat: {}\n\
             min final timeout secs: {}\n",
            self.kind.as_str(),
            self.payee,
            self.gateway,
            self.preimage_server,
            self.valid_from,
            self.valid_until,
            self.min_amount_msat,
            self.max_amount_msat,
            self.min_final_timeout_secs,
        );
        for destination in &self.destinations {
            let target = match &destination.target {
                HtlcTarget::XOnlyPubKey(key) => format!("xonly:{}", key.to_hex()),
                HtlcTarget::PubKey(key) => format!("pubkey:{}", key.to_hex()),
                HtlcTarget::LightningInvoice(_) => unreachable!("refused by check_terms"),
            };
            message.push_str(&format!("destination: {} {target}\n", destination.network));
        }
        Ok(message)
    }

    /// Terms every authorization must meet: three distinct parties, a
    /// window, an amount range, a timeout and claim-key destinations on
    /// network ids without whitespace.
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
        for destination in &self.destinations {
            let id = &destination.network.0;
            if id.is_empty() || id.chars().any(char::is_whitespace) {
                return Err(format!(
                    "network id {id:?} cannot be written in an authorization"
                ));
            }
            if matches!(destination.target, HtlcTarget::LightningInvoice(_)) {
                return Err(format!(
                    "{id}: lightning cannot be paid to an offline payee, its hold invoices need it \
                     online"
                ));
            }
        }
        Ok(())
    }

    /// Check the terms and that `payee` signed them.
    pub fn verify(&self) -> Result<(), String> {
        let message = self.message()?;
        self.signature
            .verify(&self.payee, message.as_bytes())
            .map_err(|_| "invalid payee signature on the receive authorization".to_string())
    }

    /// SHA-256 of [`ReceiveAuthorization::message`]: what a
    /// [`PreimageIssuance`] refers to it by.
    pub fn id(&self) -> Result<Bytes32, String> {
        use sha2::{Digest, Sha256};
        Ok(Bytes32(Sha256::digest(self.message()?.as_bytes()).into()))
    }

    /// The destination on `network`, if any.
    pub fn destination(&self, network: &NetworkId) -> Option<&Destination> {
        self.destinations
            .iter()
            .find(|destination| destination.network == *network)
    }

    /// Whether `now` is inside the authorization's window.
    pub fn is_valid_at(&self, now: u64) -> bool {
        self.valid_from <= now && now < self.valid_until
    }

    pub fn allows_amount(&self, amount_msat: u64) -> bool {
        (self.min_amount_msat..=self.max_amount_msat).contains(&amount_msat)
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
    /// The text the preimage server signs:
    ///
    /// ```text
    /// Cassis preimage issuance v1
    /// preimage server: <hex key>
    /// authorization: <hex id>
    /// payment hash: <hex>
    /// amount msat: <n>
    /// metadata: <hex hash, or "none">
    /// ```
    pub fn message(&self, preimage_server: &PublicKey) -> String {
        format!(
            "{ISSUANCE_HEADER}\n\
             preimage server: {preimage_server}\n\
             authorization: {}\n\
             payment hash: {}\n\
             amount msat: {}\n\
             metadata: {}\n",
            self.authorization,
            self.payment_hash,
            self.amount_msat,
            self.metadata_hash
                .map_or_else(|| "none".to_string(), |hash| hash.to_string())
        )
    }

    /// Whether the hash was issued for an invoice carrying `metadata`.
    pub fn matches_metadata(&self, metadata: Option<&Metadata>) -> bool {
        self.metadata_hash == metadata.map(Metadata::hash)
    }

    /// Sign as the preimage server whose secret is `secret`.
    pub fn sign(&mut self, secret: &[u8; 32]) {
        let message = self.message(&endpoint_public_key(secret));
        self.signature = Signature::sign(secret, message.as_bytes());
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
            .verify(preimage_server, self.message(preimage_server).as_bytes())
            .map_err(|_| "invalid preimage server signature on the payment hash".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> PublicKey {
        endpoint_public_key(&[byte; 32])
    }

    fn authorization(kind: AuthorizationKind) -> ReceiveAuthorization {
        ReceiveAuthorization::sign(
            &[1; 32],
            kind,
            key(2),
            key(3),
            1000,
            2000,
            1,
            50_000,
            DEFAULT_MIN_FINAL_TIMEOUT_SECS,
            vec![Destination {
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

    #[test]
    fn authorization_message_is_fixed_text() {
        let authorization = authorization(AuthorizationKind::Standing);
        let message = authorization.message().unwrap();
        let lines: Vec<&str> = message.lines().collect();
        assert_eq!(lines[0], "Cassis receive authorization v1");
        assert_eq!(lines[1], "kind: standing");
        assert_eq!(lines[2], format!("payee: {}", key(1)));
        assert_eq!(lines[9], "min final timeout secs: 604800");
        assert!(lines[10].starts_with("destination: cashu::localhost xonly:"));
        assert!(message.ends_with('\n'));
        authorization.verify().unwrap();
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
        let mut tampered = authorization;
        tampered.destinations[0].network = NetworkId("cashu::elsewhere".into());
        assert!(tampered.verify().is_err());
    }

    #[test]
    fn authorization_refuses_absurd_terms() {
        let mut same = authorization(AuthorizationKind::Standing);
        same.gateway = same.preimage_server;
        assert!(same.message().is_err());
        let mut spaced = authorization(AuthorizationKind::Standing);
        spaced.destinations[0].network = NetworkId("cashu::a b".into());
        assert!(spaced.message().is_err());
        let mut lightning = authorization(AuthorizationKind::Standing);
        lightning.destinations[0].target = HtlcTarget::LightningInvoice("lnbc".into());
        assert!(lightning.message().is_err());
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
}
