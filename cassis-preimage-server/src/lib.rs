//! A preimage server: an always-online iroh node that picks the payment
//! hashes of an offline payee's invoices and gives their preimages out
//! only once a gateway paid the payee (see [`cassis_core::offline`]).
//!
//! * The payee, or the gateway it authorized, asks for a payment hash
//!   ([`Request::PreimageIssue`]) under the payee's signed
//!   [`ReceiveAuthorization`], for an invoice of some amount and
//!   metadata. The server keeps no record of it: the preimage is an
//!   HMAC, keyed by a secret only the server knows, over a random nonce
//!   in the [`PreimageIssuance`] it signs and returns. What the hash was
//!   issued for is bound by that signature and checked again when the
//!   preimage is released. Without the secret nobody, the gateway
//!   included, can work the preimage out.
//! * The gateway, paid for the invoice, funds an HTLC to one of the
//!   payee's destinations and presents it ([`Request::PreimageRelease`]).
//!   The server checks it against the authorization (destination,
//!   amount, timeout) and on the network, logs it for the payee and
//!   releases the preimage, so the gateway can settle its incoming
//!   payment.
//! * The payee fetches its log ([`Request::PreimagePayments`]), with
//!   the metadata of each invoice, and claims each HTLC before it
//!   expires.
//!
//! Only HTLCs whose preimage was released are stored.

pub mod admin;
pub mod config;

use cassis_core::network::{Htlc, Network, NetworkError, NetworkId};
use cassis_core::offline::{
    endpoint_public_key, AuthorizationKind, PreimageIssuance, ReceiveAuthorization, Signature,
};
use cassis_core::protocol::{Metadata, PreimageRelease, ReceivedPayment, Request, Response};
use cassis_core::transport::{Handler, Transport};
use cassis_core::{unix_now, Bytes32};
use hmac::{Hmac, Mac};
use iroh_base::PublicKey;
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use tracing::{info, warn, Instrument, Span};

pub use db::Db;

#[orangedb::schema]
pub mod db {
    use cassis_wallet::stored::StoredDescriptor;
    /// An HTLC a gateway funded to a payee, which the server verified
    /// before releasing its preimage: what the payee needs to claim it.
    #[entity]
    #[derive(Debug, Clone, PartialEq)]
    pub struct Payment {
        /// The payment hash.
        #[id([u8; 32])]
        pub payment_hash: PaymentHash,
        /// The payee's iroh key.
        #[index]
        pub payee: [u8; 32],
        pub network: String,
        pub amount_msat: u64,
        pub expiry: u64,
        pub descriptor: StoredDescriptor,
        pub preimage: [u8; 32],
        /// The invoice's metadata, if any.
        pub metadata: Option<Vec<u8>>,
        pub released_at: u64,
    }
}

use cassis_wallet::stored::{self, stored_metadata};
use db::{Payment, PaymentHash};

pub struct ServerConfig {
    /// Secret of the server's iroh endpoint, which signs its issuances.
    pub endpoint_secret: [u8; 32],
    /// Key preimages are derived with, known to this server only (see
    /// [`cassis_core::keys::NodeKeys::preimage_server_secret`]): anyone
    /// holding it can compute every preimage. Changing it orphans every
    /// invoice issued before.
    pub preimage_secret: [u8; 32],
    pub db: Arc<Db>,
    /// Networks the server verifies HTLCs on. Authorizations paying
    /// the payee on others are refused.
    pub networks: Vec<Arc<dyn Network>>,
    pub span: Span,
}

/// What a server answered since it started.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Hashes issued.
    pub issued: u64,
    /// HTLCs logged and their preimages released.
    pub released: u64,
    /// Issues and releases refused.
    pub refused: u64,
}

#[derive(Default)]
struct Counters {
    issued: AtomicU64,
    released: AtomicU64,
    refused: AtomicU64,
}

/// Handle to a running preimage server. Cheap to clone.
#[derive(Clone)]
pub struct PreimageServer(Arc<Inner>);

struct Inner {
    endpoint_secret: [u8; 32],
    preimage_secret: [u8; 32],
    db: Arc<Db>,
    networks: Mutex<HashMap<NetworkId, Arc<dyn Network>>>,
    transport: Transport,
    span: Span,
    counters: Counters,
}

impl PreimageServer {
    /// Bind the server's endpoint and answer requests until
    /// [`PreimageServer::shutdown`].
    pub async fn start(config: ServerConfig) -> Result<Self, String> {
        let transport = Transport::bind(Some(config.endpoint_secret)).await?;
        let server = Self(Arc::new(Inner {
            endpoint_secret: config.endpoint_secret,
            preimage_secret: config.preimage_secret,
            db: config.db,
            networks: Mutex::new(
                config
                    .networks
                    .into_iter()
                    .map(|network| (network.id(), network))
                    .collect(),
            ),
            transport: transport.clone(),
            span: config.span,
            counters: Counters::default(),
        }));
        let handling = server.clone();
        let handler: Handler = Arc::new(move |request, peer| {
            let server = handling.clone();
            Box::pin(async move { server.handle(request, peer).await })
        });
        let span = server.0.span.clone();
        tokio::spawn(async move { transport.serve(handler).await }.instrument(span));
        Ok(server)
    }

    pub fn peer_id(&self) -> String {
        self.0.transport.peer_id()
    }

    pub async fn home_relay(&self) -> Option<String> {
        self.0.transport.home_relay().await
    }

    /// Close the endpoint. The database stays as it is.
    pub async fn shutdown(&self) {
        self.0.transport.close().await;
    }

    pub fn key(&self) -> PublicKey {
        endpoint_public_key(&self.0.endpoint_secret)
    }

    fn networks(&self) -> MutexGuard<'_, HashMap<NetworkId, Arc<dyn Network>>> {
        self.0.networks.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Verify HTLCs on `network` too, or anew.
    pub fn add_network(&self, network: Arc<dyn Network>) {
        self.networks().insert(network.id(), network);
    }

    /// Stop verifying HTLCs on `id`, refusing payees receiving on it.
    pub fn remove_network(&self, id: &NetworkId) {
        self.networks().remove(id);
    }

    /// The networks it verifies HTLCs on, in order.
    pub fn network_ids(&self) -> Vec<NetworkId> {
        let mut ids: Vec<NetworkId> = self.networks().keys().cloned().collect();
        ids.sort();
        ids
    }

    pub fn stats(&self) -> Stats {
        let counters = &self.0.counters;
        Stats {
            issued: counters.issued.load(Ordering::Relaxed),
            released: counters.released.load(Ordering::Relaxed),
            refused: counters.refused.load(Ordering::Relaxed),
        }
    }

    /// Every HTLC whose preimage was released.
    pub fn all_payments(&self) -> Result<Vec<Payment>, String> {
        self.0
            .db
            .payments()
            .all()
            .map_err(|e| format!("read payments: {e}"))
    }

    async fn handle(&self, request: Request, peer: String) -> Response {
        match request {
            Request::PreimageIssue {
                authorization,
                amount_msat,
                metadata,
            } => Response::PreimageIssued(self.issue(
                &peer,
                &authorization,
                amount_msat,
                metadata.as_ref(),
            )),
            Request::PreimageRelease(release) => self.release(&peer, release).await,
            Request::PreimagePayments { since } => {
                Response::PreimagePayments(self.payments(&peer, since))
            }
            _ => Response::Error(
                "this is a preimage server: it neither routes, pays nor receives".into(),
            ),
        }
    }

    /// The preimage of `issuance`'s hash: the HMAC by the server's
    /// secret over its nonce. What the hash was issued for is bound by
    /// the signed issuance and checked when the preimage is released.
    fn preimage(&self, issuance: &PreimageIssuance) -> Bytes32 {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0.preimage_secret)
            .expect("hmac accepts any key length");
        mac.update(b"cassis/preimage-server/v3\0");
        mac.update(&issuance.nonce.0);
        Bytes32(mac.finalize().into_bytes().into())
    }

    /// Check `authorization` is the payee's, names this server and asks
    /// only for networks it verifies HTLCs on.
    fn check_authorization(&self, authorization: &ReceiveAuthorization) -> Result<Bytes32, String> {
        authorization.verify()?;
        if authorization.preimage_server != self.key() {
            return Err("the authorization names another preimage server".into());
        }
        for destination in &authorization.destinations {
            self.network(destination.network())?;
        }
        authorization.id()
    }

    /// A fresh payment hash for an invoice of `amount_msat` under
    /// `authorization`, asked for by `peer`: the payee itself for a
    /// single invoice, the gateway for a standing authorization.
    fn issue(
        &self,
        peer: &str,
        authorization: &ReceiveAuthorization,
        amount_msat: u64,
        metadata: Option<&Metadata>,
    ) -> Result<PreimageIssuance, String> {
        let result = self.try_issue(peer, authorization, amount_msat, metadata);
        match &result {
            Ok(issuance) => {
                self.0.counters.issued.fetch_add(1, Ordering::Relaxed);
                info!(
                    "issued {} for {amount_msat} msat to {peer} for payee {}",
                    issuance.payment_hash.short(),
                    authorization.payee
                )
            }
            Err(reason) => {
                self.0.counters.refused.fetch_add(1, Ordering::Relaxed);
                warn!("refused to issue a hash to {peer}: {reason}")
            }
        }
        result
    }

    fn try_issue(
        &self,
        peer: &str,
        authorization: &ReceiveAuthorization,
        amount_msat: u64,
        metadata: Option<&Metadata>,
    ) -> Result<PreimageIssuance, String> {
        let id = self.check_authorization(authorization)?;
        let peer = peer_key(peer)?;
        let allowed = match authorization.kind {
            AuthorizationKind::Single => authorization.payee,
            AuthorizationKind::Standing => authorization.gateway,
        };
        if peer != allowed {
            return Err(match authorization.kind {
                AuthorizationKind::Single => "only the payee asks for hashes of its invoices",
                AuthorizationKind::Standing => {
                    "only the authorized gateway asks for hashes under a standing authorization"
                }
            }
            .into());
        }
        if !authorization.is_valid_at(unix_now()) {
            return Err("the authorization is not valid now".into());
        }
        if !authorization.allows_amount(amount_msat) {
            return Err("the payee did not authorize this amount".into());
        }
        let mut issuance = PreimageIssuance {
            payment_hash: Bytes32([0; 32]),
            amount_msat,
            metadata_hash: metadata.map(Metadata::hash),
            authorization: id,
            nonce: Bytes32::random(),
            signature: Signature([0; 64]),
        };
        issuance.payment_hash = self.preimage(&issuance).sha256();
        issuance.sign(&self.0.endpoint_secret);
        Ok(issuance)
    }

    fn network(&self, id: &NetworkId) -> Result<Arc<dyn Network>, String> {
        self.networks()
            .get(id)
            .cloned()
            .ok_or_else(|| format!("this preimage server does not verify HTLCs on {id}"))
    }

    /// Verify the HTLC a gateway funded to the payee and release the
    /// preimage, logging the HTLC for the payee. [`Response::Pending`]
    /// while the HTLC is not final yet: the gateway asks again.
    async fn release(&self, peer: &str, release: PreimageRelease) -> Response {
        match self.try_release(peer, release).await {
            Ok(Some(preimage)) => Response::PreimageReleased(Ok(preimage)),
            Ok(None) => Response::Pending,
            Err(reason) => {
                self.0.counters.refused.fetch_add(1, Ordering::Relaxed);
                warn!("RELEASE refused: {reason}");
                Response::PreimageReleased(Err(reason))
            }
        }
    }

    async fn try_release(
        &self,
        peer: &str,
        release: PreimageRelease,
    ) -> Result<Option<Bytes32>, String> {
        let PreimageRelease {
            authorization,
            preimage_metadata,
            metadata,
            network,
            htlc,
        } = release;
        let issuance = PreimageIssuance::from_metadata(&preimage_metadata)?;
        let id = self.check_authorization(&authorization)?;
        if peer_key(peer)? != authorization.gateway {
            return Err("only the authorized gateway gets preimages released".into());
        }
        issuance.verify(&self.key(), &authorization)?;
        if issuance.authorization != id {
            return Err("the hash was issued under another authorization".into());
        }
        let preimage = self.preimage(&issuance);
        let hash = preimage.sha256();
        if hash != issuance.payment_hash || htlc.payment_hash != hash {
            return Err("this server did not issue the HTLC's payment hash".into());
        }
        if !issuance.matches_metadata(metadata.as_ref()) {
            return Err("the hash was issued for other metadata".into());
        }
        if self.stored(hash)?.is_some() {
            // A repeated release: the preimage is out anyway.
            return Ok(Some(preimage));
        }
        let destination = authorization
            .destination(&network)
            .ok_or_else(|| format!("the payee does not receive on {network}"))?;
        if htlc.descriptor.target() != destination.target() {
            return Err("the HTLC does not pay the payee's destination".into());
        }
        if htlc.amount_msat < issuance.amount_msat {
            return Err(format!(
                "the HTLC locks {} msat, the invoice is for {}",
                htlc.amount_msat, issuance.amount_msat
            ));
        }
        let timeout = authorization.min_final_timeout_secs;
        if htlc.expiry < unix_now().saturating_add(timeout) {
            return Err(format!(
                "the HTLC can be refunded within {timeout}s, sooner than the payee asked"
            ));
        }
        let opened = self.network(&network)?;
        let htlc = Htlc {
            payment_hash: hash,
            ..htlc
        };
        match opened.verify_htlc(&htlc).await {
            Ok(()) => {}
            Err(NetworkError::NotYet(reason) | NetworkError::Network(reason)) => {
                info!("RELEASE {}: waiting for the HTLC: {reason}", hash.short());
                return Ok(None);
            }
            Err(error) => return Err(format!("HTLC rejected: {error}")),
        }
        let payment = Payment {
            payment_hash: PaymentHash(hash.0),
            payee: *authorization.payee.as_bytes(),
            network: network.0.clone(),
            amount_msat: htlc.amount_msat,
            expiry: htlc.expiry,
            descriptor: (&htlc.descriptor).into(),
            preimage: preimage.0,
            metadata: stored_metadata(&metadata),
            released_at: unix_now(),
        };
        let written = self.0.db.write(|tx| tx.payments().insert(&payment));
        match written {
            Ok(_) => {
                self.0.counters.released.fetch_add(1, Ordering::Relaxed);
            }
            // A concurrent release of the same payment got there first.
            Err(orangedb::Error::AlreadyExists { .. }) => {}
            Err(error) => return Err(format!("store payment: {error}")),
        }
        info!(
            "RELEASE {}: {} msat locked on {network} for payee {}, preimage released to {peer}",
            hash.short(),
            htlc.amount_msat,
            authorization.payee
        );
        Ok(Some(preimage))
    }

    fn stored(&self, hash: Bytes32) -> Result<Option<Payment>, String> {
        self.0
            .db
            .payments()
            .get(PaymentHash(hash.0))
            .map_err(|e| format!("read payment: {e}"))
    }

    /// The HTLCs released to `peer`, as payee, since `since`.
    fn payments(&self, peer: &str, since: u64) -> Result<Vec<ReceivedPayment>, String> {
        let payee = *peer_key(peer)?.as_bytes();
        let mut payments = self
            .0
            .db
            .payments()
            .by_payee(payee)
            .map_err(|e| format!("read payments: {e}"))?;
        payments.retain(|payment| payment.released_at >= since);
        payments.sort_by_key(|payment| payment.released_at);
        payments
            .into_iter()
            .map(|payment| {
                Ok(ReceivedPayment::Received {
                    payment_hash: Bytes32(payment.payment_hash.0),
                    network: NetworkId(payment.network),
                    amount_msat: payment.amount_msat,
                    expiry: payment.expiry,
                    descriptor: (&payment.descriptor).try_into()?,
                    preimage: Bytes32(payment.preimage),
                    metadata: stored::metadata(&payment.metadata)?,
                    at: payment.released_at,
                })
            })
            .collect()
    }
}

fn peer_key(peer: &str) -> Result<PublicKey, String> {
    peer.trim()
        .parse()
        .map_err(|e| format!("endpoint key {peer}: {e}"))
}
