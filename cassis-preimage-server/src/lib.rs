//! A preimage server: an always-online iroh node that picks the payment
//! hashes of an offline payee's invoices and gives their preimages out
//! only once a gateway paid the payee (see [`cassis_core::offline`]).
//!
//! * The payee, or the gateway it authorized, asks for a payment hash
//!   ([`Request::PreimageIssue`]) under the payee's signed
//!   [`ReceiveAuthorization`]. The server keeps no record of it: the
//!   preimage is an HMAC by the server's key over the authorization, the
//!   amount and a random nonce, all in the [`PreimageIssuance`] it signs
//!   and returns.
//! * The gateway, paid for the invoice, funds an HTLC to one of the
//!   payee's destinations and presents it ([`Request::PreimageRelease`]).
//!   The server checks it against the authorization (destination,
//!   amount, timeout) and on the network, logs it for the payee and
//!   releases the preimage, so the gateway can settle its incoming
//!   payment.
//! * The payee fetches its log ([`Request::PreimagePayments`]) and
//!   claims each HTLC before it expires.
//!
//! Only HTLCs whose preimage was released are stored.

use cassis_core::network::{Htlc, Network, NetworkError, NetworkId};
use cassis_core::offline::{
    AuthorizationKind, EndpointKey, PreimageIssuance, ReceiveAuthorization, Signature,
};
use cassis_core::protocol::{PreimageRelease, ReceivedPayment, Request, Response};
use cassis_core::transport::{Handler, Transport};
use cassis_core::{unix_now, Bytes32};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{info, warn, Instrument, Span};

pub use db::Db;

#[orangedb::schema]
pub mod db {
    /// A payee whose payment the server let through, by its key.
    #[entity]
    #[derive(Debug, Clone, PartialEq)]
    pub struct Payee {
        #[id(String)]
        pub key: PayeeKey,
        pub first_paid_at: u64,
    }

    /// An HTLC a gateway funded to a payee, which the server verified
    /// before releasing its preimage: what the payee needs to claim it.
    #[entity]
    #[derive(Debug, Clone, PartialEq)]
    pub struct Payment {
        /// Hex.
        #[id(String)]
        pub payment_hash: PaymentHash,
        #[references(Payee, on_delete = cascade)]
        pub payee: PayeeKey,
        pub network: String,
        pub amount_msat: u64,
        pub expiry: u64,
        /// JSON of the HTLC's `HtlcTarget`.
        pub target: String,
        /// JSON of the HTLC's `HtlcDescriptor`.
        pub descriptor: String,
        /// Hex.
        pub preimage: String,
        pub released_at: u64,
    }
}

use db::{Payee, PayeeKey, Payment, PaymentHash};

pub struct ServerConfig {
    /// Secret of the server's iroh endpoint, which signs its issuances.
    pub endpoint_secret: [u8; 32],
    /// Key preimages are derived with. Changing it orphans every
    /// invoice issued before.
    pub preimage_secret: [u8; 32],
    pub db: Arc<Db>,
    /// Networks the server verifies HTLCs on. Authorizations paying
    /// the payee on others are refused.
    pub networks: Vec<Arc<dyn Network>>,
    pub span: Span,
}

/// Handle to a running preimage server. Cheap to clone.
#[derive(Clone)]
pub struct PreimageServer(Arc<Inner>);

struct Inner {
    endpoint_secret: [u8; 32],
    preimage_secret: [u8; 32],
    db: Arc<Db>,
    networks: HashMap<NetworkId, Arc<dyn Network>>,
    transport: Transport,
    span: Span,
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
            networks: config
                .networks
                .into_iter()
                .map(|network| (network.id(), network))
                .collect(),
            transport: transport.clone(),
            span: config.span,
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

    fn key(&self) -> EndpointKey {
        EndpointKey::from_secret(&self.0.endpoint_secret)
    }

    async fn handle(&self, request: Request, peer: String) -> Response {
        match request {
            Request::PreimageIssue {
                authorization,
                amount_msat,
            } => Response::PreimageIssued(self.issue(&peer, &authorization, amount_msat)),
            Request::PreimageRelease(release) => self.release(&peer, release).await,
            Request::PreimagePayments { since } => {
                Response::PreimagePayments(self.payments(&peer, since))
            }
            _ => Response::Error(
                "this is a preimage server: it neither routes, pays nor receives".into(),
            ),
        }
    }

    /// The preimage of the hash issued for `amount_msat` under the
    /// authorization `authorization` with `nonce`.
    fn preimage(&self, authorization: &Bytes32, amount_msat: u64, nonce: &Bytes32) -> Bytes32 {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0.preimage_secret)
            .expect("hmac accepts any key length");
        mac.update(b"cassis/preimage-server/v2\0");
        mac.update(&authorization.0);
        mac.update(&amount_msat.to_be_bytes());
        mac.update(&nonce.0);
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
            self.network(&destination.network)?;
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
    ) -> Result<PreimageIssuance, String> {
        let result = self.try_issue(peer, authorization, amount_msat);
        match &result {
            Ok(issuance) => info!(
                "issued {} for {amount_msat} msat to {peer} for payee {}",
                issuance.payment_hash.short(),
                authorization.payee
            ),
            Err(reason) => warn!("refused to issue a hash to {peer}: {reason}"),
        }
        result
    }

    fn try_issue(
        &self,
        peer: &str,
        authorization: &ReceiveAuthorization,
        amount_msat: u64,
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
        let nonce = Bytes32::random();
        let mut issuance = PreimageIssuance {
            payment_hash: self.preimage(&id, amount_msat, &nonce).sha256(),
            amount_msat,
            authorization: id,
            nonce,
            signature: Signature([0; 64]),
        };
        issuance.sign(&self.0.endpoint_secret);
        Ok(issuance)
    }

    fn network(&self, id: &NetworkId) -> Result<Arc<dyn Network>, String> {
        self.0
            .networks
            .get(id)
            .cloned()
            .ok_or_else(|| format!("this preimage server does not verify HTLCs on {id}"))
    }

    /// Verify the HTLC a gateway funded to the payee and release the
    /// preimage, logging the HTLC for the payee. [`Response::Pending`]
    /// while the HTLC is not final yet: the gateway asks again.
    async fn release(&self, peer: &str, release: PreimageRelease) -> Response {
        let hash = release.issuance.payment_hash;
        match self.try_release(peer, release).await {
            Ok(Some(preimage)) => Response::PreimageReleased(Ok(preimage)),
            Ok(None) => Response::Pending,
            Err(reason) => {
                warn!("RELEASE {} refused: {reason}", hash.short());
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
            issuance,
            network,
            htlc,
        } = release;
        let id = self.check_authorization(&authorization)?;
        if peer_key(peer)? != authorization.gateway {
            return Err("only the authorized gateway gets preimages released".into());
        }
        if issuance.authorization != id {
            return Err("the hash was issued under another authorization".into());
        }
        let preimage = self.preimage(&id, issuance.amount_msat, &issuance.nonce);
        let hash = preimage.sha256();
        if hash != issuance.payment_hash || htlc.payment_hash != hash {
            return Err("this server did not issue the HTLC's payment hash".into());
        }
        if self.stored(hash)?.is_some() {
            // A repeated release: the preimage is out anyway.
            return Ok(Some(preimage));
        }
        let destination = authorization
            .destination(&network)
            .ok_or_else(|| format!("the payee does not receive on {network}"))?;
        if htlc.target != destination.target {
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
            payment_hash: PaymentHash(hash.to_string()),
            payee: PayeeKey(authorization.payee.to_string()),
            network: network.0.clone(),
            amount_msat: htlc.amount_msat,
            expiry: htlc.expiry,
            target: serde_json::to_string(&htlc.target).map_err(|e| e.to_string())?,
            descriptor: serde_json::to_string(&htlc.descriptor).map_err(|e| e.to_string())?,
            preimage: preimage.to_string(),
            released_at: unix_now(),
        };
        let written = self.0.db.write(|tx| {
            if tx.payees().get(payment.payee.clone())?.is_none() {
                tx.payees().insert(&Payee {
                    key: payment.payee.clone(),
                    first_paid_at: payment.released_at,
                })?;
            }
            tx.payments().insert(&payment)
        });
        match written {
            Ok(_) => {}
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
            .get(PaymentHash(hash.to_string()))
            .map_err(|e| format!("read payment: {e}"))
    }

    /// The HTLCs released to `peer`, as payee, since `since`.
    fn payments(&self, peer: &str, since: u64) -> Result<Vec<ReceivedPayment>, String> {
        let payee = PayeeKey(peer_key(peer)?.to_string());
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
                    payment_hash: Bytes32::from_str(&payment.payment_hash.0)?,
                    network: NetworkId(payment.network),
                    amount_msat: payment.amount_msat,
                    expiry: payment.expiry,
                    target: serde_json::from_str(&payment.target)
                        .map_err(|e| format!("stored target: {e}"))?,
                    descriptor: serde_json::from_str(&payment.descriptor)
                        .map_err(|e| format!("stored descriptor: {e}"))?,
                    preimage: Bytes32::from_str(&payment.preimage)?,
                    at: payment.released_at,
                })
            })
            .collect()
    }
}

fn peer_key(peer: &str) -> Result<EndpointKey, String> {
    peer.parse()
}
