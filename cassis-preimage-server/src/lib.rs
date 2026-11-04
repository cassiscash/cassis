//! A preimage server: an always-online iroh node that answers PREPARE
//! and COMMIT for payees who want to go offline, and keeps what they
//! need to claim their payments when they come back.
//!
//! * A payee asks for a payment hash ([`Request::PreimageInvoice`]).
//!   The server keeps no record of it: the preimage is an HMAC by the
//!   server's key over a random nonce and the payee's iroh id, both put
//!   in the invoice's metadata ([`PreimageServerMetadata`]).
//! * The payee builds the invoice on its own networks, naming this
//!   server's endpoint, and has the server sign it
//!   ([`Request::PreimageSign`]).
//! * Payers PREPARE and COMMIT here, sending the invoice along. The
//!   server checks it signed the invoice and recomputes the preimage
//!   from its metadata. On COMMIT it verifies the HTLC, which is locked
//!   to the payee's target and so cannot be claimed here, reveals the
//!   preimage and logs the HTLC in its database.
//! * The payee fetches its log ([`Request::PreimagePayments`]) and
//!   claims each HTLC before it expires.
//!
//! Only payments whose preimage was revealed are stored.

use cassis_core::network::{Htlc, HtlcTarget, Network, NetworkError, NetworkId};
use cassis_core::protocol::{
    Commit, Invoice, InvoiceSignature, PreimageInvoiceTerms, PreimageServerMetadata, PreparePayee,
    ReceivedPayment, Request, Response,
};
use cassis_core::transport::{Handler, Transport};
use cassis_core::{unix_now, Bytes32};
use hmac::{Hmac, Mac};
use iroh::PublicKey;
use sha2::Sha256;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{info, warn, Instrument, Span};

pub use db::Db;

#[orangedb::schema]
pub mod db {
    /// A payee whose payment the server let through, by the iroh id it
    /// talks to the server with.
    #[entity]
    #[derive(Debug, Clone, PartialEq)]
    pub struct Payee {
        #[id(String)]
        pub key: PayeeKey,
        pub first_paid_at: u64,
    }

    /// A payment whose HTLC the server verified and whose preimage it
    /// revealed: what its payee needs to claim it.
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
        /// JSON of the HTLC's `HtlcDescriptor`.
        pub descriptor: String,
        /// Hex.
        pub preimage: String,
        pub settled_at: u64,
    }
}

use db::{Payee, PayeeKey, Payment, PaymentHash};

pub struct ServerConfig {
    /// Secret of the server's iroh endpoint, which signs its invoices.
    pub endpoint_secret: [u8; 32],
    /// Key preimages are derived with. Changing it orphans every
    /// invoice issued before.
    pub preimage_secret: [u8; 32],
    pub db: Arc<Db>,
    /// Networks the server verifies HTLCs on. Invoices on others are
    /// refused.
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

    async fn handle(&self, request: Request, peer: String) -> Response {
        match request {
            Request::PreimageInvoice => Response::PreimageInvoice(self.issue(&peer)),
            Request::PreimageSign(invoice) => Response::PreimageSigned(self.sign(invoice, &peer)),
            Request::PreparePayee(prepare) => Response::PayeePrepared(self.prepare(&prepare)),
            Request::Commit(commit) => self.commit(commit).await,
            Request::PreimagePayments { since } => {
                Response::PreimagePayments(self.payments(&peer, since))
            }
            _ => Response::Error("this is a preimage server: it neither routes nor pays".into()),
        }
    }

    /// The preimage of the invoice whose metadata is `metadata`.
    fn preimage(&self, metadata: &PreimageServerMetadata) -> Bytes32 {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0.preimage_secret)
            .expect("hmac accepts any key length");
        mac.update(b"cassis/preimage-server/v1\0");
        mac.update(&metadata.nonce);
        mac.update(&metadata.payee);
        Bytes32(mac.finalize().into_bytes().into())
    }

    /// A fresh payment hash for `peer`.
    fn issue(&self, peer: &str) -> Result<PreimageInvoiceTerms, String> {
        let metadata = PreimageServerMetadata {
            nonce: rand::random(),
            payee: *peer_key(peer)?.as_bytes(),
        };
        let preimage = self.preimage(&metadata);
        info!("issued {} to payee {peer}", preimage.sha256().short());
        Ok(PreimageInvoiceTerms {
            payment_hash: preimage.sha256(),
            preimage,
            metadata: metadata.to_metadata(),
        })
    }

    /// The preimage of `invoice`, if this server issued its hash: its
    /// metadata must be one of ours and hash to its payment hash.
    fn derive(&self, invoice: &Invoice) -> Result<(Bytes32, PreimageServerMetadata), String> {
        let metadata = invoice
            .metadata
            .as_ref()
            .ok_or("invoice has no metadata, so this server did not issue its hash")?;
        let metadata = PreimageServerMetadata::from_metadata(metadata)?;
        let preimage = self.preimage(&metadata);
        if !invoice.payment_hash.matches_preimage(&preimage) {
            return Err("this server did not issue the invoice's payment hash".into());
        }
        Ok((preimage, metadata))
    }

    /// Sign `invoice` for the payee its hash was issued to, once it
    /// names this server and networks it can verify HTLCs on.
    fn sign(&self, mut invoice: Invoice, peer: &str) -> Result<InvoiceSignature, String> {
        let (_, metadata) = self.derive(&invoice)?;
        if metadata.payee != *peer_key(peer)?.as_bytes() {
            return Err("the invoice's hash was issued to another payee".into());
        }
        if invoice.amount_msat == 0 {
            return Err("invoice amount is zero".into());
        }
        if invoice.expires_at <= unix_now() {
            return Err("invoice expired".into());
        }
        if invoice.networks.is_empty() {
            return Err("invoice names no network".into());
        }
        for entry in &invoice.networks {
            self.network(&entry.network)?;
        }
        invoice.signature = None;
        invoice.sign(&self.0.endpoint_secret)?;
        Ok(invoice.signature.expect("just signed"))
    }

    /// The invoice a payer sent with PREPARE or COMMIT, once checked to
    /// be one this server signed for `payment_hash`, with its preimage
    /// and the payee it was issued to.
    fn signed_invoice(
        &self,
        invoice: Option<&Invoice>,
        payment_hash: Bytes32,
    ) -> Result<(Invoice, Bytes32, PublicKey), String> {
        let invoice = invoice.ok_or("send the invoice along: this server keeps no record of it")?;
        if invoice.payment_hash != payment_hash {
            return Err("the invoice is for another payment".into());
        }
        if invoice.iroh_peer_id.as_deref() != Some(self.peer_id().as_str()) {
            return Err("the invoice names another endpoint".into());
        }
        invoice.verify_signature()?;
        if invoice.expires_at <= unix_now() {
            return Err("invoice expired".into());
        }
        let (preimage, metadata) = self.derive(invoice)?;
        let payee = PublicKey::from_bytes(&metadata.payee).map_err(|e| format!("payee: {e}"))?;
        Ok((invoice.clone(), preimage, payee))
    }

    fn network(&self, id: &NetworkId) -> Result<Arc<dyn Network>, String> {
        self.0
            .networks
            .get(id)
            .cloned()
            .ok_or_else(|| format!("this preimage server does not verify HTLCs on {id}"))
    }

    /// The target and network of an HTLC paying `invoice` on `network`
    /// and expiring at `expiry`, once checked to leave the payee its
    /// claim window.
    fn payable_on(
        &self,
        invoice: &Invoice,
        network: &NetworkId,
        expiry: u64,
    ) -> Result<(HtlcTarget, Arc<dyn Network>), String> {
        let target = invoice
            .target_for(network)
            .cloned()
            .ok_or_else(|| format!("invoice is not payable on {network}"))?;
        let opened = self.network(network)?;
        // The invoice's margin on `network` includes the payee's claim
        // window: what it needs left after the preimage is out.
        if expiry.saturating_sub(invoice.incoming_delta_for(network)) <= unix_now() {
            return Err("HTLC expires too soon for the payee to claim it".into());
        }
        Ok((target, opened))
    }

    fn prepare(&self, prepare: &PreparePayee) -> Result<(), String> {
        let hash = prepare.payment_hash;
        let result = self
            .signed_invoice(prepare.invoice.as_ref(), hash)
            .and_then(|(invoice, _, payee)| {
                if self.stored(hash)?.is_some() {
                    return Err("invoice already paid".into());
                }
                self.payable_on(&invoice, &prepare.network, prepare.expiry)?;
                Ok(payee)
            });
        match result {
            Ok(payee) => {
                info!(
                    "PREPARE {} accepted on {} for payee {payee}",
                    hash.short(),
                    prepare.network
                );
                Ok(())
            }
            Err(reason) => {
                warn!("PREPARE {} rejected: {reason}", hash.short());
                Err(reason)
            }
        }
    }

    /// Verify the HTLC of `commit` and reveal the preimage, logging the
    /// HTLC for the payee. [`Response::Pending`] while the HTLC is not
    /// final yet: the payer repeats COMMIT.
    async fn commit(&self, commit: Commit) -> Response {
        let hash = commit.payment_hash;
        match self.try_commit(commit).await {
            Ok(Some(preimage)) => Response::Committed(preimage),
            Ok(None) => Response::Pending,
            Err(reason) => {
                warn!("COMMIT {} rejected: {reason}", hash.short());
                Response::Error(reason)
            }
        }
    }

    async fn try_commit(&self, commit: Commit) -> Result<Option<Bytes32>, String> {
        let hash = commit.payment_hash;
        let (invoice, preimage, payee) = self.signed_invoice(commit.invoice.as_ref(), hash)?;
        if self.stored(hash)?.is_some() {
            // A repeated COMMIT of a payment already let through: the
            // preimage is out anyway.
            return Ok(Some(preimage));
        }
        let (target, network) = self.payable_on(&invoice, &commit.network, commit.expiry)?;
        let htlc = Htlc {
            payment_hash: hash,
            amount_msat: invoice.amount_msat,
            expiry: commit.expiry,
            target,
            descriptor: commit.descriptor,
        };
        match network.verify_htlc(&htlc).await {
            Ok(()) => {}
            Err(NetworkError::NotYet(reason) | NetworkError::Network(reason)) => {
                info!("COMMIT {}: waiting for the HTLC: {reason}", hash.short());
                return Ok(None);
            }
            Err(error) => return Err(format!("HTLC rejected: {error}")),
        }
        let payment = Payment {
            payment_hash: PaymentHash(hash.to_string()),
            payee: PayeeKey(payee.to_string()),
            network: commit.network.0.clone(),
            amount_msat: htlc.amount_msat,
            expiry: htlc.expiry,
            descriptor: serde_json::to_string(&htlc.descriptor).map_err(|e| e.to_string())?,
            preimage: preimage.to_string(),
            settled_at: unix_now(),
        };
        let written = self.0.db.write(|tx| {
            if tx.payees().get(payment.payee.clone())?.is_none() {
                tx.payees().insert(&Payee {
                    key: payment.payee.clone(),
                    first_paid_at: payment.settled_at,
                })?;
            }
            tx.payments().insert(&payment)
        });
        match written {
            Ok(_) => {}
            // A concurrent COMMIT of the same payment got there first.
            Err(orangedb::Error::AlreadyExists { .. }) => {}
            Err(error) => return Err(format!("store payment: {error}")),
        }
        info!(
            "COMMIT {}: revealed the preimage of {} msat on {} for payee {payee}",
            hash.short(),
            htlc.amount_msat,
            commit.network
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

    /// The payments `peer` received since `since`.
    fn payments(&self, peer: &str, since: u64) -> Result<Vec<ReceivedPayment>, String> {
        let payee = PayeeKey(peer_key(peer)?.to_string());
        let mut payments = self
            .0
            .db
            .payments()
            .by_payee(payee)
            .map_err(|e| format!("read payments: {e}"))?;
        payments.retain(|payment| payment.settled_at >= since);
        payments.sort_by_key(|payment| payment.settled_at);
        payments
            .into_iter()
            .map(|payment| {
                Ok(ReceivedPayment::Received {
                    payment_hash: Bytes32::from_str(&payment.payment_hash.0)?,
                    network: NetworkId(payment.network),
                    expiry: payment.expiry,
                    descriptor: serde_json::from_str(&payment.descriptor)
                        .map_err(|e| format!("stored descriptor: {e}"))?,
                    preimage: Bytes32::from_str(&payment.preimage)?,
                    at: payment.settled_at,
                })
            })
            .collect()
    }
}

fn peer_key(peer: &str) -> Result<PublicKey, String> {
    PublicKey::from_str(peer).map_err(|e| format!("peer id {peer}: {e}"))
}
