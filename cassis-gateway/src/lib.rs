//! A gateway: an always-online iroh node that is paid in place of
//! offline payees and pays each of them on through an HTLC only they
//! can claim (see [`cassis_core::offline`]).
//!
//! * A payee has the gateway issue one invoice
//!   ([`Request::GatewayInvoice`]) for a hash its preimage server issued
//!   it, under a single [`ReceiveAuthorization`]; the payee then signs
//!   the invoice too.
//! * Or a payee hands the gateway a standing authorization
//!   ([`Request::GatewayAuthorize`]), and anyone can then have the
//!   gateway issue invoices in the payee's name
//!   ([`Request::GatewayInvoiceFor`]), for hashes the gateway asks the
//!   preimage server for.
//!
//! Either way the gateway refuses terms it does not want to meet (a
//! final timeout it finds too long, say), and keeps no invoice: it seals
//! the invoice's terms in its metadata, signed ([`GatewayMetadata`]),
//! which payers hand back with PREPARE and COMMIT, as with any payee.
//! On COMMIT the gateway checks its signature there, verifies the
//! incoming HTLC, funds an HTLC to the payee on one of its
//! destinations, at least as long as the payee asked for, and presents
//! it to the preimage server ([`Request::PreimageRelease`]) with the
//! issuance and the payee's metadata the invoice carried, and the server
//! releases the preimage. The gateway claims the incoming HTLC with it
//! and answers the COMMIT.
//!
//! Every HTLC to a payee is journaled in the [`Db`] as a [`PayeeHtlc`].
//! A settlement loop resumes interrupted ones and refunds those whose
//! preimage never came before they expired.

pub mod admin;
pub mod config;
pub mod db;

use crate::db::{
    Db, HandledDelegation, HandledDelegationId, PayeeHtlc, PayeeHtlcHash, PayeeOutcome,
};
use cassis_core::network::{Htlc, HtlcTarget, Network, NetworkError, NetworkId, OutgoingState};
use cassis_core::offline::{
    endpoint_public_key, AuthorizationKind, GatewayDestination, GatewayMetadata, GatewayTerms,
    ReceiveAuthorization,
};
use cassis_core::protocol::{
    Commit, GatewayInvoiceFor, GatewayInvoiceRequest, Invoice, InvoiceBody, InvoiceNetwork,
    InvoiceTarget, Metadata, PreimageRelease, PreparePayee, Request, Response,
};
use cassis_core::transport::{Handler, PeerAddr, Transport};
use cassis_core::{unix_now, Bytes32};
use cassis_wallet::stored::{metadata, stored_metadata};
use iroh_base::PublicKey;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{error, info, warn, Instrument, Span};

/// Why an HTLC to a payee left mid-funding by a restart failed: whether
/// it exists is unknown.
pub const INTERRUPTED_FUNDING: &str = "interrupted while funding";

/// How long COMMIT works before answering [`Response::Pending`].
const INLINE_WAIT: Duration = Duration::from_secs(5);
/// How often an HTLC not final yet is verified again, and a preimage
/// not released yet asked for again.
const RETRY_INTERVAL: Duration = Duration::from_secs(5);
const SETTLE_INTERVAL: Duration = Duration::from_secs(25);

/// Terms the gateway accepts from payees.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GatewayPolicy {
    /// Longest final timeout a payee may ask for: the gateway's funds
    /// stay locked that long when the payee does not claim.
    pub max_final_timeout_secs: u64,
    /// Longest a standing authorization may run.
    pub max_authorization_secs: u64,
    /// Expiry of invoices issued under a standing authorization, when
    /// the asker names none.
    pub default_invoice_expiry_secs: u64,
    /// Margin on top of each network's own, on incoming HTLCs: time to
    /// fund the HTLC to the payee and have its preimage released before
    /// the incoming one must be claimed.
    pub forward_slack_secs: u64,
    /// Margin on top of the payee's final timeout on the HTLC to it:
    /// time for the preimage server to see it final.
    pub final_slack_secs: u64,
}

impl Default for GatewayPolicy {
    fn default() -> Self {
        Self {
            max_final_timeout_secs: 30 * 24 * 3600,
            max_authorization_secs: 366 * 24 * 3600,
            default_invoice_expiry_secs: 3600,
            forward_slack_secs: 3600,
            final_slack_secs: 3600,
        }
    }
}

pub struct GatewayConfig {
    /// Secret of the gateway's iroh endpoint, which signs its invoices.
    pub endpoint_secret: [u8; 32],
    pub db: Arc<Db>,
    /// Networks the gateway is paid on and pays payees on.
    pub networks: Vec<Arc<dyn Network>>,
    pub policy: GatewayPolicy,
    pub span: Span,
}

/// Handle to a running gateway. Cheap to clone.
#[derive(Clone)]
pub struct Gateway(Arc<Inner>);

struct Inner {
    endpoint_secret: [u8; 32],
    db: Arc<Db>,
    networks: Mutex<HashMap<NetworkId, Arc<dyn Network>>>,
    policy: Mutex<GatewayPolicy>,
    transport: Transport,
    span: Span,
    /// Payment hashes some task is forwarding; others leave them be.
    busy: Mutex<HashSet<Bytes32>>,
    /// Why COMMITs failed before anything was paid to the payee, until a
    /// repeated COMMIT collects it.
    refused: Mutex<HashMap<Bytes32, String>>,
    /// Preimages the settlement loop learned from payees' claims, for
    /// forwards still waiting on the preimage server.
    learned: Mutex<HashMap<Bytes32, Bytes32>>,
    tasks: Mutex<Vec<tokio::task::AbortHandle>>,
}

/// A COMMIT checked against the invoice its metadata carries.
struct Forward {
    preimage_metadata: Metadata,
    terms: GatewayTerms,
    incoming_network: NetworkId,
    incoming: Htlc,
    claim_by: u64,
}

impl Gateway {
    /// Bind the gateway's endpoint, resume journaled HTLCs to payees and
    /// answer requests until [`Gateway::shutdown`].
    pub async fn start(config: GatewayConfig) -> Result<Self, String> {
        let transport = Transport::bind(Some(config.endpoint_secret)).await?;
        let gateway = Self(Arc::new(Inner {
            endpoint_secret: config.endpoint_secret,
            db: config.db,
            networks: Mutex::new(
                config
                    .networks
                    .into_iter()
                    .map(|network| (network.id(), network))
                    .collect(),
            ),
            policy: Mutex::new(config.policy),
            transport: transport.clone(),
            span: config.span,
            busy: Default::default(),
            refused: Default::default(),
            learned: Default::default(),
            tasks: Default::default(),
        }));
        gateway.resume()?;
        let handling = gateway.clone();
        let handler: Handler = Arc::new(move |request, peer| {
            let gateway = handling.clone();
            Box::pin(async move { gateway.handle(request, peer).await })
        });
        gateway.spawn(async move { transport.serve(handler).await });
        gateway.spawn(gateway.clone().settle_loop());
        Ok(gateway)
    }

    fn spawn(&self, task: impl std::future::Future<Output = ()> + Send + 'static) {
        let handle = tokio::spawn(task.instrument(self.0.span.clone()));
        let mut tasks = self.0.tasks.lock().unwrap_or_else(|e| e.into_inner());
        tasks.retain(|task| !task.is_finished());
        tasks.push(handle.abort_handle());
    }

    pub fn peer_id(&self) -> String {
        self.0.transport.peer_id()
    }

    pub fn key(&self) -> PublicKey {
        endpoint_public_key(&self.0.endpoint_secret)
    }

    pub async fn home_relay(&self) -> Option<String> {
        self.0.transport.home_relay().await
    }

    /// Stop serving and settling, and close the endpoint. The journal
    /// stays: a gateway started again on it resumes.
    pub async fn shutdown(&self) {
        for task in self
            .0
            .tasks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain(..)
        {
            task.abort();
        }
        self.0.transport.close().await;
    }

    pub fn db(&self) -> &Db {
        &self.0.db
    }

    pub fn payee_htlcs(&self) -> Result<Vec<PayeeHtlc>, String> {
        self.db().payee_htlcs().all().map_err(db_error)
    }

    pub fn delegations(&self) -> Result<Vec<HandledDelegation>, String> {
        self.db().handled_delegations().all().map_err(db_error)
    }

    /// Stop issuing invoices under the standing authorization `id`.
    /// Invoices issued before stay payable: they carry their own copy.
    pub fn forget_delegation(&self, id: &Bytes32) -> Result<(), String> {
        self.db()
            .handled_delegations()
            .delete(HandledDelegationId(id.to_string()))
            .map(|_| ())
            .map_err(db_error)
    }

    /// The terms it accepts now.
    pub fn policy(&self) -> GatewayPolicy {
        lock(&self.0.policy).clone()
    }

    /// Accept these terms from now on. Authorizations and invoices it
    /// took under others stay as they are.
    pub fn set_policy(&self, policy: GatewayPolicy) {
        *lock(&self.0.policy) = policy;
    }

    /// Be paid and pay payees on `network` too, or anew.
    pub fn add_network(&self, network: Arc<dyn Network>) {
        lock(&self.0.networks).insert(network.id(), network);
    }

    /// Stop using `id`. Tasks that hold it already keep it until they
    /// end, and forwards through it wait for it to come back.
    pub fn remove_network(&self, id: &NetworkId) {
        lock(&self.0.networks).remove(id);
    }

    /// The networks the gateway is on, in order.
    pub fn network_ids(&self) -> Vec<NetworkId> {
        let mut ids: Vec<NetworkId> = lock(&self.0.networks).keys().cloned().collect();
        ids.sort();
        ids
    }

    /// The HTLCs to payees that still need `id`: to claim or fund while
    /// in progress, and to see the payee claim its HTLC or refund it.
    pub fn in_flight(&self, id: &NetworkId) -> usize {
        let Ok(htlcs) = self.payee_htlcs() else {
            // Unable to tell: do not let go of the network.
            return 1;
        };
        htlcs
            .iter()
            .filter(|htlc| {
                htlc.in_flight() && (&htlc.network == id || &htlc.incoming_network == id)
            })
            .count()
    }

    async fn handle(&self, request: Request, peer: String) -> Response {
        match request {
            Request::GatewayInvoice(request) => {
                Response::GatewayInvoice(log_refusal("invoice", self.invoice(request, &peer).await))
            }
            Request::GatewayAuthorize { authorization } => Response::GatewayAuthorized(
                log_refusal("authorization", self.authorize(authorization)),
            ),
            Request::GatewayInvoiceFor(request) => {
                Response::GatewayInvoice(log_refusal("invoice", self.invoice_for(request).await))
            }
            Request::PreparePayee(prepare) => {
                Response::PayeePrepared(log_refusal("PREPARE", self.prepare(&prepare).await))
            }
            Request::Commit(commit) => self.commit(commit).await,
            _ => Response::Error("this is a gateway: it neither routes nor pays".into()),
        }
    }

    fn network(&self, id: &NetworkId) -> Result<Arc<dyn Network>, String> {
        lock(&self.0.networks)
            .get(id)
            .cloned()
            .ok_or_else(|| format!("this gateway is not on {id}"))
    }

    /// The network `id` for a forward under way, waiting for it until
    /// `until` if it is not open: it may be reopening, or fail to open
    /// for a while, and money waits on it.
    async fn network_by(&self, id: &NetworkId, until: u64) -> Result<Arc<dyn Network>, String> {
        let mut waiting = false;
        loop {
            match self.network(id) {
                Ok(network) => return Ok(network),
                Err(error) if unix_now() >= until => return Err(error),
                Err(_) => {
                    if !waiting {
                        warn!("a forward waits for {id} to open");
                        waiting = true;
                    }
                    tokio::time::sleep(RETRY_INTERVAL).await;
                }
            }
        }
    }

    /// Whether the gateway takes `authorization`, of `kind`: it names
    /// this gateway, the payee signed it, and its terms are ones the
    /// gateway can and wants to meet.
    fn check_authorization(
        &self,
        authorization: &ReceiveAuthorization,
        kind: AuthorizationKind,
    ) -> Result<(), String> {
        authorization.verify()?;
        if authorization.kind != kind {
            return Err(format!("expected a {kind:?} authorization"));
        }
        if authorization.gateway != self.key() {
            return Err("the authorization names another gateway".into());
        }
        let policy = self.policy();
        if authorization.min_final_timeout_secs > policy.max_final_timeout_secs {
            return Err(format!(
                "a final timeout of {}s is more than this gateway locks funds for ({}s)",
                authorization.min_final_timeout_secs, policy.max_final_timeout_secs
            ));
        }
        if authorization.valid_until - authorization.valid_from > policy.max_authorization_secs {
            return Err(format!(
                "authorizations may run at most {}s here",
                policy.max_authorization_secs
            ));
        }
        if authorization.valid_until <= unix_now() {
            return Err("the authorization has ended".into());
        }
        if !authorization
            .destinations
            .iter()
            .any(|destination| self.network(destination.network()).is_ok())
        {
            return Err("this gateway pays on none of the payee's networks".into());
        }
        Ok(())
    }

    /// A payee's own invoice: check its single authorization and the
    /// preimage server's issuance, and issue the invoice for the payee
    /// to sign too.
    async fn invoice(&self, request: GatewayInvoiceRequest, peer: &str) -> Result<Invoice, String> {
        let GatewayInvoiceRequest {
            authorization,
            issuance,
            expires_at,
            description,
            metadata,
        } = request;
        self.check_authorization(&authorization, AuthorizationKind::Single)?;
        if !authorization.allows_description(description.as_deref()) {
            return Err("the invoice must say what the payee authorized".into());
        }
        if peer
            .trim()
            .parse::<PublicKey>()
            .map_err(|e| format!("endpoint key {peer}: {e}"))?
            != authorization.payee
        {
            return Err("only the payee asks for its own invoices".into());
        }
        issuance.verify(&authorization.preimage_server, &authorization)?;
        if issuance.amount_msat != authorization.min_amount_msat {
            return Err("the hash was issued for another amount".into());
        }
        if !issuance.matches_metadata(metadata.as_ref()) {
            return Err("the hash was issued for other metadata".into());
        }
        if expires_at > authorization.valid_until {
            return Err("the invoice would outlive its authorization".into());
        }
        let payee = authorization.payee;
        let terms = GatewayTerms {
            payment_hash: issuance.payment_hash,
            amount_msat: issuance.amount_msat,
            authorization,
            expires_at,
            payee_metadata: metadata,
        };
        let carried = GatewayMetadata::sign(
            &self.0.endpoint_secret,
            issuance.to_metadata()?,
            terms.clone(),
        )?;
        let body = self.build(&carried, &terms, description).await?;
        let invoice = Invoice::gateway_invoice(body, payee, &self.0.endpoint_secret);
        Ok(self.issued(invoice))
    }

    /// Keep a standing authorization, so invoices can be issued under it.
    fn authorize(&self, authorization: ReceiveAuthorization) -> Result<(), String> {
        self.check_authorization(&authorization, AuthorizationKind::Standing)?;
        let id = authorization.id()?;
        info!(
            "payee {} authorized invoices of {}..{} msat until {}",
            authorization.payee,
            authorization.min_amount_msat,
            authorization.max_amount_msat,
            authorization.valid_until
        );
        self.db()
            .handled_delegations()
            .upsert(&HandledDelegation {
                authorization_id: HandledDelegationId(id.to_string()),
                payee: *authorization.payee.as_bytes(),
                authorization: (&authorization).into(),
                registered_at: unix_now(),
            })
            .map_err(db_error)
    }

    /// An invoice in the name of an offline payee, under its standing
    /// authorization that runs longest among those allowing the amount;
    /// its description is the one that authorization pins, if any.
    async fn invoice_for(&self, request: GatewayInvoiceFor) -> Result<Invoice, String> {
        let now = unix_now();
        let mut candidates = Vec::new();
        for delegation in self
            .db()
            .handled_delegations()
            .by_payee(*request.payee.as_bytes())
            .map_err(db_error)?
        {
            let authorization = ReceiveAuthorization::try_from(&delegation.authorization)?;
            if authorization.is_valid_at(now)
                && authorization.allows_amount(request.amount_msat)
                && authorization.allows_description(request.description.as_deref())
            {
                candidates.push(authorization);
            }
        }
        let authorization = candidates
            .into_iter()
            .max_by_key(|authorization| authorization.valid_until)
            .ok_or("this payee authorized no invoice like this one")?;
        // The payee may pin what its invoices say: then they say that.
        let description = authorization
            .description
            .clone()
            .or_else(|| request.description.clone());
        let expires_at = request
            .expires_at
            .unwrap_or(now + self.policy().default_invoice_expiry_secs)
            .min(authorization.valid_until);
        if expires_at <= now {
            return Err("invoice expiry must be in the future".into());
        }
        let preimage_server = PeerAddr {
            id: authorization.preimage_server.to_string(),
            relay: authorization.preimage_server_relay.clone(),
        };
        let issue = Request::PreimageIssue {
            authorization: authorization.clone(),
            amount_msat: request.amount_msat,
            metadata: request.metadata.clone(),
        };
        let issuance = match self.0.transport.request(&preimage_server, &issue).await? {
            Response::PreimageIssued(Ok(issuance)) => issuance,
            Response::PreimageIssued(Err(reason)) | Response::Error(reason) => {
                return Err(format!("preimage server refused: {reason}"))
            }
            other => return Err(format!("unexpected answer from preimage server: {other:?}")),
        };
        issuance.verify(&authorization.preimage_server, &authorization)?;
        if issuance.amount_msat != request.amount_msat
            || !issuance.matches_metadata(request.metadata.as_ref())
        {
            return Err("preimage server issued the hash for another payment".into());
        }
        let terms = GatewayTerms {
            payment_hash: issuance.payment_hash,
            amount_msat: issuance.amount_msat,
            authorization: authorization.clone(),
            expires_at,
            payee_metadata: request.metadata,
        };
        let carried = GatewayMetadata::sign(
            &self.0.endpoint_secret,
            issuance.to_metadata()?,
            terms.clone(),
        )?;
        let body = self.build(&carried, &terms, description).await?;
        let invoice = Invoice::delegated(
            body,
            authorization.payee,
            &self.0.endpoint_secret,
            authorization.preimage_server,
            issuance,
            authorization,
        );
        invoice.verify()?;
        Ok(self.issued(invoice))
    }

    /// The terms of an invoice carrying `carried` as its metadata,
    /// payable to this gateway on every network it is on.
    async fn build(
        &self,
        carried: &GatewayMetadata,
        terms: &GatewayTerms,
        description: Option<String>,
    ) -> Result<InvoiceBody, String> {
        let expires_at = terms.expires_at;
        if expires_at <= unix_now() {
            return Err("invoice expiry must be in the future".into());
        }
        let payment_hash = terms.payment_hash;
        let amount_msat = terms.amount_msat;
        let forward_slack_secs = self.policy().forward_slack_secs;
        let mut networks: Vec<Arc<dyn Network>> =
            lock(&self.0.networks).values().cloned().collect();
        networks.sort_by_key(|network| network.id());
        let mut targets = Vec::with_capacity(networks.len());
        for network in networks {
            match network
                .receive_target(payment_hash, amount_msat, expires_at)
                .await
                .map_err(|e| e.to_string())
                .and_then(|target| InvoiceTarget::new(network.id(), target))
            {
                Ok(target) => targets.push(InvoiceNetwork {
                    target,
                    incoming_delta_secs: Some(
                        network
                            .incoming_delta_secs()
                            .saturating_add(forward_slack_secs),
                    ),
                }),
                Err(error) => warn!("cannot receive on {}: {error}", network.id()),
            }
        }
        if targets.is_empty() {
            return Err("this gateway can receive on none of its networks".into());
        }
        Ok(InvoiceBody {
            payment_hash,
            amount_msat,
            expires_at,
            networks: targets,
            description,
            metadata: Some(carried.to_metadata()?),
            iroh_relay: self.home_relay().await,
        })
    }

    fn issued(&self, invoice: Invoice) -> Invoice {
        info!(
            "issued invoice {} of {} msat for payee {}",
            invoice.body.payment_hash.short(),
            invoice.body.amount_msat,
            invoice.receiver.payee()
        );
        invoice
    }

    /// The invoice this gateway issued for `payment_hash`, as the
    /// metadata a payer handed back carries it, and its opened terms.
    fn carried(
        &self,
        metadata: Option<&Metadata>,
        payment_hash: &Bytes32,
    ) -> Result<(GatewayMetadata, GatewayTerms), String> {
        let carried =
            GatewayMetadata::from_metadata(metadata.ok_or("no invoice of this gateway's")?)?;
        let terms = carried.open(&self.0.endpoint_secret, payment_hash)?;
        if terms.authorization.gateway != self.key() {
            return Err("the invoice was issued under another gateway's authorization".into());
        }
        Ok((carried, terms))
    }

    /// The target and network of an HTLC paying `terms`'s invoice on
    /// `network` expiring at `expiry`, and the time its claim must start
    /// by.
    async fn payable_on(
        &self,
        terms: &GatewayTerms,
        network: &NetworkId,
        expiry: u64,
    ) -> Result<(HtlcTarget, Arc<dyn Network>, u64), String> {
        if terms.expires_at <= unix_now() {
            return Err("invoice expired".into());
        }
        let opened = self.network(network)?;
        // Claim-key networks give the target of the invoice again.
        let target = opened
            .receive_target(terms.payment_hash, terms.amount_msat, terms.expires_at)
            .await
            .map_err(|e| format!("cannot receive on {network}: {e}"))?;
        let claim_by = expiry.saturating_sub(opened.incoming_delta_secs());
        if claim_by.saturating_sub(self.policy().forward_slack_secs) <= unix_now() {
            return Err("HTLC expires too soon to pay the payee on".into());
        }
        Ok((target, opened, claim_by))
    }

    /// The payee's destination this gateway can pay `amount_msat` on
    /// now.
    async fn destination(
        &self,
        authorization: &ReceiveAuthorization,
        amount_msat: u64,
    ) -> Result<(GatewayDestination, Arc<dyn Network>), String> {
        let mut reasons = Vec::new();
        for destination in &authorization.destinations {
            let Ok(network) = self.network(destination.network()) else {
                continue;
            };
            match network.can_send(amount_msat).await {
                Ok(()) => return Ok((destination.clone(), network)),
                Err(error) => reasons.push(format!("{}: {error}", destination.network())),
            }
        }
        Err(if reasons.is_empty() {
            "this gateway pays on none of the payee's networks".into()
        } else {
            format!("cannot pay the payee on: {}", reasons.join("; "))
        })
    }

    fn payee_htlc(&self, payment_hash: &Bytes32) -> Result<Option<PayeeHtlc>, String> {
        self.db()
            .payee_htlcs()
            .get(PayeeHtlcHash(payment_hash.0))
            .map_err(db_error)
    }

    async fn prepare(&self, prepare: &PreparePayee) -> Result<(), String> {
        let (_, terms) = self.carried(prepare.metadata.as_ref(), &prepare.payment_hash)?;
        // The payee was paid already: a new payment cannot start over.
        if let Some(htlc) = self.payee_htlc(&prepare.payment_hash)? {
            return Err(match htlc.failed {
                Some(reason) => format!("an earlier payment of this invoice failed: {reason}"),
                None => "invoice already paid".into(),
            });
        }
        self.payable_on(&terms, &prepare.network, prepare.expiry)
            .await?;
        self.destination(&terms.authorization, terms.amount_msat)
            .await?;
        info!(
            "PREPARE {} accepted on {}",
            prepare.payment_hash.short(),
            prepare.network
        );
        Ok(())
    }

    /// Start forwarding the payment of `commit`, or report on one
    /// already started: [`Response::Committed`] once the incoming HTLC
    /// is claimed, [`Response::Pending`] while it is in progress.
    async fn commit(&self, commit: Commit) -> Response {
        let hash = commit.payment_hash;
        if let Err(reason) = self.start_forward(commit).await {
            warn!("COMMIT {} refused: {reason}", hash.short());
            return Response::Error(reason);
        }
        let deadline = tokio::time::Instant::now() + INLINE_WAIT;
        loop {
            match self.payee_htlc(&hash) {
                Ok(Some(htlc)) => match (htlc.settled, htlc.preimage, htlc.failed) {
                    (true, Some(preimage), _) => return Response::Committed(Bytes32(preimage)),
                    (_, _, Some(reason)) => return Response::Error(reason),
                    _ => {}
                },
                Ok(None) => {
                    if let Some(reason) = lock(&self.0.refused).remove(&hash) {
                        return Response::Error(reason);
                    }
                    if !lock(&self.0.busy).contains(&hash) {
                        return Response::Error("forward disappeared".into());
                    }
                }
                Err(error) => return Response::Error(error),
            }
            if tokio::time::Instant::now() >= deadline {
                return Response::Pending;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Check `commit` against the invoice its metadata carries and
    /// forward it in the background, unless a forward of its payment is
    /// already under way or done.
    async fn start_forward(&self, commit: Commit) -> Result<(), String> {
        let hash = commit.payment_hash;
        let (carried, terms) = self.carried(commit.metadata.as_ref(), &hash)?;
        // A repeated COMMIT finishes a forward that is already funded:
        // it brings the preimage metadata again, so the gateway does not
        // need to have stored it.
        if let Some(mut htlc) = self.payee_htlc(&hash)? {
            if htlc.outcome == Some(PayeeOutcome::Refunded) {
                return Err("the payee HTLC was refunded".into());
            }
            if htlc.settled {
                return Ok(());
            }
            if htlc.failed.is_some() && htlc.preimage.is_some() {
                htlc.failed = None;
                self.journal(&htlc);
            }
            if htlc.failed.is_some() {
                return Ok(());
            }
            let Some(busy) = self.busy(hash) else {
                return Ok(());
            };
            lock(&self.0.refused).remove(&hash);
            let preimage_metadata = htlc.preimage.is_none().then_some(carried.preimage_metadata);
            let gateway = self.clone();
            self.spawn(async move { gateway.finish(htlc, preimage_metadata, busy).await });
            return Ok(());
        }
        let (target, _, claim_by) = self
            .payable_on(&terms, &commit.network, commit.expiry)
            .await?;
        if commit.descriptor.target() != target {
            return Err("the HTLC does not pay this invoice".into());
        }
        let Some(busy) = self.busy(hash) else {
            return Ok(());
        };
        lock(&self.0.refused).remove(&hash);
        let forward = Forward {
            incoming: Htlc {
                payment_hash: hash,
                amount_msat: terms.amount_msat,
                expiry: commit.expiry,
                descriptor: commit.descriptor,
            },
            preimage_metadata: carried.preimage_metadata,
            terms,
            incoming_network: commit.network,
            claim_by,
        };
        self.spawn(self.clone().forward(forward, busy));
        Ok(())
    }

    fn busy(&self, hash: Bytes32) -> Option<BusyGuard> {
        let mut busy = self.0.busy.lock().unwrap_or_else(|e| e.into_inner());
        busy.insert(hash).then(|| BusyGuard {
            gateway: self.0.clone(),
            hash,
        })
    }

    /// Save `htlc`, logging failures: the forward goes on either way.
    fn journal(&self, htlc: &PayeeHtlc) {
        if let Err(error) = self.db().payee_htlcs().update(htlc) {
            error!(
                "journaling the HTLC to the payee {}: {error}",
                Bytes32(htlc.payment_hash.0)
            );
        }
    }

    /// Verify the incoming HTLC of `forward`, fund the HTLC to the payee,
    /// and go on as [`Gateway::finish`] does. A failure before anything
    /// is funded is reported to the next COMMIT, and a new COMMIT may
    /// start over.
    async fn forward(self, forward: Forward, busy: BusyGuard) {
        let hash = forward.incoming.payment_hash;
        match self.verify_and_fund(&forward).await {
            Ok(htlc) => {
                self.finish(htlc, Some(forward.preimage_metadata), busy)
                    .await
            }
            Err(reason) => {
                warn!("forward {} failed: {reason}", hash.short());
                self.release_targets(&hash, None).await;
                lock(&self.0.refused).insert(hash, reason);
            }
        }
    }

    /// Wait for the incoming HTLC to verify, then fund the HTLC to the
    /// payee, journaled before the network call.
    async fn verify_and_fund(&self, forward: &Forward) -> Result<PayeeHtlc, String> {
        let hash = forward.incoming.payment_hash;
        let incoming = self
            .network_by(&forward.incoming_network, forward.claim_by)
            .await?;
        let mut waiting = false;
        loop {
            match incoming.verify_incoming_htlc(&forward.incoming).await {
                Ok(()) => break,
                Err(NetworkError::NotYet(reason)) if unix_now() < forward.claim_by => {
                    if !waiting {
                        info!("COMMIT {}: waiting for the HTLC: {reason}", hash.short());
                        waiting = true;
                    }
                    tokio::time::sleep(RETRY_INTERVAL).await;
                }
                Err(error) => return Err(format!("HTLC rejected: {error}")),
            }
        }
        let authorization = &forward.terms.authorization;
        let amount_msat = forward.terms.amount_msat;
        let (destination, outgoing) = self.destination(authorization, amount_msat).await?;
        if forward
            .claim_by
            .saturating_sub(self.policy().forward_slack_secs / 2)
            <= unix_now()
        {
            return Err("too late to pay the payee before the incoming HTLC expires".into());
        }
        let expiry = unix_now()
            .saturating_add(authorization.min_final_timeout_secs)
            .saturating_add(self.policy().final_slack_secs);
        let mut htlc = PayeeHtlc {
            payment_hash: PayeeHtlcHash(hash.0),
            incoming_network: forward.incoming_network.clone(),
            incoming: (&forward.incoming).into(),
            claim_by: forward.claim_by,
            authorization: authorization.into(),
            payee_metadata: stored_metadata(&forward.terms.payee_metadata),
            network: destination.network().clone(),
            htlc: None,
            outcome: None,
            preimage: None,
            settled: false,
            failed: None,
            created_at: unix_now(),
        };
        self.db().payee_htlcs().insert(&htlc).map_err(db_error)?;
        let funded = outgoing
            .create_outgoing_htlc(hash, amount_msat, expiry, &destination.target())
            .await;
        let descriptor = match funded {
            Ok(descriptor) => descriptor,
            Err(error) => {
                // Nothing was paid: a new COMMIT may start over.
                if let Err(error) = self.db().payee_htlcs().delete(htlc.payment_hash.clone()) {
                    error!("forgetting the HTLC to the payee {hash}: {error}");
                }
                return Err(format!(
                    "cannot pay the payee on {}: {error}",
                    destination.network()
                ));
            }
        };
        htlc.htlc = Some(
            (&Htlc {
                payment_hash: hash,
                amount_msat,
                expiry,
                descriptor,
            })
                .into(),
        );
        self.journal(&htlc);
        info!(
            "COMMIT {}: locked {amount_msat} msat to payee {} on {} until {expiry}",
            hash.short(),
            authorization.payee,
            destination.network()
        );
        Ok(htlc)
    }

    /// Have the preimage of a funded `htlc` released, unless known, and
    /// claim the payer's HTLC with it.
    async fn finish(
        &self,
        mut htlc: PayeeHtlc,
        preimage_metadata: Option<Metadata>,
        _busy: BusyGuard,
    ) {
        if htlc.preimage.is_none() {
            let Some(preimage_metadata) = preimage_metadata else {
                warn!(
                    "forward {} is funded but has no preimage metadata to release with",
                    short(&htlc)
                );
                return;
            };
            match self.release(&mut htlc, &preimage_metadata).await {
                Ok(preimage) => {
                    info!("COMMIT {}: preimage released", short(&htlc));
                    htlc.preimage = Some(preimage.0);
                    self.journal(&htlc);
                }
                Err(reason) => {
                    warn!("forward {} failed: {reason}", short(&htlc));
                    htlc.failed = Some(reason);
                    return self.journal(&htlc);
                }
            }
        }
        if let Err(reason) = self.claim(&mut htlc).await {
            warn!("forward {} failed: {reason}", short(&htlc));
            htlc.failed = Some(reason);
            self.journal(&htlc);
        }
    }

    /// Present the HTLC to the payee to the preimage server, with what
    /// the invoice carried from it, until it releases the preimage.
    async fn release(
        &self,
        htlc: &mut PayeeHtlc,
        preimage_metadata: &Metadata,
    ) -> Result<Bytes32, String> {
        let hash = Bytes32(htlc.payment_hash.0);
        let authorization = ReceiveAuthorization::try_from(&htlc.authorization)?;
        let funded = htlc.htlc.as_ref().ok_or("nothing was paid to the payee")?;
        let request = Request::PreimageRelease(PreimageRelease {
            preimage_metadata: preimage_metadata.clone(),
            metadata: metadata(&htlc.payee_metadata)?,
            network: htlc.network.clone(),
            htlc: Htlc::try_from(funded)?,
            authorization: authorization.clone(),
        });
        let preimage_server = PeerAddr {
            id: authorization.preimage_server.to_string(),
            relay: authorization.preimage_server_relay.clone(),
        };
        let mut waiting = false;
        loop {
            // Learned meanwhile, from the payee's claim.
            if let Some(preimage) = lock(&self.0.learned).remove(&hash) {
                return Ok(preimage);
            }
            match self.0.transport.request(&preimage_server, &request).await {
                Ok(Response::PreimageReleased(Ok(preimage)))
                    if hash.matches_preimage(&preimage) =>
                {
                    return Ok(preimage)
                }
                Ok(Response::PreimageReleased(Ok(_))) => {
                    return Err("preimage server released a wrong preimage".into())
                }
                Ok(Response::PreimageReleased(Err(reason))) => {
                    return Err(format!("preimage server refused: {reason}"))
                }
                Ok(Response::Pending) => {}
                Ok(other) => warn!("unexpected answer from preimage server: {other:?}"),
                Err(error) => warn!("asking the preimage server again: {error}"),
            }
            if unix_now() >= htlc.claim_by {
                return Err("the preimage server did not release the preimage in time".into());
            }
            if !waiting {
                info!("COMMIT {}: waiting for the preimage server", hash.short());
                waiting = true;
            }
            tokio::time::sleep(RETRY_INTERVAL).await;
        }
    }

    /// Claim the payer's HTLC, retrying until it expires.
    async fn claim(&self, htlc: &mut PayeeHtlc) -> Result<(), String> {
        let preimage = Bytes32(htlc.preimage.ok_or("no preimage to claim with")?);
        let incoming_network = &htlc.incoming_network;
        let incoming_htlc = Htlc::try_from(&htlc.incoming)?;
        let incoming = self
            .network_by(incoming_network, incoming_htlc.expiry)
            .await?;
        loop {
            match incoming.claim_incoming_htlc(&incoming_htlc, preimage).await {
                Ok(()) => break,
                Err(error) if unix_now() >= incoming_htlc.expiry => {
                    return Err(format!("claim failed before the HTLC expired: {error}"))
                }
                Err(error) => {
                    warn!("claiming {}: {error}; retrying", short(htlc));
                    tokio::time::sleep(RETRY_INTERVAL).await;
                }
            }
        }
        info!(
            "COMMIT {}: claimed {} msat on {incoming_network}",
            short(htlc),
            incoming_htlc.amount_msat,
        );
        htlc.settled = true;
        htlc.failed = None;
        self.journal(htlc);
        self.release_targets(&incoming_htlc.payment_hash, Some(incoming_network))
            .await;
        Ok(())
    }

    /// Release what the gateway's networks, except `claimed_on`, set up
    /// to receive `payment_hash`.
    async fn release_targets(&self, payment_hash: &Bytes32, claimed_on: Option<&NetworkId>) {
        let networks: Vec<Arc<dyn Network>> = lock(&self.0.networks).values().cloned().collect();
        for network in networks {
            let id = network.id();
            if Some(&id) == claimed_on {
                continue;
            }
            if let Err(error) = network.cancel_receive(*payment_hash).await {
                warn!("releasing invoice target on {id}: {error}");
            }
        }
    }

    /// After a restart: claim forwards whose preimage was learned, and
    /// fail those left mid-funding, which cannot be resumed: whether
    /// their HTLC to the payee exists is unknown, and funding it again
    /// could pay twice. A funded forward still waiting for its preimage
    /// waits for a repeated COMMIT, which carries the preimage metadata
    /// again, or for the payee to claim.
    fn resume(&self) -> Result<(), String> {
        for mut htlc in self.payee_htlcs()? {
            if htlc.settled || htlc.failed.is_some() {
                continue;
            }
            if htlc.htlc.is_none() {
                error!(
                    "the HTLC to the payee {} was interrupted while funding on {}; check that \
                     wallet for a lock to it",
                    Bytes32(htlc.payment_hash.0),
                    htlc.network
                );
                htlc.failed = Some(INTERRUPTED_FUNDING.into());
                self.journal(&htlc);
                continue;
            }
            if htlc.preimage.is_none() {
                // The COMMIT that carries the preimage metadata again
                // resumes it; the settlement loop refunds it if none
                // comes.
                continue;
            }
            let hash = Bytes32(htlc.payment_hash.0);
            if let Some(busy) = self.busy(hash) {
                let gateway = self.clone();
                self.spawn(async move { gateway.finish(htlc, None, busy).await });
            }
        }
        Ok(())
    }

    async fn settle_loop(self) {
        let mut ticker = tokio::time::interval(SETTLE_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            self.settle_once().await;
        }
    }

    /// One pass over the HTLCs to payees still open.
    pub async fn settle_once(&self) {
        match self.db().payee_htlcs().by_open(true) {
            Ok(htlcs) => {
                for htlc in htlcs {
                    self.settle_outgoing(htlc).await;
                }
            }
            Err(error) => warn!("listing HTLCs to payees: {error}"),
        }
    }

    /// See whether the payee claimed its HTLC (which also reveals the
    /// preimage to a forward still waiting for it), and refund it once
    /// expired if no preimage came back.
    async fn settle_outgoing(&self, saved: PayeeHtlc) {
        let hash = Bytes32(saved.payment_hash.0);
        let Some(Ok(htlc)) = saved.htlc.as_ref().map(Htlc::try_from) else {
            return;
        };
        let Ok(network) = self.network(&saved.network) else {
            return;
        };
        let outcome = match network.check_outgoing_htlc(&htlc).await {
            Ok(OutgoingState::Claimed(preimage)) if hash.matches_preimage(&preimage) => {
                Some((PayeeOutcome::Claimed, Some(preimage)))
            }
            Ok(OutgoingState::Claimed(_)) => {
                warn!("{} reported a wrong preimage", network.id());
                None
            }
            Ok(OutgoingState::Refunded) => Some((PayeeOutcome::Refunded, None)),
            Ok(OutgoingState::Pending) if unix_now() >= htlc.expiry && saved.preimage.is_none() => {
                match network.refund_outgoing_htlc(&htlc).await {
                    Ok(()) => {
                        info!(
                            "{}: no preimage came back; refunded on {}",
                            hash.short(),
                            network.id()
                        );
                        Some((PayeeOutcome::Refunded, None))
                    }
                    Err(error) => {
                        warn!("refunding {} on {}: {error}", hash.short(), network.id());
                        None
                    }
                }
            }
            Ok(OutgoingState::Pending) => None,
            Err(error) => {
                warn!("checking {} on {}: {error}", hash.short(), network.id());
                None
            }
        };
        let Some((outcome, preimage)) = outcome else {
            return;
        };
        let Some(busy) = self.busy(hash) else {
            // A forward in progress owns its record: only tell it the
            // preimage, and record the outcome on a later pass.
            if let Some(preimage) = preimage {
                lock(&self.0.learned).insert(hash, preimage);
            }
            return;
        };
        let Ok(Some(mut saved)) = self.payee_htlc(&hash) else {
            return;
        };
        if outcome == PayeeOutcome::Claimed {
            info!("{}: the payee claimed", hash.short());
        }
        saved.outcome = Some(outcome);
        saved.preimage = saved.preimage.or(preimage.map(|preimage| preimage.0));
        // A forward that gave up on the preimage server can still claim
        // with the preimage the payee revealed.
        let claimable = !saved.settled
            && saved.failed.is_some()
            && saved.preimage.is_some()
            && Htlc::try_from(&saved.incoming).is_ok_and(|incoming| unix_now() < incoming.expiry);
        if claimable {
            saved.failed = None;
        }
        self.journal(&saved);
        if claimable {
            let gateway = self.clone();
            self.spawn(async move { gateway.finish(saved, None, busy).await });
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

fn short(htlc: &PayeeHtlc) -> String {
    Bytes32(htlc.payment_hash.0).short()
}

fn db_error(error: orangedb::Error) -> String {
    format!("database: {error}")
}

struct BusyGuard {
    gateway: Arc<Inner>,
    hash: Bytes32,
}

impl Drop for BusyGuard {
    fn drop(&mut self) {
        self.gateway
            .busy
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.hash);
    }
}

fn log_refusal<T>(what: &str, result: Result<T, String>) -> Result<T, String> {
    if let Err(reason) = &result {
        warn!("{what} refused: {reason}");
    }
    result
}
