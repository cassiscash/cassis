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
//! final timeout it finds too long, say). Payers PREPARE and COMMIT
//! here, as with any payee. On COMMIT the gateway verifies the incoming
//! HTLC, funds an HTLC to the payee on one of its destinations, at
//! least as long as the payee asked for, and presents it to the
//! preimage server ([`Request::PreimageRelease`]), which releases the
//! preimage. The gateway claims the incoming HTLC with it and answers
//! the COMMIT.
//!
//! Every forward is journaled in the [`Store`]. A settlement loop
//! resumes interrupted ones and refunds HTLCs to payees who never
//! claimed them before they expired.

use cassis_core::network::{Htlc, HtlcTarget, Network, NetworkError, NetworkId, OutgoingState};
use cassis_core::offline::{
    endpoint_public_key, AuthorizationKind, Destination, PreimageIssuance, ReceiveAuthorization,
};
use cassis_core::protocol::{
    Commit, GatewayInvoiceFor, GatewayInvoiceRequest, Invoice, InvoiceBody, InvoiceNetwork,
    Metadata, PreimageRelease, PreparePayee, Request, Response,
};
use cassis_core::store::Store;
use cassis_core::transport::{Handler, PeerAddr, Transport};
use cassis_core::{unix_now, Bytes32};
use iroh_base::PublicKey;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{error, info, warn, Instrument, Span};

/// Standing authorizations, by [`ReceiveAuthorization::id`].
pub const AUTHORIZATIONS: &str = "gateway_authorizations";
/// Invoices this gateway issued, by payment hash.
pub const INVOICES: &str = "gateway_invoices";
/// Payments it forwards, by payment hash.
pub const FORWARDS: &str = "gateway_forwards";

/// How long COMMIT works before answering [`Response::Pending`].
const INLINE_WAIT: Duration = Duration::from_secs(5);
/// How often an HTLC not final yet is verified again, and a preimage
/// not released yet asked for again.
const RETRY_INTERVAL: Duration = Duration::from_secs(5);
const SETTLE_INTERVAL: Duration = Duration::from_secs(10);

/// Terms the gateway accepts from payees.
#[derive(Clone, Debug)]
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
    pub store: Arc<Store>,
    /// Networks the gateway is paid on and pays payees on.
    pub networks: Vec<Arc<dyn Network>>,
    pub policy: GatewayPolicy,
    pub span: Span,
}

/// A standing authorization a payee gave this gateway.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthorizationRecord {
    pub authorization: ReceiveAuthorization,
    pub preimage_server_relay: Option<String>,
    pub registered_at: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvoiceStatus {
    Pending,
    Paid,
    Expired,
}

/// An invoice this gateway issued, with what paying it on takes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InvoiceRecord {
    pub invoice: Invoice,
    pub authorization: ReceiveAuthorization,
    pub issuance: PreimageIssuance,
    pub preimage_server: PeerAddr,
    pub status: InvoiceStatus,
    pub created_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ForwardState {
    /// Waiting for the incoming HTLC to verify. Nothing is funded yet.
    Verifying,
    /// Funding the HTLC to the payee.
    Funding,
    /// HTLC to the payee funded; waiting for the preimage server to
    /// release the preimage.
    Releasing,
    /// Preimage known; claiming the incoming HTLC.
    Claiming,
    /// Incoming HTLC claimed.
    Settled,
    Failed(String),
}

/// What became of the HTLC to the payee.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutgoingOutcome {
    Claimed,
    Refunded,
}

/// A payment this gateway forwards: the payer's HTLC it claims and the
/// HTLC it funded to the payee in exchange.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ForwardRecord {
    pub payment_hash: Bytes32,
    pub incoming_network: NetworkId,
    pub incoming: Htlc,
    /// The incoming claim must start by then.
    pub claim_by: u64,
    pub outgoing_network: Option<NetworkId>,
    pub outgoing: Option<Htlc>,
    pub outgoing_outcome: Option<OutgoingOutcome>,
    pub state: ForwardState,
    pub preimage: Option<Bytes32>,
    pub created_at: u64,
}

/// Handle to a running gateway. Cheap to clone.
#[derive(Clone)]
pub struct Gateway(Arc<Inner>);

struct Inner {
    endpoint_secret: [u8; 32],
    store: Arc<Store>,
    networks: HashMap<NetworkId, Arc<dyn Network>>,
    policy: GatewayPolicy,
    transport: Transport,
    span: Span,
    /// Payment hashes some task is forwarding; others leave them be.
    busy: Mutex<HashSet<Bytes32>>,
    /// Preimages the settlement loop learned from payees' claims, for
    /// forwards still waiting on the preimage server.
    learned: Mutex<HashMap<Bytes32, Bytes32>>,
    tasks: Mutex<Vec<tokio::task::AbortHandle>>,
}

impl Gateway {
    /// Bind the gateway's endpoint, resume journaled forwards and answer
    /// requests until [`Gateway::shutdown`].
    pub async fn start(config: GatewayConfig) -> Result<Self, String> {
        let transport = Transport::bind(Some(config.endpoint_secret)).await?;
        let gateway = Self(Arc::new(Inner {
            endpoint_secret: config.endpoint_secret,
            store: config.store,
            networks: config
                .networks
                .into_iter()
                .map(|network| (network.id(), network))
                .collect(),
            policy: config.policy,
            transport: transport.clone(),
            span: config.span,
            busy: Default::default(),
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

    pub fn store(&self) -> &Store {
        &self.0.store
    }

    pub fn forwards(&self) -> Result<Vec<ForwardRecord>, String> {
        self.store().list(FORWARDS)
    }

    async fn handle(&self, request: Request, peer: String) -> Response {
        match request {
            Request::GatewayInvoice(request) => {
                Response::GatewayInvoice(log_refusal("invoice", self.invoice(request, &peer).await))
            }
            Request::GatewayAuthorize {
                authorization,
                preimage_server_relay,
            } => Response::GatewayAuthorized(log_refusal(
                "authorization",
                self.authorize(authorization, preimage_server_relay),
            )),
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
        self.0
            .networks
            .get(id)
            .cloned()
            .ok_or_else(|| format!("this gateway is not on {id}"))
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
        let policy = &self.0.policy;
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
            .any(|destination| self.0.networks.contains_key(&destination.network))
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
            preimage_server_relay,
        } = request;
        self.check_authorization(&authorization, AuthorizationKind::Single)?;
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
        let preimage_server = PeerAddr {
            id: authorization.preimage_server.to_string(),
            relay: preimage_server_relay,
        };
        let body = self
            .build(&issuance, expires_at, description, metadata)
            .await?;
        let invoice = Invoice::gateway_invoice(body, authorization.payee, &self.0.endpoint_secret);
        self.record(invoice, authorization, issuance, preimage_server)
    }

    /// Keep a standing authorization, so invoices can be issued under it.
    fn authorize(
        &self,
        authorization: ReceiveAuthorization,
        preimage_server_relay: Option<String>,
    ) -> Result<(), String> {
        self.check_authorization(&authorization, AuthorizationKind::Standing)?;
        let id = authorization.id()?;
        info!(
            "payee {} authorized invoices of {}..{} msat until {}",
            authorization.payee,
            authorization.min_amount_msat,
            authorization.max_amount_msat,
            authorization.valid_until
        );
        self.store().put(
            AUTHORIZATIONS,
            &id.to_string(),
            &AuthorizationRecord {
                authorization,
                preimage_server_relay,
                registered_at: unix_now(),
            },
        )
    }

    /// An invoice in the name of an offline payee, under its standing
    /// authorization that runs longest among those allowing the amount.
    async fn invoice_for(&self, request: GatewayInvoiceFor) -> Result<Invoice, String> {
        let now = unix_now();
        let record = self
            .store()
            .list::<AuthorizationRecord>(AUTHORIZATIONS)?
            .into_iter()
            .filter(|record| {
                let authorization = &record.authorization;
                authorization.payee == request.payee
                    && authorization.is_valid_at(now)
                    && authorization.allows_amount(request.amount_msat)
            })
            .max_by_key(|record| record.authorization.valid_until)
            .ok_or("this payee authorized no invoice like this one")?;
        let authorization = record.authorization;
        let expires_at = request
            .expires_at
            .unwrap_or(now + self.0.policy.default_invoice_expiry_secs)
            .min(authorization.valid_until);
        if expires_at <= now {
            return Err("invoice expiry must be in the future".into());
        }
        let preimage_server = PeerAddr {
            id: authorization.preimage_server.to_string(),
            relay: record.preimage_server_relay,
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
        let body = self
            .build(&issuance, expires_at, request.description, request.metadata)
            .await?;
        let invoice = Invoice::delegated(
            body,
            authorization.payee,
            &self.0.endpoint_secret,
            authorization.preimage_server,
            issuance.clone(),
            authorization.clone(),
        );
        invoice.verify()?;
        self.record(invoice, authorization, issuance, preimage_server)
    }

    /// The terms of an invoice for `issuance`, payable to this gateway
    /// on every network it is on.
    async fn build(
        &self,
        issuance: &PreimageIssuance,
        expires_at: u64,
        description: Option<String>,
        metadata: Option<Metadata>,
    ) -> Result<InvoiceBody, String> {
        if expires_at <= unix_now() {
            return Err("invoice expiry must be in the future".into());
        }
        let payment_hash = issuance.payment_hash;
        if self
            .store()
            .get::<InvoiceRecord>(INVOICES, &payment_hash.to_string())?
            .is_some()
        {
            return Err("this gateway already issued an invoice for the hash".into());
        }
        let mut networks: Vec<&Arc<dyn Network>> = self.0.networks.values().collect();
        networks.sort_by_key(|network| network.id());
        let mut targets = Vec::with_capacity(networks.len());
        for network in networks {
            match network
                .receive_target(payment_hash, issuance.amount_msat, expires_at)
                .await
            {
                Ok(target) => targets.push(InvoiceNetwork {
                    network: network.id(),
                    target,
                    incoming_delta_secs: Some(
                        network
                            .incoming_delta_secs()
                            .saturating_add(self.0.policy.forward_slack_secs),
                    ),
                    max_incoming_lifetime_secs: network.max_incoming_lifetime_secs(),
                }),
                Err(error) => warn!("cannot receive on {}: {error}", network.id()),
            }
        }
        if targets.is_empty() {
            return Err("this gateway can receive on none of its networks".into());
        }
        Ok(InvoiceBody {
            payment_hash,
            amount_msat: issuance.amount_msat,
            expires_at,
            networks: targets,
            description,
            metadata,
            iroh_relay: self.home_relay().await,
        })
    }

    fn record(
        &self,
        invoice: Invoice,
        authorization: ReceiveAuthorization,
        issuance: PreimageIssuance,
        preimage_server: PeerAddr,
    ) -> Result<Invoice, String> {
        info!(
            "issued invoice {} of {} msat for payee {}",
            invoice.body.payment_hash.short(),
            invoice.body.amount_msat,
            authorization.payee
        );
        self.store().put(
            INVOICES,
            &invoice.body.payment_hash.to_string(),
            &InvoiceRecord {
                invoice: invoice.clone(),
                authorization,
                issuance,
                preimage_server,
                status: InvoiceStatus::Pending,
                created_at: unix_now(),
            },
        )?;
        Ok(invoice)
    }

    fn invoice_record(&self, payment_hash: &Bytes32) -> Result<InvoiceRecord, String> {
        self.store()
            .get(INVOICES, &payment_hash.to_string())?
            .ok_or_else(|| "unknown invoice".to_string())
    }

    /// The target and network of an HTLC paying `record` on `network`
    /// expiring at `expiry`, and the time its claim must start by.
    fn payable_on(
        &self,
        record: &InvoiceRecord,
        network: &NetworkId,
        expiry: u64,
    ) -> Result<(HtlcTarget, Arc<dyn Network>, u64), String> {
        if record.status == InvoiceStatus::Expired || record.invoice.body.expires_at <= unix_now() {
            return Err("invoice expired".into());
        }
        let target = record
            .invoice
            .target_for(network)
            .cloned()
            .ok_or_else(|| format!("invoice is not payable on {network}"))?;
        let opened = self.network(network)?;
        let claim_by = expiry.saturating_sub(opened.incoming_delta_secs());
        if claim_by.saturating_sub(self.0.policy.forward_slack_secs) <= unix_now() {
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
    ) -> Result<(Destination, Arc<dyn Network>), String> {
        let mut reasons = Vec::new();
        for destination in &authorization.destinations {
            let Ok(network) = self.network(&destination.network) else {
                continue;
            };
            match network.can_send(amount_msat).await {
                Ok(()) => return Ok((destination.clone(), network)),
                Err(error) => reasons.push(format!("{}: {error}", destination.network)),
            }
        }
        Err(if reasons.is_empty() {
            "this gateway pays on none of the payee's networks".into()
        } else {
            format!("cannot pay the payee on: {}", reasons.join("; "))
        })
    }

    async fn prepare(&self, prepare: &PreparePayee) -> Result<(), String> {
        let record = self.invoice_record(&prepare.payment_hash)?;
        if record.status == InvoiceStatus::Paid
            || self
                .store()
                .get::<ForwardRecord>(FORWARDS, &prepare.payment_hash.to_string())?
                .is_some_and(|forward| !matches!(forward.state, ForwardState::Failed(_)))
        {
            return Err("invoice already paid".into());
        }
        self.payable_on(&record, &prepare.network, prepare.expiry)?;
        self.destination(&record.authorization, record.invoice.body.amount_msat)
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
        if let Err(reason) = self.start_forward(commit) {
            warn!("COMMIT {} refused: {reason}", hash.short());
            return Response::Error(reason);
        }
        let deadline = tokio::time::Instant::now() + INLINE_WAIT;
        loop {
            match self
                .store()
                .get::<ForwardRecord>(FORWARDS, &hash.to_string())
            {
                Ok(Some(forward)) => match (forward.state, forward.preimage) {
                    (ForwardState::Settled, Some(preimage)) => {
                        return Response::Committed(preimage)
                    }
                    (ForwardState::Failed(reason), _) => return Response::Error(reason),
                    _ => {}
                },
                Ok(None) => return Response::Error("forward disappeared".into()),
                Err(error) => return Response::Error(error),
            }
            if tokio::time::Instant::now() >= deadline {
                return Response::Pending;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Journal a forward for `commit` and drive it in the background,
    /// unless one is already under way. A forward that failed before
    /// funding anything starts over.
    fn start_forward(&self, commit: Commit) -> Result<(), String> {
        let hash = commit.payment_hash;
        let key = hash.to_string();
        if let Some(forward) = self.store().get::<ForwardRecord>(FORWARDS, &key)? {
            let restartable =
                matches!(forward.state, ForwardState::Failed(_)) && forward.outgoing.is_none();
            if !restartable {
                return Ok(());
            }
            if forward.incoming.descriptor == commit.descriptor
                && forward.incoming_network == commit.network
            {
                // The same HTLC failed already: report it again.
                return Ok(());
            }
        }
        let record = self.invoice_record(&hash)?;
        if record.status == InvoiceStatus::Paid {
            return Err("invoice already paid".into());
        }
        let (target, _, claim_by) = self.payable_on(&record, &commit.network, commit.expiry)?;
        let forward = ForwardRecord {
            payment_hash: hash,
            incoming_network: commit.network,
            incoming: Htlc {
                payment_hash: hash,
                amount_msat: record.invoice.body.amount_msat,
                expiry: commit.expiry,
                target,
                descriptor: commit.descriptor,
            },
            claim_by,
            outgoing_network: None,
            outgoing: None,
            outgoing_outcome: None,
            state: ForwardState::Verifying,
            preimage: None,
            created_at: unix_now(),
        };
        let Some(busy) = self.busy(hash) else {
            return Ok(());
        };
        self.save(&forward)?;
        self.spawn(self.clone().drive(forward, busy));
        Ok(())
    }

    fn busy(&self, hash: Bytes32) -> Option<BusyGuard> {
        let mut busy = self.0.busy.lock().unwrap_or_else(|e| e.into_inner());
        busy.insert(hash).then(|| BusyGuard {
            gateway: self.0.clone(),
            hash,
        })
    }

    fn save(&self, forward: &ForwardRecord) -> Result<(), String> {
        self.store()
            .put(FORWARDS, &forward.payment_hash.to_string(), forward)
    }

    /// Save `forward`, logging failures: the forward goes on either way.
    fn journal(&self, forward: &ForwardRecord) {
        if let Err(error) = self.save(forward) {
            error!("journaling forward {}: {error}", forward.payment_hash);
        }
    }

    /// Drive `forward` from its state to its end.
    async fn drive(self, mut forward: ForwardRecord, _busy: BusyGuard) {
        loop {
            let next = match &forward.state {
                ForwardState::Verifying => self.verify_and_fund(&mut forward).await,
                ForwardState::Releasing => self.release(&mut forward).await,
                ForwardState::Claiming => self.claim(&mut forward).await,
                ForwardState::Funding | ForwardState::Settled | ForwardState::Failed(_) => return,
            };
            forward.state = match next {
                Ok(state) => state,
                Err(reason) => {
                    warn!("forward {} failed: {reason}", forward.payment_hash.short());
                    if forward.outgoing.is_none() {
                        self.release_targets(&forward.payment_hash, None).await;
                    }
                    ForwardState::Failed(reason)
                }
            };
            self.journal(&forward);
        }
    }

    /// Wait for the incoming HTLC to verify, then fund the HTLC to the
    /// payee.
    async fn verify_and_fund(&self, forward: &mut ForwardRecord) -> Result<ForwardState, String> {
        let hash = forward.payment_hash;
        let incoming = self.network(&forward.incoming_network)?;
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
        let record = self.invoice_record(&hash)?;
        let authorization = &record.authorization;
        let amount_msat = record.issuance.amount_msat;
        let (destination, outgoing) = self.destination(authorization, amount_msat).await?;
        if forward
            .claim_by
            .saturating_sub(self.0.policy.forward_slack_secs / 2)
            <= unix_now()
        {
            return Err("too late to pay the payee before the incoming HTLC expires".into());
        }
        let expiry = unix_now()
            .saturating_add(authorization.min_final_timeout_secs)
            .saturating_add(self.0.policy.final_slack_secs);
        forward.state = ForwardState::Funding;
        forward.outgoing_network = Some(destination.network.clone());
        self.save(forward)?;
        let descriptor = outgoing
            .create_outgoing_htlc(hash, amount_msat, expiry, &destination.target)
            .await
            .map_err(|e| format!("cannot pay the payee on {}: {e}", destination.network))?;
        forward.outgoing = Some(Htlc {
            payment_hash: hash,
            amount_msat,
            expiry,
            target: destination.target,
            descriptor,
        });
        info!(
            "COMMIT {}: locked {amount_msat} msat to payee {} on {} until {expiry}",
            hash.short(),
            authorization.payee,
            destination.network
        );
        Ok(ForwardState::Releasing)
    }

    /// Present the HTLC to the payee to the preimage server until it
    /// releases the preimage.
    async fn release(&self, forward: &mut ForwardRecord) -> Result<ForwardState, String> {
        let hash = forward.payment_hash;
        let record = self.invoice_record(&hash)?;
        let (Some(network), Some(htlc)) = (&forward.outgoing_network, &forward.outgoing) else {
            return Err("nothing was paid to the payee".into());
        };
        let request = Request::PreimageRelease(PreimageRelease {
            authorization: record.authorization.clone(),
            issuance: record.issuance.clone(),
            metadata: record.invoice.body.metadata.clone(),
            network: network.clone(),
            htlc: htlc.clone(),
        });
        let mut waiting = false;
        loop {
            if let Some(preimage) = forward.preimage {
                // Learned meanwhile, from the payee's claim.
                return Ok(self.with_preimage(forward, preimage));
            }
            match self
                .0
                .transport
                .request(&record.preimage_server, &request)
                .await
            {
                Ok(Response::PreimageReleased(Ok(preimage)))
                    if hash.matches_preimage(&preimage) =>
                {
                    return Ok(self.with_preimage(forward, preimage))
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
            if unix_now() >= forward.claim_by {
                return Err("the preimage server did not release the preimage in time".into());
            }
            if !waiting {
                info!("COMMIT {}: waiting for the preimage server", hash.short());
                waiting = true;
            }
            tokio::time::sleep(RETRY_INTERVAL).await;
            // The settlement loop may have seen the payee claim.
            forward.preimage = self
                .0
                .learned
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&hash);
        }
    }

    fn with_preimage(&self, forward: &mut ForwardRecord, preimage: Bytes32) -> ForwardState {
        info!("COMMIT {}: preimage released", forward.payment_hash.short());
        forward.preimage = Some(preimage);
        ForwardState::Claiming
    }

    /// Claim the incoming HTLC, retrying until it expires.
    async fn claim(&self, forward: &mut ForwardRecord) -> Result<ForwardState, String> {
        let hash = forward.payment_hash;
        let preimage = forward.preimage.ok_or("no preimage to claim with")?;
        let incoming = self.network(&forward.incoming_network)?;
        loop {
            match incoming
                .claim_incoming_htlc(&forward.incoming, preimage)
                .await
            {
                Ok(()) => break,
                Err(error) if unix_now() >= forward.incoming.expiry => {
                    return Err(format!("claim failed before the HTLC expired: {error}"))
                }
                Err(error) => {
                    warn!("claiming {}: {error}; retrying", hash.short());
                    tokio::time::sleep(RETRY_INTERVAL).await;
                }
            }
        }
        info!(
            "COMMIT {}: claimed {} msat on {}",
            hash.short(),
            forward.incoming.amount_msat,
            forward.incoming_network
        );
        if let Ok(mut record) = self.invoice_record(&hash) {
            record.status = InvoiceStatus::Paid;
            if let Err(error) = self.store().put(INVOICES, &hash.to_string(), &record) {
                warn!("saving invoice {hash}: {error}");
            }
        }
        self.release_targets(&hash, Some(&forward.incoming_network))
            .await;
        Ok(ForwardState::Settled)
    }

    /// Release what the gateway's networks, except `claimed_on`, set up
    /// to receive `payment_hash`.
    async fn release_targets(&self, payment_hash: &Bytes32, claimed_on: Option<&NetworkId>) {
        for (id, network) in &self.0.networks {
            if Some(id) == claimed_on {
                continue;
            }
            if let Err(error) = network.cancel_receive(*payment_hash).await {
                warn!("releasing invoice target on {id}: {error}");
            }
        }
    }

    /// After a restart: go on with forwards in progress, and fail those
    /// left mid-funding, which cannot be resumed: whether their HTLC to
    /// the payee exists is unknown, and funding it again could pay
    /// twice.
    fn resume(&self) -> Result<(), String> {
        for mut forward in self.forwards()? {
            match forward.state {
                ForwardState::Verifying | ForwardState::Releasing | ForwardState::Claiming => {
                    if let Some(busy) = self.busy(forward.payment_hash) {
                        self.spawn(self.clone().drive(forward, busy));
                    }
                }
                ForwardState::Funding => {
                    error!(
                        "forward {} was interrupted while paying the payee on {:?}; check that \
                         wallet for a lock to it",
                        forward.payment_hash, forward.outgoing_network
                    );
                    forward.state = ForwardState::Failed("interrupted while funding".into());
                    self.save(&forward)?;
                }
                _ => {}
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

    /// One pass over HTLCs to payees still open, and expired invoices.
    pub async fn settle_once(&self) {
        match self.forwards() {
            Ok(forwards) => {
                for forward in forwards {
                    if forward.outgoing.is_some() && forward.outgoing_outcome.is_none() {
                        self.settle_outgoing(forward).await;
                    }
                }
            }
            Err(error) => warn!("listing forwards: {error}"),
        }
        match self.store().list::<InvoiceRecord>(INVOICES) {
            Ok(invoices) => {
                for mut record in invoices {
                    if record.status == InvoiceStatus::Pending
                        && record.invoice.body.expires_at <= unix_now()
                    {
                        let hash = record.invoice.body.payment_hash;
                        if self
                            .store()
                            .get::<ForwardRecord>(FORWARDS, &hash.to_string())
                            .ok()
                            .flatten()
                            .is_some_and(|forward| {
                                !matches!(forward.state, ForwardState::Failed(_))
                            })
                        {
                            continue;
                        }
                        record.status = InvoiceStatus::Expired;
                        self.release_targets(&hash, None).await;
                        if let Err(error) = self.store().put(INVOICES, &hash.to_string(), &record) {
                            warn!("expiring invoice {hash}: {error}");
                        }
                    }
                }
            }
            Err(error) => warn!("listing invoices: {error}"),
        }
    }

    /// See whether the payee claimed its HTLC (which also reveals the
    /// preimage to a forward still waiting for it), and refund it once
    /// expired.
    async fn settle_outgoing(&self, forward: ForwardRecord) {
        let hash = forward.payment_hash;
        let (Some(network), Some(htlc)) = (&forward.outgoing_network, &forward.outgoing) else {
            return;
        };
        let Ok(network) = self.network(network) else {
            return;
        };
        let outcome = match network.check_outgoing_htlc(htlc).await {
            Ok(OutgoingState::Claimed(preimage)) if hash.matches_preimage(&preimage) => {
                Some((OutgoingOutcome::Claimed, Some(preimage)))
            }
            Ok(OutgoingState::Claimed(_)) => {
                warn!("{} reported a wrong preimage", network.id());
                None
            }
            Ok(OutgoingState::Refunded) => Some((OutgoingOutcome::Refunded, None)),
            Ok(OutgoingState::Pending) if unix_now() >= htlc.expiry => {
                match network.refund_outgoing_htlc(htlc).await {
                    Ok(()) => {
                        info!(
                            "{}: the payee did not claim; refunded on {}",
                            hash.short(),
                            network.id()
                        );
                        Some((OutgoingOutcome::Refunded, None))
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
                self.0
                    .learned
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(hash, preimage);
            }
            return;
        };
        let Ok(Some(mut saved)) = self
            .store()
            .get::<ForwardRecord>(FORWARDS, &hash.to_string())
        else {
            return;
        };
        if outcome == OutgoingOutcome::Claimed {
            info!("{}: the payee claimed", hash.short());
        }
        saved.outgoing_outcome = Some(outcome);
        saved.preimage = saved.preimage.or(preimage);
        // A forward that gave up on the preimage server can still claim
        // with the preimage the payee revealed.
        let claimable = matches!(saved.state, ForwardState::Failed(_))
            && saved.preimage.is_some()
            && unix_now() < saved.incoming.expiry;
        if claimable {
            saved.state = ForwardState::Claiming;
        }
        self.journal(&saved);
        if claimable {
            self.spawn(self.clone().drive(saved, busy));
        }
    }
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
