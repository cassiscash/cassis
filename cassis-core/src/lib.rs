pub mod logging;

use std::collections::HashMap;

use async_trait::async_trait;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use tokio::sync::{Mutex, OnceCell};

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Bytes32(pub [u8; 32]);

impl fmt::Debug for Bytes32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", lowercase_hex::encode(self.0))
    }
}

impl fmt::Display for Bytes32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", lowercase_hex::encode(self.0))
    }
}

impl AsRef<[u8]> for Bytes32 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl serde::Serialize for Bytes32 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&lowercase_hex::encode(self.0))
    }
}

impl<'de> serde::Deserialize<'de> for Bytes32 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let mut bytes = [0u8; 32];
        lowercase_hex::decode_to_slice(&s, &mut bytes).map_err(serde::de::Error::custom)?;
        Ok(Bytes32(bytes))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NetworkId(pub String);

impl fmt::Display for NetworkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<&str> for NetworkId {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

/// Canonical `NetworkId` format for cashu and fedimint, used on the wire
/// (iroh `HopInstruction`) and in Nostr route-announcement `d` tags.
///
/// * cashu: `cashu::<host[:port]>` — the address has no scheme. The scheme
///   is derived implicitly from the host at connection time: loopback
///   (`localhost`, `127.0.0.1`, `::1`) is `http`, anything else is `https`.
/// * fedimint: `fedimint::<invite_code>` — the invite code is the address.
///
/// The address part for cashu is the bare `host[:port]`. The address part
/// for fedimint is the federation's invite code. No other form is accepted
/// on the wire or in Nostr events.
pub const CASHU_NETWORK_ID_PREFIX: &str = "cashu::";
pub const FEDIMINT_NETWORK_ID_PREFIX: &str = "fedimint::";

/// Build the canonical `NetworkId` for a cashu mint, given the bare
/// `host[:port]` (no scheme). The scheme is decided at connection time.
pub fn cashu_network_id(host: &str) -> NetworkId {
    NetworkId(format!("{CASHU_NETWORK_ID_PREFIX}{host}"))
}

/// Build the canonical `NetworkId` for a fedimint federation, given its
/// invite code (no prefix).
pub fn fedimint_network_id(invite_code: &str) -> NetworkId {
    NetworkId(format!("{FEDIMINT_NETWORK_ID_PREFIX}{invite_code}"))
}

/// Build the canonical `NetworkId` for a kind without a parameter
/// (liquid, ark, rootstock).
pub fn simple_network_id(kind: &str) -> NetworkId {
    NetworkId(kind.to_string())
}

/// Pass-through used by the router to canonicalize `HopInstruction`
/// network ids before adapter lookup. Only the canonical on-the-wire
/// form (`cashu::<host>`, `fedimint::<invite>`, or the simple kinds
/// `liquid` / `ark` / `rootstock`) round-trips; anything else is
/// returned unchanged so the adapter lookup rejects it.
pub fn canonicalize_network_id(id: &NetworkId) -> NetworkId {
    if let Some(rest) = id.0.strip_prefix(CASHU_NETWORK_ID_PREFIX) {
        if !rest.is_empty() && !rest.contains("://") {
            return id.clone();
        }
    }
    if let Some(rest) = id.0.strip_prefix(FEDIMINT_NETWORK_ID_PREFIX) {
        if !rest.is_empty() {
            return id.clone();
        }
    }
    if id.0 == "liquid" || id.0 == "ark" || id.0 == "rootstock" {
        return id.clone();
    }
    id.clone()
}

/// Build the full mint URL for a cashu network id, choosing the
/// scheme from the host: `http` for loopback (`localhost`, `127.0.0.1`,
/// `::1`), `https` for everything else. Returns an error if the
/// network id is not a cashu id.
pub fn cashu_mint_url(network_id: &NetworkId) -> Result<String, String> {
    let host = network_id
        .0
        .strip_prefix(CASHU_NETWORK_ID_PREFIX)
        .ok_or_else(|| format!("network id {network_id} is not a cashu id"))?;
    if host.is_empty() {
        return Err(format!("network id {network_id} has no host"));
    }
    if host.contains("://") {
        return Err(format!(
            "network id {network_id} must not contain a scheme"
        ));
    }
    let scheme = if is_loopback_host(host) { "http" } else { "https" };
    Ok(format!("{scheme}://{host}"))
}

/// True if `host` is a loopback address (`localhost`, `127.0.0.1`,
/// `::1`, with or without a port and IPv6 brackets).
pub fn is_loopback_host(host: &str) -> bool {
    let host_part: &str = if let Some(rest) = host.strip_prefix('[') {
        match rest.find(']') {
            Some(end) => &rest[..end],
            None => host,
        }
    } else if host == "::1" || host.starts_with("::1:") {
        "::1"
    } else {
        host.split(':').next().unwrap_or(host)
    };
    matches!(host_part, "localhost" | "127.0.0.1" | "::1")
}

/// A directed route offered by a node: receive on `from`, send on `to`.
/// Each announcement has its own fee schedule, parsed from kind-35515 event tags.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RouteAnnouncement {
    pub node_pubkey: ritualistic::PubKey,
    pub iroh_peer_id: String,
    pub iroh_relay: Option<String>,
    pub from: NetworkId,
    pub to: NetworkId,
    pub fee_base_msat: u64,
    pub fee_ppm: u64,
    /// Per-hop timelock budget (seconds): the time this hop needs
    /// between receiving the incoming HTLC and forwarding the outgoing
    /// one. Mirrors the `incoming_delta_secs` kind-35515 tag.
    /// `0` means the operator did not publish a value; callers fall
    /// back to a per-network default.
    pub incoming_delta_secs: u64,
    /// Per-hop transit slack (seconds): extra buffer the sender adds to
    /// deadlines to absorb in-flight latency and clock skew between
    /// sender and this hop. Independent of `incoming_delta_secs` (which
    /// is the hop's processing budget). Mirrors the `transit_slack_secs`
    /// kind-35515 tag. `0` means the operator did not publish a value;
    /// callers fall back to a global default.
    pub transit_slack_secs: u64,
    pub relays: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Invoice {
    pub payment_hash: Bytes32,
    pub amount_msat: u64,
    pub payee: String,
    pub expires_at: u64,
    pub networks: Vec<NetworkId>,
    pub description: Option<String>,
}

/// Handle to an in-flight outgoing payment initiated by
/// [`NetworkSenderAdapter::pay_invoice`]. The caller passes it to
/// [`NetworkSenderAdapter::watch_payment`] or
/// [`NetworkSenderAdapter::refund_payment`] to drive the operation to
/// its terminal state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutgoingPayment {
    pub payment_hash: Bytes32,
    pub amount_msat: u64,
    pub destination_pubkey: String,
    pub destination_network: NetworkId,
    pub expiry: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HopInstruction {
    pub payment_hash: Bytes32,
    pub amount_msat: u64,
    pub incoming_network: NetworkId,
    pub outgoing_network: NetworkId,
    pub incoming_deadline: u64,
    pub outgoing_expiry: u64,
    pub recipient: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HopAck {
    pub payment_hash: Bytes32,
    pub accepted: bool,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HopReject {
    pub payment_hash: Bytes32,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IncomingHtlc {
    pub payment_hash: Bytes32,
    pub amount_msat: u64,
    pub expiry: u64,
    pub sender: String,
    pub network: NetworkId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutgoingHtlc {
    pub payment_hash: Bytes32,
    pub amount_msat: u64,
    pub expiry: u64,
    pub recipient: String,
    pub network: NetworkId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RouteHop {
    pub node: RouteAnnouncement,
    pub incoming: NetworkId,
    pub outgoing: NetworkId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PaymentStatus {
    Completed,
    Refunded,
    Failed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaymentResult {
    pub status: PaymentStatus,
    pub preimage: Option<Bytes32>,
}

#[derive(thiserror::Error, Debug)]
pub enum WatchError {
    #[error("deadline exceeded")]
    DeadlineExceeded,
    #[error("network error: {0}")]
    Network(String),
    #[error("unimplemented")]
    Unimplemented,
}

#[derive(thiserror::Error, Debug)]
pub enum HtlcError {
    #[error("invalid parameters: {0}")]
    InvalidParams(String),
    #[error("network error: {0}")]
    Network(String),
    #[error("unimplemented")]
    Unimplemented,
}

#[derive(thiserror::Error, Debug)]
pub enum ReceiveError {
    #[error("invalid parameters: {0}")]
    InvalidParams(String),
    #[error("network error: {0}")]
    Network(String),
    #[error("invoice not found: {0}")]
    NotFound(String),
    #[error("deadline exceeded")]
    DeadlineExceeded,
    #[error("unimplemented")]
    Unimplemented,
}

#[derive(thiserror::Error, Debug)]
pub enum SendError {
    #[error("invalid parameters: {0}")]
    InvalidParams(String),
    #[error("network error: {0}")]
    Network(String),
    #[error("payment not found: {0}")]
    NotFound(String),
    #[error("deadline exceeded")]
    DeadlineExceeded,
    #[error("unimplemented")]
    Unimplemented,
}

/// Lower-level router API: an adapter that can both receive an HTLC on
/// its network and forward it onwards by creating an outgoing HTLC on
/// (typically) a different network. This is the historical "HTLC
/// instrument" interface; new code should prefer
/// [`NetworkReceiverAdapter`] and [`NetworkSenderAdapter`], which
/// expose the user-facing "create invoice / pay invoice" semantics.
///
/// Adapters implementing this trait automatically receive
/// [`NetworkReceiverAdapter`] and [`NetworkSenderAdapter`] blanket
/// implementations.
#[async_trait]
pub trait NetworkRouterAdapter: Send + Sync {
    fn network_id(&self) -> NetworkId;

    fn incoming_delta_secs(&self) -> u64;

    async fn watch_incoming_htlc(
        &self,
        payment_hash: Bytes32,
        min_amount_msat: u64,
        deadline: u64,
    ) -> Result<IncomingHtlc, WatchError>;

    async fn create_outgoing_htlc(
        &self,
        payment_hash: Bytes32,
        amount_msat: u64,
        expiry: u64,
        recipient: &str,
    ) -> Result<OutgoingHtlc, HtlcError>;

    async fn claim_incoming(
        &self,
        htlc: &IncomingHtlc,
        preimage: Bytes32,
    ) -> Result<(), HtlcError>;

    async fn refund_outgoing(&self, htlc: &OutgoingHtlc) -> Result<(), HtlcError>;

    async fn watch_preimage(
        &self,
        htlc: &OutgoingHtlc,
        deadline: u64,
    ) -> Result<Bytes32, WatchError>;
}

/// User-facing "receive" side of a network: create an invoice that
/// will be paid by some upstream hop, wait for the payment, and
/// settle the incoming HTLC.
///
/// Any [`NetworkRouterAdapter`] automatically implements this trait
/// via a blanket impl. Networks that don't fit the router model
/// (e.g. fedimint's "sells its own preimage" model) implement
/// [`NetworkReceiverAdapter`] directly.
#[async_trait]
pub trait NetworkReceiverAdapter: Send + Sync {
    fn network_id(&self) -> NetworkId;

    /// Per-hop delta the receiver needs between accepting the
    /// incoming HTLC and forwarding the outgoing one. Mirrors
    /// [`NetworkRouterAdapter::incoming_delta_secs`].
    fn incoming_delta_secs(&self) -> u64;

    /// Generate a fresh preimage, register a pending invoice on the
    /// underlying network, and return the corresponding
    /// [`Invoice`].
    ///
    /// The returned invoice's `payment_hash` is the hash of the
    /// generated preimage (or, for "sells its own preimage" networks
    /// like fedimint, the hash of the network's internally-generated
    /// preimage). The preimage is held by the receiver and is only
    /// released via [`NetworkReceiverAdapter::claim_incoming`].
    async fn create_invoice(
        &self,
        amount_msat: u64,
        expiry: u64,
        description: Option<String>,
    ) -> Result<Invoice, ReceiveError>;

    /// Wait for the upstream hop to fund the invoice. Returns the
    /// preimage if the receiver holds it (hash-locked networks); for
    /// "sells its own preimage" networks the network owns the
    /// preimage and this just blocks until funding is observed.
    async fn watch_incoming(
        &self,
        payment_hash: Bytes32,
        deadline: u64,
    ) -> Result<Bytes32, ReceiveError>;

    /// Release the preimage and settle the incoming HTLC. The
    /// `preimage` is whatever [`NetworkReceiverAdapter::watch_incoming`]
    /// returned; "sells its own preimage" networks may ignore it.
    async fn claim_incoming(
        &self,
        payment_hash: Bytes32,
        preimage: Bytes32,
    ) -> Result<(), ReceiveError>;
}

/// User-facing "send" side of a network: pay an invoice on the
/// network, wait for the preimage, and (if needed) cancel/refund.
///
/// Any [`NetworkRouterAdapter`] automatically implements this trait
/// via a blanket impl. Networks that don't fit the router model
/// implement [`NetworkSenderAdapter`] directly.
#[async_trait]
pub trait NetworkSenderAdapter: Send + Sync {
    fn network_id(&self) -> NetworkId;

    /// Initiate a payment to the given destination. The
    /// `destination_pubkey` is whatever the network needs to identify
    /// the payee: a node pubkey, a BOLT11 invoice, etc. The
    /// `destination_network` is the network the payment is being sent
    /// on (typically `self.network_id()`, but the caller passes it
    /// for symmetry with the receive side).
    async fn pay_invoice(
        &self,
        payment_hash: Bytes32,
        amount_msat: u64,
        destination_pubkey: &str,
        destination_network: &NetworkId,
        expiry: u64,
    ) -> Result<OutgoingPayment, SendError>;

    /// Block until the payment reaches a terminal state. On success
    /// returns the preimage; on failure or refund returns an error.
    async fn watch_payment(
        &self,
        payment: OutgoingPayment,
        deadline: u64,
    ) -> Result<Bytes32, SendError>;

    /// Cancel/refund the payment. Only effective if the payment
    /// hasn't completed yet; implementations may be no-ops once the
    /// preimage is revealed.
    async fn refund_payment(&self, payment: OutgoingPayment) -> Result<(), SendError>;
}

// ---------------------------------------------------------------------------
// Blanket impls: any `NetworkRouterAdapter` is automatically a
// `NetworkReceiverAdapter` and a `NetworkSenderAdapter`. Networks like
// cashu that fully fit the router model rely on these; networks like
// fedimint that don't, implement the receiver/sender traits directly
// and skip `NetworkRouterAdapter` entirely.
// ---------------------------------------------------------------------------

/// In-memory bookkeeping the auto-impl maintains for each
/// `(network_id, payment_hash)` slot.
struct PendingReceiverSlot {
    /// The HTLC returned by the router's `watch_incoming_htlc`. The
    /// router's `claim_incoming` needs this object, so we cache it
    /// between `create_invoice` and `claim_incoming`.
    htlc: IncomingHtlc,
}

static RECEIVER_AUTO_STATE: OnceCell<Mutex<HashMap<String, HashMap<Bytes32, PendingReceiverSlot>>>> =
    OnceCell::const_new();

async fn receiver_state() -> &'static Mutex<HashMap<String, HashMap<Bytes32, PendingReceiverSlot>>> {
    RECEIVER_AUTO_STATE
        .get_or_init(|| async { Mutex::new(HashMap::new()) })
        .await
}

#[derive(Clone)]
struct PendingSenderSlot {
    htlc: OutgoingHtlc,
}

static SENDER_AUTO_STATE: OnceCell<Mutex<HashMap<String, HashMap<Bytes32, PendingSenderSlot>>>> =
    OnceCell::const_new();

async fn sender_state() -> &'static Mutex<HashMap<String, HashMap<Bytes32, PendingSenderSlot>>> {
    SENDER_AUTO_STATE
        .get_or_init(|| async { Mutex::new(HashMap::new()) })
        .await
}

fn random_preimage() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

fn sha256_hash(bytes: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let out = hasher.finalize();
    let mut out32 = [0u8; 32];
    out32.copy_from_slice(&out);
    out32
}

#[async_trait]
impl<T> NetworkReceiverAdapter for T
where
    T: NetworkRouterAdapter + ?Sized,
{
    fn network_id(&self) -> NetworkId {
        NetworkRouterAdapter::network_id(self)
    }

    fn incoming_delta_secs(&self) -> u64 {
        NetworkRouterAdapter::incoming_delta_secs(self)
    }

    /// For router-based adapters we delegate to the router's
    /// `watch_incoming_htlc`, which is responsible for both
    /// registering the incoming contract on the network and waiting
    /// for it to be funded. We pass a fresh local preimage hash as a
    /// hint; "sells its own preimage" networks (e.g. cashu) ignore it
    /// and use their own. The htlc returned by the router — which
    /// carries the *network's* payment hash, not the local one — is
    /// what we expose in the `Invoice` and stash in our pending DB
    /// for `claim_incoming`.
    async fn create_invoice(
        &self,
        amount_msat: u64,
        expiry: u64,
        description: Option<String>,
    ) -> Result<Invoice, ReceiveError> {
        let preimage = random_preimage();
        let local_payment_hash = Bytes32(sha256_hash(&preimage));
        let network_id = self.network_id();
        let htlc = NetworkRouterAdapter::watch_incoming_htlc(
            self,
            local_payment_hash,
            amount_msat,
            expiry,
        )
        .await
        .map_err(|e| match e {
            WatchError::DeadlineExceeded => ReceiveError::DeadlineExceeded,
            other => ReceiveError::Network(other.to_string()),
        })?;
        let network_payment_hash = htlc.payment_hash;
        let slot = PendingReceiverSlot { htlc };
        receiver_state()
            .await
            .lock()
            .await
            .entry(network_id.0.clone())
            .or_default()
            .insert(network_payment_hash, slot);
        Ok(Invoice {
            payment_hash: network_payment_hash,
            amount_msat,
            payee: network_id.0.clone(),
            expires_at: expiry,
            networks: vec![network_id],
            description,
        })
    }

    /// No-op for the router auto-impl: `create_invoice` already
    /// delegated to `watch_incoming_htlc`, which did any wait. We
    /// return a zero preimage as a sentinel; the network owns the
    /// preimage for "sells its own preimage" adapters and the
    /// routing layer only cares that the wait completed.
    async fn watch_incoming(
        &self,
        _payment_hash: Bytes32,
        _deadline: u64,
    ) -> Result<Bytes32, ReceiveError> {
        Ok(Bytes32([0u8; 32]))
    }

    async fn claim_incoming(
        &self,
        payment_hash: Bytes32,
        preimage: Bytes32,
    ) -> Result<(), ReceiveError> {
        let network_id = self.network_id();
        let slot = receiver_state()
            .await
            .lock()
            .await
            .get_mut(&network_id.0)
            .and_then(|m| m.remove(&payment_hash))
            .ok_or_else(|| ReceiveError::NotFound(format!("{:?}", payment_hash)))?;
        NetworkRouterAdapter::claim_incoming(self, &slot.htlc, preimage)
            .await
            .map_err(|e| ReceiveError::Network(e.to_string()))
    }
}

#[async_trait]
impl<T> NetworkSenderAdapter for T
where
    T: NetworkRouterAdapter + ?Sized,
{
    fn network_id(&self) -> NetworkId {
        NetworkRouterAdapter::network_id(self)
    }

    async fn pay_invoice(
        &self,
        payment_hash: Bytes32,
        amount_msat: u64,
        destination_pubkey: &str,
        destination_network: &NetworkId,
        expiry: u64,
    ) -> Result<OutgoingPayment, SendError> {
        let htlc = NetworkRouterAdapter::create_outgoing_htlc(
            self,
            payment_hash,
            amount_msat,
            expiry,
            destination_pubkey,
        )
        .await
        .map_err(|e| match e {
            HtlcError::InvalidParams(msg) => SendError::InvalidParams(msg),
            other => SendError::Network(other.to_string()),
        })?;
        let htlc_hash = htlc.payment_hash;
        let network_id = self.network_id();
        sender_state()
            .await
            .lock()
            .await
            .entry(network_id.0.clone())
            .or_default()
            .insert(
                htlc_hash,
                PendingSenderSlot { htlc },
            );
        Ok(OutgoingPayment {
            payment_hash: htlc_hash,
            amount_msat,
            destination_pubkey: destination_pubkey.to_string(),
            destination_network: destination_network.clone(),
            expiry,
        })
    }

    async fn watch_payment(
        &self,
        payment: OutgoingPayment,
        deadline: u64,
    ) -> Result<Bytes32, SendError> {
        let network_id = self.network_id();
        let slot = sender_state()
            .await
            .lock()
            .await
            .get_mut(&network_id.0)
            .and_then(|m| m.remove(&payment.payment_hash))
            .ok_or_else(|| SendError::NotFound(format!("{:?}", payment.payment_hash)))?;
        NetworkRouterAdapter::watch_preimage(self, &slot.htlc, deadline)
            .await
            .map_err(|e| match e {
                WatchError::DeadlineExceeded => SendError::DeadlineExceeded,
                other => SendError::Network(other.to_string()),
            })
    }

    async fn refund_payment(&self, payment: OutgoingPayment) -> Result<(), SendError> {
        let network_id = self.network_id();
        let slot = sender_state()
            .await
            .lock()
            .await
            .get_mut(&network_id.0)
            .and_then(|m| m.remove(&payment.payment_hash))
            .ok_or_else(|| SendError::NotFound(format!("{:?}", payment.payment_hash)))?;
        NetworkRouterAdapter::refund_outgoing(self, &slot.htlc)
            .await
            .map_err(|e| SendError::Network(e.to_string()))
    }
}

/// Internal helper: blanket-impls need a `Send + Sync` bound on the
/// underlying `T` to use `Arc<T>` from trait objects. Kept here for
/// downstream code that wants `Arc<dyn NetworkRouterAdapter>` etc.
#[allow(dead_code)]
fn _assert_send_sync<T: Send + Sync + ?Sized>() {
    fn assert<T: Send + Sync + ?Sized>() {}
    assert::<dyn NetworkRouterAdapter>();
    assert::<dyn NetworkReceiverAdapter>();
    assert::<dyn NetworkSenderAdapter>();
}
