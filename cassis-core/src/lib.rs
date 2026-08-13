pub mod logging;
mod primitives;
pub use primitives::Bytes32;
mod network;
pub use network::{cashu_mint_url, is_loopback_host};

use async_trait::async_trait;
pub use ritualistic::PubKey as XOnlyPubKey;
use serde::{Deserialize, Serialize};
use std::fmt;
use tracing::Span;

/// Full compressed secp256k1 public key: parity byte plus 32-byte X coordinate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PubKey(pub [u8; 33]);

impl PubKey {
    pub fn from_bytes(bytes: [u8; 33]) -> Result<Self, secp256k1::Error> {
        secp256k1::PublicKey::from_slice(&bytes)?;
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 33] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        lowercase_hex::encode(self.0)
    }

    pub fn x_only(&self) -> XOnlyPubKey {
        XOnlyPubKey::from_bytes(self.0[1..].try_into().expect("32-byte X coordinate"))
            .expect("compressed public key contains valid X coordinate")
    }

    pub fn to_ecdsa_key(&self) -> secp256k1::PublicKey {
        secp256k1::PublicKey::from_slice(&self.0).expect("validated compressed public key")
    }
}

impl std::str::FromStr for PubKey {
    type Err = secp256k1::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut bytes = [0u8; 33];
        lowercase_hex::decode_to_slice(value, &mut bytes)
            .map_err(|_| secp256k1::Error::InvalidPublicKey)?;
        Self::from_bytes(bytes)
    }
}

impl serde::Serialize for PubKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> serde::Deserialize<'de> for PubKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

/// Build the per-network child span an adapter should hold and enter
/// around every log it emits.
///
/// `parent` is the caller's node span (the one carrying the `node`
/// field). The returned span adds a `network` field, so a log emitted
/// inside it has *both* in its scope and a subscriber walking
/// `event_scope()` can render `[alice/rootstock::testnet]`.
///
/// The parent is passed explicitly rather than relying on the ambient
/// `Span::current()`: adapters are constructed on whichever task
/// happened to run the builder, but their methods are later driven from
/// unrelated tasks (the router poll loop, an iroh request handler), so
/// the contextual parent at construction time is the only reliable
/// link back to the owning node.
pub fn network_span(parent: &Span, network_id: &NetworkId) -> Span {
    tracing::info_span!(parent: parent, "network", network = %network_id)
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NetworkId(pub String);

impl NetworkId {
    /// Default per-hop incoming delta (seconds) for this network.
    ///
    /// Used when a route announcement does not publish an
    /// `incoming_delta_secs` tag. Values mirror the `incoming_delta_secs()`
    /// methods declared by network adapters. Unknown networks use 30 seconds.
    pub fn default_incoming_delta(&self) -> u64 {
        match self.0.as_str() {
            "arkade" | "arkade::mutinynet" => 60,
            "bitcoin" | "bitcoin::mutinynet" => 300,
            "fedimint" => 30,
            id if id.starts_with("fedimint::") => 30,
            "cashu" => 30,
            "liquid" | "liquid::testnet" => 300,
            "rootstock" | "rootstock::testnet" => 600,
            "lightning" => 30,
            "spark" => 60,
            _ => 30,
        }
    }
}

/// Opaque operation identifier used to bind reservations and executions
/// to one authenticated peer. Payment hashes identify payment intent;
/// operation IDs identify one protocol attempt.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OperationId(pub String);

impl OperationId {
    /// Generate a fresh 128-bit operation identifier.
    pub fn random() -> Self {
        Self(lowercase_hex::encode(rand::random::<[u8; 16]>()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_valid(&self) -> bool {
        self.0.len() == 32 && self.0.bytes().all(|byte| byte.is_ascii_hexdigit())
    }
}

impl fmt::Display for OperationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

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
/// * rootstock: `rootstock` for mainnet; `rootstock::testnet` for the
///   Boltz testnet deployment (chain id 31). The EtherSwap contract address
///   differs per chain; the adapter picks the right one from the network id.
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
/// (liquid, liquid::testnet, arkade, arkade::mutinynet, bitcoin,
/// bitcoin::mutinynet, rootstock).
pub fn simple_network_id(kind: &str) -> NetworkId {
    NetworkId(kind.to_string())
}

/// Pass-through used by the router to canonicalize `HopInstruction`
/// network ids before adapter lookup. Only the canonical on-the-wire
/// form (`cashu::<host>`, `fedimint::<invite>`, or the simple kinds
/// `liquid` / `liquid::testnet` / `arkade` / `arkade::mutinynet` / `bitcoin` /
/// `bitcoin::mutinynet` / `rootstock` / `rootstock::testnet` / `lightning`)
/// round-trips;
/// anything else is returned unchanged so the adapter lookup rejects it.
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
    if id.0 == "liquid"
        || id.0 == "liquid::testnet"
        || id.0 == "arkade"
        || id.0 == "arkade::mutinynet"
        || id.0 == "bitcoin"
        || id.0 == "bitcoin::mutinynet"
        || id.0 == "rootstock"
        || id.0 == "rootstock::testnet"
        || id.0 == "lightning"
        || id.0 == "spark"
    {
        return id.clone();
    }
    id.clone()
}

/// Alias for [`canonicalize_network_id`] kept around for router
/// call-sites that want to read more like English.
pub fn normalize_network_id(network_id: &NetworkId) -> NetworkId {
    canonicalize_network_id(network_id)
}

/// Split a network spec into `(kind, param)`. The canonical
/// separator is `::`; a single `:` (e.g. `cashu:host:port`) is *not*
/// accepted and yields `(spec, None)`, which downstream parsing
/// rejects.
pub fn split_spec(spec: &str) -> (&str, Option<&str>) {
    if let Some((kind, param)) = spec.split_once("::") {
        return (kind, Some(param));
    }
    (spec, None)
}

/// Compute the [`NetworkId`] for a network spec without building the
/// adapter. Each kind is gated behind its own cargo feature; if a
/// spec is passed for a kind whose feature is not enabled, a clear
/// error is returned. Used by `cassis-router` (and any other binary)
/// to convert CLI `--network <spec>` arguments into network ids
/// before key derivation.
#[allow(unused_variables)] // `param` is only used inside feature-gated arms.
pub fn network_id_for_spec(spec: &str) -> Result<NetworkId, String> {
    let (kind, param) = split_spec(spec);
    match kind {
        #[cfg(feature = "cashu")]
        "cashu" => {
            let host = param.ok_or_else(|| {
                "network 'cashu' requires a host, e.g. cashu::mint.example.com or \
                 cashu::localhost:3338"
                    .to_string()
            })?;
            if host.is_empty() {
                return Err(
                    "network 'cashu' requires a non-empty host, e.g. cashu::mint.example.com"
                        .to_string(),
                );
            }
            if host.contains("://") {
                return Err(
                    "network 'cashu' must not include a scheme; \
                     drop the http:// or https:// prefix and use cashu::<host> instead"
                        .to_string(),
                );
            }
            Ok(cashu_network_id(host))
        }
        #[cfg(not(feature = "cashu"))]
        "cashu" => Err(
            "network 'cashu' requested but cassis-core was not compiled with the 'cashu' feature"
                .to_string(),
        ),

        "fedimint" => Err(
            "network 'fedimint' is not supported by cassis-router; \
             use cassis-cli to receive on a fedimint federation"
                .to_string(),
        ),

        #[cfg(feature = "liquid")]
        "liquid" => match param {
            None => Ok(NetworkId("liquid".to_string())),
            Some("testnet") => Ok(NetworkId("liquid::testnet".to_string())),
            Some(other) => Err(format!(
                "network 'liquid' only accepts no parameter or 'testnet', got '{other}'"
            )),
        },
        #[cfg(not(feature = "liquid"))]
        "liquid" => Err(
            "network 'liquid' requested but cassis-core was not compiled with the 'liquid' feature"
                .to_string(),
        ),

        #[cfg(feature = "arkade")]
        "arkade" => match param {
            None => Ok(NetworkId("arkade".to_string())),
            Some("mutinynet") => Ok(NetworkId("arkade::mutinynet".to_string())),
            Some(other) => Err(format!(
                "network 'arkade' only accepts no parameter or 'mutinynet', got '{other}'"
            )),
        },
        #[cfg(not(feature = "arkade"))]
        "arkade" => Err(
            "network 'arkade' requested but cassis-core was not compiled with the 'arkade' feature"
                .to_string(),
        ),

        #[cfg(feature = "bitcoin")]
        "bitcoin" => match param {
            None => Ok(NetworkId("bitcoin".to_string())),
            Some("mutinynet") => Ok(NetworkId("bitcoin::mutinynet".to_string())),
            Some(other) => Err(format!(
                "network 'bitcoin' only accepts no parameter or 'mutinynet', got '{other}'"
            )),
        },
        #[cfg(not(feature = "bitcoin"))]
        "bitcoin" => Err(
            "network 'bitcoin' requested but cassis-core was not compiled with the 'bitcoin' feature"
                .to_string(),
        ),

        #[cfg(feature = "rootstock")]
        "rootstock" => match param {
            None => Ok(NetworkId("rootstock".to_string())),
            Some("testnet") => Ok(NetworkId("rootstock::testnet".to_string())),
            Some(other) => Err(format!(
                "network 'rootstock' only accepts no parameter or 'testnet', got '{other}'"
            )),
        },
        #[cfg(not(feature = "rootstock"))]
        "rootstock" => Err(
            "network 'rootstock' requested but cassis-core was not compiled with the 'rootstock' feature"
                .to_string(),
        ),

        #[cfg(feature = "lightning")]
        "lightning" => match param {
            None => Ok(NetworkId("lightning".to_string())),
            Some(other) => Err(format!(
                "network 'lightning' does not accept a parameter, got '{other}'"
            )),
        },
        #[cfg(not(feature = "lightning"))]
        "lightning" => Err(
            "network 'lightning' requested but cassis-core was not compiled with the 'lightning' feature"
                .to_string(),
        ),

        #[cfg(feature = "spark")]
        "spark" => match param {
            None => Ok(NetworkId("spark".to_string())),
            Some(other) => Err(format!(
                "network 'spark' does not accept a parameter, got '{other}'"
            )),
        },
        #[cfg(not(feature = "spark"))]
        "spark" => Err(
            "network 'spark' requested but cassis-core was not compiled with the 'spark' feature"
                .to_string(),
        ),

        _ => Err(format!("unsupported network kind '{kind}'")),
    }
}

/// A directed route offered by a node: receive on `from`, send on `to`.
/// Each announcement has its own fee schedule, parsed from kind-35515 event tags.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RouteAnnouncement {
    pub node_pubkey: XOnlyPubKey,
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
    /// Node key of the payee. Identifies the destination node itself,
    /// independent of any per-network addressing in [`Invoice::networks`].
    pub payee: XOnlyPubKey,
    pub expires_at: u64,
    /// Networks this invoice can be paid on, each with the target the
    /// payer must address on that network.
    pub networks: Vec<InvoiceNetwork>,
    pub description: Option<String>,
    /// When `true` the payee releases the preimage itself as soon as
    /// the incoming HTLC is funded, so no COMMIT message is required.
    /// `false` means the payer must send COMMIT to trigger the claim.
    #[serde(default)]
    pub autocommit: bool,
    /// Iroh peer id of the payee's `cassis-cli` endpoint, used by
    /// the payer to send the final COMMIT message directly. `None`
    /// for invoices not produced by a cassis receiver (e.g. raw
    /// bolt11 on a non-cassis endpoint).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iroh_peer_id: Option<String>,
    /// Home relay URL for the payee's iroh endpoint, if any. The
    /// payer uses this to dial the payee even when direct addresses
    /// aren't known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iroh_relay: Option<String>,
}

/// One payable network on an [`Invoice`], paired with the target the
/// payer addresses there. Networks that address by claim key carry an
/// [`HtlcTarget::XOnlyPubKey`]/[`HtlcTarget::PubKey`], Lightning carries a
/// BOLT11 hold invoice, Spark carries a Spark address.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InvoiceNetwork {
    pub network: NetworkId,
    pub target: HtlcTarget,
}

impl Invoice {
    /// Target the payer must address to pay this invoice on `network`.
    pub fn target_for(&self, network: &NetworkId) -> Option<&HtlcTarget> {
        self.networks
            .iter()
            .find(|entry| entry.network == *network)
            .map(|entry| &entry.target)
    }
}

/// Handle to an in-flight outgoing payment. Client passes it to
/// [`crate::NetworkAdapter::watch_outgoing`] and
/// [`crate::NetworkAdapter::refund_outgoing`] to drive operation to
/// terminal state.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OutgoingPayment {
    /// Opaque identifier for this payment attempt.
    pub operation_id: OperationId,
    pub payment_hash: Bytes32,
    pub amount_msat: u64,
    pub destination: HtlcTarget,
    pub destination_network: NetworkId,
    pub expiry: u64,
    /// Descriptor produced when the HTLC was funded. Kept with the
    /// payment handle so recovery never depends on a second map lookup.
    pub descriptor: HtlcDescriptor,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HopInstruction {
    pub payment_hash: Bytes32,
    pub amount_msat: u64,
    pub incoming_network: NetworkId,
    pub outgoing_network: NetworkId,
    pub incoming_deadline: u64,
    pub outgoing_expiry: u64,
    pub recipient: HtlcTarget,
}

/// Network-specific parameters the upstream party needs to address a
/// hop's incoming HTLC. Replaces the old flat `claim_pubkey` plus the
/// lightning `incoming_descriptor` with a single self-describing
/// value: pubkey networks address by claim key, lightning by BOLT11
/// hold invoice.
///
/// Crosses the wire inside the hop protocol frames, which are
/// serialized as JSON, so like [`HtlcDescriptor`] it stays
/// externally tagged.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HtlcTarget {
    /// X-only claim key used by Cashu, Arkade, Bitcoin, and Fedimint.
    XOnlyPubKey(XOnlyPubKey),
    /// Full compressed claim key used by Liquid and Rootstock.
    PubKey(PubKey),
    /// BOLT11 hold invoice the upstream party must pay (lightning).
    LightningInvoice(String),
    /// Spark address (`spark:...`/`sp1...`) the upstream party sends a
    /// Spark HTLC transfer to (spark).
    SparkAddress(String),
}

/// Receiver-side invoice handle. Keeps secret preimage outside wire
/// invoice and lets caller persist/recover it explicitly.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InvoiceHandle {
    pub invoice: Invoice,
    pub reservation: IncomingReservation,
    pub preimage: Bytes32,
}

/// Request to reserve an incoming HTLC before any external funding starts.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IncomingRequest {
    pub operation_id: OperationId,
    pub payment_hash: Bytes32,
    pub amount_msat: u64,
    pub deadline: u64,
    /// Preimage is present only for locally-created receiver invoices.
    /// Routed PREPARE requests leave it absent.
    pub preimage: Option<Bytes32>,
}

/// Durable reservation returned by an incoming adapter.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncomingReservation {
    pub operation_id: OperationId,
    pub payment_hash: Bytes32,
    pub network: NetworkId,
    pub amount_msat: u64,
    pub deadline: u64,
    pub target: HtlcTarget,
}

/// Incoming HTLC accepted and verified for later claim.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AcceptedIncoming {
    pub reservation: IncomingReservation,
    pub descriptor: HtlcDescriptor,
    /// Native amount observed by adapter, in protocol msat units where
    /// possible. Adapters that cannot observe it use reservation amount.
    pub amount_msat: u64,
}

/// Request to fund one outgoing HTLC.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutgoingRequest {
    pub operation_id: OperationId,
    pub payment_hash: Bytes32,
    pub amount_msat: u64,
    pub expiry: u64,
    pub target: HtlcTarget,
    pub network: NetworkId,
}

/// PREPARE message (sender -> router): ask a hop to reserve capacity
/// for a payment without yet committing to it. The router checks
/// basic invariants (non-zero hash, positive amount, supported
/// networks, timelock defaults, funds on the outgoing side) and
/// replies with [`HopPrepared`]. The actual HTLCs are only created
/// after a matching EXECUTE message arrives.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HopPrepare {
    pub payment_hash: Bytes32,
    /// Payer-generated attempt identifier. Router must echo it in
    /// HopPrepared and bind all later frames to it.
    pub operation_id: OperationId,
    /// Amount locked on incoming side, in protocol msat.
    pub amount_msat: u64,
    /// Amount locked on outgoing side after this hop's fee.
    pub outgoing_amount_msat: u64,
    pub incoming_network: NetworkId,
    pub outgoing_network: NetworkId,
    pub incoming_deadline: u64,
    pub outgoing_expiry: u64,
}

/// Reply to [`HopPrepare`]. `accepted=true` means the hop has
/// reserved capacity and is ready to receive a matching EXECUTE.
/// `accepted=false` carries a human-readable reason; the sender is
/// expected to abort the whole payment if any hop rejects.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HopPrepared {
    pub payment_hash: Bytes32,
    /// Reservation identifier. Always echoed, including rejections, so
    /// every PREPARE attempt has one mandatory correlation key.
    pub operation_id: OperationId,
    pub accepted: bool,
    pub reason: Option<String>,
    /// Network-specific parameters the upstream party must use to
    /// address this hop's incoming side, as reported by
    /// `IncomingReservation::target`.
    ///
    /// For pubkey networks (cashu, liquid, arkade, rootstock,
    /// fedimint) this is the claim key the upstream party locks its
    /// outgoing HTLC to; for lightning it is the BOLT11 hold invoice
    /// the upstream party must pay. Self-reporting keeps address and
    /// claim in agreement by construction. `None` on a rejection,
    /// where there is nothing to address.
    ///
    /// Carries no `skip_serializing_if`: wire peers use ALPN
    /// `cassis-hop/2`, so required fields are always serialized.
    pub htlc_target: Option<HtlcTarget>,
}

/// EXECUTE message (sender -> router): tells a hop that a real
/// incoming HTLC matching its previous PREPARE has been deployed on
/// the hop's incoming network. The descriptor is the network-specific
/// payload the receiver of the HTLC needs to claim it (e.g. for
/// cashu: a list of base64-encoded NUT-14 proofs). The router
/// verifies the HTLC is really claimable, then creates an outgoing
/// HTLC and replies with its descriptor in [`HopExecuted`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HopExecute {
    pub payment_hash: Bytes32,
    /// Reservation returned by this hop's PREPARE.
    pub operation_id: OperationId,
    /// Network-specific handle to the deployed incoming HTLC.
    pub incoming_descriptor: HtlcDescriptor,
    /// Network-specific parameters for the hop's *outgoing* side: the
    /// downstream party's self-reported addressing parameters (the
    /// next hop's [`HopPrepared::htlc_target`], or the
    /// payee's for the last hop). For pubkey networks this is the
    /// claim key to lock the outgoing HTLC to; for lightning it is
    /// the downstream hold invoice to pay.
    ///
    /// This travels in EXECUTE rather than PREPARE because the payer
    /// PREPAREs every hop *concurrently*, so when hop `i`'s PREPARE is
    /// built the reply from hop `i+1` — and therefore its addressing
    /// parameters — is not known yet. EXECUTE is sequential and
    /// happens strictly after every PREPARE has been answered, so by
    /// then the downstream parameters are always available.
    pub htlc_target: HtlcTarget,
}

/// Reply to [`HopExecute`]. Carries the descriptor of the outgoing
/// HTLC the router has just created on its outgoing network. The
/// sender passes it to the next hop's EXECUTE.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HopExecuted {
    pub payment_hash: Bytes32,
    /// Incoming reservation consumed by this hop.
    pub operation_id: OperationId,
    pub outgoing_descriptor: HtlcDescriptor,
}

/// DISCARD message (sender -> router): abandon a reservation made by an
/// earlier [`HopPrepare`] that will never be followed by an EXECUTE.
///
/// The payer sends this to every hop still holding a reservation as
/// soon as it knows the payment cannot proceed — a hop rejected its
/// PREPARE, the payer could not fund the first HTLC, or an EXECUTE
/// failed part-way down the route. Without it a failed attempt leaves
/// capacity pinned on every hop that *did* accept until the
/// reservation ages out, so a payer retrying over an overlapping route
/// competes against its own abandoned attempts.
///
/// This can only ever free a reservation, never affect money: a hop
/// drops its [`HopPrepare`] record the moment it acts on the matching
/// EXECUTE, so by the time any HTLC exists there is nothing here left
/// to match. A DISCARD that arrives after EXECUTE finds no record and
/// is reported as `released: false` rather than unwinding anything;
/// funded HTLCs are left to the normal preimage-or-timelock path.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HopDiscard {
    pub payment_hash: Bytes32,
    /// Reservation identifier. Mandatory even when the reservation was
    /// already absent or the hop rejected PREPARE.
    pub operation_id: OperationId,
}

/// Reply to [`HopDiscard`]. `released` is true when a matching
/// reservation was found and dropped.
///
/// `released: false` is a normal, non-error outcome: the reservation
/// may have already aged out, the PREPARE may have been rejected (in
/// which case nothing was ever reserved), or an EXECUTE may have
/// already consumed it. The payer sends DISCARD as a best-effort
/// cleanup and does not fail a payment over the answer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HopDiscarded {
    pub payment_hash: Bytes32,
    /// Echo of the mandatory DISCARD operation identifier.
    pub operation_id: OperationId,
    pub released: bool,
}

/// COMMIT message (sender -> final receiver): sent directly from the
/// payer to the payee (not through routers) to claim the final
/// incoming HTLC. The receiver verifies the HTLC matches the local
/// invoice, claims it with the preimage it already stored, and
/// replies with the preimage in [`HopCommitted`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HopCommit {
    pub payment_hash: Bytes32,
    /// Payer-generated final settlement attempt identifier.
    pub operation_id: OperationId,
    pub amount_msat: u64,
    pub network: NetworkId,
    pub incoming_deadline: u64,
    pub incoming_descriptor: HtlcDescriptor,
}

/// Reply to [`HopCommit`]. Carries the preimage the receiver used to
/// claim the HTLC. The sender now has the proof-of-payment and the
/// whole route is settled.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HopCommitted {
    pub payment_hash: Bytes32,
    /// Operation identifier being settled. Final payee replies echo the
    /// COMMIT operation identifier; router fanout echoes the hop's
    /// reservation identifier.
    pub operation_id: OperationId,
    pub preimage: Bytes32,
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

/// Network-specific handle to a deployed HTLC. Each variant encodes
/// exactly what the receiver of the HTLC on that network needs in
/// order to claim it (or, in the case of networks that "sell their
/// own preimage", to observe the settlement).
///
/// This type crosses the wire inside the hop protocol frames, which
/// are serialized as JSON. The enum stays externally tagged (JSON's
/// default) so the wire shape is stable; internally-tagged
/// (`#[serde(tag, content)]`) representations would change every
/// encoded frame. Variants for networks whose adapter is still a
/// stub carry no payload; they only exist so the type stays
/// exhaustive and JSON shape is preserved across upgrades.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum HtlcDescriptor {
    /// NUT-14 HTLC locked ecash proofs, one base64-encoded JSON
    /// NUT-00 [`Proof`] per element.
    Cashu { proofs_b64: Vec<String> },
    /// Liquid HTLC: a P2WSH output on the Liquid sidechain whose
    /// single witness script has two paths — a claim path
    /// (`OP_HASH160 <RIPEMD160(payment_hash)> OP_EQUAL OP_IF
    /// <claim_pubkey>`) spendable by revealing the preimage and
    /// signing with the receiver's per-network claim key, and a
    /// CLTV refund path (`OP_ELSE <refund_locktime> OP_CLTV OP_DROP
    /// <refund_pubkey> OP_ENDIF OP_CHECKSIG`) letting the sender
    /// recover the funds after an absolute block height. The lockup
    /// output is unblinded (explicit), so the receiver can see the
    /// amount without any blinding key and the claim spend needs no
    /// blinders either.
    ///
    /// The descriptor pins the lockup transaction and carries only
    /// what the receiver cannot derive itself — the refund pubkey and
    /// locktime; the claim side it rebuilds from its own claim pubkey
    /// and the route's payment hash. The sender broadcasts the lockup
    /// non-RBF and
    /// only executes after Blockstream's 0-conf observation service
    /// reports enough functionary coverage; the receiver re-checks
    /// the same service and fetches the tx from esplora by this txid
    /// instead of scanning the lockup address.
    Liquid {
        /// Hex txid (display order) of the broadcast lockup
        /// transaction.
        lockup_txid: String,
        /// Index of the HTLC output within the lockup transaction.
        lockup_vout: u8,
        /// Hex 33-byte compressed pubkey of the sender's refund key
        /// (the witness script's ELSE branch).
        refund_pubkey: PubKey,
        /// Absolute Liquid block height opening the refund path.
        refund_locktime: u32,
    },
    /// Arkade VHTLC. Carries every [`ark_core::vhtlc::VhtlcOptions`]
    /// field the receiver needs to rebuild the VHTLC taproot script,
    /// find the locked VTXO at its address, and claim it:
    ///
    /// * `sender` is the x-only key of the party that locked the funds
    ///   (the upstream hop) and controls the refund paths.
    /// * `receiver` is the x-only key that can claim with the
    ///   preimage — always `claim_pubkeys[arkade]` of this hop, so
    ///   receiving a descriptor whose `receiver` does not match is an
    ///   identity error worth rejecting.
    /// * `server` is the operator's signer key: the script's second
    ///   claim-path signer and co-signer on any spend submitted to
    ///   that operator. The descriptor only round-trips inside one
    ///   operator.
    /// * `payment_hash160` is hex RIPEMD160(payment_hash) ==
    ///   HASH160(preimage), the 20-byte value burned into the
    ///   script (`OP_HASH160 ... OP_EQUALVERIFY`).
    /// * `refund_locktime` is an absolute unix-timestamp locktime
    ///   (the operator rejects height-based CLTVs on its scripts) and
    ///   the three unilateral CSV delays are seconds-type consensus
    ///   `u32` sequence numbers; all four pass straight through to
    ///   the script builder. The sender-alone refund delay must
    ///   exceed the claim delay, so the receiver wins any
    ///   operator-less race.
    Arkade {
        sender: XOnlyPubKey,
        receiver: XOnlyPubKey,
        server: XOnlyPubKey,
        payment_hash160: String,
        refund_locktime: u32,
        unilateral_claim_delay: u32,
        unilateral_refund_delay: u32,
        unilateral_refund_without_receiver_delay: u32,
    },
    /// On-chain EtherSwap HTLC on Rootstock. Carries the
    /// fields the receiver needs to claim:
    /// `preimageHash` is the route's payment hash (the
    /// receiver verifies it matches the incoming payment),
    /// `amount` is locked RBTC in wei, `refundAddress` is
    /// the address that locked the funds (the upstream
    /// hop), `timelock` is a block height. The receiver
    /// calls `claim(preimage, amount, refundAddress,
    /// timelock)` from its own address — `msg.sender`
    /// becomes the contract's `claimAddress`. The network
    /// kind (mainnet vs testnet) is implied by the
    /// `NetworkId` that carries the descriptor.
    Rootstock {
        contract: String,
        amount_wei: u128,
        claim_address: String,
        refund_address: String,
        timelock: u64,
    },
    /// On-chain Bitcoin HTLC: a P2TR output whose taproot tree has a
    /// single script leaf in the Liquid shape — claim path
    /// (`OP_IF <claim_pubkey>`) spendable by revealing the preimage
    /// and signing with the receiver's x-only claim key, and a CLTV
    /// refund path (`OP_ELSE <refund_locktime> OP_CLTV OP_DROP
    /// <refund_pubkey> OP_ENDIF OP_CHECKSIG`) letting the sender
    /// recover the funds after an absolute unix locktime. Keys in the
    /// leaf are x-only (BIP342), so the receiver's x-only network
    /// identity goes into the script unchanged.
    ///
    /// The descriptor pins the lockup transaction and carries the
    /// refund pubkey and locktime. The fixed BIP-341 NUMS internal
    /// taproot key is retained as a protocol assertion: the receiver
    /// derives it locally and rejects descriptors that do not match it.
    /// The receiver rebuilds the leaf hash, tweaked output key and
    /// address from its own x-only claim key plus these fields.
    Bitcoin {
        /// Hex txid (display order) of the broadcast lockup
        /// transaction.
        lockup_txid: String,
        /// Index of the HTLC output within the lockup transaction.
        lockup_vout: u8,
        /// Hex 20-byte RIPEMD160(SHA256(preimage)) burned into the
        /// script.
        payment_hash160: String,
        /// X-only BIP-341 NUMS internal taproot key. It has no known
        /// discrete logarithm, so the HTLC key path is intentionally
        /// unspendable; retained on wire as a protocol assertion.
        internal_key: XOnlyPubKey,
        /// X-only pubkey of the sender's refund leaf (the witness
        /// script's ELSE branch).
        refund_pubkey: XOnlyPubKey,
        /// Absolute unix timestamp opening the refund path.
        refund_locktime: u32,
    },
    /// Fedimint LNv2 direct HTLC: a raw `OutgoingContract` funded
    /// between two federation clients with no gateway involvement
    /// (fedimint PR #8913 client API). Registration descriptors
    /// carry only `claim_pubkey`; funding descriptors additionally
    /// carry the funding outpoint and the consensus-JSON encoding of
    /// the funded contract, which the receiver verifies at funding
    /// time and later claims with the route preimage.
    Fedimint {
        /// Hex 33-byte compressed public key the funder must lock
        /// the contract to — the receiver's claim key.
        claim_pubkey: PubKey,
        /// Hex txid of the funding transaction. `None` on
        /// registration descriptors, where nothing is funded yet.
        funding_txid: Option<String>,
        /// Index of the contract output within the funding
        /// transaction.
        funding_out_idx: Option<u64>,
        /// Consensus-JSON encoding of the funded `OutgoingContract`.
        contract: Option<String>,
    },
    /// LND BOLT11 hold invoice. The receiving LND created this invoice
    /// against the route payment hash; the sender must pay this exact
    /// request so the payment secret is preserved.
    Lightning { payment_request: String },
    /// Spark HTLC transfer. `address` is the Spark address the sender
    /// locked the HTLC to (the receiver's address; the receiver claims
    /// it with `claim_htlc` + preimage, keyed by the payment hash the
    /// descriptor travels with). `expiry_secs` is the HTLC expiry
    /// duration the sender passed, so the receiver can tell how long
    /// it has left. `transfer_id` is the Spark transfer id the sender
    /// can be re-polled by after a restart (`None` only when the
    /// sender sent without keeping the id).
    Spark {
        address: String,
        expiry_secs: u64,
        transfer_id: Option<String>,
    },
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

/// Error returned by every network adapter operation.
///
/// Core routing code handles one error type. UI and protocol layers may
/// add context, but adapters never expose separate receive/send/HTLC
/// error taxonomies.
#[derive(thiserror::Error, Debug)]
pub enum AdapterError {
    #[error("invalid parameters: {0}")]
    InvalidParams(String),
    #[error("network error: {0}")]
    Network(String),
    #[error("retryable adapter state: {0}")]
    Retryable(String),
    #[error("state not found: {0}")]
    NotFound(String),
    #[error("deadline exceeded")]
    DeadlineExceeded,
    #[error("unimplemented")]
    Unimplemented,
}

impl AdapterError {
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Network(_) | Self::Retryable(_))
    }
}

/// Lowest-level boundary between Cassis and one network.
///
/// Adapters own operation state. Every lifecycle method receives an
/// explicit state object or [`OperationId`]; payment hashes identify the
/// payment intent, never the attempt identity.
///
/// Concrete adapters implement this trait directly. Core does not wrap
/// adapters, split receive/send traits, or reconstruct state from hashes.
#[async_trait]
pub trait NetworkAdapter: Send + Sync {
    fn network_id(&self) -> NetworkId;

    /// Public identity whose secret key this adapter uses to claim funds.
    fn claim_pubkey(&self) -> XOnlyPubKey;

    fn incoming_delta_secs(&self) -> u64;

    /// Reserve an incoming contract before external funding starts.
    async fn reserve_incoming(
        &self,
        request: IncomingRequest,
    ) -> Result<IncomingReservation, AdapterError>;

    /// Rehydrate an unfunded reservation from durable invoice state.
    ///
    /// Native invoice adapters rehydrate exact remote state here.
    /// Stateless adapters can delegate to `reserve_incoming` and compare
    /// returned reservation.
    async fn restore_incoming_reservation(
        &self,
        reservation: &IncomingReservation,
    ) -> Result<(), AdapterError>;

    /// Cancel an unfunded incoming reservation.
    async fn cancel_incoming(&self, reservation: &IncomingReservation) -> Result<(), AdapterError>;

    /// Verify and atomically accept a funded incoming HTLC.
    async fn accept_incoming(
        &self,
        reservation: &IncomingReservation,
        descriptor: &HtlcDescriptor,
    ) -> Result<AcceptedIncoming, AdapterError>;

    /// Restore accepted incoming state after process restart.
    async fn restore_incoming(&self, accepted: &AcceptedIncoming) -> Result<(), AdapterError>;

    /// Wait until reservation's incoming HTLC is funded.
    async fn watch_incoming(
        &self,
        reservation: &IncomingReservation,
        deadline: u64,
    ) -> Result<(), AdapterError>;

    /// Claim an accepted incoming HTLC with its preimage.
    async fn claim_incoming(
        &self,
        accepted: &AcceptedIncoming,
        preimage: Bytes32,
    ) -> Result<(), AdapterError>;

    /// Claim a locally watched reservation after funding. Router paths use
    /// [`NetworkAdapter::claim_incoming`] because they already hold the
    /// accepted descriptor; receive paths retain only reservation state.
    async fn claim_reserved_incoming(
        &self,
        reservation: &IncomingReservation,
        preimage: Bytes32,
    ) -> Result<(), AdapterError>;

    /// Fund one outgoing HTLC and return complete recovery state.
    async fn create_outgoing(
        &self,
        request: OutgoingRequest,
    ) -> Result<OutgoingPayment, AdapterError>;

    /// Wait for preimage settlement of an outgoing HTLC.
    async fn watch_outgoing(
        &self,
        payment: &OutgoingPayment,
        deadline: u64,
    ) -> Result<Bytes32, AdapterError>;

    /// Refund an outgoing HTLC after failure or expiry.
    async fn refund_outgoing(&self, payment: &OutgoingPayment) -> Result<(), AdapterError>;

    /// Restore outgoing watcher state after process restart.
    async fn restore_outgoing(&self, payment: &OutgoingPayment) -> Result<(), AdapterError>;

    /// Check whether adapter can fund `amount_msat` now.
    async fn can_route(&self, amount_msat: u64) -> Result<(), AdapterError>;

    /// Check whether adapter can afford to claim `amount_msat` now.
    async fn can_claim(&self, amount_msat: u64) -> Result<(), AdapterError>;
}

#[allow(dead_code)]
fn _assert_network_adapter_object_safe() {
    fn assert<T: Send + Sync + ?Sized>() {}
    assert::<dyn NetworkAdapter>();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invoice_carries_a_target_per_network() {
        let cashu = NetworkId("cashu".into());
        let lightning = NetworkId("lightning".into());
        let invoice = Invoice {
            payment_hash: Bytes32([1u8; 32]),
            amount_msat: 1_000,
            payee: XOnlyPubKey([2u8; 32]),
            expires_at: 3_000,
            networks: vec![
                InvoiceNetwork {
                    network: cashu.clone(),
                    target: HtlcTarget::XOnlyPubKey(XOnlyPubKey([4u8; 32])),
                },
                InvoiceNetwork {
                    network: lightning.clone(),
                    target: HtlcTarget::LightningInvoice("lnbc1invoice".into()),
                },
            ],
            description: None,
            autocommit: false,
            iroh_peer_id: None,
            iroh_relay: None,
        };
        assert_eq!(
            invoice.target_for(&cashu),
            Some(&HtlcTarget::XOnlyPubKey(XOnlyPubKey([4u8; 32])))
        );
        assert_eq!(
            invoice.target_for(&lightning),
            Some(&HtlcTarget::LightningInvoice("lnbc1invoice".into()))
        );
        assert_eq!(invoice.target_for(&NetworkId("arkade".into())), None);
    }

    #[test]
    fn invoice_autocommit_defaults_to_false_when_absent() {
        // No `autocommit` key: older invoices must still decode, and must
        // not silently opt into skipping COMMIT.
        let decoded: Invoice = serde_json::from_str(
            r#"{
                "payment_hash": "0000000000000000000000000000000000000000000000000000000000000001",
                "amount_msat": 1000,
                "payee": "17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917",
                "expires_at": 3000,
                "networks": [
                    {
                        "network": "cashu",
                        "target": {"XOnlyPubKey": "17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917"}
                    }
                ],
                "description": null
            }"#,
        )
        .expect("invoice without autocommit must decode");
        assert!(!decoded.autocommit);
        assert_eq!(decoded.networks[0].network, NetworkId("cashu".into()));
    }

    #[test]
    fn operation_ids_are_opaque_valid_and_unique() {
        let first = OperationId::random();
        let second = OperationId::random();
        assert!(first.is_valid());
        assert!(second.is_valid());
        assert_ne!(first, second);
        assert!(!OperationId("not-opaque".into()).is_valid());
    }

    #[test]
    fn split_spec_splits_on_double_colon() {
        assert_eq!(
            split_spec("cashu::mint.example.com"),
            ("cashu", Some("mint.example.com"))
        );
        assert_eq!(split_spec("liquid"), ("liquid", None));
    }

    #[test]
    fn split_spec_treats_single_colon_as_whole_kind() {
        assert_eq!(split_spec("cashu:host:port"), ("cashu:host:port", None));
    }

    #[test]
    fn network_id_default_incoming_delta_matches_adapters() {
        for (network, expected) in [
            ("arkade", 60),
            ("arkade::mutinynet", 60),
            ("bitcoin", 300),
            ("bitcoin::mutinynet", 300),
            ("fedimint", 30),
            ("cashu", 30),
            ("liquid", 300),
            ("liquid::testnet", 300),
            ("rootstock", 600),
            ("rootstock::testnet", 600),
            ("lightning", 30),
            ("spark", 60),
        ] {
            assert_eq!(NetworkId(network.into()).default_incoming_delta(), expected);
        }
    }

    #[test]
    fn network_id_default_incoming_delta_defaults_unknown_networks() {
        assert_eq!(NetworkId("mystery".into()).default_incoming_delta(), 30);
        assert_eq!(NetworkId("".into()).default_incoming_delta(), 30);
    }

    #[cfg(feature = "cashu")]
    #[test]
    fn network_id_for_cashu_spec_uses_canonical_form() {
        let id = network_id_for_spec("cashu::mint.example.com").unwrap();
        assert_eq!(id.0, "cashu::mint.example.com");
    }

    #[cfg(feature = "cashu")]
    #[test]
    fn network_id_for_cashu_spec_loopback_uses_canonical_form() {
        let id = network_id_for_spec("cashu::localhost:3338").unwrap();
        assert_eq!(id.0, "cashu::localhost:3338");
    }

    #[cfg(feature = "cashu")]
    #[test]
    fn network_id_for_cashu_spec_rejects_legacy_single_colon() {
        assert!(network_id_for_spec("cashu:localhost:3338").is_err());
    }

    #[cfg(feature = "cashu")]
    #[test]
    fn network_id_for_cashu_spec_rejects_explicit_scheme() {
        assert!(network_id_for_spec("cashu::https://mint.example.com").is_err());
    }

    #[cfg(feature = "cashu")]
    #[test]
    fn network_id_for_cashu_spec_rejects_empty_host() {
        assert!(network_id_for_spec("cashu::").is_err());
    }

    #[cfg(not(feature = "cashu"))]
    #[test]
    fn network_id_for_cashu_spec_reports_missing_feature() {
        let err = network_id_for_spec("cashu::mint.example.com").unwrap_err();
        assert!(
            err.contains("'cashu' feature"),
            "expected feature-related error, got: {err}"
        );
    }

    #[test]
    fn network_id_for_fedimint_spec_is_rejected() {
        let err = network_id_for_spec("fedimint::fed1qabc").unwrap_err();
        assert!(
            err.contains("fedimint"),
            "expected fedimint-related error, got: {err}"
        );
    }

    #[cfg(feature = "liquid")]
    #[test]
    fn network_id_for_liquid_spec_uses_canonical_form() {
        let id = network_id_for_spec("liquid").unwrap();
        assert_eq!(id.0, "liquid");
    }

    #[cfg(feature = "liquid")]
    #[test]
    fn network_id_for_liquid_testnet_spec_uses_canonical_form() {
        let id = network_id_for_spec("liquid::testnet").unwrap();
        assert_eq!(id.0, "liquid::testnet");
        assert!(network_id_for_spec("liquid::foo").is_err());
    }

    #[cfg(not(feature = "liquid"))]
    #[test]
    fn network_id_for_liquid_spec_reports_missing_feature() {
        let err = network_id_for_spec("liquid").unwrap_err();
        assert!(
            err.contains("'liquid' feature"),
            "expected feature-related error, got: {err}"
        );
    }

    #[cfg(feature = "arkade")]
    #[test]
    fn network_id_for_arkade_spec_uses_canonical_form() {
        let id = network_id_for_spec("arkade").unwrap();
        assert_eq!(id.0, "arkade");
        let id = network_id_for_spec("arkade::mutinynet").unwrap();
        assert_eq!(id.0, "arkade::mutinynet");
    }

    #[cfg(feature = "arkade")]
    #[test]
    fn network_id_for_arkade_spec_rejects_unknown_parameter() {
        assert!(network_id_for_spec("arkade::foo").is_err());
    }

    #[cfg(feature = "bitcoin")]
    #[test]
    fn network_id_for_bitcoin_spec_uses_canonical_form() {
        let id = network_id_for_spec("bitcoin").unwrap();
        assert_eq!(id.0, "bitcoin");
        let id = network_id_for_spec("bitcoin::mutinynet").unwrap();
        assert_eq!(id.0, "bitcoin::mutinynet");
    }

    #[cfg(feature = "bitcoin")]
    #[test]
    fn network_id_for_bitcoin_spec_rejects_unknown_parameter() {
        assert!(network_id_for_spec("bitcoin::foo").is_err());
        assert!(network_id_for_spec("bitcoin::testnet").is_err());
    }

    #[cfg(not(feature = "arkade"))]
    #[test]
    fn network_id_for_arkade_spec_reports_missing_feature() {
        let err = network_id_for_spec("arkade").unwrap_err();
        assert!(
            err.contains("'arkade' feature"),
            "expected feature-related error, got: {err}"
        );
    }

    #[cfg(feature = "rootstock")]
    #[test]
    fn network_id_for_rootstock_spec_uses_canonical_form() {
        let id = network_id_for_spec("rootstock").unwrap();
        assert_eq!(id.0, "rootstock");
    }

    #[cfg(feature = "rootstock")]
    #[test]
    fn network_id_for_rootstock_testnet_spec_uses_canonical_form() {
        let id = network_id_for_spec("rootstock::testnet").unwrap();
        assert_eq!(id.0, "rootstock::testnet");
    }

    #[cfg(feature = "rootstock")]
    #[test]
    fn network_id_for_rootstock_spec_rejects_unknown_parameter() {
        assert!(network_id_for_spec("rootstock::foo").is_err());
    }

    #[cfg(not(feature = "rootstock"))]
    #[test]
    fn network_id_for_rootstock_spec_reports_missing_feature() {
        let err = network_id_for_spec("rootstock").unwrap_err();
        assert!(
            err.contains("'rootstock' feature"),
            "expected feature-related error, got: {err}"
        );
    }

    #[test]
    fn network_id_for_spec_rejects_unknown_kind() {
        assert!(network_id_for_spec("foo").is_err());
        assert!(network_id_for_spec("foo::bar").is_err());
    }

    #[cfg(feature = "cashu")]
    #[test]
    fn cashu_mint_url_uses_https_for_remote_hostname() {
        assert_eq!(
            cashu_mint_url(&NetworkId(format!(
                "{CASHU_NETWORK_ID_PREFIX}mint.example.com"
            )))
            .unwrap(),
            "https://mint.example.com"
        );
    }

    #[cfg(feature = "cashu")]
    #[test]
    fn cashu_mint_url_uses_https_for_hostname_with_port() {
        assert_eq!(
            cashu_mint_url(&NetworkId(format!(
                "{CASHU_NETWORK_ID_PREFIX}mint.example.com:3338"
            )))
            .unwrap(),
            "https://mint.example.com:3338"
        );
    }

    #[cfg(feature = "cashu")]
    #[test]
    fn cashu_mint_url_uses_http_for_localhost() {
        assert_eq!(
            cashu_mint_url(&NetworkId(format!("{CASHU_NETWORK_ID_PREFIX}localhost"))).unwrap(),
            "http://localhost"
        );
        assert_eq!(
            cashu_mint_url(&NetworkId(format!(
                "{CASHU_NETWORK_ID_PREFIX}localhost:3338"
            )))
            .unwrap(),
            "http://localhost:3338"
        );
    }

    #[cfg(feature = "cashu")]
    #[test]
    fn cashu_mint_url_uses_http_for_loopback_ips() {
        assert_eq!(
            cashu_mint_url(&NetworkId(format!("{CASHU_NETWORK_ID_PREFIX}127.0.0.1"))).unwrap(),
            "http://127.0.0.1"
        );
        assert_eq!(
            cashu_mint_url(&NetworkId(format!(
                "{CASHU_NETWORK_ID_PREFIX}127.0.0.1:3338"
            )))
            .unwrap(),
            "http://127.0.0.1:3338"
        );
        assert_eq!(
            cashu_mint_url(&NetworkId(format!("{CASHU_NETWORK_ID_PREFIX}::1"))).unwrap(),
            "http://::1"
        );
        assert_eq!(
            cashu_mint_url(&NetworkId(format!("{CASHU_NETWORK_ID_PREFIX}[::1]:3338"))).unwrap(),
            "http://[::1]:3338"
        );
    }

    #[test]
    fn canonicalize_passes_through_canonical_cashu() {
        assert_eq!(
            canonicalize_network_id(&NetworkId("cashu::localhost:3338".to_string())).0,
            "cashu::localhost:3338"
        );
        assert_eq!(
            canonicalize_network_id(&NetworkId("cashu::mint.example.com".to_string())).0,
            "cashu::mint.example.com"
        );
    }

    #[test]
    fn canonicalize_passes_through_canonical_fedimint() {
        assert_eq!(
            canonicalize_network_id(&NetworkId("fedimint::fed1qabc".to_string())).0,
            "fedimint::fed1qabc"
        );
    }

    #[test]
    fn canonicalize_leaves_other_kinds_alone() {
        assert_eq!(
            canonicalize_network_id(&NetworkId("liquid".to_string())).0,
            "liquid"
        );
        assert_eq!(
            canonicalize_network_id(&NetworkId("liquid::testnet".to_string())).0,
            "liquid::testnet"
        );
        assert_eq!(
            canonicalize_network_id(&NetworkId("arkade".to_string())).0,
            "arkade"
        );
        assert_eq!(
            canonicalize_network_id(&NetworkId("bitcoin".to_string())).0,
            "bitcoin"
        );
        assert_eq!(
            canonicalize_network_id(&NetworkId("bitcoin::mutinynet".to_string())).0,
            "bitcoin::mutinynet"
        );
        assert_eq!(
            canonicalize_network_id(&NetworkId("arkade::mutinynet".to_string())).0,
            "arkade::mutinynet"
        );
        assert_eq!(
            canonicalize_network_id(&NetworkId("rootstock".to_string())).0,
            "rootstock"
        );
        assert_eq!(
            canonicalize_network_id(&NetworkId("rootstock::testnet".to_string())).0,
            "rootstock::testnet"
        );
    }

    #[test]
    fn canonicalize_does_not_convert_legacy_or_invalid_forms() {
        // Legacy single-colon forms are NOT converted — downstream
        // lookups reject the iroh instruction at adapter-lookup time.
        // The canonicalize function only ever passes through valid input.
        for raw in [
            "cashu:localhost:3338",
            "cashu:https://mint.example.com",
            "fedimint:fed1qabc",
            "cashu:",
            "fedimint:",
            "cashu::",
            "fedimint::",
            "cashu::https://mint.example.com",
        ] {
            let id = NetworkId(raw.to_string());
            assert_eq!(canonicalize_network_id(&id).0, raw);
        }
    }

    #[test]
    fn normalize_network_id_passes_through_canonical() {
        assert_eq!(
            normalize_network_id(&NetworkId("cashu::localhost:8093".to_string())).0,
            "cashu::localhost:8093"
        );
        assert_eq!(
            normalize_network_id(&NetworkId("cashu::mint.example.com".to_string())).0,
            "cashu::mint.example.com"
        );
        assert_eq!(
            normalize_network_id(&NetworkId("fedimint::fed1qabc".to_string())).0,
            "fedimint::fed1qabc"
        );
        assert_eq!(
            normalize_network_id(&NetworkId("liquid".to_string())).0,
            "liquid"
        );
        assert_eq!(
            normalize_network_id(&NetworkId("rootstock".to_string())).0,
            "rootstock"
        );
        assert_eq!(
            normalize_network_id(&NetworkId("rootstock::testnet".to_string())).0,
            "rootstock::testnet"
        );
    }
}
