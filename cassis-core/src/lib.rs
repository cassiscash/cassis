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
    pub payee: XOnlyPubKey,
    pub expires_at: u64,
    pub networks: Vec<NetworkId>,
    pub address: HtlcTarget,
    pub description: Option<String>,
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

/// Handle to an in-flight outgoing payment initiated by
/// [`NetworkSenderAdapter::pay_invoice`]. The caller passes it to
/// [`NetworkSenderAdapter::watch_payment`] or
/// [`NetworkSenderAdapter::refund_payment`] to drive the operation to
/// its terminal state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutgoingPayment {
    pub payment_hash: Bytes32,
    pub amount_msat: u64,
    pub destination: HtlcTarget,
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
    /// X-only claim key used by Cashu, Liquid, and Arkade.
    XOnlyPubKey(XOnlyPubKey),
    /// Full compressed claim key used by Fedimint.
    PubKey(PubKey),
    /// BOLT11 hold invoice the upstream party must pay (lightning).
    LightningInvoice(String),
}

/// PREPARE message (sender -> router): ask a hop to reserve capacity
/// for a payment without yet committing to it. The router checks
/// basic invariants (non-zero hash, positive amount, supported
/// networks, timelock defaults, funds on the outgoing side) and
/// replies with [`HopPrepared`]. The actual HTLCs are only created
/// after a matching DISPATCH message arrives.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HopPrepare {
    pub payment_hash: Bytes32,
    pub amount_msat: u64,
    pub incoming_network: NetworkId,
    pub outgoing_network: NetworkId,
    pub incoming_deadline: u64,
    pub outgoing_expiry: u64,
}

/// Reply to [`HopPrepare`]. `accepted=true` means the hop has
/// reserved capacity and is ready to receive a matching DISPATCH.
/// `accepted=false` carries a human-readable reason; the sender is
/// expected to abort the whole payment if any hop rejects.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HopPrepared {
    pub payment_hash: Bytes32,
    pub accepted: bool,
    pub reason: Option<String>,
    /// Network-specific parameters the upstream party must use to
    /// address this hop's incoming side, as reported by its incoming
    /// adapter ([`NetworkRouterAdapter::htlc_target`]).
    ///
    /// For pubkey networks (cashu, liquid, arkade, rootstock,
    /// fedimint) this is the claim key the upstream party locks its
    /// outgoing HTLC to; for lightning it is the BOLT11 hold invoice
    /// the upstream party must pay. Self-reporting keeps address and
    /// claim in agreement by construction. `None` on a rejection,
    /// where there is nothing to address.
    ///
    /// Deliberately carries no `skip_serializing_if`: these frames go
    /// over the wire and are decoded positionally by version-tolerant
    /// peers, so omitting a field desynchronizes the decoder rather
    /// than falling back to a default. Always serialized, like
    /// `reason` above.
    pub htlc_target: Option<HtlcTarget>,
}

/// DISPATCH message (sender -> router): tells a hop that a real
/// incoming HTLC matching its previous PREPARE has been deployed on
/// the hop's incoming network. The descriptor is the network-specific
/// payload the receiver of the HTLC needs to claim it (e.g. for
/// cashu: a list of base64-encoded NUT-14 proofs). The router
/// verifies the HTLC is really claimable, then creates an outgoing
/// HTLC and replies with its descriptor in [`HopDispatched`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HopDispatch {
    pub payment_hash: Bytes32,
    /// Network-specific handle to the deployed incoming HTLC.
    pub incoming_descriptor: HtlcDescriptor,
    /// Network-specific parameters for the hop's *outgoing* side: the
    /// downstream party's self-reported addressing parameters (the
    /// next hop's [`HopPrepared::htlc_target`], or the
    /// payee's for the last hop). For pubkey networks this is the
    /// claim key to lock the outgoing HTLC to; for lightning it is
    /// the downstream hold invoice to pay.
    ///
    /// This travels in DISPATCH rather than PREPARE because the payer
    /// PREPAREs every hop *concurrently*, so when hop `i`'s PREPARE is
    /// built the reply from hop `i+1` — and therefore its addressing
    /// parameters — is not known yet. DISPATCH is sequential and
    /// happens strictly after every PREPARE has been answered, so by
    /// then the downstream parameters are always available.
    pub htlc_target: HtlcTarget,
}

/// Reply to [`HopDispatch`]. Carries the descriptor of the outgoing
/// HTLC the router has just created on its outgoing network. The
/// sender passes it to the next hop's DISPATCH.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HopDispatched {
    pub payment_hash: Bytes32,
    pub outgoing_descriptor: HtlcDescriptor,
}

/// DISCARD message (sender -> router): abandon a reservation made by an
/// earlier [`HopPrepare`] that will never be followed by a DISPATCH.
///
/// The payer sends this to every hop still holding a reservation as
/// soon as it knows the payment cannot proceed — a hop rejected its
/// PREPARE, the payer could not fund the first HTLC, or a DISPATCH
/// failed part-way down the route. Without it a failed attempt leaves
/// capacity pinned on every hop that *did* accept until the
/// reservation ages out, so a payer retrying over an overlapping route
/// competes against its own abandoned attempts.
///
/// This can only ever free a reservation, never affect money: a hop
/// drops its [`HopPrepare`] record the moment it acts on the matching
/// DISPATCH, so by the time any HTLC exists there is nothing here left
/// to match. A DISCARD that arrives after DISPATCH finds no record and
/// is reported as `released: false` rather than unwinding anything;
/// funded HTLCs are left to the normal preimage-or-timelock path.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HopDiscard {
    pub payment_hash: Bytes32,
}

/// Reply to [`HopDiscard`]. `released` is true when a matching
/// reservation was found and dropped.
///
/// `released: false` is a normal, non-error outcome: the reservation
/// may have already aged out, the PREPARE may have been rejected (in
/// which case nothing was ever reserved), or a DISPATCH may have
/// already consumed it. The payer sends DISCARD as a best-effort
/// cleanup and does not fail a payment over the answer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HopDiscarded {
    pub payment_hash: Bytes32,
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
    /// only dispatches after Blockstream's 0-conf observation service
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
    /// The descriptor pins the lockup transaction and carries what the
    /// receiver cannot derive itself: the sender's internal taproot
    /// key (the refunable key-path signer, and the collaborator for
    /// future joint settlement), the refund pubkey and locktime. The
    /// receiver rebuilds leaf hash, tweaked output key and address
    /// from its own x-only claim key plus these fields.
    Bitcoin {
        /// Hex txid (display order) of the broadcast lockup
        /// transaction.
        lockup_txid: String,
        /// Index of the HTLC output within the lockup transaction.
        lockup_vout: u8,
        /// Hex 20-byte RIPEMD160(SHA256(preimage)) burned into the
        /// script.
        payment_hash160: String,
        /// X-only key of the sender's internal taproot key: the
        /// unpruned key path can later serve collaborative
        /// settlement.
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
///
/// The `claim_incoming` / `watch_preimage` / `refund_outgoing`
/// methods are keyed by `payment_hash` only; implementations are
/// expected to look up any other HTLC fields (amount, expiry,
/// sender, etc.) from their own per-payment state, populated by
/// the matching `register_incoming_htlc` / `accept_incoming_htlc` /
/// `create_outgoing_htlc` call.
#[async_trait]
pub trait NetworkRouterAdapter: Send + Sync {
    fn network_id(&self) -> NetworkId;

    fn invoice_pubkey(&self) -> XOnlyPubKey;

    /// The identity this adapter can actually *claim* an incoming HTLC
    /// with: the public key whose secret key the adapter holds and
    /// signs claims with on this network.
    ///
    /// Counterparties must lock HTLCs destined for this adapter to this
    /// key. Self-reporting it (rather than letting the counterparty
    /// guess from an announced node key) is what keeps lock and claim
    /// in agreement by construction.
    ///
    /// Defaults to [`NetworkRouterAdapter::invoice_pubkey`], which is
    /// correct for networks whose claim signature is over the invoice
    /// key (cashu). Networks holding a separate per-network key — e.g.
    /// rootstock, whose claim is an on-chain transaction signed by a
    /// dedicated EVM account — must override this.
    fn claim_pubkey(&self) -> XOnlyPubKey {
        self.invoice_pubkey()
    }

    fn incoming_delta_secs(&self) -> u64;

    /// Register an incoming HTLC before the payer funds it (PREPARE
    /// time). Nothing is watched or polled here — the adapter only
    /// parks whatever per-payment state its network needs so the
    /// later [`NetworkRouterAdapter::accept_incoming_htlc`] (DISPATCH)
    /// and [`NetworkRouterAdapter::claim_incoming`] calls can find it.
    /// Adapters that need a remote registration before funding (LND
    /// hold invoice) create it here.
    ///
    /// The default is a no-op — adapters needing pre-funding state
    /// must override.
    async fn register_incoming_htlc(
        &self,
        _payment_hash: Bytes32,
        _min_amount_msat: u64,
        _deadline: u64,
    ) -> Result<(), HtlcError> {
        Ok(())
    }

    /// The [`HtlcTarget`] the upstream party must use to
    /// address a registered incoming HTLC on this adapter. The router
    /// returns this in the [`HopPrepared`] reply to PREPARE.
    ///
    /// Defaults to the claim key ([`NetworkRouterAdapter::claim_pubkey`]),
    /// correct for networks addressed by pubkey (cashu, liquid, arkade,
    /// rootstock, fedimint). Lightning overrides this to return the
    /// per-payment BOLT11 hold invoice created during
    /// [`NetworkRouterAdapter::register_incoming_htlc`].
    async fn htlc_target(&self, _payment_hash: Bytes32) -> Result<HtlcTarget, HtlcError> {
        Ok(HtlcTarget::XOnlyPubKey(self.claim_pubkey()))
    }

    /// Cancel an incoming registration that was prepared but never funded.
    /// Most adapters have no remote registration to cancel.
    async fn cancel_incoming_htlc(&self, _payment_hash: Bytes32) -> Result<(), HtlcError> {
        Ok(())
    }

    async fn create_outgoing_htlc(
        &self,
        payment_hash: Bytes32,
        amount_msat: u64,
        expiry: u64,
        htlc_target: &HtlcTarget,
    ) -> Result<OutgoingHtlc, HtlcError>;

    async fn claim_incoming(
        &self,
        payment_hash: Bytes32,
        preimage: Bytes32,
    ) -> Result<(), HtlcError>;

    async fn refund_outgoing(&self, payment_hash: Bytes32) -> Result<(), HtlcError>;

    async fn watch_preimage(
        &self,
        payment_hash: Bytes32,
        deadline: u64,
    ) -> Result<Bytes32, WatchError>;

    /// PREPARE-time check: does this adapter have enough funds /
    /// capacity to route `amount_msat` on its network right now?
    /// Called for the hop's *outgoing* adapter so the router can
    /// reject a PREPARE before any HTLCs are deployed. Default
    /// implementation accepts unconditionally so stub adapters don't
    /// have to implement it.
    async fn can_route(&self, _amount_msat: u64) -> Result<(), HtlcError> {
        Ok(())
    }

    /// PREPARE-time check on the hop's *incoming* adapter: can this
    /// adapter afford to eventually *claim* what it is owed?
    ///
    /// [`NetworkRouterAdapter::can_route`] only proves the outgoing side
    /// can be funded. On networks where claiming costs something of its
    /// own — rootstock, where the claim is an on-chain transaction the
    /// router pays gas for — that leaves a gap: the hop accepts the
    /// route, locks its outgoing HTLC, and only then discovers it cannot
    /// claim upstream. Funds are committed downstream and unclaimable
    /// upstream until the timelock expires.
    ///
    /// Checking here means the PREPARE is rejected before anything is
    /// locked. Defaults to accepting: on networks where a claim is just
    /// a signed message (cashu), there is nothing to afford.
    async fn can_claim(&self, _amount_msat: u64) -> Result<(), HtlcError> {
        Ok(())
    }

    /// DISPATCH-time check: is `descriptor` really claimable on
    /// this adapter for the given `payment_hash`? The router calls
    /// this on the hop's *incoming* adapter right after receiving a
    /// DISPATCH and before creating the outgoing HTLC. For cashu this
    /// verifies the NUT-14 proofs decode, are HTLC-locked, and
    /// reference the right payment hash. Default rejects so
    /// unimplemented networks fail closed.
    async fn verify_incoming_htlc(
        &self,
        _descriptor: &HtlcDescriptor,
        _payment_hash: Bytes32,
    ) -> Result<(), HtlcError> {
        Err(HtlcError::Unimplemented)
    }

    /// Accept an incoming HTLC for later claim. Called on the
    /// hop's *incoming* adapter during DISPATCH: stores the HTLC
    /// payload (e.g. cashu proofs) so a later
    /// [`NetworkRouterAdapter::claim_incoming`] call can find it.
    /// Default is a no-op for stub networks.
    async fn accept_incoming_htlc(
        &self,
        _payment_hash: Bytes32,
        _descriptor: &HtlcDescriptor,
        _deadline: u64,
    ) -> Result<(), HtlcError> {
        Ok(())
    }

    /// DISPATCH-time accessor: return the network-specific handle
    /// to the outgoing HTLC just produced by
    /// [`NetworkRouterAdapter::create_outgoing_htlc`]. Called on the
    /// hop's *outgoing* adapter to build the [`HopDispatched`]
    /// reply. For cashu this serializes the locked proofs as
    /// base64. Default is unimplemented so stub networks fail
    /// closed.
    async fn outgoing_htlc_descriptor(
        &self,
        _payment_hash: Bytes32,
    ) -> Result<HtlcDescriptor, HtlcError> {
        Err(HtlcError::Unimplemented)
    }

    /// Restore sender-side state for an outgoing HTLC created before a
    /// process restart. `descriptor` is the wire handle previously returned
    /// by [`NetworkRouterAdapter::outgoing_htlc_descriptor`]. Adapters that
    /// keep watcher state only in memory should override this to rebuild it.
    async fn restore_outgoing_htlc(
        &self,
        _payment: &OutgoingPayment,
        _descriptor: Option<&HtlcDescriptor>,
    ) -> Result<(), HtlcError> {
        Err(HtlcError::Unimplemented)
    }
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

    /// Identity this receiver claims incoming HTLCs with on this
    /// network, advertised to payers via [`Invoice::claim_pubkeys`] so
    /// the last hop locks the final HTLC to a key the payee can
    /// actually spend. Mirrors [`NetworkRouterAdapter::claim_pubkey`].
    ///
    /// `None` means "no network-specific identity": the payer falls
    /// back to [`Invoice::payee`].
    fn claim_pubkey(&self) -> Option<XOnlyPubKey> {
        None
    }

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

    /// Register a caller-selected payment hash for an invoice. Networks
    /// whose native invoice is externally encoded may return that request so
    /// the payer can carry it through the Cassis route.
    async fn register_invoice(
        &self,
        _payment_hash: Bytes32,
        _amount_msat: u64,
        _expiry: u64,
        _description: Option<String>,
    ) -> Result<Option<String>, ReceiveError> {
        Ok(None)
    }

    /// Wait for the upstream hop to fund the invoice.
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

    /// Store the wire-level handle to an incoming HTLC the
    /// sender pushed at us. The COMMIT flow uses this so the
    /// payee can claim a HTLC it learned about via
    /// [`crate::HopCommit`] instead of waiting for the network
    /// to detect an incoming payment. Default is a no-op so
    /// stub networks don't have to implement it.
    async fn accept_incoming_via_descriptor(
        &self,
        _payment_hash: Bytes32,
        _descriptor: &HtlcDescriptor,
        _deadline: u64,
    ) -> Result<(), ReceiveError> {
        Ok(())
    }
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

    /// Initiate a payment to the given destination. `addressing` is
    /// the destination's self-reported [`HtlcTarget`]: the
    /// claim key to lock to for pubkey networks, or the BOLT11 hold
    /// invoice to pay for lightning. `destination_network` is the
    /// network the payment is being sent on (typically
    /// `self.network_id()`, but the caller passes it for symmetry
    /// with the receive side).
    async fn pay_invoice(
        &self,
        payment_hash: Bytes32,
        amount_msat: u64,
        addressing: &HtlcTarget,
        destination_network: &NetworkId,
        expiry: u64,
    ) -> Result<OutgoingPayment, SendError>;

    /// Block until the payment reaches a terminal state.
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

    /// Returns the wire-level handle to the outgoing HTLC just
    /// produced by [`NetworkSenderAdapter::pay_invoice`]. Used by
    /// the multi-hop client to forward the descriptor to the next
    /// router hop's DISPATCH. For router-style networks the
    /// blanket impl forwards to
    /// [`NetworkRouterAdapter::outgoing_htlc_descriptor`]; sender-
    /// only networks (fedimint) return
    /// [`SendError::Unimplemented`].
    async fn outgoing_htlc_descriptor(
        &self,
        _payment_hash: Bytes32,
    ) -> Result<HtlcDescriptor, SendError> {
        Err(SendError::Unimplemented)
    }

    /// Restore sender-side state for a pending outgoing HTLC after a
    /// process restart. The descriptor is the wire handle previously
    /// returned by `outgoing_htlc_descriptor`.
    async fn restore_outgoing_payment(
        &self,
        _payment: &OutgoingPayment,
        _descriptor: Option<&HtlcDescriptor>,
    ) -> Result<(), SendError> {
        Err(SendError::Unimplemented)
    }
}

// ---------------------------------------------------------------------------
// Blanket impls: any `NetworkRouterAdapter` is automatically a
// `NetworkReceiverAdapter` and a `NetworkSenderAdapter`. Networks like
// cashu that fully fit the router model rely on these; networks like
// fedimint that don't, implement the receiver/sender traits directly
// and skip `NetworkRouterAdapter` entirely.
//
// Per-payment state (the HTLC objects) lives on the adapter itself,
// keyed by `payment_hash`; the blanket impls carry nothing between
// calls.
// ---------------------------------------------------------------------------

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

    fn claim_pubkey(&self) -> Option<XOnlyPubKey> {
        Some(NetworkRouterAdapter::claim_pubkey(self))
    }

    /// Register an incoming contract with the router adapter. The
    /// payment hash is locally generated; the receiver learns the
    /// matching preimage from its own invoice store and claims via
    /// COMMIT. The `payment_hash` on the returned `Invoice` is the
    /// one the upstream hop funds.
    async fn create_invoice(
        &self,
        amount_msat: u64,
        expiry: u64,
        description: Option<String>,
    ) -> Result<Invoice, ReceiveError> {
        let network_id = self.network_id();
        let payment_hash = Bytes32(rand::random::<[u8; 32]>());
        let descriptor =
            NetworkRouterAdapter::register_incoming_htlc(self, payment_hash, amount_msat, expiry)
                .await
                .map_err(|e| ReceiveError::Network(e.to_string()))?;
        let _ = descriptor;
        let address = match NetworkRouterAdapter::htlc_target(self, payment_hash).await {
            Ok(target) => target,
            Err(_) => HtlcTarget::XOnlyPubKey(self.claim_pubkey()),
        };
        Ok(Invoice {
            payment_hash,
            amount_msat,
            payee: self.invoice_pubkey(),
            expires_at: expiry,
            networks: vec![network_id],
            description,
            iroh_peer_id: None,
            iroh_relay: None,
            address,
        })
    }

    async fn register_invoice(
        &self,
        payment_hash: Bytes32,
        amount_msat: u64,
        expiry: u64,
        _description: Option<String>,
    ) -> Result<Option<String>, ReceiveError> {
        let descriptor =
            NetworkRouterAdapter::register_incoming_htlc(self, payment_hash, amount_msat, expiry)
                .await
                .map_err(|e| ReceiveError::Network(e.to_string()))?;
        let _ = descriptor;
        Ok(
            match NetworkRouterAdapter::htlc_target(self, payment_hash).await {
                Ok(HtlcTarget::LightningInvoice(payment_request)) => Some(payment_request),
                _ => None,
            },
        )
    }

    /// No-op for the router auto-impl: registration (PREPARE) and
    /// acceptance (DISPATCH) already happened on other paths, and the
    /// payee originates the preimage itself. We return a zero
    /// preimage as a sentinel; the routing layer only cares that the
    /// wait completed.
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
        NetworkRouterAdapter::claim_incoming(self, payment_hash, preimage)
            .await
            .map_err(|e| match e {
                HtlcError::InvalidParams(msg) => ReceiveError::InvalidParams(msg),
                other => ReceiveError::Network(other.to_string()),
            })
    }

    async fn accept_incoming_via_descriptor(
        &self,
        payment_hash: Bytes32,
        descriptor: &HtlcDescriptor,
        deadline: u64,
    ) -> Result<(), ReceiveError> {
        NetworkRouterAdapter::accept_incoming_htlc(self, payment_hash, descriptor, deadline)
            .await
            .map_err(|e| match e {
                HtlcError::InvalidParams(msg) => ReceiveError::InvalidParams(msg),
                other => ReceiveError::Network(other.to_string()),
            })
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
        addressing: &HtlcTarget,
        destination_network: &NetworkId,
        expiry: u64,
    ) -> Result<OutgoingPayment, SendError> {
        let htlc = NetworkRouterAdapter::create_outgoing_htlc(
            self,
            payment_hash,
            amount_msat,
            expiry,
            addressing,
        )
        .await
        .map_err(|e| match e {
            HtlcError::InvalidParams(msg) => SendError::InvalidParams(msg),
            other => SendError::Network(other.to_string()),
        })?;
        Ok(OutgoingPayment {
            payment_hash: htlc.payment_hash,
            amount_msat: htlc.amount_msat,
            destination: addressing.clone(),
            destination_network: destination_network.clone(),
            expiry,
        })
    }

    async fn watch_payment(
        &self,
        payment: OutgoingPayment,
        deadline: u64,
    ) -> Result<Bytes32, SendError> {
        NetworkRouterAdapter::watch_preimage(self, payment.payment_hash, deadline)
            .await
            .map_err(|e| match e {
                WatchError::DeadlineExceeded => SendError::DeadlineExceeded,
                other => SendError::Network(other.to_string()),
            })
    }

    async fn refund_payment(&self, payment: OutgoingPayment) -> Result<(), SendError> {
        NetworkRouterAdapter::refund_outgoing(self, payment.payment_hash)
            .await
            .map_err(|e| match e {
                HtlcError::InvalidParams(msg) => SendError::InvalidParams(msg),
                other => SendError::Network(other.to_string()),
            })
    }

    async fn outgoing_htlc_descriptor(
        &self,
        payment_hash: Bytes32,
    ) -> Result<HtlcDescriptor, SendError> {
        NetworkRouterAdapter::outgoing_htlc_descriptor(self, payment_hash)
            .await
            .map_err(|e| match e {
                HtlcError::InvalidParams(msg) => SendError::InvalidParams(msg),
                other => SendError::Network(other.to_string()),
            })
    }

    async fn restore_outgoing_payment(
        &self,
        payment: &OutgoingPayment,
        descriptor: Option<&HtlcDescriptor>,
    ) -> Result<(), SendError> {
        NetworkRouterAdapter::restore_outgoing_htlc(self, payment, descriptor)
            .await
            .map_err(|e| match e {
                HtlcError::InvalidParams(msg) => SendError::InvalidParams(msg),
                other => SendError::Network(other.to_string()),
            })
    }
}

/// Internal helper: blanket-impls need a `Send + Sync` bound on the
/// underlying `T` to use `Arc<T>` from trait objects. Kept here for
/// downstream code that wants `Arc<dyn NetworkRouterAdapter>` etc.
#[allow(dead_code)]
fn _assert_send_sync() {
    fn assert<T: Send + Sync + ?Sized>() {}
    assert::<dyn NetworkRouterAdapter>();
    assert::<dyn NetworkReceiverAdapter>();
    assert::<dyn NetworkSenderAdapter>();
}

#[cfg(test)]
mod tests {
    use super::*;

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
