//! The boundary between Cassis and one network.
//!
//! [`Network`] is the single trait every network crate implements. Its
//! methods are the lowest-level HTLC operations every supported layer
//! can express ("claim with the preimage of `H` before `t`, else
//! refund"). Adapters keep no per-payment state: everything they need
//! travels in the [`Htlc`] passed to them, and all coordination —
//! reservations, journaling, retries, timeouts, polling — lives in the
//! node (see `cassis-wallet`).

use crate::offline::GatewayDestination;
use crate::primitives::{Bytes32, PubKey, XOnlyPubKey};
use async_trait::async_trait;
use serde::ser::SerializeStruct;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeMap;
use std::convert::Infallible;
use std::fmt;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;

/// Canonical network identifier: `<kind>` or `<kind>::<param>`.
///
/// * `cashu::<host[:port]>` — a mint, addressed without scheme
///   (loopback hosts use `http`, everything else `https`).
/// * `fedimint::<invite code>`
/// * `liquid`, `liquid::testnet`
/// * `arkade`, `arkade::mutinynet` — the public operators — or
///   `arkade::<host[:port]>`, any other operator (loopback hosts use
///   `http`, everything else `https`)
/// * `bitcoin`, `bitcoin::mutinynet`, `bitcoin::regtest`
/// * `rootstock`, `rootstock::testnet`
/// * `lightning`, or `lightning::signet`, `lightning::mutinynet`,
///   `lightning::regtest` — Lightning on a test chain
///
/// The same string is used on the wire, in route announcements and on
/// the command line.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct NetworkId(pub String);

impl NetworkId {
    /// Parse and validate a network spec.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let (kind, param) = match spec.split_once("::") {
            Some((kind, param)) => (kind, Some(param)),
            None => (spec, None),
        };
        let allowed: &[&str] = match kind {
            "cashu" => {
                let host = param.filter(|host| !host.is_empty()).ok_or(
                    "network 'cashu' requires a host, e.g. cashu::mint.example.com or \
                     cashu::localhost:3338",
                )?;
                if host.contains("://") {
                    return Err(
                        "network 'cashu' must not include a scheme; use cashu::<host>".to_string(),
                    );
                }
                return Ok(Self(spec.to_string()));
            }
            "fedimint" => {
                param
                    .filter(|invite| !invite.is_empty())
                    .ok_or("network 'fedimint' requires an invite code, e.g. fedimint::fed1q...")?;
                return Ok(Self(spec.to_string()));
            }
            "arkade" => {
                if param.is_some_and(|host| host.is_empty() || host.contains("://")) {
                    return Err(
                        "network 'arkade' takes 'mutinynet' or an operator host without \
                         scheme, e.g. arkade::127.0.0.1:7070"
                            .to_string(),
                    );
                }
                return Ok(Self(spec.to_string()));
            }
            "liquid" | "rootstock" => &["testnet"],
            "bitcoin" => &["mutinynet", "regtest"],
            "lightning" => &["signet", "mutinynet", "regtest"],
            other => return Err(format!("unsupported network kind '{other}'")),
        };
        match param {
            None => Ok(Self(spec.to_string())),
            Some(param) if allowed.contains(&param) => Ok(Self(spec.to_string())),
            Some(param) => Err(format!(
                "network '{kind}' accepts {}, got '{param}'",
                if allowed.is_empty() {
                    "no parameter".to_string()
                } else {
                    format!("no parameter or '{}'", allowed.join("', '"))
                }
            )),
        }
    }

    /// The part before `::`: `cashu`, `liquid`, ...
    pub fn kind(&self) -> &str {
        self.0.split_once("::").map_or(&self.0, |(kind, _)| kind)
    }

    /// The part after `::`, if any.
    pub fn param(&self) -> Option<&str> {
        self.0.split_once("::").map(|(_, param)| param)
    }

    /// `https://<param>` for a network addressed by host (a cashu mint,
    /// an arkade operator), `http` for loopback hosts.
    pub fn host_url(&self) -> Result<String, String> {
        let host = self
            .param()
            .filter(|host| !host.is_empty())
            .ok_or_else(|| format!("{self} names no host"))?;
        let scheme = if is_loopback_host(host) {
            "http"
        } else {
            "https"
        };
        Ok(format!("{scheme}://{host}"))
    }

    /// Default safety margin of an HTLC received on this network: how
    /// long a router needs, after learning the preimage at the last
    /// moment (its outgoing HTLC's expiry), to get its claim of the
    /// incoming HTLC through before that one can be refunded. Each hop
    /// adds the margin of its incoming network, so expiries grow from
    /// the payee back to the payer.
    pub fn default_incoming_delta(&self) -> u64 {
        const MINUTE: u64 = 60;
        match self.kind() {
            // One request to the mint, timed by the mint's clock: covers
            // clock skew and short downtime.
            "cashu" => 5 * MINUTE,
            // Contracts expire after a number of bitcoin blocks, which
            // can come early: about four blocks of margin.
            "fedimint" => 40 * MINUTE,
            // An offchain claim co-signed by the operator, timed by the
            // chain tip's time.
            "arkade" => 20 * MINUTE,
            // The claim must confirm on-chain before a refund can.
            "bitcoin" => 60 * MINUTE,
            // Regular one-minute blocks.
            "liquid" => 10 * MINUTE,
            // ~30s blocks, with some variance.
            "rootstock" => 20 * MINUTE,
            // The hold invoice must be settled before its CLTV, counted
            // in bitcoin blocks, runs out.
            "lightning" => 60 * MINUTE,
            // Unknown kinds: the most cautious of the above.
            _ => 60 * MINUTE,
        }
    }
}

/// `localhost`, `127.0.0.1` or `::1`, with or without port and brackets.
fn is_loopback_host(host: &str) -> bool {
    let host = if let Some(rest) = host.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest)
    } else if host == "::1" || host.starts_with("::1:") {
        "::1"
    } else {
        host.split(':').next().unwrap_or(host)
    };
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

impl fmt::Display for NetworkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// What a payer locks an HTLC to on one network: who can claim it, with
/// one variant per network kind.
///
/// `L` is what a Lightning target carries: a BOLT11 hold invoice, or
/// [`Infallible`] where Lightning cannot be paid (see
/// [`crate::offline::GatewayDestination`]).
///
/// Crosses the wire as `{"network": <id>, "target": {<kind of key>: <key>}}`:
/// `{"XOnlyPubKey": <hex>}`, `{"PubKey": <hex>}` or
/// `{"LightningInvoice": <BOLT11>}`, which must be the network's kind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InvoiceTarget<L = String> {
    Cashu {
        network: NetworkId,
        target: XOnlyPubKey,
    },
    Fedimint {
        network: NetworkId,
        target: XOnlyPubKey,
    },
    Arkade {
        network: NetworkId,
        target: XOnlyPubKey,
    },
    Bitcoin {
        network: NetworkId,
        target: XOnlyPubKey,
    },
    Liquid {
        network: NetworkId,
        target: PubKey,
    },
    Rootstock {
        network: NetworkId,
        target: PubKey,
    },
    Lightning {
        network: NetworkId,
        invoice: L,
    },
}

/// What an [`InvoiceTarget::Lightning`] carries.
pub trait LightningTarget: Sized {
    /// The target paying `invoice` on `network`.
    fn from_invoice(network: &NetworkId, invoice: String) -> Result<Self, String>;

    fn invoice(&self) -> &str;
}

impl LightningTarget for String {
    fn from_invoice(_: &NetworkId, invoice: String) -> Result<Self, String> {
        Ok(invoice)
    }

    fn invoice(&self) -> &str {
        self
    }
}

/// No Lightning target at all: hold invoices need the payee online.
impl LightningTarget for Infallible {
    fn from_invoice(network: &NetworkId, _: String) -> Result<Self, String> {
        Err(format!(
            "{network} cannot be paid to an offline payee: its hold invoices need it online"
        ))
    }

    fn invoice(&self) -> &str {
        match *self {}
    }
}

impl<L: LightningTarget> InvoiceTarget<L> {
    /// The target on `network` that `target` names: a claim key in hex,
    /// or a BOLT11 invoice, as the network's kind says.
    pub fn parse(network: NetworkId, target: &str) -> Result<Self, String> {
        let x_only = || {
            target
                .parse::<XOnlyPubKey>()
                .map_err(|_| format!("{network} pays to an x-only key"))
        };
        let full = || {
            target
                .parse::<PubKey>()
                .map_err(|_| format!("{network} pays to a full public key"))
        };
        Ok(match network.kind() {
            "cashu" => Self::Cashu {
                target: x_only()?,
                network,
            },
            "fedimint" => Self::Fedimint {
                target: x_only()?,
                network,
            },
            "arkade" => Self::Arkade {
                target: x_only()?,
                network,
            },
            "bitcoin" => Self::Bitcoin {
                target: x_only()?,
                network,
            },
            "liquid" => Self::Liquid {
                target: full()?,
                network,
            },
            "rootstock" => Self::Rootstock {
                target: full()?,
                network,
            },
            "lightning" => Self::Lightning {
                invoice: L::from_invoice(&network, target.to_string())?,
                network,
            },
            _ => return Err(format!("{network} is not a network kind Cassis supports")),
        })
    }

    /// The kind of key the target is, as it is tagged on the wire.
    fn tag(&self) -> &'static str {
        match self {
            Self::Cashu { .. }
            | Self::Fedimint { .. }
            | Self::Arkade { .. }
            | Self::Bitcoin { .. } => "XOnlyPubKey",
            Self::Liquid { .. } | Self::Rootstock { .. } => "PubKey",
            Self::Lightning { .. } => "LightningInvoice",
        }
    }

    /// The target [`InvoiceTarget::parse`] reads back.
    pub fn target_string(&self) -> String {
        match self {
            Self::Cashu { target, .. }
            | Self::Fedimint { target, .. }
            | Self::Arkade { target, .. }
            | Self::Bitcoin { target, .. } => target.to_hex(),
            Self::Liquid { target, .. } | Self::Rootstock { target, .. } => target.to_hex(),
            Self::Lightning { invoice, .. } => invoice.invoice().to_string(),
        }
    }
}

impl<L> InvoiceTarget<L> {
    pub fn network(&self) -> &NetworkId {
        match self {
            Self::Cashu { network, .. }
            | Self::Fedimint { network, .. }
            | Self::Arkade { network, .. }
            | Self::Bitcoin { network, .. }
            | Self::Liquid { network, .. }
            | Self::Rootstock { network, .. }
            | Self::Lightning { network, .. } => network,
        }
    }

    /// This target, a Lightning one replaced by `lightning`.
    fn map_lightning<M, E>(
        self,
        lightning: impl FnOnce(NetworkId, L) -> Result<InvoiceTarget<M>, E>,
    ) -> Result<InvoiceTarget<M>, E> {
        Ok(match self {
            Self::Cashu { network, target } => InvoiceTarget::Cashu { network, target },
            Self::Fedimint { network, target } => InvoiceTarget::Fedimint { network, target },
            Self::Arkade { network, target } => InvoiceTarget::Arkade { network, target },
            Self::Bitcoin { network, target } => InvoiceTarget::Bitcoin { network, target },
            Self::Liquid { network, target } => InvoiceTarget::Liquid { network, target },
            Self::Rootstock { network, target } => InvoiceTarget::Rootstock { network, target },
            Self::Lightning { network, invoice } => lightning(network, invoice)?,
        })
    }

    /// The destination this target is, or the network and invoice of a
    /// Lightning one.
    pub fn destination(self) -> Result<GatewayDestination, (NetworkId, L)> {
        self.map_lightning(|network, invoice| Err((network, invoice)))
    }
}

impl From<GatewayDestination> for InvoiceTarget {
    fn from(destination: GatewayDestination) -> Self {
        let Ok(target) = destination.map_lightning::<String, Infallible>(|_, never| match never {});
        target
    }
}

impl<L: LightningTarget> InvoiceTarget<L> {
    /// The wire `target`: a one-entry map from [`InvoiceTarget::tag`] to
    /// [`InvoiceTarget::target_string`].
    pub(crate) fn tagged_target(&self) -> [(&'static str, String); 1] {
        [(self.tag(), self.target_string())]
    }

    /// Read back what [`InvoiceTarget::tagged_target`] wrote.
    pub(crate) fn from_tagged(
        network: NetworkId,
        target: BTreeMap<String, String>,
    ) -> Result<Self, String> {
        let mut entries = target.into_iter();
        let (Some((tag, target)), None) = (entries.next(), entries.next()) else {
            return Err("a target names exactly one kind of key".into());
        };
        let parsed = Self::parse(network, &target)?;
        if parsed.tag() != tag {
            return Err(format!(
                "{} pays to a {}, not a {tag}",
                parsed.network(),
                parsed.tag()
            ));
        }
        Ok(parsed)
    }
}

impl<L: LightningTarget> Serialize for InvoiceTarget<L> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut target = serializer.serialize_struct("InvoiceTarget", 2)?;
        target.serialize_field("network", self.network())?;
        target.serialize_field("target", &BTreeMap::from(self.tagged_target()))?;
        target.end()
    }
}

impl<'de, L: LightningTarget> Deserialize<'de> for InvoiceTarget<L> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor<L>(PhantomData<L>);

        impl<'de, L: LightningTarget> de::Visitor<'de> for Visitor<L> {
            type Value = InvoiceTarget<L>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a network and its target")
            }

            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let network = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let target = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                InvoiceTarget::from_tagged(network, target).map_err(de::Error::custom)
            }

            fn visit_map<A: de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut network = None;
                let mut target = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "network" => network = Some(map.next_value()?),
                        "target" => target = Some(map.next_value()?),
                        _ => {
                            map.next_value::<de::IgnoredAny>()?;
                        }
                    }
                }
                let network = network.ok_or_else(|| de::Error::missing_field("network"))?;
                let target = target.ok_or_else(|| de::Error::missing_field("target"))?;
                InvoiceTarget::from_tagged(network, target).map_err(de::Error::custom)
            }
        }

        deserializer.deserialize_struct(
            "InvoiceTarget",
            &["network", "target"],
            Visitor(PhantomData),
        )
    }
}

/// Network-specific handle to a funded HTLC: who can claim it, in this
/// network's kind of [`InvoiceTarget`], and what the receiver needs, on
/// top of the common [`Htlc`] fields, to find, verify and claim it, and
/// what the sender needs to watch and refund it. Anything derivable
/// from the common fields (payment hash, amount) is left out so it
/// cannot disagree with them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HtlcDescriptor {
    /// NUT-14 HTLC-locked ecash proofs, one base64-encoded JSON proof
    /// per element.
    Cashu {
        proofs_b64: Vec<String>,
        target: XOnlyPubKey,
    },
    /// P2WSH lockup output on Liquid (see `cassis-liquid`). Refund opens
    /// at an absolute block height.
    Liquid {
        lockup_txid: String,
        lockup_vout: u32,
        refund_pubkey: PubKey,
        refund_locktime: u32,
        target: PubKey,
    },
    /// Arkade VHTLC (see `cassis-arkade`). The receiver is the target,
    /// the server is the operator both parties use.
    Arkade {
        sender: XOnlyPubKey,
        refund_locktime: u32,
        unilateral_claim_delay: u32,
        unilateral_refund_delay: u32,
        unilateral_refund_without_receiver_delay: u32,
        target: XOnlyPubKey,
    },
    /// P2TR lockup output on Bitcoin (see `cassis-bitcoin`). Refund
    /// opens at an absolute unix timestamp.
    Bitcoin {
        lockup_txid: String,
        lockup_vout: u32,
        refund_pubkey: XOnlyPubKey,
        refund_locktime: u32,
        target: XOnlyPubKey,
    },
    /// EtherSwap lock on Rootstock (see `cassis-rootstock`). Refund opens
    /// at a block height.
    Rootstock {
        amount_wei: u128,
        refund_address: String,
        timelock: u64,
        target: PubKey,
    },
    /// Fedimint LNv2 direct HTLC: the funded `OutgoingContract`
    /// (consensus JSON) and where it was funded.
    Fedimint {
        funding_txid: String,
        funding_out_idx: u64,
        contract: String,
        target: XOnlyPubKey,
    },
    /// A payment of the `target` BOLT11 hold invoice; LND tracks it by
    /// hash.
    Lightning { target: String },
}

impl HtlcDescriptor {
    /// Whether `target` can claim it, on whichever network.
    pub fn pays<L: LightningTarget>(&self, target: &InvoiceTarget<L>) -> bool {
        match (self, target) {
            (Self::Cashu { target, .. }, InvoiceTarget::Cashu { target: claim, .. })
            | (Self::Fedimint { target, .. }, InvoiceTarget::Fedimint { target: claim, .. })
            | (Self::Arkade { target, .. }, InvoiceTarget::Arkade { target: claim, .. })
            | (Self::Bitcoin { target, .. }, InvoiceTarget::Bitcoin { target: claim, .. }) => {
                target == claim
            }
            (Self::Liquid { target, .. }, InvoiceTarget::Liquid { target: claim, .. })
            | (Self::Rootstock { target, .. }, InvoiceTarget::Rootstock { target: claim, .. }) => {
                target == claim
            }
            (Self::Lightning { target }, InvoiceTarget::Lightning { invoice, .. }) => {
                target == invoice.invoice()
            }
            _ => false,
        }
    }
}

/// One HTLC on one network, as both parties see it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Htlc {
    pub payment_hash: Bytes32,
    /// Agreed amount. Networks with coarser units lock at least this
    /// much (rounded up).
    pub amount_msat: u64,
    /// Unix seconds before which the sender cannot refund.
    pub expiry: u64,
    pub descriptor: HtlcDescriptor,
}

/// Observed state of an outgoing HTLC.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OutgoingState {
    /// Funded and neither claimed nor refunded yet.
    Pending,
    /// The receiver claimed it, revealing this preimage.
    Claimed(Bytes32),
    /// The funds are back with the sender (refunded or failed).
    Refunded,
}

/// Error returned by every [`Network`] operation.
#[derive(thiserror::Error, Debug)]
pub enum NetworkError {
    /// The request or the HTLC is wrong; retrying will not help.
    #[error("invalid: {0}")]
    Invalid(String),
    /// The network or a backend service failed; retrying may help.
    #[error("network: {0}")]
    Network(String),
    /// Valid, but not usable yet (an unconfirmed lockup, say): ask
    /// again later.
    #[error("not yet: {0}")]
    NotYet(String),
}

impl NetworkError {
    pub fn invalid(message: impl fmt::Display) -> Self {
        Self::Invalid(message.to_string())
    }

    pub fn network(message: impl fmt::Display) -> Self {
        Self::Network(message.to_string())
    }

    pub fn not_yet(message: impl fmt::Display) -> Self {
        Self::NotYet(message.to_string())
    }
}

/// The one trait every network implements.
///
/// Callers (the node) guarantee before each call: amounts are
/// positive, expiries are in the future when creating, preimages hash
/// to the payment hash when claiming, and refunds are only attempted
/// once the expiry has passed. Adapters perform every network-specific
/// check listed on each method, and nothing else.
#[async_trait]
pub trait Network: Send + Sync {
    fn id(&self) -> NetworkId;

    /// Seconds this network needs to get a claim through once the
    /// preimage is known. A router requires at least this much between
    /// the expiry of its outgoing HTLC and the expiry of the incoming
    /// one it claims on this network. Defaults to
    /// [`NetworkId::default_incoming_delta`]; see
    /// [`with_incoming_delta`] to change it.
    fn incoming_delta_secs(&self) -> u64 {
        self.id().default_incoming_delta()
    }

    /// What a payer must lock an HTLC for `payment_hash` to so that this
    /// node can claim it. Idempotent per payment hash. Networks whose
    /// target is a claim key return it without side effects; Lightning
    /// registers a hold invoice for `amount_msat` valid until `expiry`.
    async fn receive_target(
        &self,
        payment_hash: Bytes32,
        amount_msat: u64,
        expiry: u64,
    ) -> Result<InvoiceTarget, NetworkError>;

    /// Release whatever [`Network::receive_target`] set up for a payment
    /// that will not be funded. No-op for claim-key networks.
    async fn cancel_receive(&self, payment_hash: Bytes32) -> Result<(), NetworkError>;

    /// Check that `htlc` is a real HTLC this node can claim. Every
    /// adapter checks, in this order:
    /// 1. the descriptor is this network's kind and well formed;
    /// 2. the HTLC pays the descriptor's target, and that target is this
    ///    node's;
    /// 3. it is locked to `htlc.payment_hash`;
    /// 4. it locks at least `htlc.amount_msat`;
    /// 5. its refund cannot happen before `htlc.expiry`;
    /// 6. it is funded, final enough to rely on, and not yet spent.
    ///
    /// [`NetworkError::NotYet`] means the HTLC is right but not final
    /// enough yet (e.g. unconfirmed): callers wait and verify again.
    async fn verify_incoming_htlc(&self, htlc: &Htlc) -> Result<(), NetworkError>;

    /// [`Network::verify_incoming_htlc`] for an HTLC paying any
    /// target, not only this node's: every check but whose
    /// target it is. A preimage server runs it before revealing the
    /// preimage of an HTLC its payee will claim later.
    async fn verify_htlc(&self, htlc: &Htlc) -> Result<(), NetworkError> {
        let _ = htlc;
        Err(NetworkError::invalid(format!(
            "{} cannot verify HTLCs paying other keys",
            self.id()
        )))
    }

    /// Claim a verified incoming HTLC by revealing `preimage`.
    async fn claim_incoming_htlc(&self, htlc: &Htlc, preimage: Bytes32)
        -> Result<(), NetworkError>;

    /// Lock at least `amount_msat` to `target` behind `payment_hash`,
    /// refundable no earlier than `expiry`. Returns once the receiver
    /// can verify it with [`Network::verify_incoming_htlc`].
    async fn create_outgoing_htlc(
        &self,
        payment_hash: Bytes32,
        amount_msat: u64,
        expiry: u64,
        target: &InvoiceTarget,
    ) -> Result<HtlcDescriptor, NetworkError>;

    /// One-shot look at an outgoing HTLC: still pending, claimed (with
    /// the revealed preimage) or refunded.
    async fn check_outgoing_htlc(&self, htlc: &Htlc) -> Result<OutgoingState, NetworkError>;

    /// Take an expired outgoing HTLC back. Called only after
    /// `htlc.expiry`; returns an error while the network does not allow
    /// the refund yet.
    async fn refund_outgoing_htlc(&self, htlc: &Htlc) -> Result<(), NetworkError>;

    /// Whether this node can fund an outgoing HTLC of `amount_msat`
    /// right now (balance plus any fees the lock costs).
    async fn can_send(&self, amount_msat: u64) -> Result<(), NetworkError>;

    /// Whether this node can afford to claim an incoming HTLC of
    /// `amount_msat` (e.g. gas paid from its own balance).
    async fn can_receive(&self, amount_msat: u64) -> Result<(), NetworkError>;

    /// How often a long-running node should call [`Network::maintain`];
    /// `None` when this network's wallet needs no upkeep.
    fn maintenance_interval(&self) -> Option<Duration> {
        None
    }

    /// Upkeep that keeps the wallet usable while the node runs, outside
    /// of any payment (e.g. refreshing coins before they expire).
    async fn maintain(&self) -> Result<(), NetworkError> {
        Ok(())
    }
}

/// `network` with a safety margin of `secs` instead of its own (see
/// [`Network::incoming_delta_secs`]), e.g. to test expiries without
/// waiting for the real margins.
pub fn with_incoming_delta(network: Arc<dyn Network>, secs: u64) -> Arc<dyn Network> {
    Arc::new(Overridden {
        network,
        incoming_delta_secs: secs,
    })
}

/// A network with its safety margin replaced.
struct Overridden {
    network: Arc<dyn Network>,
    incoming_delta_secs: u64,
}

#[async_trait]
impl Network for Overridden {
    fn id(&self) -> NetworkId {
        self.network.id()
    }

    fn incoming_delta_secs(&self) -> u64 {
        self.incoming_delta_secs
    }

    async fn receive_target(
        &self,
        payment_hash: Bytes32,
        amount_msat: u64,
        expiry: u64,
    ) -> Result<InvoiceTarget, NetworkError> {
        self.network
            .receive_target(payment_hash, amount_msat, expiry)
            .await
    }

    async fn cancel_receive(&self, payment_hash: Bytes32) -> Result<(), NetworkError> {
        self.network.cancel_receive(payment_hash).await
    }

    async fn verify_incoming_htlc(&self, htlc: &Htlc) -> Result<(), NetworkError> {
        self.network.verify_incoming_htlc(htlc).await
    }

    async fn verify_htlc(&self, htlc: &Htlc) -> Result<(), NetworkError> {
        self.network.verify_htlc(htlc).await
    }

    async fn claim_incoming_htlc(
        &self,
        htlc: &Htlc,
        preimage: Bytes32,
    ) -> Result<(), NetworkError> {
        self.network.claim_incoming_htlc(htlc, preimage).await
    }

    async fn create_outgoing_htlc(
        &self,
        payment_hash: Bytes32,
        amount_msat: u64,
        expiry: u64,
        target: &InvoiceTarget,
    ) -> Result<HtlcDescriptor, NetworkError> {
        self.network
            .create_outgoing_htlc(payment_hash, amount_msat, expiry, target)
            .await
    }

    async fn check_outgoing_htlc(&self, htlc: &Htlc) -> Result<OutgoingState, NetworkError> {
        self.network.check_outgoing_htlc(htlc).await
    }

    async fn refund_outgoing_htlc(&self, htlc: &Htlc) -> Result<(), NetworkError> {
        self.network.refund_outgoing_htlc(htlc).await
    }

    async fn can_send(&self, amount_msat: u64) -> Result<(), NetworkError> {
        self.network.can_send(amount_msat).await
    }

    async fn can_receive(&self, amount_msat: u64) -> Result<(), NetworkError> {
        self.network.can_receive(amount_msat).await
    }

    fn maintenance_interval(&self) -> Option<Duration> {
        self.network.maintenance_interval()
    }

    async fn maintain(&self) -> Result<(), NetworkError> {
        self.network.maintain().await
    }
}

/// Build the per-network child span an adapter enters around its logs.
///
/// `parent` is the caller's node span (the one carrying `node`), so a
/// log inside it renders as `[alice/rootstock::testnet]`. Passed
/// explicitly because adapter methods run on unrelated tasks.
pub fn network_span(parent: &tracing::Span, network_id: &NetworkId) -> tracing::Span {
    tracing::info_span!(parent: parent, "network", network = %network_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_every_kind() {
        for spec in [
            "cashu::mint.example.com",
            "cashu::localhost:3338",
            "fedimint::fed1qabc",
            "liquid",
            "liquid::testnet",
            "arkade",
            "arkade::mutinynet",
            "arkade::127.0.0.1:7070",
            "bitcoin",
            "bitcoin::mutinynet",
            "bitcoin::regtest",
            "rootstock",
            "rootstock::testnet",
            "lightning",
            "lightning::mutinynet",
        ] {
            assert_eq!(NetworkId::parse(spec).unwrap().0, spec);
        }
    }

    #[test]
    fn rejects_bad_specs() {
        for spec in [
            "cashu",
            "cashu::",
            "cashu::https://mint.example.com",
            "cashu:localhost:3338",
            "fedimint::",
            "liquid::foo",
            "arkade::",
            "arkade::https://operator.example.com",
            "bitcoin::testnet",
            "lightning::testnet",
            "mystery",
        ] {
            assert!(NetworkId::parse(spec).is_err(), "{spec} should be rejected");
        }
    }

    #[test]
    fn kind_and_param() {
        let id = NetworkId::parse("cashu::localhost:3338").unwrap();
        assert_eq!(id.kind(), "cashu");
        assert_eq!(id.param(), Some("localhost:3338"));
        assert_eq!(NetworkId::parse("liquid").unwrap().param(), None);
    }

    #[test]
    fn host_url_scheme_follows_the_host() {
        let url = |id: &str| NetworkId(id.into()).host_url().unwrap();
        assert_eq!(url("cashu::mint.example.com"), "https://mint.example.com");
        assert_eq!(
            url("cashu::mint.example.com:3338"),
            "https://mint.example.com:3338"
        );
        assert_eq!(url("arkade::localhost:7070"), "http://localhost:7070");
        assert_eq!(url("cashu::127.0.0.1"), "http://127.0.0.1");
        assert_eq!(url("cashu::::1"), "http://::1");
        assert_eq!(url("cashu::[::1]:3338"), "http://[::1]:3338");
        assert!(NetworkId("liquid".into()).host_url().is_err());
    }

    #[test]
    fn default_incoming_delta_uses_the_kind() {
        let delta = |id: &str| NetworkId(id.into()).default_incoming_delta() / 60;
        assert_eq!(delta("cashu::localhost"), 5);
        assert_eq!(delta("fedimint::fed1q"), 40);
        assert_eq!(delta("arkade::mutinynet"), 20);
        assert_eq!(delta("bitcoin"), 60);
        assert_eq!(delta("liquid::testnet"), 10);
        assert_eq!(delta("rootstock"), 20);
        assert_eq!(delta("lightning"), 60);
    }
}
