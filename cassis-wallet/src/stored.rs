//! How wire types are stored: one `#[orangedb::embed]` mirror for each,
//! with conversions both ways. The wire types change with the protocol;
//! these change only with a migration. Shared by the schemas of the
//! wallet, the router and the gateway.

use cassis_core::network::{Htlc, HtlcDescriptor, InvoiceTarget, LightningTarget};
use cassis_core::offline::{
    GatewayDestination, PayeeGatewayReceiveAuthorization, PayeeGatewayReceiveAuthorizationKind,
    Signature,
};
use cassis_core::protocol::{FailReason, InvoiceNetwork, Metadata};
use cassis_core::{Bytes32, Ed25519PubKey, NetworkId, PubKey, StarknetAddress, XOnlyPubKey};
use iroh_base::PublicKey;
use std::convert::Infallible;

pub mod v1;

/// A compressed secp256k1 public key: its parity byte and X coordinate.
/// Stored as exactly 33 bytes, since serde and orangedb know arrays only
/// up to 32.
#[orangedb::embed]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoredPubKey {
    pub parity: u8,
    pub x: [u8; 32],
}

impl From<&PubKey> for StoredPubKey {
    fn from(key: &PubKey) -> Self {
        let bytes = key.as_bytes();
        Self {
            parity: bytes[0],
            x: bytes[1..].try_into().expect("a key after its parity byte"),
        }
    }
}

impl TryFrom<&StoredPubKey> for PubKey {
    type Error = String;

    fn try_from(key: &StoredPubKey) -> Result<Self, String> {
        let mut bytes = [0u8; 33];
        bytes[0] = key.parity;
        bytes[1..].copy_from_slice(&key.x);
        PubKey::from_bytes(bytes).map_err(|_| corrupt("public key"))
    }
}

/// An [`HtlcDescriptor`].
#[orangedb::embed]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoredDescriptor {
    Cashu {
        proofs_b64: Vec<String>,
        target: [u8; 32],
    },
    Liquid {
        lockup_txid: [u8; 32],
        lockup_vout: u32,
        refund_pubkey: StoredPubKey,
        refund_locktime: u32,
        target: StoredPubKey,
    },
    Arkade {
        sender: [u8; 32],
        refund_locktime: u32,
        unilateral_claim_delay: u32,
        unilateral_refund_delay: u32,
        unilateral_refund_without_receiver_delay: u32,
        target: [u8; 32],
    },
    Bitcoin {
        lockup_txid: [u8; 32],
        lockup_vout: u32,
        refund_pubkey: [u8; 32],
        refund_locktime: u32,
        target: [u8; 32],
    },
    Rootstock {
        amount_wei: u128,
        refund_address: String,
        timelock: u64,
        target: StoredPubKey,
    },
    Fedimint {
        funding_txid: [u8; 32],
        funding_out_idx: u64,
        contract: String,
        target: [u8; 32],
    },
    Lightning {
        target: String,
    },
    Citrea {
        amount_wei: u128,
        refund_address: String,
        sequence: u64,
        refund_after: u64,
        target: StoredPubKey,
    },
    StarknetWbtc {
        amount_sat: u64,
        refund_address: [u8; 32],
        sequence: u64,
        refund_after: u64,
        target: [u8; 32],
    },
    SolanaWbtc {
        amount_sat: u64,
        refund_address: [u8; 32],
        sequence: u64,
        refund_after: u64,
        target: [u8; 32],
    },
}

/// An [`Htlc`].
#[orangedb::embed]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredHtlc {
    pub payment_hash: [u8; 32],
    pub amount_msat: u64,
    pub expiry: u64,
    pub descriptor: StoredDescriptor,
}

/// An [`InvoiceNetwork`].
#[orangedb::embed]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredInvoiceNetwork {
    pub target: StoredInvoiceTarget,
    pub incoming_delta_secs: Option<u64>,
}

/// An [`InvoiceTarget`]: `L` is what a Lightning target carries, as
/// stored (see [`StoredLightning`]).
#[orangedb::embed]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoredInvoiceTarget<L = String> {
    Cashu {
        network: String,
        target: [u8; 32],
    },
    Fedimint {
        network: String,
        target: [u8; 32],
    },
    Arkade {
        network: String,
        target: [u8; 32],
    },
    Bitcoin {
        network: String,
        target: [u8; 32],
    },
    Liquid {
        network: String,
        target: StoredPubKey,
    },
    Rootstock {
        network: String,
        target: StoredPubKey,
    },
    Lightning {
        network: String,
        invoice: L,
    },
    Citrea {
        network: String,
        target: StoredPubKey,
    },
    StarknetWbtc {
        network: String,
        target: [u8; 32],
    },
    SolanaWbtc {
        network: String,
        target: [u8; 32],
    },
}

/// A [`GatewayDestination`]: an invoice target without Lightning.
pub type StoredGatewayDestination = StoredInvoiceTarget<StoredNever>;

/// Stored where nothing is: what [`std::convert::Infallible`] is
/// stored as, which orangedb has no fingerprint for.
#[orangedb::embed]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoredNever {}

/// What a core [`InvoiceTarget`] carries on Lightning, and what stores it.
pub trait StoredLightning: LightningTarget {
    type Stored;

    fn store(&self) -> Self::Stored;

    fn load(stored: &Self::Stored) -> Self;
}

impl StoredLightning for String {
    type Stored = String;

    fn store(&self) -> String {
        self.clone()
    }

    fn load(stored: &String) -> Self {
        stored.clone()
    }
}

impl StoredLightning for Infallible {
    type Stored = StoredNever;

    fn store(&self) -> StoredNever {
        match *self {}
    }

    fn load(stored: &StoredNever) -> Self {
        match *stored {}
    }
}

/// An [`PayeeGatewayReceiveAuthorizationKind`].
#[orangedb::embed]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoredPayeeGatewayReceiveAuthorizationKind {
    Single,
    Standing,
}

/// A [`PayeeGatewayReceiveAuthorization`].
#[orangedb::embed]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredPayeeGatewayReceiveAuthorization {
    pub kind: StoredPayeeGatewayReceiveAuthorizationKind,
    pub payee: [u8; 32],
    pub gateway: [u8; 32],
    pub preimage_server: [u8; 32],
    pub description: Option<String>,
    pub valid_from: u64,
    pub valid_until: u64,
    pub min_amount_msat: u64,
    pub max_amount_msat: u64,
    pub min_final_timeout_secs: u64,
    pub destinations: Vec<StoredGatewayDestination>,
    /// 64 bytes.
    pub signature: Vec<u8>,
}

/// A stored value that no longer reads as its wire type.
fn corrupt(what: &str) -> String {
    format!("stored {what} is invalid")
}

fn x_only(bytes: [u8; 32]) -> Result<XOnlyPubKey, String> {
    XOnlyPubKey::from_bytes(bytes).map_err(|_| corrupt("x-only key"))
}

fn starknet_address(bytes: [u8; 32]) -> Result<StarknetAddress, String> {
    StarknetAddress::from_bytes(bytes).map_err(|_| corrupt("Starknet address"))
}

pub fn endpoint_key(bytes: &[u8; 32]) -> Result<PublicKey, String> {
    PublicKey::from_bytes(bytes).map_err(|_| corrupt("endpoint key"))
}

impl<L: StoredLightning> From<&InvoiceTarget<L>> for StoredInvoiceTarget<L::Stored> {
    fn from(target: &InvoiceTarget<L>) -> Self {
        match target {
            InvoiceTarget::Cashu { network, target } => Self::Cashu {
                network: network.0.clone(),
                target: target.0,
            },
            InvoiceTarget::Fedimint { network, target } => Self::Fedimint {
                network: network.0.clone(),
                target: target.0,
            },
            InvoiceTarget::Arkade { network, target } => Self::Arkade {
                network: network.0.clone(),
                target: target.0,
            },
            InvoiceTarget::Bitcoin { network, target } => Self::Bitcoin {
                network: network.0.clone(),
                target: target.0,
            },
            InvoiceTarget::Liquid { network, target } => Self::Liquid {
                network: network.0.clone(),
                target: target.into(),
            },
            InvoiceTarget::Rootstock { network, target } => Self::Rootstock {
                network: network.0.clone(),
                target: target.into(),
            },
            InvoiceTarget::Lightning { network, invoice } => Self::Lightning {
                network: network.0.clone(),
                invoice: invoice.store(),
            },
            InvoiceTarget::Citrea { network, target } => Self::Citrea {
                network: network.0.clone(),
                target: target.into(),
            },
            InvoiceTarget::StarknetWbtc { network, target } => Self::StarknetWbtc {
                network: network.0.clone(),
                target: target.0,
            },
            InvoiceTarget::SolanaWbtc { network, target } => Self::SolanaWbtc {
                network: network.0.clone(),
                target: target.0,
            },
        }
    }
}

impl<L: StoredLightning> TryFrom<&StoredInvoiceTarget<L::Stored>> for InvoiceTarget<L> {
    type Error = String;

    fn try_from(target: &StoredInvoiceTarget<L::Stored>) -> Result<Self, String> {
        Ok(match target {
            StoredInvoiceTarget::Cashu { network, target } => Self::Cashu {
                network: NetworkId(network.clone()),
                target: x_only(*target)?,
            },
            StoredInvoiceTarget::Fedimint { network, target } => Self::Fedimint {
                network: NetworkId(network.clone()),
                target: x_only(*target)?,
            },
            StoredInvoiceTarget::Arkade { network, target } => Self::Arkade {
                network: NetworkId(network.clone()),
                target: x_only(*target)?,
            },
            StoredInvoiceTarget::Bitcoin { network, target } => Self::Bitcoin {
                network: NetworkId(network.clone()),
                target: x_only(*target)?,
            },
            StoredInvoiceTarget::Liquid { network, target } => Self::Liquid {
                network: NetworkId(network.clone()),
                target: target.try_into()?,
            },
            StoredInvoiceTarget::Rootstock { network, target } => Self::Rootstock {
                network: NetworkId(network.clone()),
                target: target.try_into()?,
            },
            StoredInvoiceTarget::Lightning { network, invoice } => Self::Lightning {
                network: NetworkId(network.clone()),
                invoice: L::load(invoice),
            },
            StoredInvoiceTarget::Citrea { network, target } => Self::Citrea {
                network: NetworkId(network.clone()),
                target: target.try_into()?,
            },
            StoredInvoiceTarget::StarknetWbtc { network, target } => Self::StarknetWbtc {
                network: NetworkId(network.clone()),
                target: starknet_address(*target)?,
            },
            StoredInvoiceTarget::SolanaWbtc { network, target } => Self::SolanaWbtc {
                network: NetworkId(network.clone()),
                target: Ed25519PubKey(*target),
            },
        })
    }
}

impl<L> StoredInvoiceTarget<L> {
    pub fn network(&self) -> &str {
        match self {
            Self::Cashu { network, .. }
            | Self::Fedimint { network, .. }
            | Self::Arkade { network, .. }
            | Self::Bitcoin { network, .. }
            | Self::Liquid { network, .. }
            | Self::Rootstock { network, .. }
            | Self::Lightning { network, .. }
            | Self::Citrea { network, .. }
            | Self::StarknetWbtc { network, .. }
            | Self::SolanaWbtc { network, .. } => network,
        }
    }
}

impl From<&HtlcDescriptor> for StoredDescriptor {
    fn from(descriptor: &HtlcDescriptor) -> Self {
        match descriptor.clone() {
            HtlcDescriptor::Cashu { proofs_b64, target } => Self::Cashu {
                proofs_b64,
                target: target.0,
            },
            HtlcDescriptor::Liquid {
                lockup_txid,
                lockup_vout,
                refund_pubkey,
                refund_locktime,
                target,
            } => Self::Liquid {
                lockup_txid: lockup_txid.0,
                lockup_vout,
                refund_pubkey: (&refund_pubkey).into(),
                refund_locktime,
                target: (&target).into(),
            },
            HtlcDescriptor::Arkade {
                sender,
                refund_locktime,
                unilateral_claim_delay,
                unilateral_refund_delay,
                unilateral_refund_without_receiver_delay,
                target,
            } => Self::Arkade {
                sender: sender.0,
                refund_locktime,
                unilateral_claim_delay,
                unilateral_refund_delay,
                unilateral_refund_without_receiver_delay,
                target: target.0,
            },
            HtlcDescriptor::Bitcoin {
                lockup_txid,
                lockup_vout,
                refund_pubkey,
                refund_locktime,
                target,
            } => Self::Bitcoin {
                lockup_txid: lockup_txid.0,
                lockup_vout,
                refund_pubkey: refund_pubkey.0,
                refund_locktime,
                target: target.0,
            },
            HtlcDescriptor::Rootstock {
                amount_wei,
                refund_address,
                timelock,
                target,
            } => Self::Rootstock {
                amount_wei,
                refund_address,
                timelock,
                target: (&target).into(),
            },
            HtlcDescriptor::Fedimint {
                funding_txid,
                funding_out_idx,
                contract,
                target,
            } => Self::Fedimint {
                funding_txid: funding_txid.0,
                funding_out_idx,
                contract,
                target: target.0,
            },
            HtlcDescriptor::Lightning { target } => Self::Lightning { target },
            HtlcDescriptor::Citrea {
                amount_wei,
                refund_address,
                sequence,
                refund_after,
                target,
            } => Self::Citrea {
                amount_wei,
                refund_address,
                sequence,
                refund_after,
                target: (&target).into(),
            },
            HtlcDescriptor::StarknetWbtc {
                amount_sat,
                refund_address,
                sequence,
                refund_after,
                target,
            } => Self::StarknetWbtc {
                amount_sat,
                refund_address: refund_address.0,
                sequence,
                refund_after,
                target: target.0,
            },
            HtlcDescriptor::SolanaWbtc {
                amount_sat,
                refund_address,
                sequence,
                refund_after,
                target,
            } => Self::SolanaWbtc {
                amount_sat,
                refund_address: refund_address.0,
                sequence,
                refund_after,
                target: target.0,
            },
        }
    }
}

impl TryFrom<&StoredDescriptor> for HtlcDescriptor {
    type Error = String;

    fn try_from(descriptor: &StoredDescriptor) -> Result<Self, String> {
        Ok(match descriptor.clone() {
            StoredDescriptor::Cashu { proofs_b64, target } => Self::Cashu {
                proofs_b64,
                target: x_only(target)?,
            },
            StoredDescriptor::Liquid {
                lockup_txid,
                lockup_vout,
                refund_pubkey,
                refund_locktime,
                target,
            } => Self::Liquid {
                lockup_txid: Bytes32(lockup_txid),
                lockup_vout,
                refund_pubkey: (&refund_pubkey).try_into()?,
                refund_locktime,
                target: (&target).try_into()?,
            },
            StoredDescriptor::Arkade {
                sender,
                refund_locktime,
                unilateral_claim_delay,
                unilateral_refund_delay,
                unilateral_refund_without_receiver_delay,
                target,
            } => Self::Arkade {
                sender: x_only(sender)?,
                refund_locktime,
                unilateral_claim_delay,
                unilateral_refund_delay,
                unilateral_refund_without_receiver_delay,
                target: x_only(target)?,
            },
            StoredDescriptor::Bitcoin {
                lockup_txid,
                lockup_vout,
                refund_pubkey,
                refund_locktime,
                target,
            } => Self::Bitcoin {
                lockup_txid: Bytes32(lockup_txid),
                lockup_vout,
                refund_pubkey: x_only(refund_pubkey)?,
                refund_locktime,
                target: x_only(target)?,
            },
            StoredDescriptor::Rootstock {
                amount_wei,
                refund_address,
                timelock,
                target,
            } => Self::Rootstock {
                amount_wei,
                refund_address,
                timelock,
                target: (&target).try_into()?,
            },
            StoredDescriptor::Fedimint {
                funding_txid,
                funding_out_idx,
                contract,
                target,
            } => Self::Fedimint {
                funding_txid: Bytes32(funding_txid),
                funding_out_idx,
                contract,
                target: x_only(target)?,
            },
            StoredDescriptor::Lightning { target } => Self::Lightning { target },
            StoredDescriptor::Citrea {
                amount_wei,
                refund_address,
                sequence,
                refund_after,
                target,
            } => Self::Citrea {
                amount_wei,
                refund_address,
                sequence,
                refund_after,
                target: (&target).try_into()?,
            },
            StoredDescriptor::StarknetWbtc {
                amount_sat,
                refund_address,
                sequence,
                refund_after,
                target,
            } => Self::StarknetWbtc {
                amount_sat,
                refund_address: starknet_address(refund_address)?,
                sequence,
                refund_after,
                target: starknet_address(target)?,
            },
            StoredDescriptor::SolanaWbtc {
                amount_sat,
                refund_address,
                sequence,
                refund_after,
                target,
            } => Self::SolanaWbtc {
                amount_sat,
                refund_address: Ed25519PubKey(refund_address),
                sequence,
                refund_after,
                target: Ed25519PubKey(target),
            },
        })
    }
}

impl From<&Htlc> for StoredHtlc {
    fn from(htlc: &Htlc) -> Self {
        Self {
            payment_hash: htlc.payment_hash.0,
            amount_msat: htlc.amount_msat,
            expiry: htlc.expiry,
            descriptor: (&htlc.descriptor).into(),
        }
    }
}

impl TryFrom<&StoredHtlc> for Htlc {
    type Error = String;

    fn try_from(htlc: &StoredHtlc) -> Result<Self, String> {
        Ok(Self {
            payment_hash: Bytes32(htlc.payment_hash),
            amount_msat: htlc.amount_msat,
            expiry: htlc.expiry,
            descriptor: (&htlc.descriptor).try_into()?,
        })
    }
}

impl From<&InvoiceNetwork> for StoredInvoiceNetwork {
    fn from(entry: &InvoiceNetwork) -> Self {
        Self {
            target: (&entry.target).into(),
            incoming_delta_secs: entry.incoming_delta_secs,
        }
    }
}

impl TryFrom<&StoredInvoiceNetwork> for InvoiceNetwork {
    type Error = String;

    fn try_from(entry: &StoredInvoiceNetwork) -> Result<Self, String> {
        Ok(Self {
            target: (&entry.target).try_into()?,
            incoming_delta_secs: entry.incoming_delta_secs,
        })
    }
}

impl From<&PayeeGatewayReceiveAuthorization> for StoredPayeeGatewayReceiveAuthorization {
    fn from(authorization: &PayeeGatewayReceiveAuthorization) -> Self {
        Self {
            kind: match authorization.kind {
                PayeeGatewayReceiveAuthorizationKind::Single => {
                    StoredPayeeGatewayReceiveAuthorizationKind::Single
                }
                PayeeGatewayReceiveAuthorizationKind::Standing => {
                    StoredPayeeGatewayReceiveAuthorizationKind::Standing
                }
            },
            payee: *authorization.payee.as_bytes(),
            gateway: *authorization.gateway.as_bytes(),
            preimage_server: *authorization.preimage_server.as_bytes(),
            description: authorization.description.clone(),
            valid_from: authorization.valid_from,
            valid_until: authorization.valid_until,
            min_amount_msat: authorization.min_amount_msat,
            max_amount_msat: authorization.max_amount_msat,
            min_final_timeout_secs: authorization.min_final_timeout_secs,
            destinations: authorization
                .destinations
                .iter()
                .map(StoredGatewayDestination::from)
                .collect(),
            signature: authorization.signature.0.to_vec(),
        }
    }
}

impl TryFrom<&StoredPayeeGatewayReceiveAuthorization> for PayeeGatewayReceiveAuthorization {
    type Error = String;

    fn try_from(authorization: &StoredPayeeGatewayReceiveAuthorization) -> Result<Self, String> {
        Ok(Self {
            kind: match authorization.kind {
                StoredPayeeGatewayReceiveAuthorizationKind::Single => {
                    PayeeGatewayReceiveAuthorizationKind::Single
                }
                StoredPayeeGatewayReceiveAuthorizationKind::Standing => {
                    PayeeGatewayReceiveAuthorizationKind::Standing
                }
            },
            payee: endpoint_key(&authorization.payee)?,
            gateway: endpoint_key(&authorization.gateway)?,
            preimage_server: endpoint_key(&authorization.preimage_server)?,
            description: authorization.description.clone(),
            valid_from: authorization.valid_from,
            valid_until: authorization.valid_until,
            min_amount_msat: authorization.min_amount_msat,
            max_amount_msat: authorization.max_amount_msat,
            min_final_timeout_secs: authorization.min_final_timeout_secs,
            destinations: authorization
                .destinations
                .iter()
                .map(GatewayDestination::try_from)
                .collect::<Result<_, String>>()?,
            signature: signature(&authorization.signature)?,
        })
    }
}

fn signature(bytes: &[u8]) -> Result<Signature, String> {
    Ok(Signature(
        bytes.try_into().map_err(|_| corrupt("signature"))?,
    ))
}

/// [`Metadata`] as stored: its bytes.
pub fn stored_metadata(metadata: &Option<Metadata>) -> Option<Vec<u8>> {
    metadata
        .as_ref()
        .map(|metadata| metadata.as_bytes().to_vec())
}

pub fn metadata(bytes: &Option<Vec<u8>>) -> Result<Option<Metadata>, String> {
    bytes.clone().map(Metadata::new).transpose()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cassis_core::offline::endpoint_public_key;

    #[test]
    fn wire_types_round_trip() {
        let key = ritualistic::SecretKey::from_bytes([4; 32])
            .unwrap()
            .pubkey();
        let htlc = Htlc {
            payment_hash: Bytes32([1; 32]),
            amount_msat: 1000,
            expiry: 2000,
            descriptor: HtlcDescriptor::Liquid {
                lockup_txid: Bytes32([5; 32]),
                lockup_vout: 1,
                refund_pubkey: PubKey::from_x_only(&key).unwrap(),
                refund_locktime: 2,
                target: PubKey::from_x_only(&key).unwrap(),
            },
        };
        assert_eq!(Htlc::try_from(&StoredHtlc::from(&htlc)).unwrap(), htlc);

        let authorization = PayeeGatewayReceiveAuthorization::sign(
            &[1; 32],
            PayeeGatewayReceiveAuthorizationKind::Standing,
            endpoint_public_key(&[2; 32]),
            endpoint_public_key(&[3; 32]),
            Some("coffee".into()),
            1000,
            2000,
            1,
            50_000,
            3600,
            vec![
                GatewayDestination::Cashu {
                    network: NetworkId("cashu::localhost".into()),
                    target: key,
                },
                GatewayDestination::Liquid {
                    network: NetworkId("liquid".into()),
                    target: PubKey::from_x_only(&key).unwrap(),
                },
            ],
        )
        .unwrap();
        let stored = StoredPayeeGatewayReceiveAuthorization::from(&authorization);
        assert_eq!(
            PayeeGatewayReceiveAuthorization::try_from(&stored).unwrap(),
            authorization
        );
    }
}

/// A [`FailReason`]. Variants keep their position: `FundingFailed` is
/// what hops journaled before funding failures were told apart.
#[orangedb::embed]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoredFailReason {
    NetworkUnavailable,
    IncomingRejected,
    ExpiredWhileVerifying,
    FundingFailed,
    InterruptedWhileFunding,
    PreimageNotReceived,
    ClaimFailed,
    InvalidOutgoingTarget,
    JournalingFailed,
    OutgoingFundingRefused(String),
}

impl From<&FailReason> for StoredFailReason {
    fn from(reason: &FailReason) -> Self {
        match reason {
            FailReason::NetworkUnavailable => Self::NetworkUnavailable,
            FailReason::IncomingRejected => Self::IncomingRejected,
            FailReason::ExpiredWhileVerifying => Self::ExpiredWhileVerifying,
            FailReason::InvalidOutgoingTarget => Self::InvalidOutgoingTarget,
            FailReason::JournalingFailed => Self::JournalingFailed,
            FailReason::OutgoingFundingRefused(error) => {
                Self::OutgoingFundingRefused(error.clone())
            }
            FailReason::InterruptedWhileFunding => Self::InterruptedWhileFunding,
            FailReason::PreimageNotReceived => Self::PreimageNotReceived,
            FailReason::ClaimFailed => Self::ClaimFailed,
        }
    }
}

impl From<&StoredFailReason> for FailReason {
    fn from(reason: &StoredFailReason) -> Self {
        match reason {
            StoredFailReason::NetworkUnavailable => Self::NetworkUnavailable,
            StoredFailReason::IncomingRejected => Self::IncomingRejected,
            StoredFailReason::ExpiredWhileVerifying => Self::ExpiredWhileVerifying,
            StoredFailReason::FundingFailed => {
                Self::OutgoingFundingRefused("cause not journaled".into())
            }
            StoredFailReason::InterruptedWhileFunding => Self::InterruptedWhileFunding,
            StoredFailReason::PreimageNotReceived => Self::PreimageNotReceived,
            StoredFailReason::ClaimFailed => Self::ClaimFailed,
            StoredFailReason::InvalidOutgoingTarget => Self::InvalidOutgoingTarget,
            StoredFailReason::JournalingFailed => Self::JournalingFailed,
            StoredFailReason::OutgoingFundingRefused(error) => {
                Self::OutgoingFundingRefused(error.clone())
            }
        }
    }
}
