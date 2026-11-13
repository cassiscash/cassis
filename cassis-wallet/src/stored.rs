//! How wire types are stored: one `#[orangedb::embed]` mirror for each,
//! with conversions both ways. The wire types change with the protocol;
//! these change only with a migration. Shared by the schemas of the
//! wallet, the router and the gateway.

use cassis_core::network::{Htlc, HtlcDescriptor, HtlcTarget};
use cassis_core::offline::{AuthorizationKind, Destination, ReceiveAuthorization, Signature};
use cassis_core::protocol::{InvoiceNetwork, Metadata};
use cassis_core::{Bytes32, NetworkId, PubKey, XOnlyPubKey};
use iroh_base::PublicKey;

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

/// An [`HtlcTarget`].
#[orangedb::embed]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoredTarget {
    XOnlyPubKey([u8; 32]),
    PubKey(StoredPubKey),
    LightningInvoice(String),
}

/// An [`HtlcDescriptor`].
#[orangedb::embed]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoredDescriptor {
    Cashu {
        proofs_b64: Vec<String>,
    },
    Liquid {
        lockup_txid: String,
        lockup_vout: u32,
        refund_pubkey: StoredPubKey,
        refund_locktime: u32,
    },
    Arkade {
        sender: [u8; 32],
        refund_locktime: u32,
        unilateral_claim_delay: u32,
        unilateral_refund_delay: u32,
        unilateral_refund_without_receiver_delay: u32,
    },
    Bitcoin {
        lockup_txid: String,
        lockup_vout: u32,
        refund_pubkey: [u8; 32],
        refund_locktime: u32,
    },
    Rootstock {
        amount_wei: u128,
        refund_address: String,
        timelock: u64,
    },
    Fedimint {
        funding_txid: String,
        funding_out_idx: u64,
        contract: String,
    },
    Lightning,
}

/// An [`Htlc`].
#[orangedb::embed]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredHtlc {
    pub payment_hash: [u8; 32],
    pub amount_msat: u64,
    pub expiry: u64,
    pub target: StoredTarget,
    pub descriptor: StoredDescriptor,
}

/// An [`InvoiceNetwork`].
#[orangedb::embed]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredInvoiceNetwork {
    pub network: String,
    pub target: StoredTarget,
    pub incoming_delta_secs: Option<u64>,
}

/// An [`AuthorizationKind`].
#[orangedb::embed]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoredAuthorizationKind {
    Single,
    Standing,
}

/// A [`Destination`].
#[orangedb::embed]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredDestination {
    pub network: String,
    pub target: StoredTarget,
}

/// A [`ReceiveAuthorization`].
#[orangedb::embed]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredAuthorization {
    pub kind: StoredAuthorizationKind,
    pub payee: [u8; 32],
    pub gateway: [u8; 32],
    pub preimage_server: [u8; 32],
    pub preimage_server_relay: Option<String>,
    pub valid_from: u64,
    pub valid_until: u64,
    pub min_amount_msat: u64,
    pub max_amount_msat: u64,
    pub min_final_timeout_secs: u64,
    pub destinations: Vec<StoredDestination>,
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

pub fn endpoint_key(bytes: &[u8; 32]) -> Result<PublicKey, String> {
    PublicKey::from_bytes(bytes).map_err(|_| corrupt("endpoint key"))
}

impl From<&HtlcTarget> for StoredTarget {
    fn from(target: &HtlcTarget) -> Self {
        match target {
            HtlcTarget::XOnlyPubKey(key) => Self::XOnlyPubKey(key.0),
            HtlcTarget::PubKey(key) => Self::PubKey(key.into()),
            HtlcTarget::LightningInvoice(invoice) => Self::LightningInvoice(invoice.clone()),
        }
    }
}

impl TryFrom<&StoredTarget> for HtlcTarget {
    type Error = String;

    fn try_from(target: &StoredTarget) -> Result<Self, String> {
        Ok(match target {
            StoredTarget::XOnlyPubKey(key) => Self::XOnlyPubKey(x_only(*key)?),
            StoredTarget::PubKey(key) => Self::PubKey(key.try_into()?),
            StoredTarget::LightningInvoice(invoice) => Self::LightningInvoice(invoice.clone()),
        })
    }
}

impl From<&HtlcDescriptor> for StoredDescriptor {
    fn from(descriptor: &HtlcDescriptor) -> Self {
        match descriptor.clone() {
            HtlcDescriptor::Cashu { proofs_b64 } => Self::Cashu { proofs_b64 },
            HtlcDescriptor::Liquid {
                lockup_txid,
                lockup_vout,
                refund_pubkey,
                refund_locktime,
            } => Self::Liquid {
                lockup_txid,
                lockup_vout,
                refund_pubkey: (&refund_pubkey).into(),
                refund_locktime,
            },
            HtlcDescriptor::Arkade {
                sender,
                refund_locktime,
                unilateral_claim_delay,
                unilateral_refund_delay,
                unilateral_refund_without_receiver_delay,
            } => Self::Arkade {
                sender: sender.0,
                refund_locktime,
                unilateral_claim_delay,
                unilateral_refund_delay,
                unilateral_refund_without_receiver_delay,
            },
            HtlcDescriptor::Bitcoin {
                lockup_txid,
                lockup_vout,
                refund_pubkey,
                refund_locktime,
            } => Self::Bitcoin {
                lockup_txid,
                lockup_vout,
                refund_pubkey: refund_pubkey.0,
                refund_locktime,
            },
            HtlcDescriptor::Rootstock {
                amount_wei,
                refund_address,
                timelock,
            } => Self::Rootstock {
                amount_wei,
                refund_address,
                timelock,
            },
            HtlcDescriptor::Fedimint {
                funding_txid,
                funding_out_idx,
                contract,
            } => Self::Fedimint {
                funding_txid,
                funding_out_idx,
                contract,
            },
            HtlcDescriptor::Lightning => Self::Lightning,
        }
    }
}

impl TryFrom<&StoredDescriptor> for HtlcDescriptor {
    type Error = String;

    fn try_from(descriptor: &StoredDescriptor) -> Result<Self, String> {
        Ok(match descriptor.clone() {
            StoredDescriptor::Cashu { proofs_b64 } => Self::Cashu { proofs_b64 },
            StoredDescriptor::Liquid {
                lockup_txid,
                lockup_vout,
                refund_pubkey,
                refund_locktime,
            } => Self::Liquid {
                lockup_txid,
                lockup_vout,
                refund_pubkey: (&refund_pubkey).try_into()?,
                refund_locktime,
            },
            StoredDescriptor::Arkade {
                sender,
                refund_locktime,
                unilateral_claim_delay,
                unilateral_refund_delay,
                unilateral_refund_without_receiver_delay,
            } => Self::Arkade {
                sender: x_only(sender)?,
                refund_locktime,
                unilateral_claim_delay,
                unilateral_refund_delay,
                unilateral_refund_without_receiver_delay,
            },
            StoredDescriptor::Bitcoin {
                lockup_txid,
                lockup_vout,
                refund_pubkey,
                refund_locktime,
            } => Self::Bitcoin {
                lockup_txid,
                lockup_vout,
                refund_pubkey: x_only(refund_pubkey)?,
                refund_locktime,
            },
            StoredDescriptor::Rootstock {
                amount_wei,
                refund_address,
                timelock,
            } => Self::Rootstock {
                amount_wei,
                refund_address,
                timelock,
            },
            StoredDescriptor::Fedimint {
                funding_txid,
                funding_out_idx,
                contract,
            } => Self::Fedimint {
                funding_txid,
                funding_out_idx,
                contract,
            },
            StoredDescriptor::Lightning => Self::Lightning,
        })
    }
}

impl From<&Htlc> for StoredHtlc {
    fn from(htlc: &Htlc) -> Self {
        Self {
            payment_hash: htlc.payment_hash.0,
            amount_msat: htlc.amount_msat,
            expiry: htlc.expiry,
            target: (&htlc.target).into(),
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
            target: (&htlc.target).try_into()?,
            descriptor: (&htlc.descriptor).try_into()?,
        })
    }
}

impl From<&InvoiceNetwork> for StoredInvoiceNetwork {
    fn from(entry: &InvoiceNetwork) -> Self {
        Self {
            network: entry.network.0.clone(),
            target: (&entry.target).into(),
            incoming_delta_secs: entry.incoming_delta_secs,
        }
    }
}

impl TryFrom<&StoredInvoiceNetwork> for InvoiceNetwork {
    type Error = String;

    fn try_from(entry: &StoredInvoiceNetwork) -> Result<Self, String> {
        Ok(Self {
            network: NetworkId(entry.network.clone()),
            target: (&entry.target).try_into()?,
            incoming_delta_secs: entry.incoming_delta_secs,
        })
    }
}

impl From<&ReceiveAuthorization> for StoredAuthorization {
    fn from(authorization: &ReceiveAuthorization) -> Self {
        Self {
            kind: match authorization.kind {
                AuthorizationKind::Single => StoredAuthorizationKind::Single,
                AuthorizationKind::Standing => StoredAuthorizationKind::Standing,
            },
            payee: *authorization.payee.as_bytes(),
            gateway: *authorization.gateway.as_bytes(),
            preimage_server: *authorization.preimage_server.as_bytes(),
            preimage_server_relay: authorization.preimage_server_relay.clone(),
            valid_from: authorization.valid_from,
            valid_until: authorization.valid_until,
            min_amount_msat: authorization.min_amount_msat,
            max_amount_msat: authorization.max_amount_msat,
            min_final_timeout_secs: authorization.min_final_timeout_secs,
            destinations: authorization
                .destinations
                .iter()
                .map(|destination| StoredDestination {
                    network: destination.network.0.clone(),
                    target: (&destination.target).into(),
                })
                .collect(),
            signature: authorization.signature.0.to_vec(),
        }
    }
}

impl TryFrom<&StoredAuthorization> for ReceiveAuthorization {
    type Error = String;

    fn try_from(authorization: &StoredAuthorization) -> Result<Self, String> {
        Ok(Self {
            kind: match authorization.kind {
                StoredAuthorizationKind::Single => AuthorizationKind::Single,
                StoredAuthorizationKind::Standing => AuthorizationKind::Standing,
            },
            payee: endpoint_key(&authorization.payee)?,
            gateway: endpoint_key(&authorization.gateway)?,
            preimage_server: endpoint_key(&authorization.preimage_server)?,
            preimage_server_relay: authorization.preimage_server_relay.clone(),
            valid_from: authorization.valid_from,
            valid_until: authorization.valid_until,
            min_amount_msat: authorization.min_amount_msat,
            max_amount_msat: authorization.max_amount_msat,
            min_final_timeout_secs: authorization.min_final_timeout_secs,
            destinations: authorization
                .destinations
                .iter()
                .map(|destination| {
                    Ok(Destination {
                        network: NetworkId(destination.network.clone()),
                        target: (&destination.target).try_into()?,
                    })
                })
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
            target: HtlcTarget::PubKey(PubKey::from_x_only(&key).unwrap()),
            descriptor: HtlcDescriptor::Arkade {
                sender: key,
                refund_locktime: 1,
                unilateral_claim_delay: 2,
                unilateral_refund_delay: 3,
                unilateral_refund_without_receiver_delay: 4,
            },
        };
        assert_eq!(Htlc::try_from(&StoredHtlc::from(&htlc)).unwrap(), htlc);

        let authorization = ReceiveAuthorization::sign(
            &[1; 32],
            AuthorizationKind::Standing,
            endpoint_public_key(&[2; 32]),
            endpoint_public_key(&[3; 32]),
            Some("https://relay.example".into()),
            1000,
            2000,
            1,
            50_000,
            3600,
            vec![Destination {
                network: NetworkId("cashu::localhost".into()),
                target: HtlcTarget::XOnlyPubKey(key),
            }],
        )
        .unwrap();
        let stored = StoredAuthorization::from(&authorization);
        assert_eq!(
            ReceiveAuthorization::try_from(&stored).unwrap(),
            authorization
        );
    }
}
