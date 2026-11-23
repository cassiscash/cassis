//! The stored types as the first schemas stored them, before Citrea,
//! WBTC on Starknet and WBTC on Solana: what the migrations of the
//! wallet, router, gateway and preimage server schemas read old rows
//! as. Frozen: never change these, add a new version instead.

/// [`super::StoredPubKey`] as v1 stored it.
#[orangedb::embed]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoredPubKey {
    pub parity: u8,
    pub x: [u8; 32],
}

/// [`super::StoredNever`] as v1 stored it.
#[orangedb::embed]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoredNever {}

/// [`super::StoredPayeeGatewayReceiveAuthorizationKind`] as v1 stored it.
#[orangedb::embed]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoredPayeeGatewayReceiveAuthorizationKind {
    Single,
    Standing,
}

/// [`super::StoredFailReason`] as v1 stored it.
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

/// [`super::StoredDescriptor`] as v1 stored it.
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
}

/// [`super::StoredHtlc`] as v1 stored it.
#[orangedb::embed]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredHtlc {
    pub payment_hash: [u8; 32],
    pub amount_msat: u64,
    pub expiry: u64,
    pub descriptor: StoredDescriptor,
}

/// [`super::StoredInvoiceNetwork`] as v1 stored it.
#[orangedb::embed]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredInvoiceNetwork {
    pub target: StoredInvoiceTarget,
    pub incoming_delta_secs: Option<u64>,
}

/// [`super::StoredInvoiceTarget`] as v1 stored it.
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
}

/// [`super::StoredGatewayDestination`] as v1 stored it.
pub type StoredGatewayDestination = StoredInvoiceTarget<StoredNever>;

/// [`super::StoredPayeeGatewayReceiveAuthorization`] as v1 stored it.
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

impl From<StoredDescriptor> for super::StoredDescriptor {
    fn from(descriptor: StoredDescriptor) -> Self {
        match descriptor {
            StoredDescriptor::Cashu { proofs_b64, target } => Self::Cashu { proofs_b64, target },
            StoredDescriptor::Liquid {
                lockup_txid,
                lockup_vout,
                refund_pubkey,
                refund_locktime,
                target,
            } => Self::Liquid {
                lockup_txid,
                lockup_vout,
                refund_pubkey: refund_pubkey.into(),
                refund_locktime,
                target: target.into(),
            },
            StoredDescriptor::Arkade {
                sender,
                refund_locktime,
                unilateral_claim_delay,
                unilateral_refund_delay,
                unilateral_refund_without_receiver_delay,
                target,
            } => Self::Arkade {
                sender,
                refund_locktime,
                unilateral_claim_delay,
                unilateral_refund_delay,
                unilateral_refund_without_receiver_delay,
                target,
            },
            StoredDescriptor::Bitcoin {
                lockup_txid,
                lockup_vout,
                refund_pubkey,
                refund_locktime,
                target,
            } => Self::Bitcoin {
                lockup_txid,
                lockup_vout,
                refund_pubkey,
                refund_locktime,
                target,
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
                target: target.into(),
            },
            StoredDescriptor::Fedimint {
                funding_txid,
                funding_out_idx,
                contract,
                target,
            } => Self::Fedimint {
                funding_txid,
                funding_out_idx,
                contract,
                target,
            },
            StoredDescriptor::Lightning { target } => Self::Lightning { target },
        }
    }
}

impl From<StoredHtlc> for super::StoredHtlc {
    fn from(htlc: StoredHtlc) -> Self {
        Self {
            payment_hash: htlc.payment_hash,
            amount_msat: htlc.amount_msat,
            expiry: htlc.expiry,
            descriptor: htlc.descriptor.into(),
        }
    }
}

impl From<StoredInvoiceNetwork> for super::StoredInvoiceNetwork {
    fn from(entry: StoredInvoiceNetwork) -> Self {
        Self {
            target: entry.target.into(),
            incoming_delta_secs: entry.incoming_delta_secs,
        }
    }
}

impl<L: Into<M>, M> From<StoredInvoiceTarget<L>> for super::StoredInvoiceTarget<M> {
    fn from(target: StoredInvoiceTarget<L>) -> Self {
        match target {
            StoredInvoiceTarget::Cashu { network, target } => Self::Cashu { network, target },
            StoredInvoiceTarget::Fedimint { network, target } => Self::Fedimint { network, target },
            StoredInvoiceTarget::Arkade { network, target } => Self::Arkade { network, target },
            StoredInvoiceTarget::Bitcoin { network, target } => Self::Bitcoin { network, target },
            StoredInvoiceTarget::Liquid { network, target } => Self::Liquid {
                network,
                target: target.into(),
            },
            StoredInvoiceTarget::Rootstock { network, target } => Self::Rootstock {
                network,
                target: target.into(),
            },
            StoredInvoiceTarget::Lightning { network, invoice } => Self::Lightning {
                network,
                invoice: invoice.into(),
            },
        }
    }
}

impl From<StoredPayeeGatewayReceiveAuthorization>
    for super::StoredPayeeGatewayReceiveAuthorization
{
    fn from(authorization: StoredPayeeGatewayReceiveAuthorization) -> Self {
        Self {
            kind: match authorization.kind {
                StoredPayeeGatewayReceiveAuthorizationKind::Single => {
                    super::StoredPayeeGatewayReceiveAuthorizationKind::Single
                }
                StoredPayeeGatewayReceiveAuthorizationKind::Standing => {
                    super::StoredPayeeGatewayReceiveAuthorizationKind::Standing
                }
            },
            payee: authorization.payee,
            gateway: authorization.gateway,
            preimage_server: authorization.preimage_server,
            description: authorization.description,
            valid_from: authorization.valid_from,
            valid_until: authorization.valid_until,
            min_amount_msat: authorization.min_amount_msat,
            max_amount_msat: authorization.max_amount_msat,
            min_final_timeout_secs: authorization.min_final_timeout_secs,
            destinations: authorization
                .destinations
                .into_iter()
                .map(Into::into)
                .collect(),
            signature: authorization.signature,
        }
    }
}

impl From<StoredPubKey> for super::StoredPubKey {
    fn from(key: StoredPubKey) -> Self {
        Self {
            parity: key.parity,
            x: key.x,
        }
    }
}

impl From<StoredNever> for super::StoredNever {
    fn from(never: StoredNever) -> Self {
        match never {}
    }
}

impl From<StoredFailReason> for super::StoredFailReason {
    fn from(reason: StoredFailReason) -> Self {
        match reason {
            StoredFailReason::NetworkUnavailable => Self::NetworkUnavailable,
            StoredFailReason::IncomingRejected => Self::IncomingRejected,
            StoredFailReason::ExpiredWhileVerifying => Self::ExpiredWhileVerifying,
            StoredFailReason::FundingFailed => Self::FundingFailed,
            StoredFailReason::InterruptedWhileFunding => Self::InterruptedWhileFunding,
            StoredFailReason::PreimageNotReceived => Self::PreimageNotReceived,
            StoredFailReason::ClaimFailed => Self::ClaimFailed,
            StoredFailReason::InvalidOutgoingTarget => Self::InvalidOutgoingTarget,
            StoredFailReason::JournalingFailed => Self::JournalingFailed,
            StoredFailReason::OutgoingFundingRefused(error) => Self::OutgoingFundingRefused(error),
        }
    }
}
