//! Citrea network: HTLCs are cBTC escrows in atomiq's `EscrowManager`.
//!
//! An escrow names a claim handler and a refund handler, contracts that
//! decide when it can be claimed and refunded. Every escrow here uses
//! atomiq's hashlock claim handler (claimable with the SHA-256 preimage
//! of `claimData`) and timelock refund handler (refundable once a
//! block's timestamp is past `refundData`), so it is an HTLC.
//!
//! * **Lock**: `initialize(escrow, "", timeout, "")` from the offerer,
//!   with the amount attached. No signature is needed: the reputation
//!   flag is off. The escrow is identified on chain by the keccak hash of
//!   its ABI encoding, which commits to every field, so a receiver that
//!   rebuilds the escrow from its descriptor and finds it committed has
//!   checked all of its terms.
//! * **Claim**: `claim(escrow, preimage)`, from anyone: the contract pays
//!   the escrow's claimer, whoever sends it. It emits `Claim(offerer,
//!   claimer, escrowHash, claimHandler, preimage)`, where the sender
//!   reads the preimage.
//! * **Refund**: `refund(escrow, "")` once a block's timestamp is past
//!   the expiry, paid to the offerer.
//!
//! `getState(escrow)` reports an escrow as committed, claimed or
//! refunded, and the block it was finished in, where the claim is found.
//!
//! The claimer of a [`PubKey`] identity is the address of that point, and
//! the adapter's account is the first standard BIP44 Ethereum address of
//! its mnemonic (see [`account_key`]).

use alloy::consensus::Transaction as _;
use alloy::eips::BlockNumberOrTag;
use alloy::network::{Ethereum, EthereumWallet};
use alloy::primitives::{Address, B256, Bytes, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::eth::{Filter, TransactionRequest};
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use alloy::sol_types::{SolCall, SolEvent};
use alloy::transports::http::reqwest::Url;
use async_trait::async_trait;
use cassis_core::keys::{Mnemonic, bip44_key};
use cassis_core::{
    Bytes32, Htlc, HtlcDescriptor, InvoiceTarget, Network, NetworkError, NetworkId, OutgoingState,
    PubKey,
};
use std::str::FromStr;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{Span, debug, info, warn};

sol! {
    /// An escrow, as `EscrowManager` takes it in every call.
    #[derive(Debug, PartialEq, Eq)]
    struct EscrowData {
        address offerer;
        address claimer;
        uint256 amount;
        address token;
        uint256 flags;
        address claimHandler;
        bytes32 claimData;
        address refundHandler;
        bytes32 refundData;
        uint256 securityDeposit;
        uint256 claimerBounty;
        address depositToken;
        bytes32 successActionCommitment;
    }

    #[derive(Debug)]
    struct EscrowState {
        uint64 initBlockheight;
        uint64 finishBlockheight;
        uint8 state;
    }

    #[derive(Debug)]
    contract IEscrowManager {
        event Claim(
            address indexed offerer,
            address indexed claimer,
            bytes32 indexed escrowHash,
            address claimHandler,
            bytes witnessResult
        );

        function initialize(
            EscrowData calldata escrow,
            bytes calldata signature,
            uint256 timeout,
            bytes calldata _extraData
        ) payable;

        function claim(EscrowData calldata escrow, bytes calldata witness);

        function refund(EscrowData calldata escrow, bytes calldata witness);

        function getState(EscrowData calldata escrowData) view returns (EscrowState memory result);
    }
}

pub const CITREA_MAINNET_RPC: &str = "https://rpc.mainnet.citrea.xyz";
pub const CITREA_TESTNET_RPC: &str = "https://rpc.testnet.citrea.xyz";

/// The contracts of atomiq's escrows on one Citrea chain.
#[derive(Clone, Copy, Debug)]
pub struct Contracts {
    pub escrow_manager: Address,
    /// Claim handler of HTLCs: `sha256(witness) == claimData`.
    pub hashlock: Address,
    /// Refund handler of HTLCs: `block.timestamp > refundData`.
    pub timelock: Address,
}

/// atomiq's deployment on Citrea mainnet.
pub const CITREA_MAINNET_CONTRACTS: Contracts = Contracts {
    escrow_manager: alloy::primitives::address!("c98Ef084d3911C8447DBbE4dDa18bC2c9bB0584e"),
    hashlock: alloy::primitives::address!("8A44f1995a54fD976c904Cccf9EbaB49c3182eb3"),
    timelock: alloy::primitives::address!("2920EE496693A5027249a027A6FD3F643E743745"),
};

/// atomiq's deployment on Citrea testnet4.
pub const CITREA_TESTNET_CONTRACTS: Contracts = Contracts {
    escrow_manager: alloy::primitives::address!("Bbf7755b674dD107d59F0650D1A3fA9C60bf6Fe6"),
    hashlock: alloy::primitives::address!("1120e1Eb3049148AeBEe497331774BfE1f6c174D"),
    timelock: alloy::primitives::address!("4699450973c21d6Fe09e36A8A475EaE4D78a3137"),
};

/// Escrow flags: pay the claimer out of the contract (not into its LP
/// vault), and take the funds from the offerer (not from its vault).
const FLAG_PAY_OUT: u64 = 0x01;
const FLAG_PAY_IN: u64 = 0x02;

/// `EscrowManager` states.
const STATE_NOT_COMMITTED: u8 = 0;
const STATE_COMMITTED: u8 = 1;
const STATE_CLAIMED: u8 = 2;
const STATE_REFUNDED: u8 = 3;

/// Gas reserved for an `initialize()` of a cBTC escrow (about 66k)
/// before committing to a route. Transactions themselves get the node's
/// estimate plus [`GAS_MARGIN_PERCENT`].
pub const LOCK_TX_GAS: u64 = 100_000;
/// Gas reserved for a `claim()` paying out cBTC (about 136k): the
/// reserve for the incoming side of a route.
pub const CLAIM_TX_GAS: u64 = 160_000;
/// Headroom over a node's gas estimate, which is exact only for the
/// state it was made on.
pub const GAS_MARGIN_PERCENT: u64 = 25;
/// How long a sent transaction is waited for. One that takes longer is
/// reported as failed, and found (or sent again) by the next attempt.
const RECEIPT_TIMEOUT: Duration = Duration::from_secs(180);
/// JSON-RPC "method not found", what a node without `eth_getLogs`
/// answers.
pub const METHOD_NOT_FOUND: i64 = -32601;
const WEI_PER_CBTC: u128 = 1_000_000_000_000_000_000;
const MSAT_PER_CBTC: u128 = 100_000_000_000;

/// The public node and atomiq's contracts of `citrea` or
/// `citrea::testnet`.
pub fn deployment(id: &NetworkId) -> Result<(&'static str, Contracts), String> {
    match id.param() {
        None => Ok((CITREA_MAINNET_RPC, CITREA_MAINNET_CONTRACTS)),
        Some("testnet") => Ok((CITREA_TESTNET_RPC, CITREA_TESTNET_CONTRACTS)),
        Some(other) => Err(format!("unknown citrea network '{other}'")),
    }
}

fn rpc_error(context: &str) -> impl Fn(alloy::transports::TransportError) -> NetworkError + '_ {
    move |e| NetworkError::network(format!("{context}: {e}"))
}

/// The escrow of an [`Htlc`]: everything but the payment hash, which
/// the escrow's claim data is. A wallet that funds or claims HTLCs
/// without a [`CitreaAdapter`] builds this from an
/// [`HtlcRequest`](cassis_core::HtlcRequest) or an [`Htlc`], and sends
/// the calldata below to the escrow manager of [`deployment`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Escrow {
    pub amount_wei: U256,
    pub claimer: Address,
    pub offerer: Address,
    /// Salts the escrow, so that two with the same terms differ.
    pub sequence: u64,
    /// Unix seconds after which a block can refund the escrow.
    pub refund_after: u64,
}

impl Escrow {
    /// The escrow to make for a payment claimable by `claim` (the key of
    /// an [`InvoiceTarget::Citrea`]): `amount_msat` locked from
    /// `offerer`, refundable after `expiry`.
    pub fn for_lock(amount_msat: u64, expiry: u64, claim: &PubKey, offerer: Address) -> Self {
        Self {
            amount_wei: msat_to_wei(amount_msat),
            claimer: evm_address_from_pubkey(claim),
            offerer,
            sequence: rand::random(),
            refund_after: expiry,
        }
    }

    pub fn of(htlc: &Htlc) -> Result<Self, NetworkError> {
        let HtlcDescriptor::Citrea {
            amount_wei,
            refund_address,
            sequence,
            refund_after,
            target: claim,
        } = &htlc.descriptor
        else {
            return Err(NetworkError::invalid("not a citrea HTLC"));
        };
        Ok(Self {
            amount_wei: U256::from(*amount_wei),
            claimer: evm_address_from_pubkey(claim),
            offerer: Address::from_str(refund_address).map_err(NetworkError::invalid)?,
            sequence: *sequence,
            refund_after: *refund_after,
        })
    }

    /// The descriptor of this escrow, claimable by `target` (whose EVM
    /// address is the escrow's claimer).
    pub fn descriptor(&self, target: PubKey) -> Result<HtlcDescriptor, NetworkError> {
        Ok(HtlcDescriptor::Citrea {
            amount_wei: self.amount_wei.try_into().map_err(NetworkError::invalid)?,
            refund_address: format!("{:#x}", self.offerer),
            sequence: self.sequence,
            refund_after: self.refund_after,
            target,
        })
    }

    /// The escrow as the contract takes it: a native cBTC HTLC on
    /// `contracts`' handlers, with no deposit, bounty or action on claim.
    pub fn data(&self, payment_hash: &Bytes32, contracts: &Contracts) -> EscrowData {
        EscrowData {
            offerer: self.offerer,
            claimer: self.claimer,
            amount: self.amount_wei,
            token: Address::ZERO,
            flags: (U256::from(self.sequence) << 64) | U256::from(FLAG_PAY_IN | FLAG_PAY_OUT),
            claimHandler: contracts.hashlock,
            claimData: B256::from(payment_hash.0),
            refundHandler: contracts.timelock,
            refundData: B256::from(U256::from(self.refund_after)),
            securityDeposit: U256::ZERO,
            claimerBounty: U256::ZERO,
            depositToken: Address::ZERO,
            successActionCommitment: B256::ZERO,
        }
    }
}

/// Calldata of `EscrowManager.initialize`, sent from the offerer with
/// the amount attached. The offerer needs no signature, so the
/// authorization never expires.
pub fn lock_calldata(escrow: EscrowData) -> Vec<u8> {
    IEscrowManager::initializeCall {
        escrow,
        signature: Bytes::new(),
        timeout: U256::from(u64::MAX),
        _extraData: Bytes::new(),
    }
    .abi_encode()
}

/// Calldata of `EscrowManager.claim`, from any account.
pub fn claim_calldata(escrow: EscrowData, preimage: &Bytes32) -> Vec<u8> {
    IEscrowManager::claimCall {
        escrow,
        witness: Bytes::copy_from_slice(&preimage.0),
    }
    .abi_encode()
}

/// Calldata of `EscrowManager.refund`, from any account once a block's
/// timestamp is past the escrow's `refund_after`.
pub fn refund_calldata(escrow: EscrowData) -> Vec<u8> {
    IEscrowManager::refundCall {
        escrow,
        witness: Bytes::new(),
    }
    .abi_encode()
}

/// What `contract` holds of `escrow`.
pub async fn escrow_state(
    provider: &dyn Provider,
    contract: Address,
    escrow: &EscrowData,
) -> Result<EscrowState, NetworkError> {
    let output = provider
        .call(
            TransactionRequest::default().to(contract).input(
                IEscrowManager::getStateCall::new((escrow.clone(),))
                    .abi_encode()
                    .into(),
            ),
        )
        .await
        .map_err(rpc_error("getState"))?;
    IEscrowManager::getStateCall::abi_decode_returns(&output).map_err(NetworkError::network)
}

/// What became of `escrow`, locked for `payment_hash`: pending while
/// committed, claimed with the preimage its claim revealed, or refunded.
pub async fn escrow_outcome(
    provider: &dyn Provider,
    contract: Address,
    payment_hash: Bytes32,
    escrow: &EscrowData,
) -> Result<OutgoingState, NetworkError> {
    let state = escrow_state(provider, contract, escrow).await?;
    match state.state {
        STATE_COMMITTED => Ok(OutgoingState::Pending),
        STATE_REFUNDED => Ok(OutgoingState::Refunded),
        STATE_CLAIMED => claimed_preimage(
            provider,
            contract,
            payment_hash,
            escrow,
            state.finishBlockheight,
        )
        .await
        .map(OutgoingState::Claimed),
        STATE_NOT_COMMITTED => Err(NetworkError::network(format!(
            "no escrow of {} in the contract",
            payment_hash.short()
        ))),
        other => Err(NetworkError::network(format!(
            "escrow of {} is in unknown state {other}",
            payment_hash.short()
        ))),
    }
}

/// The preimage the claim of `escrow` revealed in `block`: from its
/// `Claim` event, or, on nodes without `eth_getLogs`, from the claim
/// transaction itself.
async fn claimed_preimage(
    provider: &dyn Provider,
    contract: Address,
    payment_hash: Bytes32,
    escrow: &EscrowData,
    block: u64,
) -> Result<Bytes32, NetworkError> {
    let preimage_of = |witness: &[u8]| {
        let preimage = Bytes32(witness.try_into().ok()?);
        payment_hash.matches_preimage(&preimage).then_some(preimage)
    };
    let filter = Filter::new()
        .address(contract)
        .event_signature(IEscrowManager::Claim::SIGNATURE_HASH)
        .topic1(escrow.offerer.into_word())
        .topic2(escrow.claimer.into_word())
        .from_block(block)
        .to_block(block);
    match provider.get_logs(&filter).await {
        Ok(logs) => {
            for log in logs {
                let claim = log
                    .log_decode::<IEscrowManager::Claim>()
                    .map_err(NetworkError::network)?;
                if let Some(preimage) = preimage_of(&claim.inner.data.witnessResult) {
                    return Ok(preimage);
                }
            }
        }
        Err(error)
            if error
                .as_error_resp()
                .is_some_and(|response| response.code == METHOD_NOT_FOUND) =>
        {
            let block = provider
                .get_block_by_number(BlockNumberOrTag::Number(block))
                .full()
                .await
                .map_err(rpc_error("block"))?
                .ok_or_else(|| NetworkError::network(format!("block {block} not found")))?;
            for tx in block.transactions.txns() {
                if tx.to() != Some(contract) {
                    continue;
                }
                if let Ok(claim) = IEscrowManager::claimCall::abi_decode(tx.input())
                    && let Some(preimage) = preimage_of(&claim.witness)
                {
                    return Ok(preimage);
                }
            }
        }
        Err(error) => return Err(rpc_error("logs")(error)),
    }
    Err(NetworkError::network(format!(
        "escrow of {} was claimed in block {block}, but the node shows no claim there",
        payment_hash.short()
    )))
}

pub struct CitreaAdapter {
    id: NetworkId,
    span: Span,
    address: Address,
    /// Public key of the account, which maps to `address`.
    claim_pubkey: PubKey,
    contracts: Contracts,
    provider: Box<dyn Provider + Send + Sync>,
    /// Held while a transaction is sent, so that two never take the
    /// same nonce.
    sending: Mutex<()>,
}

impl CitreaAdapter {
    /// Connect to `citrea` or `citrea::testnet` through a public node.
    /// All state is on chain.
    pub fn open(id: NetworkId, mnemonic: &Mnemonic, span: &Span) -> Result<Self, String> {
        let (rpc_url, contracts) = deployment(&id)?;
        let secret = account_key(mnemonic)?;
        let signer = PrivateKeySigner::from_bytes(&B256::from_slice(&secret))
            .map_err(|e| format!("invalid citrea key: {e}"))?;
        let address = signer.address();
        let claim_pubkey = PubKey::from_bytes(
            secp256k1::SecretKey::from_byte_array(secret)
                .map_err(|e| format!("invalid citrea key: {e}"))?
                .public_key(&secp256k1::Secp256k1::signing_only())
                .serialize(),
        )
        .map_err(|e| format!("invalid citrea public key: {e}"))?;
        if evm_address_from_pubkey(&claim_pubkey) != address {
            return Err("claim identity does not map to the signing address".into());
        }
        let provider: Box<dyn Provider + Send + Sync> = Box::new(
            ProviderBuilder::new_with_network::<Ethereum>()
                .wallet(EthereumWallet::from(signer))
                .connect_http(Url::from_str(rpc_url).map_err(|e| e.to_string())?),
        );
        let span = cassis_core::network_span(span, &id);
        debug!(parent: &span, "citrea wallet ready: address={address} rpc={rpc_url}");
        Ok(Self {
            id,
            span,
            address,
            claim_pubkey,
            contracts,
            provider,
            sending: Mutex::new(()),
        })
    }

    /// The account HTLCs to this node pay out to, and that funds its own.
    pub fn address(&self) -> Address {
        self.address
    }

    /// cBTC balance, in msat.
    pub async fn balance_msat(&self) -> Result<u64, String> {
        let wei = self
            .provider
            .get_balance(self.address)
            .await
            .map_err(|e| e.to_string())?;
        u64::try_from(wei / U256::from(WEI_PER_MSAT)).map_err(|e| e.to_string())
    }

    /// Plain cBTC transfer of `amount_msat` to `to`. Returns the tx hash.
    pub async fn transfer(&self, to: &str, amount_msat: u64) -> Result<B256, String> {
        let to = Address::from_str(to.trim()).map_err(|e| format!("invalid address: {e}"))?;
        let request = TransactionRequest::default()
            .to(to)
            .value(msat_to_wei(amount_msat))
            .gas_price(self.gas_price().await.map_err(|e| e.to_string())?);
        let pending = self
            .provider
            .send_transaction(request)
            .await
            .map_err(|e| e.to_string())?;
        Ok(*pending.tx_hash())
    }

    fn claim_target(&self) -> InvoiceTarget {
        InvoiceTarget::Citrea {
            network: self.id.clone(),
            target: self.claim_pubkey,
        }
    }

    async fn gas_price(&self) -> Result<u128, NetworkError> {
        self.provider
            .get_gas_price()
            .await
            .map_err(rpc_error("gas price"))
    }

    async fn balance_wei(&self) -> Result<U256, NetworkError> {
        self.provider
            .get_balance(self.address)
            .await
            .map_err(rpc_error("balance"))
    }

    /// Timestamp of the chain tip, what refunds are held against.
    async fn tip_timestamp(&self) -> Result<u64, NetworkError> {
        Ok(self
            .provider
            .get_block_by_number(BlockNumberOrTag::Latest)
            .await
            .map_err(rpc_error("tip"))?
            .ok_or_else(|| NetworkError::network("node has no tip"))?
            .header
            .timestamp)
    }

    /// Send a call to the escrow manager, its gas limit the node's
    /// estimate with [`GAS_MARGIN_PERCENT`] more, and wait for it to
    /// succeed.
    async fn transact(
        &self,
        request: TransactionRequest,
        what: &str,
    ) -> Result<B256, NetworkError> {
        let request = request
            .from(self.address)
            .to(self.contracts.escrow_manager)
            .gas_price(self.gas_price().await?);
        let pending = {
            let _sending = self.sending.lock().await;
            let estimate = self
                .provider
                .estimate_gas(request.clone())
                .await
                .map_err(rpc_error(what))?;
            let request = request.gas_limit(estimate + estimate * GAS_MARGIN_PERCENT / 100);
            self.provider
                .send_transaction(request)
                .await
                .map_err(rpc_error(what))?
        };
        let tx_hash = *pending.tx_hash();
        let receipt = tokio::time::timeout(RECEIPT_TIMEOUT, pending.get_receipt())
            .await
            .map_err(|_| NetworkError::network(format!("{what} {tx_hash}: no receipt yet")))?
            .map_err(|e| NetworkError::network(format!("{what} {tx_hash}: {e}")))?;
        if !receipt.status() {
            return Err(NetworkError::network(format!("{what} {tx_hash} reverted")));
        }
        Ok(tx_hash)
    }

    fn escrow_data(&self, htlc: &Htlc) -> Result<EscrowData, NetworkError> {
        Ok(Escrow::of(htlc)?.data(&htlc.payment_hash, &self.contracts))
    }

    /// What became of the escrow of `htlc`, see [`escrow_outcome`].
    async fn outcome(
        &self,
        htlc: &Htlc,
        escrow: &EscrowData,
    ) -> Result<OutgoingState, NetworkError> {
        escrow_outcome(
            &*self.provider,
            self.contracts.escrow_manager,
            htlc.payment_hash,
            escrow,
        )
        .await
    }
}

#[async_trait]
impl Network for CitreaAdapter {
    fn id(&self) -> NetworkId {
        self.id.clone()
    }

    async fn receive_target(
        &self,
        _payment_hash: Bytes32,
        _amount_msat: u64,
        _expiry: u64,
    ) -> Result<InvoiceTarget, NetworkError> {
        Ok(self.claim_target())
    }

    async fn cancel_receive(&self, _payment_hash: Bytes32) -> Result<(), NetworkError> {
        Ok(())
    }

    async fn verify_incoming_htlc(&self, htlc: &Htlc) -> Result<(), NetworkError> {
        if !htlc.descriptor.pays(&self.claim_target()) {
            return Err(NetworkError::invalid("HTLC is not addressed to this node"));
        }
        self.verify_htlc(htlc).await
    }

    async fn verify_htlc(&self, htlc: &Htlc) -> Result<(), NetworkError> {
        let escrow = Escrow::of(htlc)?;
        if escrow.amount_wei < msat_to_wei(htlc.amount_msat) {
            return Err(NetworkError::invalid("escrow is worth less than the HTLC"));
        }
        if escrow.refund_after < htlc.expiry {
            return Err(NetworkError::invalid("refund opens before the expiry"));
        }
        // The escrow's hash commits to every term above, the payment
        // hash, and atomiq's hashlock and timelock handlers: one that is
        // committed is this HTLC. A node behind the sender's may not have
        // it yet.
        let data = escrow.data(&htlc.payment_hash, &self.contracts);
        let state = escrow_state(&*self.provider, self.contracts.escrow_manager, &data).await?;
        match state.state {
            STATE_COMMITTED => Ok(()),
            STATE_NOT_COMMITTED => Err(NetworkError::not_yet("no such escrow in the contract")),
            _ => Err(NetworkError::invalid("the escrow is already settled")),
        }
    }

    async fn claim_incoming_htlc(
        &self,
        htlc: &Htlc,
        preimage: Bytes32,
    ) -> Result<(), NetworkError> {
        let escrow = self.escrow_data(htlc)?;
        // An earlier attempt may have gone through after it was given
        // up on.
        match self.outcome(htlc, &escrow).await {
            Ok(OutgoingState::Claimed(_)) => return Ok(()),
            Ok(OutgoingState::Refunded) => {
                return Err(NetworkError::invalid("the escrow was refunded"));
            }
            Ok(OutgoingState::Pending) | Err(_) => {}
        }
        let request = TransactionRequest::default().input(claim_calldata(escrow, &preimage).into());
        let tx = self.transact(request, "claim").await?;
        info!(parent: &self.span, "claimed {}: tx {tx}", htlc.payment_hash.short());
        Ok(())
    }

    async fn create_outgoing_htlc(
        &self,
        payment_hash: Bytes32,
        amount_msat: u64,
        expiry: u64,
        target: &InvoiceTarget,
    ) -> Result<HtlcDescriptor, NetworkError> {
        let InvoiceTarget::Citrea { target: claim, .. } = target else {
            return Err(NetworkError::invalid(
                "citrea HTLCs are locked to a full key",
            ));
        };
        let escrow = Escrow::for_lock(amount_msat, expiry, claim, self.address);
        let descriptor = escrow.descriptor(*claim)?;
        let request = TransactionRequest::default()
            .value(escrow.amount_wei)
            .input(lock_calldata(escrow.data(&payment_hash, &self.contracts)).into());
        let tx = self.transact(request, "lock").await?;
        info!(
            parent: &self.span,
            "locked {amount_msat} msat for {} until {}: tx {tx}",
            payment_hash.short(),
            escrow.refund_after
        );
        Ok(descriptor)
    }

    async fn check_outgoing_htlc(&self, htlc: &Htlc) -> Result<OutgoingState, NetworkError> {
        let escrow = self.escrow_data(htlc)?;
        self.outcome(htlc, &escrow).await
    }

    async fn refund_outgoing_htlc(&self, htlc: &Htlc) -> Result<(), NetworkError> {
        let refund_after = Escrow::of(htlc)?.refund_after;
        let escrow = self.escrow_data(htlc)?;
        match self.outcome(htlc, &escrow).await {
            Ok(OutgoingState::Refunded) => return Ok(()),
            Ok(OutgoingState::Claimed(_)) => {
                return Err(NetworkError::invalid("the escrow was claimed"));
            }
            Ok(OutgoingState::Pending) | Err(_) => {}
        }
        let tip = self.tip_timestamp().await?;
        if tip <= refund_after {
            return Err(NetworkError::network(format!(
                "refund opens after {refund_after}, tip is at {tip}"
            )));
        }
        let request = TransactionRequest::default().input(refund_calldata(escrow).into());
        let tx = self.transact(request, "refund").await?;
        info!(parent: &self.span, "refunded {}: tx {tx}", htlc.payment_hash.short());
        Ok(())
    }

    async fn can_send(&self, amount_msat: u64) -> Result<(), NetworkError> {
        let needed =
            msat_to_wei(amount_msat).saturating_add(gas_cost(LOCK_TX_GAS, self.gas_price().await?));
        let balance = self.balance_wei().await?;
        if balance < needed {
            return Err(NetworkError::invalid(format!(
                "need {needed} wei with gas, account has {balance} wei"
            )));
        }
        Ok(())
    }

    /// Claims pay gas from the account.
    async fn can_receive(&self, _amount_msat: u64) -> Result<(), NetworkError> {
        let needed = gas_cost(CLAIM_TX_GAS, self.gas_price().await?);
        let balance = self.balance_wei().await?;
        if balance < needed {
            warn!(parent: &self.span, "cannot afford claim gas: {balance} < {needed} wei");
            return Err(NetworkError::invalid(format!(
                "claiming needs {needed} wei of gas, account has {balance} wei"
            )));
        }
        Ok(())
    }
}

/// 1 msat is 10^7 wei (1 cBTC = 10^11 msat = 10^18 wei).
pub const WEI_PER_MSAT: u128 = WEI_PER_CBTC / MSAT_PER_CBTC;

/// The wei of `msat`.
pub fn msat_to_wei(msat: u64) -> U256 {
    U256::from(msat).saturating_mul(U256::from(WEI_PER_MSAT))
}

pub fn gas_cost(gas: u64, gas_price: u128) -> U256 {
    U256::from(gas).saturating_mul(U256::from(gas_price))
}

/// SLIP-44 coin type of Ethereum, which EVM wallets use on every chain.
const ETHEREUM_COIN_TYPE: u32 = 60;

/// The key of the account of `mnemonic`: BIP44 `m/44'/60'/0'/0/0`, the
/// first address an Ethereum wallet lists under the same mnemonic, on
/// mainnet and testnet alike.
pub fn account_key(mnemonic: &Mnemonic) -> Result<[u8; 32], String> {
    bip44_key(&mnemonic.to_seed(""), ETHEREUM_COIN_TYPE, 0).map_err(|e| format!("citrea key: {e}"))
}

/// Map a cassis identity to the EVM address an HTLC locked to it pays
/// out to: `keccak256(X || Y)[12..]` of its point.
pub fn evm_address_from_pubkey(pubkey: &PubKey) -> Address {
    let uncompressed = pubkey.to_ecdsa_key().serialize_uncompressed();
    // Skip the 0x04 tag: keccak is over the raw 64-byte X || Y.
    Address::from_slice(&alloy::primitives::keccak256(&uncompressed[1..]).0[12..])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The account is the first address of an Ethereum wallet under the
    /// same mnemonic.
    #[test]
    fn account_is_the_first_ethereum_address() {
        let mnemonic = Mnemonic::parse(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap();
        let signer =
            PrivateKeySigner::from_bytes(&B256::from_slice(&account_key(&mnemonic).unwrap()))
                .unwrap();
        assert_eq!(
            signer.address(),
            alloy::primitives::address!("9858EfFD232B4033E47d90003D41EC34EcaEda94")
        );
    }

    /// The flags carry the sequence above the pay-in and pay-out bits.
    #[test]
    fn flags_salt_the_escrow_with_the_sequence() {
        let escrow = Escrow {
            amount_wei: U256::from(1),
            claimer: Address::ZERO,
            offerer: Address::ZERO,
            sequence: 5,
            refund_after: 1_000,
        };
        let data = escrow.data(&Bytes32([7; 32]), &CITREA_MAINNET_CONTRACTS);
        assert_eq!(data.flags, U256::from((5u128 << 64) | 3));
        assert_eq!(data.refundData, B256::from(U256::from(1_000)));
    }
}
