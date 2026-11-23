//! Rootstock network: HTLCs are locks in Boltz's EtherSwap contract.
//!
//! * **Lock**: `lock(preimageHash, claimAddress, timelock)` with the
//!   value attached. The swap is identified on chain by
//!   `hashValues(preimageHash, amount, claimAddress, refundAddress,
//!   timelock)`, which `swaps()` reports while it is locked.
//! * **Claim**: `claim(preimage, amount, refundAddress, timelock)` from
//!   the claim address; the contract emits `Claim(preimageHash,
//!   preimage)`, where the sender reads the preimage.
//! * **Refund**: `refund(...)` once the block height reaches `timelock`.
//!
//! Senders read claims from the contract's events, or, on nodes without
//! `eth_getLogs` (Rootstock's public ones), from the claim transaction
//! itself, found by scanning blocks once `swaps()` no longer has the
//! lock.
//!
//! The claim address of a [`PubKey`] identity is the address of that
//! point, and the adapter's account is the first standard BIP44 address
//! of its mnemonic (see [`account_key`]).

use alloy::consensus::Transaction as _;
use alloy::eips::BlockNumberOrTag;
use alloy::network::{Ethereum, EthereumWallet, TransactionResponse as _};
use alloy::primitives::{Address, B256, U256};
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
    PubKey, unix_now,
};
use std::str::FromStr;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{Span, debug, info, warn};

sol! {
    #[derive(Debug)]
    contract IEtherSwap {
        event Lockup(
            bytes32 indexed preimageHash,
            uint256 amount,
            address indexed claimAddress,
            uint256 timelock
        );

        event Claim(
            bytes32 indexed preimageHash,
            bytes32 preimage
        );

        event Refund(
            bytes32 indexed preimageHash
        );

        function lock(
            bytes32 preimageHash,
            address claimAddress,
            uint256 timelock
        ) payable;

        function claim(
            bytes32 preimage,
            uint256 amount,
            address refundAddress,
            uint256 timelock
        );

        function refund(
            bytes32 preimageHash,
            uint256 amount,
            address claimAddress,
            uint256 timelock
        );

        function hashValues(
            bytes32 preimageHash,
            uint256 amount,
            address claimAddress,
            address refundAddress,
            uint256 timelock
        ) pure returns (bytes32);

        function swaps(bytes32) view returns (bool);
    }
}

pub const ROOTSTOCK_MAINNET_RPC: &str = "https://public-node.rsk.co";
pub const ROOTSTOCK_TESTNET_RPC: &str = "https://public-node.testnet.rsk.co";

/// EtherSwap v3 contract on Rootstock mainnet. Deployed by
/// Boltz (`0x1Bdf482F5da32ef51c20D9A94960385c5be9AaB7`).
pub const ROOTSTOCK_MAINNET_CONTRACT: &str = "0x3612e393cA2fbB8874854B88fFCf04307a518239";
pub const ROOTSTOCK_TESTNET_CONTRACT: &str = "0x165f8e654b3fe310a854805323718d51977ad95f";

/// Gas reserved for an `EtherSwap.lock()` (about 46k in practice)
/// before committing to a route. Transactions themselves get the node's
/// estimate plus [`GAS_MARGIN_PERCENT`].
pub const LOCK_TX_GAS: u64 = 60_000;
/// Gas reserved for an `EtherSwap.claim()`: the reserve for the
/// incoming side of a route.
pub const CLAIM_TX_GAS: u64 = 60_000;
/// Headroom over a node's gas estimate, which is exact only for the
/// state it was made on.
pub const GAS_MARGIN_PERCENT: u64 = 25;
/// How long a sent transaction is waited for. One that takes longer is
/// reported as failed, and found (or sent again) by the next attempt.
const RECEIPT_TIMEOUT: Duration = Duration::from_secs(180);
/// JSON-RPC "method not found", what Rootstock's public nodes answer
/// `eth_getLogs` with.
pub const METHOD_NOT_FOUND: i64 = -32601;

/// Shortest average block interval assumed over an HTLC's life, to
/// turn expiries into timelocks no block cadence reaches early. Blocks
/// target about 30s but often come faster (testnet averages ~25s).
pub const RSK_FAST_BLOCK_SECS: u64 = 20;
/// Blocks a lock's timelock adds over [`RSK_FAST_BLOCK_SECS`], so the
/// tip moving on before the receiver verifies does not fail the check.
pub const LOCK_MARGIN_BLOCKS: u64 = 10;
const WEI_PER_RBTC: u128 = 1_000_000_000_000_000_000;
const MSAT_PER_RBTC: u128 = 100_000_000_000;

/// How far before an HTLC's timelock its lock can lie, when searching
/// the contract's events for it (one day of blocks).
pub const MAX_LOCK_BLOCKS: u64 = 24 * 60 * 60 / RSK_FAST_BLOCK_SECS;

/// The public node and the EtherSwap contract of `rootstock` or
/// `rootstock::testnet`.
pub fn deployment(id: &NetworkId) -> Result<(&'static str, Address), String> {
    let (rpc_url, contract) = match id.param() {
        None => (ROOTSTOCK_MAINNET_RPC, ROOTSTOCK_MAINNET_CONTRACT),
        Some("testnet") => (ROOTSTOCK_TESTNET_RPC, ROOTSTOCK_TESTNET_CONTRACT),
        Some(other) => return Err(format!("unknown rootstock network '{other}'")),
    };
    Ok((
        rpc_url,
        Address::from_str(contract).map_err(|e| e.to_string())?,
    ))
}

/// The timelock (block height) a lock for an HTLC expiring at `expiry`
/// (unix seconds) is made with, given the chain's `tip_block`: the
/// blocks `expiry` is away, plus [`LOCK_MARGIN_BLOCKS`].
pub fn lock_timelock(tip_block: u64, expiry: u64) -> u64 {
    tip_block
        + expiry
            .saturating_sub(unix_now())
            .div_ceil(RSK_FAST_BLOCK_SECS)
        + LOCK_MARGIN_BLOCKS
}

/// The lowest timelock a receiver accepts for an HTLC expiring at
/// `expiry`, given the chain's `tip_block`. A lock made with
/// [`lock_timelock`] is never below it.
pub fn min_timelock(tip_block: u64, expiry: u64) -> u64 {
    tip_block
        + expiry
            .saturating_sub(unix_now())
            .div_ceil(RSK_FAST_BLOCK_SECS)
}

fn rpc_error(context: &str) -> impl Fn(alloy::transports::TransportError) -> NetworkError + '_ {
    move |e| NetworkError::network(format!("{context}: {e}"))
}

/// The EtherSwap lock of an [`Htlc`]. A wallet that funds or claims
/// HTLCs without a [`RootstockAdapter`] builds this from an
/// [`HtlcRequest`](cassis_core::HtlcRequest) or an [`Htlc`], and sends
/// the calldata below to the contract of [`deployment`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Swap {
    pub amount_wei: U256,
    pub claim_address: Address,
    pub refund_address: Address,
    pub timelock: u64,
}

impl Swap {
    /// The lock to make for a payment claimable by `claim` (the key of
    /// an [`InvoiceTarget::Rootstock`]): `amount_msat` locked from
    /// `refund_address`, refundable at the block [`lock_timelock`] gives.
    pub fn for_lock(
        amount_msat: u64,
        expiry: u64,
        claim: &PubKey,
        refund_address: Address,
        tip_block: u64,
    ) -> Self {
        Self {
            amount_wei: msat_to_wei(amount_msat),
            claim_address: evm_address_from_pubkey(claim),
            refund_address,
            timelock: lock_timelock(tip_block, expiry),
        }
    }

    pub fn of(htlc: &Htlc) -> Result<Self, NetworkError> {
        let HtlcDescriptor::Rootstock {
            amount_wei,
            refund_address,
            timelock,
            target: claim,
        } = &htlc.descriptor
        else {
            return Err(NetworkError::invalid("not a rootstock HTLC"));
        };
        Ok(Self {
            amount_wei: U256::from(*amount_wei),
            claim_address: evm_address_from_pubkey(claim),
            refund_address: Address::from_str(refund_address).map_err(NetworkError::invalid)?,
            timelock: *timelock,
        })
    }

    /// The descriptor of this swap, claimable by `target` (whose EVM
    /// address is the swap's claim address).
    pub fn descriptor(&self, target: PubKey) -> Result<HtlcDescriptor, NetworkError> {
        Ok(HtlcDescriptor::Rootstock {
            amount_wei: self.amount_wei.try_into().map_err(NetworkError::invalid)?,
            refund_address: format!("{:#x}", self.refund_address),
            timelock: self.timelock,
            target,
        })
    }

    /// Calldata of `EtherSwap.lock`, to send with `amount_wei` attached.
    pub fn lock_calldata(&self, payment_hash: &Bytes32) -> Vec<u8> {
        IEtherSwap::lockCall {
            preimageHash: B256::from(payment_hash.0),
            claimAddress: self.claim_address,
            timelock: U256::from(self.timelock),
        }
        .abi_encode()
    }

    /// Calldata of `EtherSwap.claim`, sent from the claim address.
    pub fn claim_calldata(&self, preimage: &Bytes32) -> Vec<u8> {
        IEtherSwap::claimCall {
            preimage: B256::from(preimage.0),
            amount: self.amount_wei,
            refundAddress: self.refund_address,
            timelock: U256::from(self.timelock),
        }
        .abi_encode()
    }

    /// Calldata of `EtherSwap.refund`, sent from the refund address
    /// once the chain reaches the timelock.
    pub fn refund_calldata(&self, payment_hash: &Bytes32) -> Vec<u8> {
        IEtherSwap::refundCall {
            preimageHash: B256::from(payment_hash.0),
            amount: self.amount_wei,
            claimAddress: self.claim_address,
            timelock: U256::from(self.timelock),
        }
        .abi_encode()
    }
}

/// Whether the `contract` holds `swap` for `payment_hash`.
pub async fn swap_exists(
    provider: &dyn Provider,
    contract: Address,
    payment_hash: Bytes32,
    swap: &Swap,
) -> Result<bool, NetworkError> {
    let call = |input: Vec<u8>| {
        TransactionRequest::default()
            .to(contract)
            .input(input.into())
    };
    let swap_hash = provider
        .call(call(
            IEtherSwap::hashValuesCall {
                preimageHash: B256::from(payment_hash.0),
                amount: swap.amount_wei,
                claimAddress: swap.claim_address,
                refundAddress: swap.refund_address,
                timelock: U256::from(swap.timelock),
            }
            .abi_encode(),
        ))
        .await
        .map_err(rpc_error("hashValues"))?;
    let exists = provider
        .call(call(
            IEtherSwap::swapsCall(B256::from_slice(&swap_hash[..32])).abi_encode(),
        ))
        .await
        .map_err(rpc_error("swaps"))?;
    Ok(exists.last().is_some_and(|byte| *byte != 0))
}

/// What became of the lock of `htlc` in `contract`: pending while the
/// contract holds it, else claimed or refunded.
///
/// `Claim` and `Refund` events name only the payment hash, and
/// anyone can lock, claim and refund other swaps under the same
/// hash. So nothing is settled while the contract holds this swap,
/// whose hash commits to all of its terms; once it is gone, any
/// claim reveals the preimage, and only without one was it refunded.
pub async fn swap_outcome(
    provider: &dyn Provider,
    contract: Address,
    htlc: &Htlc,
    swap: &Swap,
) -> Result<OutgoingState, NetworkError> {
    if swap_exists(provider, contract, htlc.payment_hash, swap).await? {
        return Ok(OutgoingState::Pending);
    }
    let filter = Filter::new()
        .address(contract)
        .topic1(B256::from(htlc.payment_hash.0))
        .from_block(BlockNumberOrTag::Number(
            swap.timelock.saturating_sub(MAX_LOCK_BLOCKS),
        ));
    let logs = match provider.get_logs(&filter).await {
        Ok(logs) => logs,
        Err(error)
            if error
                .as_error_resp()
                .is_some_and(|response| response.code == METHOD_NOT_FOUND) =>
        {
            return swap_outcome_without_logs(provider, contract, htlc, swap).await;
        }
        Err(error) => return Err(rpc_error("logs")(error)),
    };
    let mut refunded = false;
    for log in logs {
        match log.topic0() {
            Some(topic) if *topic == IEtherSwap::Claim::SIGNATURE_HASH => {
                let claim = log
                    .log_decode::<IEtherSwap::Claim>()
                    .map_err(NetworkError::network)?;
                let preimage = Bytes32(claim.inner.data.preimage.0);
                if htlc.payment_hash.matches_preimage(&preimage) {
                    return Ok(OutgoingState::Claimed(preimage));
                }
            }
            Some(topic) if *topic == IEtherSwap::Refund::SIGNATURE_HASH => refunded = true,
            _ => {}
        }
    }
    if refunded {
        return Ok(OutgoingState::Refunded);
    }
    Err(NetworkError::network(format!(
        "lock of {} is gone but the node shows no claim or refund of it",
        htlc.payment_hash.short()
    )))
}

/// [`swap_outcome`] of a lock the contract no longer holds, on nodes
/// without `eth_getLogs`: any `claim` revealing the preimage, else
/// the successful `refund` of this very swap, found scanning back from
/// the tip.
async fn swap_outcome_without_logs(
    provider: &dyn Provider,
    contract: Address,
    htlc: &Htlc,
    swap: &Swap,
) -> Result<OutgoingState, NetworkError> {
    let tip = provider
        .get_block_number()
        .await
        .map_err(rpc_error("block number"))?;
    let oldest = swap.timelock.saturating_sub(MAX_LOCK_BLOCKS);
    let mut refunded = false;
    for number in (oldest..=tip).rev() {
        let block = provider
            .get_block_by_number(BlockNumberOrTag::Number(number))
            .full()
            .await
            .map_err(rpc_error("block"))?
            .ok_or_else(|| NetworkError::network(format!("block {number} not found")))?;
        for tx in block.transactions.txns() {
            if tx.to() != Some(contract) {
                continue;
            }
            if let Ok(claim) = IEtherSwap::claimCall::abi_decode(tx.input()) {
                let preimage = Bytes32(claim.preimage.0);
                if htlc.payment_hash.matches_preimage(&preimage) {
                    return Ok(OutgoingState::Claimed(preimage));
                }
            } else if let Ok(refund) = IEtherSwap::refundCall::abi_decode(tx.input()) {
                // The refund of another swap under the same hash is
                // not ours.
                if refunded
                    || refund.preimageHash.0 != htlc.payment_hash.0
                    || refund.amount != swap.amount_wei
                    || refund.claimAddress != swap.claim_address
                    || refund.timelock != U256::from(swap.timelock)
                    || tx.from() != swap.refund_address
                {
                    continue;
                }
                let receipt = provider
                    .get_transaction_receipt(*tx.inner.tx_hash())
                    .await
                    .map_err(rpc_error("receipt"))?;
                refunded = receipt.is_some_and(|receipt| receipt.status());
            }
        }
    }
    if refunded {
        return Ok(OutgoingState::Refunded);
    }
    Err(NetworkError::network(format!(
        "lock of {} is gone but no claim or refund of it since block {oldest}",
        htlc.payment_hash.short()
    )))
}

pub struct RootstockAdapter {
    id: NetworkId,
    span: Span,
    address: Address,
    /// Public key of the account, which maps to `address`.
    claim_pubkey: PubKey,
    contract: Address,
    provider: Box<dyn Provider + Send + Sync>,
    /// Held while a transaction is sent, so that two never take the
    /// same nonce.
    sending: Mutex<()>,
}

impl RootstockAdapter {
    /// Connect to `rootstock` or `rootstock::testnet` through a public
    /// node. All state is on chain.
    pub fn open(id: NetworkId, mnemonic: &Mnemonic, span: &Span) -> Result<Self, String> {
        let (rpc_url, contract) = deployment(&id)?;
        let secret = account_key(&id, mnemonic)?;
        let signer = PrivateKeySigner::from_bytes(&B256::from_slice(&secret))
            .map_err(|e| format!("invalid rootstock key: {e}"))?;
        let address = signer.address();
        let claim_pubkey = PubKey::from_bytes(
            secp256k1::SecretKey::from_byte_array(secret)
                .map_err(|e| format!("invalid rootstock key: {e}"))?
                .public_key(&secp256k1::Secp256k1::signing_only())
                .serialize(),
        )
        .map_err(|e| format!("invalid rootstock public key: {e}"))?;
        if evm_address_from_pubkey(&claim_pubkey) != address {
            return Err("claim identity does not map to the signing address".into());
        }
        let provider: Box<dyn Provider + Send + Sync> = Box::new(
            ProviderBuilder::new_with_network::<Ethereum>()
                .wallet(EthereumWallet::from(signer))
                .connect_http(Url::from_str(rpc_url).map_err(|e| e.to_string())?),
        );
        let span = cassis_core::network_span(span, &id);
        debug!(parent: &span, "rootstock wallet ready: address={address} rpc={rpc_url}");
        Ok(Self {
            id,
            span,
            address,
            claim_pubkey,
            contract,
            provider,
            sending: Mutex::new(()),
        })
    }

    /// The account HTLCs to this node are claimed from.
    pub fn address(&self) -> Address {
        self.address
    }

    /// RBTC balance, in msat.
    pub async fn balance_msat(&self) -> Result<u64, String> {
        let wei = self
            .provider
            .get_balance(self.address)
            .await
            .map_err(|e| e.to_string())?;
        u64::try_from(wei / U256::from(WEI_PER_MSAT)).map_err(|e| e.to_string())
    }

    /// Plain RBTC transfer of `amount_msat` to `to`. Returns the tx hash.
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
        InvoiceTarget::Rootstock {
            network: self.id.clone(),
            target: self.claim_pubkey,
        }
    }

    async fn block_number(&self) -> Result<u64, NetworkError> {
        self.provider
            .get_block_number()
            .await
            .map_err(rpc_error("block number"))
    }

    /// Rootstock has no EIP-1559: every transaction is legacy with an
    /// explicit gas price.
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

    /// Whether the contract holds `swap` for `payment_hash`.
    async fn swap_exists(&self, payment_hash: Bytes32, swap: &Swap) -> Result<bool, NetworkError> {
        swap_exists(&*self.provider, self.contract, payment_hash, swap).await
    }

    /// Send a contract call, its gas limit the node's estimate with
    /// [`GAS_MARGIN_PERCENT`] more, and wait for it to succeed.
    async fn transact(
        &self,
        request: TransactionRequest,
        what: &str,
    ) -> Result<B256, NetworkError> {
        let request = request.from(self.address).to(self.contract);
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

    /// What became of the lock of `htlc`, see [`swap_outcome`].
    async fn outcome(&self, htlc: &Htlc, swap: &Swap) -> Result<OutgoingState, NetworkError> {
        swap_outcome(&*self.provider, self.contract, htlc, swap).await
    }
}

#[async_trait]
impl Network for RootstockAdapter {
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
        let swap = Swap::of(htlc)?;
        if swap.amount_wei < msat_to_wei(htlc.amount_msat) {
            return Err(NetworkError::invalid("lock is worth less than the HTLC"));
        }
        if swap.timelock < min_timelock(self.block_number().await?, htlc.expiry) {
            return Err(NetworkError::invalid("refund opens before the expiry"));
        }
        // The swap hash commits to the payment hash and every term above.
        // A node behind the sender's may not have it yet.
        if !self.swap_exists(htlc.payment_hash, &swap).await? {
            return Err(NetworkError::not_yet("no such lock in the contract"));
        }
        Ok(())
    }

    async fn claim_incoming_htlc(
        &self,
        htlc: &Htlc,
        preimage: Bytes32,
    ) -> Result<(), NetworkError> {
        let swap = Swap::of(htlc)?;
        // An earlier attempt may have gone through after it was given
        // up on.
        match self.outcome(htlc, &swap).await {
            Ok(OutgoingState::Claimed(_)) => return Ok(()),
            Ok(OutgoingState::Refunded) => {
                return Err(NetworkError::invalid("the lock was refunded"));
            }
            Ok(OutgoingState::Pending) | Err(_) => {}
        }
        let gas_price = self.gas_price().await?;
        let request = TransactionRequest::default()
            .gas_price(gas_price)
            .input(swap.claim_calldata(&preimage).into());
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
        let InvoiceTarget::Rootstock { target: claim, .. } = target else {
            return Err(NetworkError::invalid(
                "rootstock HTLCs are locked to a full key",
            ));
        };
        let swap = Swap::for_lock(
            amount_msat,
            expiry,
            claim,
            self.address,
            self.block_number().await?,
        );
        let descriptor = swap.descriptor(*claim)?;
        let request = TransactionRequest::default()
            .value(swap.amount_wei)
            .gas_price(self.gas_price().await?)
            .input(swap.lock_calldata(&payment_hash).into());
        let tx = self.transact(request, "lock").await?;
        info!(
            parent: &self.span,
            "locked {amount_msat} msat for {} until block {}: tx {tx}",
            payment_hash.short(),
            swap.timelock
        );
        Ok(descriptor)
    }

    async fn check_outgoing_htlc(&self, htlc: &Htlc) -> Result<OutgoingState, NetworkError> {
        let swap = Swap::of(htlc)?;
        self.outcome(htlc, &swap).await
    }

    async fn refund_outgoing_htlc(&self, htlc: &Htlc) -> Result<(), NetworkError> {
        let swap = Swap::of(htlc)?;
        match self.outcome(htlc, &swap).await {
            Ok(OutgoingState::Refunded) => return Ok(()),
            Ok(OutgoingState::Claimed(_)) => {
                return Err(NetworkError::invalid("the lock was claimed"));
            }
            Ok(OutgoingState::Pending) | Err(_) => {}
        }
        let height = self.block_number().await?;
        if height < swap.timelock {
            return Err(NetworkError::network(format!(
                "refund opens at block {}, tip is {height}",
                swap.timelock
            )));
        }
        let request = TransactionRequest::default()
            .gas_price(self.gas_price().await?)
            .input(swap.refund_calldata(&htlc.payment_hash).into());
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

/// 1 msat is 10^7 wei (1 RBTC = 10^11 msat = 10^18 wei).
pub const WEI_PER_MSAT: u128 = WEI_PER_RBTC / MSAT_PER_RBTC;

/// The wei of `msat`.
pub fn msat_to_wei(msat: u64) -> U256 {
    U256::from(msat).saturating_mul(U256::from(WEI_PER_MSAT))
}

pub fn gas_cost(gas: u64, gas_price: u128) -> U256 {
    U256::from(gas).saturating_mul(U256::from(gas_price))
}

/// SLIP-44 coin type of RSK mainnet, and the one RSK's wallets use on
/// its testnet.
const RSK_MAINNET_COIN_TYPE: u32 = 137;
const RSK_TESTNET_COIN_TYPE: u32 = 37310;

/// The key of the account of `mnemonic` on `id`: BIP44
/// `m/44'/<RSK coin type>'/0'/0/0` (RSKIP-57), the first address every
/// RSK wallet lists under the same mnemonic.
pub fn account_key(id: &NetworkId, mnemonic: &Mnemonic) -> Result<[u8; 32], String> {
    let coin_type = match id.param() {
        None => RSK_MAINNET_COIN_TYPE,
        Some(_) => RSK_TESTNET_COIN_TYPE,
    };
    bip44_key(&mnemonic.to_seed(""), coin_type, 0).map_err(|e| format!("rootstock key: {e}"))
}

/// Derive the EVM address for a 32-byte secret key without
/// touching the network. Used by the CLI's `info` subcommand
/// so showing the local address doesn't need an RPC
/// connection.
///
pub fn address_from_sk(sk: [u8; 32]) -> Result<Address, String> {
    let signer = PrivateKeySigner::from_bytes(&B256::from_slice(&sk))
        .map_err(|e| format!("invalid secret key: {e}"))?;
    Ok(signer.address())
}

/// Map a cassis identity to the EVM address that can claim an HTLC
/// locked to it: `keccak256(X || Y)[12..]` of its point.
///
/// This is the single source of truth for the identity -> address
/// mapping. It is used both to pick the `claimAddress` when locking an
/// outgoing HTLC for a counterparty and (via the constructor
/// self-check) to validate our own address, so the two can never drift.
pub fn evm_address_from_pubkey(pubkey: &PubKey) -> Address {
    let uncompressed = pubkey.to_ecdsa_key().serialize_uncompressed();
    // Skip the 0x04 tag: keccak is over the raw 64-byte X || Y.
    Address::from_slice(&alloy::primitives::keccak256(&uncompressed[1..]).0[12..])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The account is the standard BIP44 key of the first address, and
    /// its identity maps to the address it signs for.
    #[test]
    fn account_is_the_first_bip44_address() {
        let mnemonic = Mnemonic::parse(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap();
        let mainnet = account_key(&NetworkId("rootstock".into()), &mnemonic).unwrap();
        let testnet = account_key(&NetworkId("rootstock::testnet".into()), &mnemonic).unwrap();
        assert_ne!(mainnet, testnet);
        let secret = secp256k1::SecretKey::from_byte_array(mainnet).unwrap();
        let public = PubKey::from_bytes(
            secret
                .public_key(&secp256k1::Secp256k1::signing_only())
                .serialize(),
        )
        .unwrap();
        assert_eq!(
            evm_address_from_pubkey(&public),
            address_from_sk(mainnet).unwrap()
        );
    }

    #[test]
    fn msat_to_wei_uses_one_rbtc_per_100_billion_msat() {
        let one_rbtc_in_msat = 100_000_000_000u64;
        let one_rbtc_in_wei = U256::from(1_000_000_000_000_000_000u128);
        assert_eq!(msat_to_wei(one_rbtc_in_msat), one_rbtc_in_wei);
    }
}
