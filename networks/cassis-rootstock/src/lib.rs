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
//! The claim address of an x-only identity is the address of its even-Y
//! point, and the adapter normalizes its own key to that point (see
//! [`normalized_key`]).

use alloy::consensus::Transaction as _;
use alloy::eips::BlockNumberOrTag;
use alloy::network::{Ethereum, EthereumWallet};
use alloy::primitives::{Address, B256, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::eth::{Filter, TransactionRequest};
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use alloy::sol_types::{SolCall, SolEvent};
use alloy::transports::http::reqwest::Url;
use async_trait::async_trait;
use cassis_core::{
    unix_now, Bytes32, Htlc, HtlcDescriptor, HtlcTarget, Network, NetworkError, NetworkId,
    OutgoingState, PubKey, XOnlyPubKey,
};
use std::str::FromStr;
use tracing::{debug, info, warn, Span};

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

const ROOTSTOCK_MAINNET_RPC: &str = "https://public-node.rsk.co";
const ROOTSTOCK_TESTNET_RPC: &str = "https://public-node.testnet.rsk.co";

/// EtherSwap v3 contract on Rootstock mainnet. Deployed by
/// Boltz (`0x1Bdf482F5da32ef51c20D9A94960385c5be9AaB7`).
const ROOTSTOCK_MAINNET_CONTRACT: &str = "0x3612e393cA2fbB8874854B88fFCf04307a518239";
const ROOTSTOCK_TESTNET_CONTRACT: &str = "0x165f8e654b3fe310a854805323718d51977ad95f";

/// Gas reserved for an `EtherSwap.lock()` (about 46k in practice)
/// before committing to a route. Transactions themselves get the node's
/// estimate plus [`GAS_MARGIN_PERCENT`].
const LOCK_TX_GAS: u64 = 60_000;
/// Gas reserved for an `EtherSwap.claim()`: the reserve for the
/// incoming side of a route.
const CLAIM_TX_GAS: u64 = 60_000;
/// Headroom over a node's gas estimate, which is exact only for the
/// state it was made on.
const GAS_MARGIN_PERCENT: u64 = 25;
/// JSON-RPC "method not found", what Rootstock's public nodes answer
/// `eth_getLogs` with.
const METHOD_NOT_FOUND: i64 = -32601;

/// Shortest average block interval assumed over an HTLC's life, to
/// turn expiries into timelocks no block cadence reaches early. Blocks
/// target about 30s but often come faster (testnet averages ~25s).
const RSK_FAST_BLOCK_SECS: u64 = 20;
/// Blocks a lock's timelock adds over [`RSK_FAST_BLOCK_SECS`], so the
/// tip moving on before the receiver verifies does not fail the check.
const LOCK_MARGIN_BLOCKS: u64 = 10;
const WEI_PER_RBTC: u128 = 1_000_000_000_000_000_000;
const MSAT_PER_RBTC: u128 = 100_000_000_000;

/// How far before an HTLC's timelock its lock can lie, when searching
/// the contract's events for it (one day of blocks).
const MAX_LOCK_BLOCKS: u64 = 24 * 60 * 60 / RSK_FAST_BLOCK_SECS;

fn rpc_error(context: &str) -> impl Fn(alloy::transports::TransportError) -> NetworkError + '_ {
    move |e| NetworkError::network(format!("{context}: {e}"))
}

/// The EtherSwap lock of an [`Htlc`].
#[derive(Clone, Debug, PartialEq, Eq)]
struct Swap {
    amount_wei: U256,
    claim_address: Address,
    refund_address: Address,
    timelock: u64,
}

impl Swap {
    fn of(htlc: &Htlc) -> Result<Self, NetworkError> {
        let HtlcDescriptor::Rootstock {
            amount_wei,
            refund_address,
            timelock,
        } = &htlc.descriptor
        else {
            return Err(NetworkError::invalid("not a rootstock HTLC"));
        };
        let HtlcTarget::PubKey(claim) = &htlc.target else {
            return Err(NetworkError::invalid(
                "rootstock HTLCs are locked to a full key",
            ));
        };
        Ok(Self {
            amount_wei: U256::from(*amount_wei),
            claim_address: evm_address_from_pubkey(claim),
            refund_address: Address::from_str(refund_address).map_err(NetworkError::invalid)?,
            timelock: *timelock,
        })
    }

    fn descriptor(&self) -> Result<HtlcDescriptor, NetworkError> {
        Ok(HtlcDescriptor::Rootstock {
            amount_wei: self.amount_wei.try_into().map_err(NetworkError::invalid)?,
            refund_address: format!("{:#x}", self.refund_address),
            timelock: self.timelock,
        })
    }
}

pub struct RootstockAdapter {
    id: NetworkId,
    span: Span,
    address: Address,
    /// x-only identity of the (normalized) key; `02 || x` maps to
    /// `address`.
    claim_pubkey: XOnlyPubKey,
    contract: Address,
    provider: Box<dyn Provider + Send + Sync>,
}

impl RootstockAdapter {
    /// Connect to `rootstock` or `rootstock::testnet` through a public
    /// node. All state is on chain.
    pub fn open(id: NetworkId, secret: [u8; 32], span: &Span) -> Result<Self, String> {
        let (rpc_url, contract) = match id.param() {
            None => (ROOTSTOCK_MAINNET_RPC, ROOTSTOCK_MAINNET_CONTRACT),
            Some("testnet") => (ROOTSTOCK_TESTNET_RPC, ROOTSTOCK_TESTNET_CONTRACT),
            Some(other) => return Err(format!("unknown rootstock network '{other}'")),
        };
        let (secret, claim_pubkey) = normalized_key(secret)?;
        let signer = PrivateKeySigner::from_bytes(&B256::from_slice(&secret))
            .map_err(|e| format!("invalid rootstock key: {e}"))?;
        let address = signer.address();
        if evm_address_from_xonly(&claim_pubkey) != address {
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
            contract: Address::from_str(contract).map_err(|e| e.to_string())?,
            provider,
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

    fn claim_target(&self) -> HtlcTarget {
        HtlcTarget::PubKey(PubKey::from_x_only(&self.claim_pubkey).expect("valid key"))
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
        let call = |input: Vec<u8>| {
            TransactionRequest::default()
                .to(self.contract)
                .input(input.into())
        };
        let swap_hash = self
            .provider
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
        let exists = self
            .provider
            .call(call(
                IEtherSwap::swapsCall(B256::from_slice(&swap_hash[..32])).abi_encode(),
            ))
            .await
            .map_err(rpc_error("swaps"))?;
        Ok(exists.last().is_some_and(|byte| *byte != 0))
    }

    /// Send a contract call, its gas limit the node's estimate with
    /// [`GAS_MARGIN_PERCENT`] more, and wait for it to succeed.
    async fn transact(
        &self,
        request: TransactionRequest,
        what: &str,
    ) -> Result<B256, NetworkError> {
        let request = request.from(self.address).to(self.contract);
        let estimate = self
            .provider
            .estimate_gas(request.clone())
            .await
            .map_err(rpc_error(what))?;
        let request = request.gas_limit(estimate + estimate * GAS_MARGIN_PERCENT / 100);
        let pending = self
            .provider
            .send_transaction(request)
            .await
            .map_err(rpc_error(what))?;
        let tx_hash = *pending.tx_hash();
        let receipt = pending
            .get_receipt()
            .await
            .map_err(|e| NetworkError::network(format!("{what} {tx_hash}: {e}")))?;
        if !receipt.status() {
            return Err(NetworkError::network(format!("{what} {tx_hash} reverted")));
        }
        Ok(tx_hash)
    }

    /// [`Network::check_outgoing_htlc`] without `eth_getLogs`: pending
    /// while the contract still holds the lock, else settled by the
    /// latest `claim` revealing the preimage or successful `refund` of
    /// it, found scanning back from the tip.
    async fn check_outgoing_without_logs(
        &self,
        htlc: &Htlc,
        swap: &Swap,
    ) -> Result<OutgoingState, NetworkError> {
        if self.swap_exists(htlc.payment_hash, swap).await? {
            return Ok(OutgoingState::Pending);
        }
        let tip = self.block_number().await?;
        let oldest = swap.timelock.saturating_sub(MAX_LOCK_BLOCKS);
        for number in (oldest..=tip).rev() {
            let block = self
                .provider
                .get_block_by_number(BlockNumberOrTag::Number(number))
                .full()
                .await
                .map_err(rpc_error("block"))?
                .ok_or_else(|| NetworkError::network(format!("block {number} not found")))?;
            for tx in block.transactions.txns() {
                if tx.to() != Some(self.contract) {
                    continue;
                }
                if let Ok(claim) = IEtherSwap::claimCall::abi_decode(tx.input()) {
                    let preimage = Bytes32(claim.preimage.0);
                    if htlc.payment_hash.matches_preimage(&preimage) {
                        return Ok(OutgoingState::Claimed(preimage));
                    }
                } else if let Ok(refund) = IEtherSwap::refundCall::abi_decode(tx.input()) {
                    if refund.preimageHash.0 != htlc.payment_hash.0 {
                        continue;
                    }
                    let receipt = self
                        .provider
                        .get_transaction_receipt(*tx.inner.tx_hash())
                        .await
                        .map_err(rpc_error("receipt"))?;
                    if receipt.is_some_and(|receipt| receipt.status()) {
                        return Ok(OutgoingState::Refunded);
                    }
                }
            }
        }
        Err(NetworkError::network(format!(
            "lock of {} is gone but no claim or refund of it since block {oldest}",
            htlc.payment_hash.short()
        )))
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
    ) -> Result<HtlcTarget, NetworkError> {
        Ok(self.claim_target())
    }

    async fn cancel_receive(&self, _payment_hash: Bytes32) -> Result<(), NetworkError> {
        Ok(())
    }

    async fn verify_incoming_htlc(&self, htlc: &Htlc) -> Result<(), NetworkError> {
        if htlc.target != self.claim_target() {
            return Err(NetworkError::invalid("HTLC is not addressed to this node"));
        }
        self.verify_htlc(htlc).await
    }

    async fn verify_htlc(&self, htlc: &Htlc) -> Result<(), NetworkError> {
        let swap = Swap::of(htlc)?;
        if swap.amount_wei < msat_to_wei(htlc.amount_msat) {
            return Err(NetworkError::invalid("lock is worth less than the HTLC"));
        }
        let blocks = htlc
            .expiry
            .saturating_sub(unix_now())
            .div_ceil(RSK_FAST_BLOCK_SECS);
        if swap.timelock < self.block_number().await? + blocks {
            return Err(NetworkError::invalid("refund opens before the expiry"));
        }
        // The swap hash commits to the payment hash and every term above.
        if !self.swap_exists(htlc.payment_hash, &swap).await? {
            return Err(NetworkError::invalid("no such lock in the contract"));
        }
        Ok(())
    }

    async fn claim_incoming_htlc(
        &self,
        htlc: &Htlc,
        preimage: Bytes32,
    ) -> Result<(), NetworkError> {
        let swap = Swap::of(htlc)?;
        let gas_price = self.gas_price().await?;
        let request = TransactionRequest::default().gas_price(gas_price).input(
            IEtherSwap::claimCall {
                preimage: B256::from(preimage.0),
                amount: swap.amount_wei,
                refundAddress: swap.refund_address,
                timelock: U256::from(swap.timelock),
            }
            .abi_encode()
            .into(),
        );
        let tx = self.transact(request, "claim").await?;
        info!(parent: &self.span, "claimed {}: tx {tx}", htlc.payment_hash.short());
        Ok(())
    }

    async fn create_outgoing_htlc(
        &self,
        payment_hash: Bytes32,
        amount_msat: u64,
        expiry: u64,
        target: &HtlcTarget,
    ) -> Result<HtlcDescriptor, NetworkError> {
        let HtlcTarget::PubKey(claim) = target else {
            return Err(NetworkError::invalid(
                "rootstock HTLCs are locked to a full key",
            ));
        };
        let blocks = expiry
            .saturating_sub(unix_now())
            .div_ceil(RSK_FAST_BLOCK_SECS)
            + LOCK_MARGIN_BLOCKS;
        let swap = Swap {
            amount_wei: msat_to_wei(amount_msat),
            claim_address: evm_address_from_pubkey(claim),
            refund_address: self.address,
            timelock: self.block_number().await? + blocks,
        };
        let descriptor = swap.descriptor()?;
        let request = TransactionRequest::default()
            .value(swap.amount_wei)
            .gas_price(self.gas_price().await?)
            .input(
                IEtherSwap::lockCall {
                    preimageHash: B256::from(payment_hash.0),
                    claimAddress: swap.claim_address,
                    timelock: U256::from(swap.timelock),
                }
                .abi_encode()
                .into(),
            );
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
        let filter = Filter::new()
            .address(self.contract)
            .topic1(B256::from(htlc.payment_hash.0))
            .from_block(BlockNumberOrTag::Number(
                swap.timelock.saturating_sub(MAX_LOCK_BLOCKS),
            ));
        let logs = match self.provider.get_logs(&filter).await {
            Ok(logs) => logs,
            Err(error)
                if error
                    .as_error_resp()
                    .is_some_and(|response| response.code == METHOD_NOT_FOUND) =>
            {
                return self.check_outgoing_without_logs(htlc, &swap).await;
            }
            Err(error) => return Err(rpc_error("logs")(error)),
        };
        for log in logs {
            match log.topic0() {
                Some(topic) if *topic == IEtherSwap::Claim::SIGNATURE_HASH => {
                    let claim = log
                        .log_decode::<IEtherSwap::Claim>()
                        .map_err(NetworkError::network)?;
                    return Ok(OutgoingState::Claimed(Bytes32(claim.inner.data.preimage.0)));
                }
                Some(topic) if *topic == IEtherSwap::Refund::SIGNATURE_HASH => {
                    return Ok(OutgoingState::Refunded);
                }
                _ => {}
            }
        }
        Ok(OutgoingState::Pending)
    }

    async fn refund_outgoing_htlc(&self, htlc: &Htlc) -> Result<(), NetworkError> {
        let swap = Swap::of(htlc)?;
        let height = self.block_number().await?;
        if height < swap.timelock {
            return Err(NetworkError::network(format!(
                "refund opens at block {}, tip is {height}",
                swap.timelock
            )));
        }
        let request = TransactionRequest::default()
            .gas_price(self.gas_price().await?)
            .input(
                IEtherSwap::refundCall {
                    preimageHash: B256::from(htlc.payment_hash.0),
                    amount: swap.amount_wei,
                    claimAddress: swap.claim_address,
                    timelock: U256::from(swap.timelock),
                }
                .abi_encode()
                .into(),
            );
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
const WEI_PER_MSAT: u128 = WEI_PER_RBTC / MSAT_PER_RBTC;

fn msat_to_wei(msat: u64) -> U256 {
    U256::from(msat).saturating_mul(U256::from(WEI_PER_MSAT))
}

fn gas_cost(gas: u64, gas_price: u128) -> U256 {
    U256::from(gas).saturating_mul(U256::from(gas_price))
}

/// Derive the EVM address for a 32-byte secret key without
/// touching the network. Used by the CLI's `info` subcommand
/// so showing the local address doesn't need an RPC
/// connection.
///
/// Normalizes the key exactly like [`RootstockAdapter::new`], so the
/// address shown here is always the address the adapter actually uses.
pub fn address_from_sk(sk: [u8; 32]) -> Result<Address, String> {
    let (sk, _) = normalized_key(sk)?;
    let signer = PrivateKeySigner::from_bytes(&B256::from_slice(&sk))
        .map_err(|e| format!("invalid secret key: {e}"))?;
    Ok(signer.address())
}

/// Normalize a secret key to the representative whose public key has an
/// even Y coordinate, returning it unchanged if it already does.
///
/// Cassis identities are BIP340 x-only keys: 32 bytes of X with the Y
/// parity discarded. Reconstructing a full point from one therefore has
/// to assume a parity, and everything here assumes even (the `0x02`
/// prefix). Ethereum addresses, however, are `keccak256(X || Y)[12..]`,
/// so `P` and `-P` — same X, opposite Y — hash to *different*
/// addresses.
///
/// Without this, a key whose public point has odd Y would advertise an
/// x-only identity that maps to `evm_addr(-P)` while the signer could
/// only produce signatures for `evm_addr(P)`: HTLCs would be locked to
/// an address the adapter cannot claim from, for roughly half of all
/// keys, at random.
///
/// Since `(n - sk) * G == -(sk * G)`, negating the scalar yields the
/// even-Y twin with an identical X. The x-only pubkey is therefore
/// unchanged, so nostr/npub and cashu (BIP340, x-only) identities are
/// unaffected — only the EVM address becomes well defined.
/// Normalize `sk` to its even-Y form and return it together with the
/// x-only identity it maps to, sharing one secp context and one scalar
/// multiplication (every caller needs both halves). Kept private:
/// external callers want [`address_from_sk`] or the adapter itself.
fn normalized_key(sk: [u8; 32]) -> Result<([u8; 32], XOnlyPubKey), String> {
    let secp = secp256k1::Secp256k1::signing_only();
    let secret = secp256k1::SecretKey::from_byte_array(sk)
        .map_err(|e| format!("invalid secret key: {e}"))?;
    let (xonly, parity) = secret.x_only_public_key(&secp);
    let normalized = match parity {
        secp256k1::Parity::Even => sk,
        // Negating the scalar flips Y and leaves X untouched, so the
        // x-only identity computed above still holds.
        secp256k1::Parity::Odd => secret.negate().secret_bytes(),
    };
    let pubkey = XOnlyPubKey::from_bytes(xonly.serialize())
        .map_err(|e| format!("invalid x-only pubkey: {e}"))?;
    Ok((normalized, pubkey))
}

/// Map a cassis x-only identity to the EVM address that can claim an
/// HTLC locked to it: `keccak256(X || Y)[12..]` of the even-Y point.
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

fn evm_address_from_xonly(pubkey: &XOnlyPubKey) -> Address {
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02;
    compressed[1..].copy_from_slice(pubkey.as_bytes());
    let full = PubKey::from_bytes(compressed).expect("valid x-only public key");
    evm_address_from_pubkey(&full)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msat_to_wei_uses_one_rbtc_per_100_billion_msat() {
        let one_rbtc_in_msat = 100_000_000_000u64;
        let one_rbtc_in_wei = U256::from(1_000_000_000_000_000_000u128);
        assert_eq!(msat_to_wei(one_rbtc_in_msat), one_rbtc_in_wei);
    }

    /// Walk enough keys to hit both Y parities (each is ~50% likely, so
    /// 24 candidates makes a miss vanishingly unlikely) and assert the
    /// normalization invariants on every one.
    #[test]
    fn normalize_sk_preserves_x_only_identity_and_yields_signable_address() {
        let mut covered_even = false;
        let mut covered_odd = false;
        for seed in 1u8..25 {
            let sk = [seed; 32];
            let (normalized, pubkey) = normalized_key(sk).expect("valid key");
            if normalized == sk {
                covered_even = true;
            } else {
                covered_odd = true;
            }

            // The x-only identity must survive normalization, otherwise
            // negating the scalar would change the node's identity on
            // every other network (nostr, cashu) too.
            let (renormalized, pubkey_again) = normalized_key(normalized).expect("valid key");
            assert_eq!(
                pubkey, pubkey_again,
                "normalization must not change the x-only identity",
            );

            // The crux: the address derived from the advertised x-only
            // identity must be the address the normalized key can sign
            // for. Without normalization this fails for odd-Y keys.
            assert_eq!(
                evm_address_from_xonly(&pubkey),
                address_from_sk(sk).unwrap(),
                "advertised identity must map to the signable address",
            );

            // Idempotent: normalizing an already-normalized key is a
            // no-op, so repeated construction is stable.
            assert_eq!(renormalized, normalized);
        }
        assert!(
            covered_even && covered_odd,
            "expected the sample to cover both Y parities",
        );
    }
}
