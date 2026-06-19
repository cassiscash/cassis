use alloy::dyn_abi::{DynSolType, DynSolValue, JsonAbiExt};
use alloy::eips::BlockNumberOrTag;
use alloy::network::{Ethereum, EthereumWallet};
use alloy::primitives::{Address, Bytes, B256, I256, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::eth::{Filter, TransactionRequest};
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use alloy::sol_types::{SolCall, SolEvent};
use alloy::transports::http::reqwest::Url;
use async_trait::async_trait;
use cassis_core::{
    Bytes32, HtlcDescriptor, HtlcError, IncomingHtlc, NetworkId, NetworkRouterAdapter,
    OutgoingHtlc, WatchError,
};
use log::{debug, warn};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, Notify};

sol! {
    #[derive(Debug)]
    contract IEtherSwap {
        event Lockup(
            bytes32 indexed preimageHash,
            uint256 amount,
            address indexed claimAddress,
            address indexed refundAddress,
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
            address refundAddress,
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
const ROOTSTOCK_MAINNET_CHAIN_ID: u64 = 30;
const ROOTSTOCK_TESTNET_CHAIN_ID: u64 = 31;

/// EtherSwap v3 contract on Rootstock mainnet. Deployed by
/// Boltz (`0x1Bdf482F5da32ef51c20D9A94960385c5be9AaB7`).
const ROOTSTOCK_MAINNET_CONTRACT: &str = "0x3612e393cA2fbB8874854B88fFCf04307a518239";
const ROOTSTOCK_TESTNET_CONTRACT: &str = "0x165f8e654b3fe310a854805323718d51977ad95f";

const RSK_BLOCK_TIME_SECS: u64 = 30;
const POLL_INTERVAL_SECS: u64 = 5;
const WEI_PER_RBTC: u128 = 1_000_000_000_000_000_000;
const MSAT_PER_RBTC: u128 = 100_000_000_000;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid address: {0}")]
    InvalidAddress(String),
    #[error(
        "contract address not configured for {0}; set it explicitly when constructing the adapter"
    )]
    MissingContract(NetworkId),
    #[error("rpc error: {0}")]
    Rpc(String),
    #[error("invalid parameters: {0}")]
    InvalidParams(String),
    #[error("no incoming HTLC registered for {0}")]
    NoIncoming(String),
    #[error("no outgoing HTLC for {0}")]
    NoOutgoing(String),
}

impl From<Error> for HtlcError {
    fn from(e: Error) -> HtlcError {
        match e {
            Error::InvalidParams(s) | Error::InvalidAddress(s) => HtlcError::InvalidParams(s),
            Error::NoIncoming(s) | Error::NoOutgoing(s) => HtlcError::InvalidParams(s),
            other => HtlcError::Network(other.to_string()),
        }
    }
}

impl From<Error> for WatchError {
    fn from(e: Error) -> WatchError {
        WatchError::Network(e.to_string())
    }
}

#[derive(Clone, Debug)]
pub struct RootstockConfig {
    pub network_id: NetworkId,
    pub rpc_url: String,
    pub contract: Option<String>,
    pub chain_id: u64,
    /// 32-byte secret key for the EVM account that locks /
    /// claims / refunds HTLCs. Derived from
    /// `cassis/network/<network_id>`.
    pub sk: [u8; 32],
}

#[derive(Clone, Debug)]
struct PendingIncoming {
    contract: Address,
    amount_wei: U256,
    refund_address: Address,
    timelock: u64,
    deadline: u64,
    arrival: Arc<Notify>,
}

#[derive(Clone, Debug)]
struct PendingOutgoing {
    contract: Address,
    amount_wei: U256,
    refund_address: Address,
    timelock: u64,
}

pub struct RootstockAdapter {
    config: RootstockConfig,
    address: Address,
    contract: Address,
    provider: Box<dyn Provider + Send + Sync>,
    incoming: Mutex<HashMap<Bytes32, PendingIncoming>>,
    outgoing: Mutex<HashMap<Bytes32, PendingOutgoing>>,
}

impl std::fmt::Debug for RootstockAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RootstockAdapter")
            .field("network_id", &self.config.network_id)
            .field("contract", &self.contract)
            .field("address", &self.address)
            .field("chain_id", &self.config.chain_id)
            .finish()
    }
}

impl RootstockAdapter {
    pub async fn new(config: RootstockConfig) -> Result<Arc<Self>, Error> {
        let contract_str = config
            .contract
            .clone()
            .ok_or_else(|| Error::MissingContract(config.network_id.clone()))?;
        let contract = Address::from_str(&contract_str)
            .map_err(|e| Error::InvalidAddress(format!("{contract_str}: {e}")))?;
        let signer = PrivateKeySigner::from_bytes(&B256::from_slice(&config.sk))
            .map_err(|e| Error::InvalidParams(format!("invalid secret key: {e}")))?;
        let address = signer.address();
        let url = Url::from_str(&config.rpc_url)
            .map_err(|e| Error::InvalidParams(format!("invalid rpc url: {e}")))?;
        let wallet = EthereumWallet::from(signer);
        let provider: Box<dyn Provider + Send + Sync> = Box::new(
            ProviderBuilder::new_with_network::<Ethereum>()
                .wallet(wallet)
                .connect_http(url),
        );
        Ok(Arc::new(Self {
            config,
            address,
            contract,
            provider,
            incoming: Mutex::new(HashMap::new()),
            outgoing: Mutex::new(HashMap::new()),
        }))
    }

    fn msat_to_wei(msat: u64) -> U256 {
        U256::from(msat as u128).saturating_mul(U256::from(WEI_PER_RBTC / MSAT_PER_RBTC))
    }

    async fn block_number(&self) -> Result<u64, Error> {
        self.provider
            .get_block_number()
            .await
            .map_err(|e| Error::Rpc(e.to_string()))
    }

    /// Current legacy gas price (wei) via `eth_gasPrice`. RSK has
    /// no EIP-1559, so `eth_maxPriorityFeePerGas` is unsupported;
    /// we always build legacy transactions with this price.
    async fn gas_price_wei(&self) -> Result<u128, Error> {
        self.provider
            .get_gas_price()
            .await
            .map_err(|e| Error::Rpc(format!("get_gas_price: {e}")))
    }

    fn unix_now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn compute_swap_hash(
        preimage_hash: B256,
        amount: U256,
        claim: Address,
        refund: Address,
        timelock: u64,
    ) -> B256 {
        use alloy::primitives::keccak256;
        let mut buf = [0u8; 160];
        buf[0..32].copy_from_slice(preimage_hash.as_slice());
        buf[32..64].copy_from_slice(&amount.to_be_bytes::<32>());
        buf[64..84].copy_from_slice(claim.as_slice());
        buf[84..104].copy_from_slice(refund.as_slice());
        let timelock_be = U256::from(timelock).to_be_bytes::<32>();
        buf[128..160].copy_from_slice(&timelock_be);
        keccak256(buf)
    }

    /// Cached EVM address derived from `config.sk` in `new()`.
    pub fn address(&self) -> Address {
        self.address
    }

    /// On-chain RBTC balance of the local EVM address, in msat.
    /// No HTLC state is consulted; this is a plain
    /// `eth_getBalance` against the configured RPC.
    pub async fn balance_msat(&self) -> Result<u64, Error> {
        let wei = self
            .provider
            .get_balance(self.address)
            .await
            .map_err(|e| Error::Rpc(e.to_string()))?;
        let ratio = U256::from(WEI_PER_RBTC / MSAT_PER_RBTC);
        let msat = wei.checked_div(ratio).unwrap_or(U256::ZERO);
        let msat: u128 = msat
            .try_into()
            .map_err(|_| Error::InvalidParams("balance overflows u128".into()))?;
        Ok(u64::try_from(msat)
            .map_err(|_| Error::InvalidParams("balance exceeds u64::MAX msat".into()))?)
    }

    /// Send `amount_msat` worth of RBTC to `to` as a plain
    /// value transfer (no HTLC, no contract call). `to` is a
    /// hex-encoded EVM address (`0x`-prefixed or bare).
    /// Returns the transaction hash; the caller can poll the
    /// RPC for the receipt if they want to confirm inclusion.
    pub async fn transfer(&self, to: &str, amount_msat: u64) -> Result<B256, Error> {
        if amount_msat == 0 {
            return Err(Error::InvalidParams("amount must be > 0".into()));
        }
        let to_addr = parse_address(to)?;
        let wei = Self::msat_to_wei(amount_msat);
        // RSK does not support EIP-1559 (`eth_maxPriorityFeePerGas`
        // → -32601 method not found). Force a legacy tx by setting
        // the gas price explicitly so alloy's gas filler takes the
        // legacy path via `eth_gasPrice`.
        let gas_price = self.gas_price_wei().await?;
        let request = TransactionRequest::default()
            .to(to_addr)
            .value(wei)
            .gas_price(gas_price);
        let pending = self
            .provider
            .send_transaction(request)
            .await
            .map_err(|e| Error::Rpc(format!("transfer send: {e}")))?;
        Ok(*pending.tx_hash())
    }

    /// Raw read-only `eth_call`. `to` is a hex-encoded EVM
    /// address; `calldata` is the already-encoded ABI
    /// calldata bytes (selector + args). Returns the raw
    /// returndata bytes; the caller decodes. Used by the CLI's
    /// `read` subcommand.
    pub async fn eth_call(&self, to: &str, calldata: &[u8]) -> Result<Bytes, Error> {
        let to_addr = parse_address(to)?;
        let request = TransactionRequest::default()
            .to(to_addr)
            .input(Bytes::copy_from_slice(calldata).into());
        let out = self
            .provider
            .call(request)
            .await
            .map_err(|e| Error::Rpc(format!("eth_call: {e}")))?;
        Ok(out)
    }

    /// Broadcast an arbitrary contract call as a signed tx.
    /// `to` is a hex-encoded EVM address; `calldata` is the
    /// already-encoded ABI calldata bytes; `value_msat` is the
    /// RBTC value to attach (may be 0). Returns the tx hash
    /// immediately, then waits for the receipt and returns its
    /// status boolean and gas used.
    pub async fn send_call(
        &self,
        to: &str,
        calldata: &[u8],
        value_msat: u64,
    ) -> Result<(B256, u64, bool), Error> {
        let to_addr = parse_address(to)?;
        let value_wei = Self::msat_to_wei(value_msat);
        // Force legacy gas pricing (see `transfer`).
        let gas_price = self.gas_price_wei().await?;
        let request = TransactionRequest::default()
            .to(to_addr)
            .input(Bytes::copy_from_slice(calldata).into())
            .value(value_wei)
            .gas_price(gas_price);
        let pending = self
            .provider
            .send_transaction(request)
            .await
            .map_err(|e| Error::Rpc(format!("send_call send: {e}")))?;
        let tx_hash = *pending.tx_hash();
        let receipt = pending
            .get_receipt()
            .await
            .map_err(|e| Error::Rpc(format!("send_call receipt: {e}")))?;
        let gas_used = receipt.gas_used;
        Ok((tx_hash, gas_used, receipt.status()))
    }
}

#[async_trait]
impl NetworkRouterAdapter for RootstockAdapter {
    fn network_id(&self) -> NetworkId {
        self.config.network_id.clone()
    }

    /// Rootstock blocks land every ~30 s; the router needs
    /// headroom to lock, watch and claim. Mirrors the
    /// `fallback_incoming_delta` table.
    fn incoming_delta_secs(&self) -> u64 {
        600
    }

    async fn watch_incoming_htlc(
        &self,
        payment_hash: Bytes32,
        min_amount_msat: u64,
        deadline: u64,
    ) -> Result<IncomingHtlc, WatchError> {
        if deadline <= Self::unix_now() {
            return Err(WatchError::DeadlineExceeded);
        }
        let arrival = Arc::new(Notify::new());
        let slot = PendingIncoming {
            contract: self.contract,
            amount_wei: Self::msat_to_wei(min_amount_msat),
            refund_address: Address::ZERO,
            timelock: 0,
            deadline,
            arrival,
        };
        let mut incoming = self.incoming.lock().await;
        incoming.insert(payment_hash, slot);
        Ok(IncomingHtlc {
            payment_hash,
            amount_msat: min_amount_msat,
            expiry: deadline,
            sender: String::new(),
            network: self.config.network_id.clone(),
        })
    }

    async fn create_outgoing_htlc(
        &self,
        payment_hash: Bytes32,
        amount_msat: u64,
        expiry: u64,
        recipient: &str,
    ) -> Result<OutgoingHtlc, HtlcError> {
        if amount_msat == 0 {
            return Err(HtlcError::InvalidParams("amount must be > 0".into()));
        }
        let now = Self::unix_now();
        if expiry <= now {
            return Err(HtlcError::InvalidParams("expiry in the past".into()));
        }
        let claim_address = Address::from_str(recipient).map_err(|e| {
            HtlcError::InvalidParams(format!(
                "recipient '{recipient}' is not an EVM address: {e}"
            ))
        })?;
        let amount_wei = Self::msat_to_wei(amount_msat);
        let latest = self
            .block_number()
            .await
            .map_err(|e| HtlcError::Network(e.to_string()))?;
        let remaining = expiry.saturating_sub(now);
        let blocks_ahead = remaining.div_ceil(RSK_BLOCK_TIME_SECS);
        let timelock = latest.saturating_add(blocks_ahead);

        let preimage_hash = B256::from_slice(payment_hash.as_ref());
        let gas_price = self
            .gas_price_wei()
            .await
            .map_err(|e| HtlcError::Network(e.to_string()))?;
        let request = TransactionRequest::default()
            .to(self.contract)
            .value(amount_wei)
            .gas_price(gas_price)
            .input(
                IEtherSwap::lockCall {
                    preimageHash: preimage_hash,
                    claimAddress: claim_address,
                    refundAddress: self.address,
                    timelock: U256::from(timelock),
                }
                .abi_encode()
                .into(),
            );
        let pending = self
            .provider
            .send_transaction(request)
            .await
            .map_err(|e| HtlcError::Network(format!("lock send: {e}")))?;
        let tx_hash = *pending.tx_hash();
        debug!(
            target: "cassis_rootstock",
            "lock tx sent: payment_hash={} claim={} amount_wei={} timelock={} tx={tx_hash}",
            payment_hash,
            claim_address,
            amount_wei,
            timelock,
        );
        let mut outgoing = self.outgoing.lock().await;
        outgoing.insert(
            payment_hash,
            PendingOutgoing {
                contract: self.contract,
                amount_wei,
                refund_address: self.address,
                timelock,
            },
        );
        Ok(OutgoingHtlc {
            payment_hash,
            amount_msat,
            expiry,
            recipient: recipient.to_string(),
            network: self.config.network_id.clone(),
        })
    }

    async fn claim_incoming(
        &self,
        payment_hash: Bytes32,
        preimage: Bytes32,
    ) -> Result<(), HtlcError> {
        let slot = {
            let incoming = self.incoming.lock().await;
            incoming.get(&payment_hash).cloned()
        };
        let slot = slot.ok_or_else(|| {
            HtlcError::InvalidParams(format!("no incoming HTLC for {payment_hash:?}"))
        })?;
        let now = Self::unix_now();
        if slot.deadline <= now {
            return Err(HtlcError::Network("incoming deadline exceeded".into()));
        }
        if slot.amount_wei.is_zero() {
            return Err(HtlcError::InvalidParams(
                "incoming HTLC has no amount (descriptor not yet accepted)".into(),
            ));
        }
        let gas_price = self
            .gas_price_wei()
            .await
            .map_err(|e| HtlcError::Network(e.to_string()))?;
        let request = TransactionRequest::default()
            .to(slot.contract)
            .gas_price(gas_price)
            .input(
                IEtherSwap::claimCall {
                    preimage: B256::from_slice(preimage.as_ref()),
                    amount: slot.amount_wei,
                    refundAddress: slot.refund_address,
                    timelock: U256::from(slot.timelock),
                }
                .abi_encode()
                .into(),
            );
        let pending = self
            .provider
            .send_transaction(request)
            .await
            .map_err(|e| HtlcError::Network(format!("claim send: {e}")))?;
        let receipt = pending
            .get_receipt()
            .await
            .map_err(|e| HtlcError::Network(format!("claim receipt: {e}")))?;
        if !receipt.status() {
            return Err(HtlcError::Network("claim tx reverted".into()));
        }
        let mut incoming = self.incoming.lock().await;
        incoming.remove(&payment_hash);
        Ok(())
    }

    async fn refund_outgoing(&self, payment_hash: Bytes32) -> Result<(), HtlcError> {
        let slot = {
            let outgoing = self.outgoing.lock().await;
            outgoing.get(&payment_hash).cloned()
        };
        let slot = slot.ok_or_else(|| {
            HtlcError::InvalidParams(format!("no outgoing HTLC for {payment_hash:?}"))
        })?;
        let latest = self
            .block_number()
            .await
            .map_err(|e| HtlcError::Network(e.to_string()))?;
        if latest < slot.timelock {
            return Err(HtlcError::InvalidParams(format!(
                "timelock not reached: latest={latest} timelock={}",
                slot.timelock
            )));
        }
        let gas_price = self
            .gas_price_wei()
            .await
            .map_err(|e| HtlcError::Network(e.to_string()))?;
        let request = TransactionRequest::default()
            .to(slot.contract)
            .gas_price(gas_price)
            .input(
                IEtherSwap::refundCall {
                    preimageHash: B256::from_slice(payment_hash.as_ref()),
                    amount: slot.amount_wei,
                    claimAddress: self.address,
                    timelock: U256::from(slot.timelock),
                }
                .abi_encode()
                .into(),
            );
        let pending = self
            .provider
            .send_transaction(request)
            .await
            .map_err(|e| HtlcError::Network(format!("refund send: {e}")))?;
        let receipt = pending
            .get_receipt()
            .await
            .map_err(|e| HtlcError::Network(format!("refund receipt: {e}")))?;
        if !receipt.status() {
            return Err(HtlcError::Network("refund tx reverted".into()));
        }
        let mut outgoing = self.outgoing.lock().await;
        outgoing.remove(&payment_hash);
        Ok(())
    }

    async fn watch_preimage(
        &self,
        payment_hash: Bytes32,
        deadline: u64,
    ) -> Result<Bytes32, WatchError> {
        let topic = B256::from_slice(payment_hash.as_ref());
        let interval = Duration::from_secs(POLL_INTERVAL_SECS);
        loop {
            if Self::unix_now() >= deadline {
                return Err(WatchError::DeadlineExceeded);
            }
            let filter = Filter::new()
                .address(self.contract)
                .event_signature(IEtherSwap::Claim::SIGNATURE_HASH)
                .topic1(topic)
                .from_block(BlockNumberOrTag::Latest);
            match self.provider.get_logs(&filter).await {
                Ok(logs) => {
                    for log in logs {
                        if log.topics().len() < 2 {
                            continue;
                        }
                        let decoded = match log.log_decode::<IEtherSwap::Claim>() {
                            Ok(d) => d,
                            Err(_) => continue,
                        };
                        let args = &decoded.inner.data;
                        let mut out = [0u8; 32];
                        out.copy_from_slice(args.preimage.as_slice());
                        return Ok(Bytes32(out));
                    }
                }
                Err(e) => {
                    warn!(
                        target: "cassis_rootstock",
                        "watch_preimage get_logs failed: {e}"
                    );
                }
            }
            tokio::time::sleep(interval).await;
        }
    }

    async fn can_route(&self, amount_msat: u64) -> Result<(), HtlcError> {
        let balance = self
            .provider
            .get_balance(self.address)
            .await
            .map_err(|e| HtlcError::Network(e.to_string()))?;
        let needed = Self::msat_to_wei(amount_msat);
        if balance < needed {
            return Err(HtlcError::InvalidParams(format!(
                "insufficient rootstock balance: need {needed} wei, have {balance} wei"
            )));
        }
        Ok(())
    }

    async fn verify_incoming_htlc(
        &self,
        descriptor: &HtlcDescriptor,
        payment_hash: Bytes32,
    ) -> Result<(), HtlcError> {
        let (contract_addr, amount_wei, refund_addr, timelock) = match descriptor {
            HtlcDescriptor::Rootstock {
                contract,
                amount_wei,
                refund_address,
                timelock,
            } => {
                let contract_addr = Address::from_str(contract).map_err(|e| {
                    HtlcError::InvalidParams(format!("invalid contract address: {e}"))
                })?;
                let refund_addr = Address::from_str(refund_address).map_err(|e| {
                    HtlcError::InvalidParams(format!("invalid refund address: {e}"))
                })?;
                (
                    contract_addr,
                    U256::from(*amount_wei),
                    refund_addr,
                    *timelock,
                )
            }
            other => {
                return Err(HtlcError::Network(format!(
                    "unsupported htlc descriptor for rootstock network: {other:?}"
                )));
            }
        };
        let hash = Self::compute_swap_hash(
            B256::from_slice(payment_hash.as_ref()),
            amount_wei,
            self.address,
            refund_addr,
            timelock,
        );
        let call = IEtherSwap::swapsCall(hash);
        let request = TransactionRequest::default()
            .to(contract_addr)
            .input(call.abi_encode().into());
        let out_bytes = self
            .provider
            .call(request)
            .await
            .map_err(|e| HtlcError::Network(e.to_string()))?;
        if out_bytes.len() < 32 {
            return Err(HtlcError::Network(format!(
                "swaps() returned {} bytes, expected >=32",
                out_bytes.len()
            )));
        }
        let locked = out_bytes[31] != 0;
        if !locked {
            return Err(HtlcError::Network(
                "swap not found on chain (hash mismatch)".into(),
            ));
        }
        Ok(())
    }

    async fn accept_incoming_htlc(
        &self,
        payment_hash: Bytes32,
        descriptor: &HtlcDescriptor,
        deadline: u64,
    ) -> Result<(), HtlcError> {
        self.verify_incoming_htlc(descriptor, payment_hash).await?;
        let (contract_str, amount_wei, refund_address, timelock) = match descriptor {
            HtlcDescriptor::Rootstock {
                contract,
                amount_wei,
                refund_address,
                timelock,
            } => (
                contract.clone(),
                *amount_wei,
                refund_address.clone(),
                *timelock,
            ),
            _ => unreachable!("verify_incoming_htlc rejects other variants"),
        };
        let contract = Address::from_str(&contract_str)
            .map_err(|e| HtlcError::InvalidParams(format!("invalid contract address: {e}")))?;
        let refund_address = Address::from_str(&refund_address)
            .map_err(|e| HtlcError::InvalidParams(format!("invalid refund address: {e}")))?;
        let mut incoming = self.incoming.lock().await;
        let arrival = match incoming.get_mut(&payment_hash) {
            Some(slot) => {
                slot.contract = contract;
                slot.amount_wei = U256::from(amount_wei);
                slot.refund_address = refund_address;
                slot.timelock = timelock;
                slot.deadline = deadline;
                slot.arrival.clone()
            }
            None => {
                let arrival = Arc::new(Notify::new());
                incoming.insert(
                    payment_hash,
                    PendingIncoming {
                        contract,
                        amount_wei: U256::from(amount_wei),
                        refund_address,
                        timelock,
                        deadline,
                        arrival: arrival.clone(),
                    },
                );
                arrival
            }
        };
        drop(incoming);
        arrival.notify_one();
        Ok(())
    }

    async fn outgoing_htlc_descriptor(
        &self,
        payment_hash: Bytes32,
    ) -> Result<HtlcDescriptor, HtlcError> {
        let slot = {
            let outgoing = self.outgoing.lock().await;
            outgoing.get(&payment_hash).cloned()
        };
        let slot = slot.ok_or_else(|| {
            HtlcError::InvalidParams(format!("no outgoing HTLC for {payment_hash:?}"))
        })?;
        let amount_wei: u128 = slot
            .amount_wei
            .try_into()
            .map_err(|_| HtlcError::Network("amount_wei overflows u128".into()))?;
        Ok(HtlcDescriptor::Rootstock {
            contract: format!("{:#x}", slot.contract),
            amount_wei,
            refund_address: format!("{:#x}", slot.refund_address),
            timelock: slot.timelock,
        })
    }
}

/// Pick the canonical config for a given `NetworkId`. Returns
/// the public RPC endpoint and the configured EtherSwap
/// contract for mainnet (`rootstock`) or testnet
/// (`rootstock::testnet`). Callers can override `contract` on the
/// returned config before constructing the adapter.
pub fn default_config(network_id: NetworkId, sk: [u8; 32]) -> RootstockConfig {
    match network_id.0.as_str() {
        "rootstock::testnet" => RootstockConfig {
            network_id,
            rpc_url: ROOTSTOCK_TESTNET_RPC.to_string(),
            contract: Some(ROOTSTOCK_TESTNET_CONTRACT.to_string()),
            chain_id: ROOTSTOCK_TESTNET_CHAIN_ID,
            sk,
        },
        _ => RootstockConfig {
            network_id,
            rpc_url: ROOTSTOCK_MAINNET_RPC.to_string(),
            contract: Some(ROOTSTOCK_MAINNET_CONTRACT.to_string()),
            chain_id: ROOTSTOCK_MAINNET_CHAIN_ID,
            sk,
        },
    }
}

/// Derive the EVM address for a 32-byte secret key without
/// touching the network. Used by the CLI's `info` subcommand
/// so showing the local address doesn't need an RPC
/// connection.
pub fn address_from_sk(sk: [u8; 32]) -> Result<Address, Error> {
    let signer = PrivateKeySigner::from_bytes(&B256::from_slice(&sk))
        .map_err(|e| Error::InvalidParams(format!("invalid secret key: {e}")))?;
    Ok(signer.address())
}

/// Parse a hex-encoded `0x`-prefixed (or bare) EVM address.
pub fn parse_address(s: &str) -> Result<Address, Error> {
    Address::from_str(s.trim()).map_err(|e| Error::InvalidAddress(format!("'{s}': {e}")))
}

/// Parse hex calldata (`0x`-prefixed or bare) into bytes. Odd
/// length or non-hex characters produce `Error::InvalidParams`.
pub fn parse_hex(s: &str) -> Result<Vec<u8>, Error> {
    let trimmed = s.trim();
    let stripped = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if stripped.len() % 2 != 0 {
        return Err(Error::InvalidParams(format!(
            "hex string has odd length ({} chars)",
            stripped.len()
        )));
    }
    let bytes = stripped.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i]).ok_or_else(|| {
            Error::InvalidParams(format!("invalid hex char '{}'", bytes[i] as char))
        })?;
        let lo = hex_nibble(bytes[i + 1]).ok_or_else(|| {
            Error::InvalidParams(format!("invalid hex char '{}'", bytes[i + 1] as char))
        })?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// ABI-encode a function call from a JSON ABI entry and a JSON
/// array of args. `abi_entry_json` is a function ABI entry:
///
/// ```json
/// {"name":"transfer","inputs":[{"name":"to","type":"address"},
///                              {"name":"amount","type":"uint256"}],
///  "outputs":[]}
/// ```
///
/// `args_json` is a JSON array of values, one per input, in
/// order. Returns the encoded calldata (4-byte selector +
/// ABI-encoded args).
pub fn encode_call(abi_entry_json: &str, args_json: &str) -> Result<Vec<u8>, Error> {
    use alloy::json_abi::Function;
    let function: Function = serde_json::from_str(abi_entry_json)
        .map_err(|e| Error::InvalidParams(format!("invalid ABI entry: {e}")))?;
    let args: serde_json::Value = serde_json::from_str(args_json)
        .map_err(|e| Error::InvalidParams(format!("invalid args JSON: {e}")))?;
    let args = args
        .as_array()
        .ok_or_else(|| Error::InvalidParams("--args must be a JSON array".into()))?;
    if args.len() != function.inputs.len() {
        return Err(Error::InvalidParams(format!(
            "arg count mismatch: ABI has {} input(s), got {} arg(s)",
            function.inputs.len(),
            args.len()
        )));
    }
    let mut values = Vec::with_capacity(args.len());
    for (input, arg) in function.inputs.iter().zip(args.iter()) {
        let ty = DynSolType::parse(&input.ty)
            .map_err(|e| Error::InvalidParams(format!("invalid type '{}': {e}", input.ty)))?;
        values.push(json_to_dyn(&ty, arg)?);
    }
    function
        .abi_encode_input(&values)
        .map_err(|e| Error::InvalidParams(format!("ABI encode: {e}")))
}

/// Convert a JSON value to a [`DynSolValue`] matching `ty`.
/// Supports the common Solidity types: bool, signed/unsigned
/// ints, addresses, bytes, strings, and nested arrays/tuples.
fn json_to_dyn(ty: &DynSolType, v: &serde_json::Value) -> Result<DynSolValue, Error> {
    use serde_json::Value;
    match ty {
        DynSolType::Bool => match v {
            Value::Bool(b) => Ok(DynSolValue::Bool(*b)),
            _ => Err(Error::InvalidParams("expected JSON bool".into())),
        },
        DynSolType::Int(bits) => {
            let i = json_i256(v)?;
            Ok(DynSolValue::Int(i, *bits))
        }
        DynSolType::Uint(bits) => {
            let u = json_u256(v)?;
            Ok(DynSolValue::Uint(u, *bits))
        }
        DynSolType::FixedBytes(len) => {
            let b = json_bytes(v)?;
            if b.len() != *len {
                return Err(Error::InvalidParams(format!(
                    "bytes{} expected, got {} byte(s)",
                    len,
                    b.len()
                )));
            }
            let mut word = [0u8; 32];
            word[..b.len()].copy_from_slice(&b);
            Ok(DynSolValue::FixedBytes(B256::from(word), *len))
        }
        DynSolType::Address => {
            let s = json_scalar_string(v)?;
            let a = parse_address(&s)?;
            Ok(DynSolValue::Address(a))
        }
        DynSolType::Function => Err(Error::InvalidParams(
            "ABI 'function' type is not supported".into(),
        )),
        DynSolType::Bytes => Ok(DynSolValue::Bytes(json_bytes(v)?)),
        DynSolType::String => {
            let s = match v {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            Ok(DynSolValue::String(s))
        }
        DynSolType::Array(inner) => {
            let arr = v
                .as_array()
                .ok_or_else(|| Error::InvalidParams("expected JSON array".into()))?;
            let mut out = Vec::with_capacity(arr.len());
            for el in arr {
                out.push(json_to_dyn(inner, el)?);
            }
            Ok(DynSolValue::Array(out))
        }
        DynSolType::FixedArray(inner, n) => {
            let arr = v
                .as_array()
                .ok_or_else(|| Error::InvalidParams("expected JSON array".into()))?;
            if arr.len() != *n {
                return Err(Error::InvalidParams(format!(
                    "expected array of {n}, got {} element(s)",
                    arr.len()
                )));
            }
            let mut out = Vec::with_capacity(arr.len());
            for el in arr {
                out.push(json_to_dyn(inner, el)?);
            }
            Ok(DynSolValue::FixedArray(out))
        }
        DynSolType::Tuple(inners) => {
            let arr = v
                .as_array()
                .ok_or_else(|| Error::InvalidParams("expected JSON array".into()))?;
            if arr.len() != inners.len() {
                return Err(Error::InvalidParams(format!(
                    "tuple expects {} element(s), got {}",
                    inners.len(),
                    arr.len()
                )));
            }
            let mut out = Vec::with_capacity(arr.len());
            for (inner, el) in inners.iter().zip(arr.iter()) {
                out.push(json_to_dyn(inner, el)?);
            }
            Ok(DynSolValue::Tuple(out))
        }
        #[allow(unreachable_patterns)]
        other => Err(Error::InvalidParams(format!(
            "type '{}' not supported",
            other
        ))),
    }
}

/// Extract a JSON number (decimal or `0x`-hex) or hex string as
/// a [`U256`].
fn json_u256(v: &serde_json::Value) -> Result<U256, Error> {
    match v {
        serde_json::Value::Number(n) => {
            let s = n.to_string();
            U256::from_str_radix(&s, 10)
                .map_err(|e| Error::InvalidParams(format!("invalid uint '{s}': {e}")))
        }
        serde_json::Value::String(s) => number_from_hex_or_dec(s),
        other => Err(Error::InvalidParams(format!("expected uint, got {other}"))),
    }
}

fn json_i256(v: &serde_json::Value) -> Result<I256, Error> {
    match v {
        serde_json::Value::Number(n) => {
            let s = n.to_string();
            I256::from_dec_str(&s)
                .map_err(|e| Error::InvalidParams(format!("invalid int '{s}': {e}")))
        }
        serde_json::Value::String(s) => int_from_hex_or_dec(s),
        other => Err(Error::InvalidParams(format!("expected int, got {other}"))),
    }
}

fn number_from_hex_or_dec(s: &str) -> Result<U256, Error> {
    let t = s.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        U256::from_str_radix(hex, 16)
            .map_err(|e| Error::InvalidParams(format!("invalid hex number '{t}': {e}")))
    } else {
        U256::from_str_radix(t, 10)
            .map_err(|e| Error::InvalidParams(format!("invalid number '{t}': {e}")))
    }
}

fn int_from_hex_or_dec(s: &str) -> Result<I256, Error> {
    let t = s.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        I256::from_hex_str(hex)
            .map_err(|e| Error::InvalidParams(format!("invalid hex int '{t}': {e}")))
    } else {
        I256::from_dec_str(t).map_err(|e| Error::InvalidParams(format!("invalid int '{t}': {e}")))
    }
}

fn json_bytes(v: &serde_json::Value) -> Result<Vec<u8>, Error> {
    match v {
        serde_json::Value::String(s) => parse_hex(s),
        serde_json::Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    serde_json::Value::Number(n) => {
                        let byte = n
                            .as_u64()
                            .ok_or_else(|| Error::InvalidParams(format!("invalid byte '{n}'")))?;
                        out.push(u8::try_from(byte).map_err(|_| {
                            Error::InvalidParams(format!("byte out of range '{n}'"))
                        })?);
                    }
                    other => {
                        return Err(Error::InvalidParams(format!("expected byte, got {other}")))
                    }
                }
            }
            Ok(out)
        }
        other => Err(Error::InvalidParams(format!(
            "expected hex string or byte array, got {other}"
        ))),
    }
}

fn json_scalar_string(v: &serde_json::Value) -> Result<String, Error> {
    match v {
        serde_json::Value::String(s) => Ok(s.clone()),
        other => Err(Error::InvalidParams(format!(
            "expected string value, got {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msat_to_wei_uses_one_rbtc_per_100_billion_msat() {
        let one_rbtc_in_msat = 100_000_000_000u64;
        let one_rbtc_in_wei = U256::from(1_000_000_000_000_000_000u128);
        assert_eq!(
            RootstockAdapter::msat_to_wei(one_rbtc_in_msat),
            one_rbtc_in_wei
        );
    }

    #[test]
    fn compute_swap_hash_matches_keccak_of_abi_packed_fields() {
        let preimage_hash = B256::from_slice(&[1u8; 32]);
        let amount = U256::from(123_456u64);
        let claim = Address::from_str("0x1111111111111111111111111111111111111111").unwrap();
        let refund = Address::from_str("0x2222222222222222222222222222222222222222").unwrap();
        let timelock: u64 = 9999;
        let h = RootstockAdapter::compute_swap_hash(preimage_hash, amount, claim, refund, timelock);
        let mut buf = [0u8; 160];
        buf[0..32].copy_from_slice(preimage_hash.as_slice());
        buf[32..64].copy_from_slice(&amount.to_be_bytes::<32>());
        buf[64..84].copy_from_slice(claim.as_slice());
        buf[84..104].copy_from_slice(refund.as_slice());
        let timelock_be = U256::from(timelock).to_be_bytes::<32>();
        buf[128..160].copy_from_slice(&timelock_be);
        let expected = alloy::primitives::keccak256(buf);
        assert_eq!(h, expected);
    }

    #[test]
    fn default_config_mainnet_has_contract_and_rpc() {
        let cfg = default_config(NetworkId("rootstock".to_string()), [7u8; 32]);
        assert_eq!(cfg.rpc_url, ROOTSTOCK_MAINNET_RPC);
        assert_eq!(cfg.chain_id, 30);
        assert_eq!(cfg.contract.as_deref(), Some(ROOTSTOCK_MAINNET_CONTRACT));
    }

    #[test]
    fn default_config_testnet_has_contract_and_rpc() {
        let cfg = default_config(NetworkId("rootstock::testnet".to_string()), [7u8; 32]);
        assert_eq!(cfg.rpc_url, ROOTSTOCK_TESTNET_RPC);
        assert_eq!(cfg.chain_id, 31);
        assert_eq!(cfg.contract.as_deref(), Some(ROOTSTOCK_TESTNET_CONTRACT));
    }

    #[test]
    fn encode_call_transfer_selectors_and_args() {
        let calldata = encode_call(
            r#"{"name":"transfer","inputs":[{"name":"to","type":"address"},{"name":"amount","type":"uint256"}],"outputs":[]}"#,
            r#"["0x1111111111111111111111111111111111111111", 5]"#,
        )
        .unwrap();
        // transfer(address,uint256) -> 0xa9059cbb
        assert_eq!(calldata[0..4], [0xa9, 0x05, 0x9c, 0xbb]);
        assert_eq!(calldata.len(), 4 + 32 + 32);
    }

    #[test]
    fn encode_call_rejects_arg_count_mismatch() {
        let result = encode_call(
            r#"{"name":"transfer","inputs":[{"name":"to","type":"address"},{"name":"amount","type":"uint256"}],"outputs":[]}"#,
            r#"["0x1111111111111111111111111111111111111111"]"#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn encode_call_supports_string_and_bool() {
        let calldata = encode_call(
            r#"{"name":"set","inputs":[{"name":"msg","type":"string"},{"name":"flag","type":"bool"}],"outputs":[]}"#,
            r#"["hello world", true]"#,
        )
        .unwrap();
        // selector + offset + bool + string len + padded "hello world" (32)
        assert_eq!(calldata.len(), 4 + 32 + 32 + 32 + 32);
    }

    #[test]
    fn encode_call_supports_hex_uint_and_bytes() {
        let calldata = encode_call(
            r#"{"name":"f","inputs":[{"name":"a","type":"uint256"},{"name":"b","type":"bytes"}],"outputs":[]}"#,
            r#"["0xff", "0xabcd"]"#,
        )
        .unwrap();
        assert_eq!(calldata[4 + 32 - 1], 0xff);
        assert!(calldata.contains(&0xab));
        assert!(calldata.contains(&0xcd));
    }
}
