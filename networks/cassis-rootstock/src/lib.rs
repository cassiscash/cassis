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
        let request = TransactionRequest::default()
            .to(self.contract)
            .value(amount_wei)
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
        let request = TransactionRequest::default().to(slot.contract).input(
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
        let request = TransactionRequest::default().to(slot.contract).input(
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
}
