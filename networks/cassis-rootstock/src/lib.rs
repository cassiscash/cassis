use alloy::consensus::Transaction;
use alloy::dyn_abi::{DynSolType, DynSolValue, JsonAbiExt};
use alloy::eips::BlockNumberOrTag;
use alloy::network::{Ethereum, EthereumWallet};
use alloy::primitives::{Address, Bytes, B256, I256, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::eth::{BlockTransactions, TransactionRequest};
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use alloy::sol_types::SolCall;
use alloy::transports::http::reqwest::Url;
use async_trait::async_trait;
use cassis_core::{
    AcceptedIncoming, AdapterError, Bytes32, HtlcDescriptor, HtlcTarget, IncomingRequest,
    IncomingReservation, NetworkAdapter, NetworkId, OperationId, OutgoingPayment, OutgoingRequest,
    PubKey, XOnlyPubKey,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, Notify};
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
const ROOTSTOCK_MAINNET_CHAIN_ID: u64 = 30;
const ROOTSTOCK_TESTNET_CHAIN_ID: u64 = 31;

/// EtherSwap v3 contract on Rootstock mainnet. Deployed by
/// Boltz (`0x1Bdf482F5da32ef51c20D9A94960385c5be9AaB7`).
const ROOTSTOCK_MAINNET_CONTRACT: &str = "0x3612e393cA2fbB8874854B88fFCf04307a518239";
const ROOTSTOCK_TESTNET_CONTRACT: &str = "0x165f8e654b3fe310a854805323718d51977ad95f";

/// Gas a `EtherSwap.lock()` consumes, used to reserve gas before
/// committing to a route and to cap the lock transaction itself.
const LOCK_TX_GAS: u64 = 50_000;
/// Gas an `EtherSwap.claim()` consumes; the reserve for the incoming
/// side of a route.
const CLAIM_TX_GAS: u64 = 30_000;

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

impl From<Error> for AdapterError {
    fn from(e: Error) -> AdapterError {
        match e {
            Error::InvalidParams(s) | Error::InvalidAddress(s) => AdapterError::InvalidParams(s),
            Error::NoIncoming(s) | Error::NoOutgoing(s) => AdapterError::InvalidParams(s),
            other => AdapterError::Network(other.to_string()),
        }
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
    ///
    /// Normalized to its even-Y form in [`RootstockAdapter::new`] so
    /// that the x-only pubkey advertised via
    /// [`NetworkAdapter::claim_pubkey`] maps to exactly one EVM
    /// address, and that address is the one this key can sign for.
    pub sk: [u8; 32],
    pub invoice_pubkey: XOnlyPubKey,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RootstockHtlc {
    contract: Address,
    amount_wei: U256,
    claim_address: Address,
    refund_address: Address,
    timelock: u64,
}

impl RootstockHtlc {
    fn parse(descriptor: &HtlcDescriptor) -> Result<Self, AdapterError> {
        let HtlcDescriptor::Rootstock {
            contract,
            amount_wei,
            claim_address,
            refund_address,
            timelock,
        } = descriptor
        else {
            return Err(AdapterError::InvalidParams(format!(
                "unsupported htlc descriptor for rootstock network: {descriptor:?}"
            )));
        };
        Ok(Self {
            contract: Address::from_str(contract).map_err(|e| {
                AdapterError::InvalidParams(format!("invalid contract address: {e}"))
            })?,
            amount_wei: U256::from(*amount_wei),
            claim_address: Address::from_str(claim_address)
                .map_err(|e| AdapterError::InvalidParams(format!("invalid claim address: {e}")))?,
            refund_address: Address::from_str(refund_address)
                .map_err(|e| AdapterError::InvalidParams(format!("invalid refund address: {e}")))?,
            timelock: *timelock,
        })
    }

    fn to_descriptor(&self) -> Result<HtlcDescriptor, AdapterError> {
        Ok(HtlcDescriptor::Rootstock {
            contract: format!("{:#x}", self.contract),
            amount_wei: self.amount_wei.try_into().map_err(|_| {
                AdapterError::Network("amount_wei overflows descriptor field".into())
            })?,
            claim_address: format!("{:#x}", self.claim_address),
            refund_address: format!("{:#x}", self.refund_address),
            timelock: self.timelock,
        })
    }
}

#[derive(Clone, Debug)]
struct PendingIncoming {
    payment_hash: Bytes32,
    reserved_amount_wei: U256,
    deadline: u64,
    accepted: Option<AcceptedIncoming>,
    arrival: Arc<Notify>,
}

#[derive(Clone, Debug)]
struct PendingOutgoing {
    payment_hash: Bytes32,
    amount_msat: u64,
    expiry: u64,
    recipient: PubKey,
    funded: Option<RootstockHtlc>,
    verified: bool,
}

pub struct RootstockAdapter {
    config: RootstockConfig,
    /// `config.span` with this adapter's `network` field attached, so
    /// every log below carries both the owning node and the network.
    /// Built once in [`RootstockAdapter::new`]: the adapter's methods
    /// are driven from unrelated tasks (the router's poll loop, an iroh
    /// request handler), so the ambient span at call time is no help.
    span: Span,
    address: Address,
    /// x-only pubkey of the (normalized) `config.sk`. Advertised to
    /// counterparties so they lock HTLCs to `self.address`.
    claim_pubkey: XOnlyPubKey,
    contract: Address,
    provider: Box<dyn Provider + Send + Sync>,
    incoming: Mutex<HashMap<OperationId, PendingIncoming>>,
    outgoing: Mutex<HashMap<OperationId, PendingOutgoing>>,
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
        // Normalize before deriving anything: the claim identity we
        // advertise is x-only, so the secret key must be the even-Y
        // representative or the address we advertise is not the address
        // we can sign for. See `normalized_key`.
        let mut config = config;
        let (normalized_sk, claim_pubkey) = normalized_key(config.sk)?;
        config.sk = normalized_sk;
        let signer = PrivateKeySigner::from_bytes(&B256::from_slice(&config.sk))
            .map_err(|e| Error::InvalidParams(format!("invalid secret key: {e}")))?;
        let address = signer.address();
        // Fail loudly at startup rather than on-chain: if these ever
        // disagree, every counterparty would lock HTLCs to an address
        // this adapter cannot claim from, and the funds would sit until
        // the timelock expired.
        let derived = evm_address_from_xonly(&claim_pubkey);
        if derived != address {
            return Err(Error::InvalidParams(format!(
                "claim identity mismatch: x-only pubkey {} maps to {derived} but the \
                 signing key controls {address}",
                claim_pubkey.to_hex(),
            )));
        }
        let url = Url::from_str(&config.rpc_url)
            .map_err(|e| Error::InvalidParams(format!("invalid rpc url: {e}")))?;
        let wallet = EthereumWallet::from(signer);
        let provider: Box<dyn Provider + Send + Sync> = Box::new(
            ProviderBuilder::new_with_network::<Ethereum>()
                .wallet(wallet)
                .connect_http(url),
        );
        let span = cassis_core::network_span(&config.span, &config.network_id);
        // `debug!`, not `info!`: adapters are rebuilt for every balance
        // query, so this would otherwise fire on each poll.
        span.in_scope(|| {
            debug!(
                target: "cassis_rootstock",
                "adapter ready: address={address} contract={contract} \
                 claim_pubkey={} rpc={}",
                claim_pubkey.to_hex(),
                config.rpc_url,
            );
        });
        Ok(Arc::new(Self {
            config,
            span,
            address,
            claim_pubkey,
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

    /// Reject a balance that cannot cover the gas for an HTLC claim.
    ///
    /// Shared by the PREPARE-time [`NetworkAdapter::can_claim`]
    /// and the claim itself, so both agree on what "affordable" means.
    /// The lock side lives in [`NetworkAdapter::can_route`], which
    /// reserves the same gas on top of the HTLC value.
    fn ensure_claim_gas(&self, balance: U256, gas_price: u128) -> Result<(), AdapterError> {
        let reserve = gas_reserve(CLAIM_TX_GAS, gas_price);
        if balance < reserve {
            return Err(AdapterError::InvalidParams(format!(
                "account {} cannot afford claim gas on {}: \
                 need ~{reserve} wei at {gas_price} wei/gas, have {balance} wei",
                self.address, self.config.network_id,
            )));
        }
        Ok(())
    }

    fn unix_now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
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
        u64::try_from(msat)
            .map_err(|_| Error::InvalidParams("balance exceeds u64::MAX msat".into()))
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
            .map_err(|e| Error::Rpc(format!("send_call receipt (tx {tx_hash}): {e}")))?;
        let gas_used = receipt.gas_used;
        if !receipt.status() {
            return Err(Error::Rpc(format!(
                "send_call transaction {tx_hash} reverted"
            )));
        }
        Ok((tx_hash, gas_used, receipt.status()))
    }
}

impl RootstockAdapter {
    async fn find_claim_preimage_in_block(
        &self,
        block_number: u64,
        payment_hash: Bytes32,
    ) -> Result<Option<Bytes32>, Error> {
        let block = self
            .provider
            .get_block_by_number(BlockNumberOrTag::Number(block_number))
            .full()
            .await
            .map_err(|e| Error::Rpc(format!("get_block_by_number({block_number}): {e}")))?;

        let Some(block) = block else {
            return Ok(None);
        };
        let BlockTransactions::Full(transactions) = &block.transactions else {
            return Ok(None);
        };

        for transaction in transactions {
            if transaction.to() != Some(self.contract) {
                continue;
            }
            let input = transaction.input();
            if input.len() < 4 {
                continue;
            }
            let Ok(decoded) = IEtherSwap::claimCall::abi_decode(input) else {
                continue;
            };
            let digest = Sha256::digest(decoded.preimage.as_slice());
            if digest.as_slice() == payment_hash.as_ref() {
                let mut preimage = [0u8; 32];
                preimage.copy_from_slice(decoded.preimage.as_slice());
                return Ok(Some(Bytes32(preimage)));
            }
        }
        Ok(None)
    }
}

impl RootstockAdapter {
    fn claim_target(&self) -> Result<HtlcTarget, AdapterError> {
        let mut compressed = [0u8; 33];
        compressed[0] = 0x02;
        compressed[1..].copy_from_slice(self.claim_pubkey.as_bytes());
        let pubkey = PubKey::from_bytes(compressed)
            .map_err(|e| AdapterError::InvalidParams(format!("invalid claim pubkey: {e}")))?;
        Ok(HtlcTarget::PubKey(pubkey))
    }

    fn validate_incoming_request(&self, request: &IncomingRequest) -> Result<(), AdapterError> {
        if !request.operation_id.is_valid() {
            return Err(AdapterError::InvalidParams(
                "operation_id must be 32 hexadecimal characters".into(),
            ));
        }
        if request.payment_hash.0.iter().all(|byte| *byte == 0) {
            return Err(AdapterError::InvalidParams("zero payment hash".into()));
        }
        if request.amount_msat == 0 {
            return Err(AdapterError::InvalidParams(
                "incoming amount must be > 0".into(),
            ));
        }
        if request
            .preimage
            .is_some_and(|preimage| !request.payment_hash.matches_preimage(&preimage))
        {
            return Err(AdapterError::InvalidParams(
                "incoming preimage does not match payment hash".into(),
            ));
        }
        Ok(())
    }

    fn incoming_reservation(
        &self,
        request: &IncomingRequest,
        target: HtlcTarget,
    ) -> IncomingReservation {
        IncomingReservation {
            operation_id: request.operation_id.clone(),
            payment_hash: request.payment_hash,
            network: self.network_id(),
            amount_msat: request.amount_msat,
            deadline: request.deadline,
            target,
        }
    }

    fn validate_incoming_reservation(
        &self,
        reservation: &IncomingReservation,
    ) -> Result<(), AdapterError> {
        if !reservation.operation_id.is_valid() {
            return Err(AdapterError::InvalidParams(
                "operation_id must be 32 hexadecimal characters".into(),
            ));
        }
        if reservation.network != self.network_id() {
            return Err(AdapterError::InvalidParams(format!(
                "reservation network {} does not match adapter {}",
                reservation.network,
                self.network_id()
            )));
        }
        if reservation.payment_hash.0.iter().all(|byte| *byte == 0) {
            return Err(AdapterError::InvalidParams("zero payment hash".into()));
        }
        if reservation.amount_msat == 0 {
            return Err(AdapterError::InvalidParams(
                "incoming amount must be > 0".into(),
            ));
        }
        if reservation.target != self.claim_target()? {
            return Err(AdapterError::InvalidParams(
                "incoming reservation targets wrong Rootstock claim key".into(),
            ));
        }
        Ok(())
    }

    fn validate_incoming_state(
        &self,
        state: &PendingIncoming,
        reservation: &IncomingReservation,
    ) -> Result<(), AdapterError> {
        if state.payment_hash != reservation.payment_hash
            || state.deadline != reservation.deadline
            || state.reserved_amount_wei != Self::msat_to_wei(reservation.amount_msat)
        {
            return Err(AdapterError::InvalidParams(format!(
                "incoming reservation does not match operation {}",
                reservation.operation_id
            )));
        }
        Ok(())
    }

    fn accepted_incoming_matches(left: &AcceptedIncoming, right: &AcceptedIncoming) -> bool {
        left.reservation == right.reservation
            && left.descriptor == right.descriptor
            && left.amount_msat == right.amount_msat
    }

    fn amount_msat_from_wei(&self, amount_wei: U256) -> Result<u64, AdapterError> {
        let wei_per_msat = U256::from(WEI_PER_RBTC / MSAT_PER_RBTC);
        let (msat, remainder) = (amount_wei / wei_per_msat, amount_wei % wei_per_msat);
        if !remainder.is_zero() {
            return Err(AdapterError::InvalidParams(
                "Rootstock HTLC amount is not a whole number of msat".into(),
            ));
        }
        let msat: u128 = msat
            .try_into()
            .map_err(|_| AdapterError::InvalidParams("HTLC amount overflows u128 msat".into()))?;
        u64::try_from(msat)
            .map_err(|_| AdapterError::InvalidParams("HTLC amount overflows u64 msat".into()))
    }

    fn validate_outgoing_request(&self, request: &OutgoingRequest) -> Result<PubKey, AdapterError> {
        if !request.operation_id.is_valid() {
            return Err(AdapterError::InvalidParams(
                "operation_id must be 32 hexadecimal characters".into(),
            ));
        }
        if request.network != self.network_id() {
            return Err(AdapterError::InvalidParams(format!(
                "outgoing network {} does not match adapter {}",
                request.network,
                self.network_id()
            )));
        }
        if request.payment_hash.0.iter().all(|byte| *byte == 0) {
            return Err(AdapterError::InvalidParams("zero payment hash".into()));
        }
        if request.amount_msat == 0 {
            return Err(AdapterError::InvalidParams("amount must be > 0".into()));
        }
        match request.target {
            HtlcTarget::PubKey(pubkey) => Ok(pubkey),
            HtlcTarget::XOnlyPubKey(_)
            | HtlcTarget::LightningInvoice(_)
            | HtlcTarget::SparkAddress(_) => Err(AdapterError::InvalidParams(
                "rootstock requires a full pubkey target".into(),
            )),
        }
    }

    fn validate_outgoing_payment(
        &self,
        payment: &OutgoingPayment,
    ) -> Result<(PubKey, RootstockHtlc), AdapterError> {
        if !payment.operation_id.is_valid() {
            return Err(AdapterError::InvalidParams(
                "operation_id must be 32 hexadecimal characters".into(),
            ));
        }
        if payment.destination_network != self.network_id() {
            return Err(AdapterError::InvalidParams(format!(
                "outgoing network {} does not match adapter {}",
                payment.destination_network,
                self.network_id()
            )));
        }
        if payment.payment_hash.0.iter().all(|byte| *byte == 0) {
            return Err(AdapterError::InvalidParams("zero payment hash".into()));
        }
        if payment.amount_msat == 0 {
            return Err(AdapterError::InvalidParams("amount must be > 0".into()));
        }
        let recipient = match payment.destination {
            HtlcTarget::PubKey(pubkey) => pubkey,
            HtlcTarget::XOnlyPubKey(_)
            | HtlcTarget::LightningInvoice(_)
            | HtlcTarget::SparkAddress(_) => {
                return Err(AdapterError::InvalidParams(
                    "rootstock requires a full pubkey destination".into(),
                ))
            }
        };
        let htlc = RootstockHtlc::parse(&payment.descriptor)?;
        if htlc.contract != self.contract {
            return Err(AdapterError::InvalidParams(format!(
                "descriptor contract {} does not match configured contract {}",
                htlc.contract, self.contract
            )));
        }
        if htlc.amount_wei != Self::msat_to_wei(payment.amount_msat) {
            return Err(AdapterError::InvalidParams(
                "Rootstock descriptor amount does not match outgoing payment".into(),
            ));
        }
        if htlc.claim_address != evm_address_from_pubkey(&recipient) {
            return Err(AdapterError::InvalidParams(
                "Rootstock descriptor claim address does not match destination".into(),
            ));
        }
        if htlc.refund_address != self.address {
            return Err(AdapterError::InvalidParams(
                "Rootstock descriptor refund address is not this adapter".into(),
            ));
        }
        Ok((recipient, htlc))
    }

    fn outgoing_state_matches_request(
        state: &PendingOutgoing,
        request: &OutgoingRequest,
        recipient: &PubKey,
    ) -> Result<(), AdapterError> {
        if state.payment_hash != request.payment_hash
            || state.amount_msat != request.amount_msat
            || state.expiry != request.expiry
            || state.recipient != *recipient
        {
            return Err(AdapterError::InvalidParams(format!(
                "outgoing operation {} already exists with different parameters",
                request.operation_id
            )));
        }
        Ok(())
    }

    fn outgoing_state_matches_payment(
        &self,
        state: &PendingOutgoing,
        payment: &OutgoingPayment,
        recipient: &PubKey,
        htlc: &RootstockHtlc,
    ) -> Result<(), AdapterError> {
        if state.payment_hash != payment.payment_hash
            || state.amount_msat != payment.amount_msat
            || state.expiry != payment.expiry
            || state.recipient != *recipient
        {
            return Err(AdapterError::InvalidParams(format!(
                "outgoing state does not match operation {}",
                payment.operation_id
            )));
        }
        let Some(funded) = state.funded.as_ref() else {
            return Err(AdapterError::NotFound(format!(
                "outgoing operation {} is still being created",
                payment.operation_id
            )));
        };
        if funded.contract != htlc.contract
            || funded.amount_wei != htlc.amount_wei
            || funded.claim_address != htlc.claim_address
            || funded.refund_address != htlc.refund_address
            || funded.timelock != htlc.timelock
        {
            return Err(AdapterError::InvalidParams(format!(
                "outgoing state does not match descriptor for operation {}",
                payment.operation_id
            )));
        }
        Ok(())
    }

    fn outgoing_payment_from_state(
        &self,
        operation_id: &OperationId,
        state: &PendingOutgoing,
    ) -> Result<OutgoingPayment, AdapterError> {
        let funded = state.funded.as_ref().ok_or_else(|| {
            AdapterError::Retryable(format!(
                "outgoing operation {operation_id} is still being created"
            ))
        })?;
        Ok(OutgoingPayment {
            operation_id: operation_id.clone(),
            payment_hash: state.payment_hash,
            amount_msat: state.amount_msat,
            destination: HtlcTarget::PubKey(state.recipient),
            destination_network: self.network_id(),
            expiry: state.expiry,
            descriptor: funded.to_descriptor()?,
        })
    }

    async fn discard_unfunded_outgoing(&self, operation_id: &OperationId, payment_hash: Bytes32) {
        let mut outgoing = self.outgoing.lock().await;
        if outgoing
            .get(operation_id)
            .is_some_and(|state| state.payment_hash == payment_hash && state.funded.is_none())
        {
            outgoing.remove(operation_id);
        }
    }

    async fn verify_htlc(
        &self,
        htlc: &RootstockHtlc,
        payment_hash: Bytes32,
    ) -> Result<(), AdapterError> {
        if htlc.contract != self.contract {
            return Err(AdapterError::InvalidParams(format!(
                "descriptor contract {} does not match configured contract {}",
                htlc.contract, self.contract
            )));
        }
        self.span.in_scope(|| {
            info!(
                target: "cassis_rootstock",
                "checking htlc target={} amount={} hash={}",
                htlc.claim_address,
                htlc.amount_wei,
                payment_hash.short(),
            );
        });
        let hash_values_request = TransactionRequest::default().to(htlc.contract).input(
            IEtherSwap::hashValuesCall {
                preimageHash: B256::from_slice(payment_hash.as_ref()),
                amount: htlc.amount_wei,
                claimAddress: htlc.claim_address,
                refundAddress: htlc.refund_address,
                timelock: U256::from(htlc.timelock),
            }
            .abi_encode()
            .into(),
        );
        let hash_values = self
            .provider
            .call(hash_values_request)
            .await
            .map_err(|e| AdapterError::Network(format!("hashValues() failed: {e}")))?;
        if hash_values.len() < 32 {
            return Err(AdapterError::Network(format!(
                "hashValues() returned {} bytes, expected 32",
                hash_values.len()
            )));
        }
        let swap_hash = B256::from_slice(&hash_values[..32]);
        let request = TransactionRequest::default()
            .to(htlc.contract)
            .input(IEtherSwap::swapsCall(swap_hash).abi_encode().into());
        let out_bytes = self
            .provider
            .call(request)
            .await
            .map_err(|e| AdapterError::Network(e.to_string()))?;
        if out_bytes.len() < 32 {
            return Err(AdapterError::Network(format!(
                "swaps() returned {} bytes, expected >=32",
                out_bytes.len()
            )));
        }
        if out_bytes[31] == 0 {
            return Err(AdapterError::Network(
                "swap not found on chain (hash mismatch)".into(),
            ));
        }
        Ok(())
    }

    async fn accepted_incoming_from_descriptor(
        &self,
        reservation: &IncomingReservation,
        descriptor: &HtlcDescriptor,
        verify_chain: bool,
    ) -> Result<AcceptedIncoming, AdapterError> {
        self.validate_incoming_reservation(reservation)?;
        let htlc = RootstockHtlc::parse(descriptor)?;
        if htlc.contract != self.contract {
            return Err(AdapterError::InvalidParams(format!(
                "descriptor contract {} does not match configured contract {}",
                htlc.contract, self.contract
            )));
        }
        if htlc.claim_address != self.address {
            return Err(AdapterError::InvalidParams(format!(
                "incoming HTLC is locked to {}, which this node cannot claim; expected {} \
                 (upstream hop locked to the wrong identity)",
                htlc.claim_address, self.address
            )));
        }
        let amount_msat = self.amount_msat_from_wei(htlc.amount_wei)?;
        if amount_msat < reservation.amount_msat {
            return Err(AdapterError::InvalidParams(format!(
                "Rootstock HTLC amount {amount_msat} msat below reserved {} msat",
                reservation.amount_msat
            )));
        }
        if verify_chain {
            let latest = self
                .block_number()
                .await
                .map_err(|e| AdapterError::Network(e.to_string()))?;
            let required_timelock = latest.saturating_add(
                reservation
                    .deadline
                    .saturating_sub(Self::unix_now())
                    .div_ceil(RSK_BLOCK_TIME_SECS),
            );
            if htlc.timelock < required_timelock {
                return Err(AdapterError::InvalidParams(format!(
                    "Rootstock refund timelock {} opens before claim deadline (need {required_timelock})",
                    htlc.timelock
                )));
            }
            self.verify_htlc(&htlc, reservation.payment_hash).await?;
        }
        Ok(AcceptedIncoming {
            reservation: reservation.clone(),
            descriptor: descriptor.clone(),
            amount_msat,
        })
    }
}

#[async_trait]
impl NetworkAdapter for RootstockAdapter {
    fn network_id(&self) -> NetworkId {
        self.config.network_id.clone()
    }

    fn invoice_pubkey(&self) -> XOnlyPubKey {
        self.config.invoice_pubkey
    }

    /// Rootstock claims use dedicated per-network EVM account, not invoice key.
    fn claim_pubkey(&self) -> XOnlyPubKey {
        self.claim_pubkey
    }

    fn incoming_delta_secs(&self) -> u64 {
        600
    }

    async fn reserve_incoming(
        &self,
        request: IncomingRequest,
    ) -> Result<IncomingReservation, AdapterError> {
        self.validate_incoming_request(&request)?;
        let reservation = self.incoming_reservation(&request, self.claim_target()?);
        let mut incoming = self.incoming.lock().await;
        if let Some(existing) = incoming.get(&request.operation_id) {
            self.validate_incoming_state(existing, &reservation)?;
            return Ok(reservation);
        }
        if request.deadline <= Self::unix_now() {
            return Err(AdapterError::InvalidParams("deadline in the past".into()));
        }
        if incoming
            .values()
            .any(|state| state.payment_hash == request.payment_hash)
        {
            return Err(AdapterError::Retryable(
                "Rootstock payment hash already has an active reservation".into(),
            ));
        }
        incoming.insert(
            request.operation_id.clone(),
            PendingIncoming {
                payment_hash: request.payment_hash,
                reserved_amount_wei: Self::msat_to_wei(request.amount_msat),
                deadline: request.deadline,
                accepted: None,
                arrival: Arc::new(Notify::new()),
            },
        );
        Ok(reservation)
    }

    async fn cancel_incoming(&self, reservation: &IncomingReservation) -> Result<(), AdapterError> {
        self.validate_incoming_reservation(reservation)?;
        let mut incoming = self.incoming.lock().await;
        let Some(state) = incoming.get(&reservation.operation_id) else {
            return Ok(());
        };
        self.validate_incoming_state(state, reservation)?;
        if state.accepted.is_some() {
            return Err(AdapterError::InvalidParams(
                "cannot cancel an accepted incoming HTLC".into(),
            ));
        }
        let arrival = state.arrival.clone();
        incoming.remove(&reservation.operation_id);
        arrival.notify_waiters();
        Ok(())
    }

    async fn accept_incoming(
        &self,
        reservation: &IncomingReservation,
        descriptor: &HtlcDescriptor,
    ) -> Result<AcceptedIncoming, AdapterError> {
        self.validate_incoming_reservation(reservation)?;
        {
            let incoming = self.incoming.lock().await;
            let state = incoming.get(&reservation.operation_id).ok_or_else(|| {
                AdapterError::NotFound(format!(
                    "no incoming reservation for operation {}",
                    reservation.operation_id
                ))
            })?;
            self.validate_incoming_state(state, reservation)?;
            if let Some(accepted) = &state.accepted {
                if accepted.descriptor == *descriptor {
                    return Ok(accepted.clone());
                }
                return Err(AdapterError::InvalidParams(format!(
                    "incoming operation {} was accepted with a different descriptor",
                    reservation.operation_id
                )));
            }
        }

        let accepted = self
            .accepted_incoming_from_descriptor(reservation, descriptor, true)
            .await?;
        let mut incoming = self.incoming.lock().await;
        let state = incoming.get_mut(&reservation.operation_id).ok_or_else(|| {
            AdapterError::NotFound(format!(
                "incoming reservation for operation {} disappeared",
                reservation.operation_id
            ))
        })?;
        self.validate_incoming_state(state, reservation)?;
        if let Some(existing) = &state.accepted {
            if existing.descriptor == accepted.descriptor {
                return Ok(existing.clone());
            }
            return Err(AdapterError::InvalidParams(format!(
                "incoming operation {} was accepted with a different descriptor",
                reservation.operation_id
            )));
        }
        let arrival = state.arrival.clone();
        state.accepted = Some(accepted.clone());
        drop(incoming);
        arrival.notify_waiters();
        Ok(accepted)
    }

    async fn restore_incoming(&self, accepted: &AcceptedIncoming) -> Result<(), AdapterError> {
        {
            let incoming = self.incoming.lock().await;
            if let Some(state) = incoming.get(&accepted.reservation.operation_id) {
                self.validate_incoming_state(state, &accepted.reservation)?;
                if let Some(existing) = &state.accepted {
                    if Self::accepted_incoming_matches(existing, accepted) {
                        return Ok(());
                    }
                    return Err(AdapterError::InvalidParams(format!(
                        "incoming operation {} has different restored state",
                        accepted.reservation.operation_id
                    )));
                }
            } else if incoming
                .values()
                .any(|state| state.payment_hash == accepted.reservation.payment_hash)
            {
                return Err(AdapterError::Retryable(
                    "Rootstock payment hash already belongs to another active reservation".into(),
                ));
            }
        }

        let canonical = self
            .accepted_incoming_from_descriptor(&accepted.reservation, &accepted.descriptor, true)
            .await?;
        if !Self::accepted_incoming_matches(&canonical, accepted) {
            return Err(AdapterError::InvalidParams(
                "restored incoming state does not match its descriptor".into(),
            ));
        }

        let mut incoming = self.incoming.lock().await;
        if let Some(state) = incoming.get(&accepted.reservation.operation_id) {
            self.validate_incoming_state(state, &accepted.reservation)?;
            if let Some(existing) = &state.accepted {
                if Self::accepted_incoming_matches(existing, accepted) {
                    return Ok(());
                }
                return Err(AdapterError::InvalidParams(format!(
                    "incoming operation {} was accepted with a different descriptor",
                    accepted.reservation.operation_id
                )));
            }
            let arrival = state.arrival.clone();
            incoming
                .get_mut(&accepted.reservation.operation_id)
                .expect("entry checked above")
                .accepted = Some(accepted.clone());
            drop(incoming);
            arrival.notify_waiters();
            return Ok(());
        }
        if incoming
            .values()
            .any(|state| state.payment_hash == accepted.reservation.payment_hash)
        {
            return Err(AdapterError::Retryable(
                "Rootstock payment hash already belongs to another active reservation".into(),
            ));
        }
        let arrival = Arc::new(Notify::new());
        incoming.insert(
            accepted.reservation.operation_id.clone(),
            PendingIncoming {
                payment_hash: accepted.reservation.payment_hash,
                reserved_amount_wei: Self::msat_to_wei(accepted.reservation.amount_msat),
                deadline: accepted.reservation.deadline,
                accepted: Some(accepted.clone()),
                arrival: arrival.clone(),
            },
        );
        drop(incoming);
        arrival.notify_waiters();
        Ok(())
    }

    async fn watch_incoming(
        &self,
        reservation: &IncomingReservation,
        deadline: u64,
    ) -> Result<(), AdapterError> {
        self.validate_incoming_reservation(reservation)?;
        let (arrival, accepted, reservation_deadline) = {
            let incoming = self.incoming.lock().await;
            let state = incoming.get(&reservation.operation_id).ok_or_else(|| {
                AdapterError::Retryable(format!(
                    "incoming reservation for operation {} no longer exists",
                    reservation.operation_id
                ))
            })?;
            self.validate_incoming_state(state, reservation)?;
            (
                state.arrival.clone(),
                state.accepted.clone(),
                state.deadline,
            )
        };
        if accepted.is_some() {
            return Ok(());
        }
        let deadline = deadline.min(reservation_deadline);
        loop {
            let now = Self::unix_now();
            if now >= deadline {
                return Err(AdapterError::DeadlineExceeded);
            }
            let wait = Duration::from_secs((deadline - now).clamp(1, POLL_INTERVAL_SECS));
            if tokio::time::timeout(wait, arrival.notified())
                .await
                .is_err()
            {
                continue;
            }
            let incoming = self.incoming.lock().await;
            let state = incoming.get(&reservation.operation_id).ok_or_else(|| {
                AdapterError::Retryable(format!(
                    "incoming reservation for operation {} was canceled",
                    reservation.operation_id
                ))
            })?;
            self.validate_incoming_state(state, reservation)?;
            if state.accepted.is_some() {
                return Ok(());
            }
        }
    }

    async fn claim_incoming(
        &self,
        accepted: &AcceptedIncoming,
        preimage: Bytes32,
    ) -> Result<(), AdapterError> {
        let canonical = self
            .accepted_incoming_from_descriptor(&accepted.reservation, &accepted.descriptor, false)
            .await?;
        if !Self::accepted_incoming_matches(&canonical, accepted) {
            return Err(AdapterError::InvalidParams(
                "accepted incoming state does not match its descriptor".into(),
            ));
        }
        if !accepted
            .reservation
            .payment_hash
            .matches_preimage(&preimage)
        {
            return Err(AdapterError::InvalidParams(
                "preimage does not hash to the payment hash".into(),
            ));
        }
        let htlc = RootstockHtlc::parse(&accepted.descriptor)?;
        let state: Option<PendingIncoming> = {
            let incoming = self.incoming.lock().await;
            let state = incoming.get(&accepted.reservation.operation_id);
            if let Some(state) = state {
                self.validate_incoming_state(state, &accepted.reservation)?;
                let stored = state.accepted.as_ref().ok_or_else(|| {
                    AdapterError::InvalidParams(format!(
                        "incoming operation {} has not been accepted",
                        accepted.reservation.operation_id
                    ))
                })?;
                if !Self::accepted_incoming_matches(stored, accepted) {
                    return Err(AdapterError::InvalidParams(
                        "accepted incoming state does not match adapter state".into(),
                    ));
                }
                Some(state.clone())
            } else {
                None
            }
        };
        let Some(state) = state else {
            // Successful claim already removed state. Same-handle retry is complete.
            return Ok(());
        };
        let stored = state
            .accepted
            .as_ref()
            .expect("accepted state checked above");
        if Self::unix_now() >= stored.reservation.deadline {
            return Err(AdapterError::Network("incoming deadline exceeded".into()));
        }
        let gas_price = self
            .gas_price_wei()
            .await
            .map_err(|e| AdapterError::Network(e.to_string()))?;
        let balance = self
            .provider
            .get_balance(self.address)
            .await
            .map_err(|e| AdapterError::Network(format!("get_balance: {e}")))?;
        self.span.in_scope(|| {
            info!(
                target: "cassis_rootstock",
                "claiming htlc {} from={} balance={} wei amount={} wei gas_price={} wei",
                accepted.reservation.payment_hash.short(),
                self.address,
                balance,
                htlc.amount_wei,
                gas_price,
            );
        });
        self.ensure_claim_gas(balance, gas_price)?;
        let request = TransactionRequest::default()
            .to(htlc.contract)
            .gas_price(gas_price)
            .gas_limit(CLAIM_TX_GAS)
            .input(
                IEtherSwap::claimCall {
                    preimage: B256::from_slice(preimage.as_ref()),
                    amount: htlc.amount_wei,
                    refundAddress: htlc.refund_address,
                    timelock: U256::from(htlc.timelock),
                }
                .abi_encode()
                .into(),
            );
        let pending = self
            .provider
            .send_transaction(request)
            .await
            .map_err(|e| AdapterError::Network(format!("claim send: {e}")))?;
        let tx_hash = *pending.tx_hash();
        let receipt = pending
            .get_receipt()
            .await
            .map_err(|e| AdapterError::Network(format!("claim receipt (tx {tx_hash}): {e}")))?;
        if !receipt.status() {
            return Err(AdapterError::Network(format!(
                "claim transaction {tx_hash} reverted"
            )));
        }
        self.span.in_scope(|| {
            info!(
                target: "cassis_rootstock",
                "htlc claimed for {}: tx={tx_hash}",
                accepted.reservation.payment_hash.short(),
            );
        });
        self.incoming
            .lock()
            .await
            .remove(&accepted.reservation.operation_id);
        Ok(())
    }

    async fn claim_reserved_incoming(
        &self,
        reservation: &IncomingReservation,
        preimage: Bytes32,
    ) -> Result<(), AdapterError> {
        let accepted = {
            let incoming = self.incoming.lock().await;
            let slot = incoming.get(&reservation.operation_id).ok_or_else(|| {
                AdapterError::NotFound(format!(
                    "no incoming Rootstock reservation for operation {}",
                    reservation.operation_id
                ))
            })?;
            slot.accepted.clone().ok_or(AdapterError::Unimplemented)
        }?;
        self.claim_incoming(&accepted, preimage).await
    }

    async fn create_outgoing(
        &self,
        request: OutgoingRequest,
    ) -> Result<OutgoingPayment, AdapterError> {
        let recipient = self.validate_outgoing_request(&request)?;
        let existing_funded = {
            let mut outgoing = self.outgoing.lock().await;
            if let Some(existing) = outgoing.get(&request.operation_id) {
                Self::outgoing_state_matches_request(existing, &request, &recipient)?;
                let funded = existing.funded.clone();
                if funded.is_none() {
                    return Err(AdapterError::Retryable(format!(
                        "Rootstock outgoing operation {} is already being created",
                        request.operation_id
                    )));
                }
                if existing.verified {
                    return self.outgoing_payment_from_state(&request.operation_id, existing);
                }
                funded
            } else {
                if request.expiry <= Self::unix_now() {
                    return Err(AdapterError::InvalidParams("expiry in the past".into()));
                }
                if outgoing
                    .values()
                    .any(|state| state.payment_hash == request.payment_hash)
                {
                    return Err(AdapterError::Retryable(
                        "Rootstock payment hash already has an active outgoing payment".into(),
                    ));
                }
                outgoing.insert(
                    request.operation_id.clone(),
                    PendingOutgoing {
                        payment_hash: request.payment_hash,
                        amount_msat: request.amount_msat,
                        expiry: request.expiry,
                        recipient,
                        funded: None,
                        verified: false,
                    },
                );
                None
            }
        };

        if let Some(funded) = existing_funded {
            let htlc = funded.to_descriptor()?;
            let parsed = RootstockHtlc::parse(&htlc)?;
            self.verify_htlc(&parsed, request.payment_hash).await?;
            let mut outgoing = self.outgoing.lock().await;
            let state = outgoing.get_mut(&request.operation_id).ok_or_else(|| {
                AdapterError::NotFound(format!(
                    "outgoing operation {} disappeared during verification",
                    request.operation_id
                ))
            })?;
            state.verified = true;
            return self.outgoing_payment_from_state(&request.operation_id, state);
        }

        let operation_id = request.operation_id.clone();
        let payment_hash = request.payment_hash;
        let result: Result<B256, AdapterError> = async {
            let now = Self::unix_now();
            let latest = self
                .block_number()
                .await
                .map_err(|e| AdapterError::Network(e.to_string()))?;
            let remaining = request.expiry.saturating_sub(now);
            let blocks_ahead = remaining.div_ceil(RSK_BLOCK_TIME_SECS);
            let timelock = latest.saturating_add(blocks_ahead);
            let claim_address = evm_address_from_pubkey(&recipient);
            let amount_wei = Self::msat_to_wei(request.amount_msat);
            let htlc = RootstockHtlc {
                contract: self.contract,
                amount_wei,
                claim_address,
                refund_address: self.address,
                timelock,
            };
            // Validate descriptor range before broadcasting funds.
            let _ = htlc.to_descriptor()?;
            self.span.in_scope(|| {
                info!(
                    target: "cassis_rootstock",
                    "preparing htlc amount={} to={} hash={}",
                    request.amount_msat,
                    claim_address,
                    payment_hash.short(),
                );
            });
            let gas_price = self
                .gas_price_wei()
                .await
                .map_err(|e| AdapterError::Network(e.to_string()))?;
            let tx_request = TransactionRequest::default()
                .to(self.contract)
                .value(amount_wei)
                .gas_price(gas_price)
                .gas_limit(LOCK_TX_GAS)
                .input(
                    IEtherSwap::lockCall {
                        preimageHash: B256::from_slice(payment_hash.as_ref()),
                        claimAddress: claim_address,
                        timelock: U256::from(timelock),
                    }
                    .abi_encode()
                    .into(),
                );
            let pending = self
                .provider
                .send_transaction(tx_request)
                .await
                .map_err(|e| AdapterError::Network(format!("lock send: {e}")))?;
            let tx_hash = *pending.tx_hash();

            // Persist recovery state as soon as broadcast is accepted, before
            // waiting on receipt. Later receipt/verification errors must not
            // make exact retry fund a second HTLC.
            {
                let mut outgoing = self.outgoing.lock().await;
                let state = outgoing.get_mut(&operation_id).ok_or_else(|| {
                    AdapterError::Network("outgoing operation disappeared after lock send".into())
                })?;
                if state.payment_hash != payment_hash {
                    return Err(AdapterError::Network(
                        "outgoing operation state changed after lock send".into(),
                    ));
                }
                state.funded = Some(htlc);
            }

            let receipt = pending
                .get_receipt()
                .await
                .map_err(|e| AdapterError::Network(format!("lock receipt (tx {tx_hash}): {e}")))?;
            if !receipt.status() {
                return Err(AdapterError::Network(format!(
                    "lock transaction {tx_hash} reverted"
                )));
            }
            self.span.in_scope(|| {
                info!(target: "cassis_rootstock", "htlc prepared tx={tx_hash}");
                debug!(
                    target: "cassis_rootstock",
                    "lock tx sent: payment_hash={} claim={} amount_wei={} timelock={} tx={tx_hash}",
                    payment_hash, claim_address, amount_wei, timelock,
                );
            });
            let funded = {
                let state = self.outgoing.lock().await;
                let state = state.get(&operation_id).ok_or_else(|| {
                    AdapterError::Network("outgoing operation disappeared after lock".into())
                })?;
                state.funded.clone().ok_or_else(|| {
                    AdapterError::Network("outgoing recovery state missing after lock".into())
                })?
            };
            self.verify_htlc(&funded, payment_hash).await?;
            Ok(tx_hash)
        }
        .await;
        if result.is_err() {
            self.discard_unfunded_outgoing(&operation_id, payment_hash)
                .await;
        }
        result?;

        let mut outgoing = self.outgoing.lock().await;
        let state = outgoing.get_mut(&operation_id).ok_or_else(|| {
            AdapterError::NotFound(format!(
                "outgoing operation {operation_id} disappeared after funding"
            ))
        })?;
        state.verified = true;
        self.outgoing_payment_from_state(&operation_id, state)
    }

    async fn watch_outgoing(
        &self,
        payment: &OutgoingPayment,
        deadline: u64,
    ) -> Result<Bytes32, AdapterError> {
        let (recipient, htlc) = self.validate_outgoing_payment(payment)?;
        {
            let outgoing = self.outgoing.lock().await;
            let state = outgoing.get(&payment.operation_id).ok_or_else(|| {
                AdapterError::NotFound(format!(
                    "no outgoing payment for operation {}",
                    payment.operation_id
                ))
            })?;
            self.outgoing_state_matches_payment(state, payment, &recipient, &htlc)?;
        }
        let interval = Duration::from_secs(POLL_INTERVAL_SECS);
        let mut last_scanned = None;
        loop {
            if Self::unix_now() >= deadline {
                return Err(AdapterError::DeadlineExceeded);
            }
            let latest = match self.block_number().await {
                Ok(number) => number,
                Err(error) => {
                    self.span.in_scope(|| {
                        warn!(target: "cassis_rootstock", "outgoing watch block_number failed: {error}");
                    });
                    tokio::time::sleep(interval).await;
                    continue;
                }
            };
            let from = last_scanned.map(|number| number + 1).unwrap_or(latest);
            for block_number in from..=latest {
                match self
                    .find_claim_preimage_in_block(block_number, payment.payment_hash)
                    .await
                {
                    Ok(Some(preimage)) => {
                        self.span.in_scope(|| {
                            info!(
                                target: "cassis_rootstock",
                                "preimage observed on chain in block {block_number} for {}",
                                payment.payment_hash.short(),
                            );
                        });
                        return Ok(preimage);
                    }
                    Ok(None) => {}
                    Err(error) => self.span.in_scope(|| {
                        warn!(
                            target: "cassis_rootstock",
                            "outgoing watch block scan failed at {block_number}: {error}"
                        );
                    }),
                }
            }
            last_scanned = Some(latest);
            tokio::time::sleep(interval).await;
        }
    }

    async fn refund_outgoing(&self, payment: &OutgoingPayment) -> Result<(), AdapterError> {
        let (recipient, htlc) = self.validate_outgoing_payment(payment)?;
        let funded = {
            let outgoing = self.outgoing.lock().await;
            let Some(state) = outgoing.get(&payment.operation_id) else {
                // Successful refund already removed state. Same-handle retry is complete.
                return Ok(());
            };
            self.outgoing_state_matches_payment(state, payment, &recipient, &htlc)?;
            state.funded.clone().expect("validated funded state")
        };
        let latest = self
            .block_number()
            .await
            .map_err(|e| AdapterError::Network(e.to_string()))?;
        if latest < funded.timelock {
            return Err(AdapterError::Retryable(format!(
                "timelock not reached: latest={latest} timelock={}",
                funded.timelock
            )));
        }
        let gas_price = self
            .gas_price_wei()
            .await
            .map_err(|e| AdapterError::Network(e.to_string()))?;
        let request = TransactionRequest::default()
            .to(funded.contract)
            .gas_price(gas_price)
            .input(
                IEtherSwap::refundCall {
                    preimageHash: B256::from_slice(payment.payment_hash.as_ref()),
                    amount: funded.amount_wei,
                    // Four-argument refund commits to original claim address.
                    claimAddress: funded.claim_address,
                    timelock: U256::from(funded.timelock),
                }
                .abi_encode()
                .into(),
            );
        let pending = self
            .provider
            .send_transaction(request)
            .await
            .map_err(|e| AdapterError::Network(format!("refund send: {e}")))?;
        let tx_hash = *pending.tx_hash();
        let receipt = pending
            .get_receipt()
            .await
            .map_err(|e| AdapterError::Network(format!("refund receipt (tx {tx_hash}): {e}")))?;
        if !receipt.status() {
            return Err(AdapterError::Network(format!(
                "refund transaction {tx_hash} reverted"
            )));
        }
        self.outgoing.lock().await.remove(&payment.operation_id);
        Ok(())
    }

    async fn restore_outgoing(&self, payment: &OutgoingPayment) -> Result<(), AdapterError> {
        let (recipient, htlc) = self.validate_outgoing_payment(payment)?;
        {
            let outgoing = self.outgoing.lock().await;
            if let Some(state) = outgoing.get(&payment.operation_id) {
                self.outgoing_state_matches_payment(state, payment, &recipient, &htlc)?;
                if state.verified {
                    return Ok(());
                }
            } else if outgoing
                .values()
                .any(|state| state.payment_hash == payment.payment_hash)
            {
                return Err(AdapterError::Retryable(
                    "Rootstock payment hash already has another active outgoing payment".into(),
                ));
            }
        }

        self.verify_htlc(&htlc, payment.payment_hash).await?;
        let mut outgoing = self.outgoing.lock().await;
        if let Some(state) = outgoing.get_mut(&payment.operation_id) {
            self.outgoing_state_matches_payment(state, payment, &recipient, &htlc)?;
            state.verified = true;
            return Ok(());
        }
        if outgoing
            .values()
            .any(|state| state.payment_hash == payment.payment_hash)
        {
            return Err(AdapterError::Retryable(
                "Rootstock payment hash already has another active outgoing payment".into(),
            ));
        }
        outgoing.insert(
            payment.operation_id.clone(),
            PendingOutgoing {
                payment_hash: payment.payment_hash,
                amount_msat: payment.amount_msat,
                expiry: payment.expiry,
                recipient,
                funded: Some(htlc),
                verified: true,
            },
        );
        Ok(())
    }

    async fn restore_incoming_reservation(
        &self,
        reservation: &IncomingReservation,
    ) -> Result<(), AdapterError> {
        let restored = self
            .reserve_incoming(IncomingRequest {
                operation_id: reservation.operation_id.clone(),
                payment_hash: reservation.payment_hash,
                amount_msat: reservation.amount_msat,
                deadline: reservation.deadline,
                preimage: None,
            })
            .await?;
        if restored == *reservation {
            Ok(())
        } else {
            Err(AdapterError::InvalidParams(
                "restored Rootstock reservation differs from persisted state".into(),
            ))
        }
    }

    async fn can_route(&self, amount_msat: u64) -> Result<(), AdapterError> {
        let balance = self
            .provider
            .get_balance(self.address)
            .await
            .map_err(|e| AdapterError::Network(e.to_string()))?;
        let gas_price = self
            .gas_price_wei()
            .await
            .map_err(|e| AdapterError::Network(e.to_string()))?;
        let gas = gas_reserve(LOCK_TX_GAS, gas_price);
        let needed = Self::msat_to_wei(amount_msat).saturating_add(gas);
        if balance < needed {
            return Err(AdapterError::InvalidParams(format!(
                "insufficient rootstock balance on {}: need {needed} wei \
                 (including ~{gas} wei gas), have {balance} wei",
                self.address,
            )));
        }
        Ok(())
    }

    async fn can_claim(&self, _amount_msat: u64) -> Result<(), AdapterError> {
        let balance = self
            .provider
            .get_balance(self.address)
            .await
            .map_err(|e| AdapterError::Network(format!("get_balance: {e}")))?;
        let gas_price = self
            .gas_price_wei()
            .await
            .map_err(|e| AdapterError::Network(e.to_string()))?;
        self.ensure_claim_gas(balance, gas_price)
    }
}

/// Pick the canonical config for a given `NetworkId`. Returns
/// the public RPC endpoint and the configured EtherSwap
/// contract for mainnet (`rootstock`) or testnet
/// (`rootstock::testnet`). Callers can override `contract` on the
/// returned config before constructing the adapter.
pub fn default_config(
    network_id: NetworkId,
    sk: [u8; 32],
    invoice_pubkey: XOnlyPubKey,
    span: Span,
) -> RootstockConfig {
    match network_id.0.as_str() {
        "rootstock::testnet" => RootstockConfig {
            network_id,
            rpc_url: ROOTSTOCK_TESTNET_RPC.to_string(),
            contract: Some(ROOTSTOCK_TESTNET_CONTRACT.to_string()),
            chain_id: ROOTSTOCK_TESTNET_CHAIN_ID,
            sk,
            invoice_pubkey,
            span: span.clone(),
        },
        _ => RootstockConfig {
            network_id,
            rpc_url: ROOTSTOCK_MAINNET_RPC.to_string(),
            contract: Some(ROOTSTOCK_MAINNET_CONTRACT.to_string()),
            chain_id: ROOTSTOCK_MAINNET_CHAIN_ID,
            sk,
            invoice_pubkey,
            span,
        },
    }
}

/// Derive the EVM address for a 32-byte secret key without
/// touching the network. Used by the CLI's `info` subcommand
/// so showing the local address doesn't need an RPC
/// connection.
///
/// Normalizes the key exactly like [`RootstockAdapter::new`], so the
/// address shown here is always the address the adapter actually uses.
pub fn address_from_sk(sk: [u8; 32]) -> Result<Address, Error> {
    let (sk, _) = normalized_key(sk)?;
    let signer = PrivateKeySigner::from_bytes(&B256::from_slice(&sk))
        .map_err(|e| Error::InvalidParams(format!("invalid secret key: {e}")))?;
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
fn normalized_key(sk: [u8; 32]) -> Result<([u8; 32], XOnlyPubKey), Error> {
    let secp = secp256k1::Secp256k1::signing_only();
    let secret = secp256k1::SecretKey::from_byte_array(sk)
        .map_err(|e| Error::InvalidParams(format!("invalid secret key: {e}")))?;
    let (xonly, parity) = secret.x_only_public_key(&secp);
    let normalized = match parity {
        secp256k1::Parity::Even => sk,
        // Negating the scalar flips Y and leaves X untouched, so the
        // x-only identity computed above still holds.
        secp256k1::Parity::Odd => secret.negate().secret_bytes(),
    };
    let pubkey = XOnlyPubKey::from_bytes(xonly.serialize())
        .map_err(|e| Error::InvalidParams(format!("invalid x-only pubkey: {e}")))?;
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

/// Wei to reserve for an HTLC transaction of `gas` units at `gas_price`.
fn gas_reserve(gas: u64, gas_price: u128) -> U256 {
    U256::from(gas).saturating_mul(U256::from(gas_price))
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
    if !stripped.len().is_multiple_of(2) {
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

    #[test]
    fn default_config_mainnet_has_contract_and_rpc() {
        let cfg = default_config(
            NetworkId("rootstock".to_string()),
            [7u8; 32],
            "17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917"
                .parse()
                .unwrap(),
            Span::none(),
        );
        assert_eq!(cfg.rpc_url, ROOTSTOCK_MAINNET_RPC);
        assert_eq!(cfg.chain_id, 30);
        assert_eq!(cfg.contract.as_deref(), Some(ROOTSTOCK_MAINNET_CONTRACT));
    }

    #[test]
    fn default_config_testnet_has_contract_and_rpc() {
        let cfg = default_config(
            NetworkId("rootstock::testnet".to_string()),
            [7u8; 32],
            "17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917"
                .parse()
                .unwrap(),
            Span::none(),
        );
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
