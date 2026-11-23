//! WBTC on Starknet: HTLCs are WBTC escrows in atomiq's escrow manager.
//!
//! An escrow names a claim handler and a refund handler, contracts that
//! decide when it can be claimed and refunded. Every escrow here uses
//! atomiq's hashlock claim handler (claimable with a preimage whose
//! SHA-256, as eight big-endian `u32` words, Poseidon-hashes to
//! `claim_data`) and timelock refund handler (refundable once a block's
//! timestamp is past `refund_data`), so it is an HTLC.
//!
//! * **Lock**: `approve` the escrow manager and `initialize(escrow, [],
//!   timeout, [])` in one multicall from the offerer. No signature is
//!   needed: the reputation flag is off. The escrow is identified on chain
//!   by the Poseidon hash of its fields, which commits to all of them, so
//!   a receiver that rebuilds the escrow from its descriptor and finds it
//!   committed has checked all of its terms.
//! * **Claim**: `claim(escrow, preimage words)`, from anyone: the contract
//!   pays the escrow's claimer, whoever sends it. It emits `Claim` keyed
//!   by offerer, claimer and claim data, with the preimage words, where
//!   the sender reads the preimage.
//! * **Refund**: `refund(escrow, [])` once a block's timestamp is past the
//!   expiry, paid to the offerer.
//!
//! `get_state(escrow)` reports an escrow as committed, claimed or
//! refunded, and the block it was finished in, where the claim is found.
//!
//! The adapter's account is an OpenZeppelin account (the class atomiq's
//! own keypair wallets use) of a Stark key derived from the mnemonic
//! (see [`account_key`]). Its address is known before it is deployed; it
//! is deployed, paying in STRK, before its first transaction. Fees are
//! always paid in STRK.

use async_trait::async_trait;
use cassis_core::keys::{Mnemonic, bip44_key};
use cassis_core::{
    Bytes32, Htlc, HtlcDescriptor, InvoiceTarget, MSAT_PER_SAT, Network, NetworkError, NetworkId,
    OutgoingState, StarknetAddress, sats_for_msat,
};
use num_bigint::BigUint;
use sha2::{Digest, Sha256};
use starknet_rust::accounts::{
    Account, AccountFactory, ConnectedAccount, ExecutionEncoding, OpenZeppelinAccountFactory,
    SingleOwnerAccount,
};
use starknet_rust::core::chain_id;

use starknet_rust::core::types::{
    AddressFilter, BlockId, BlockTag, Call, EventFilter, ExecutionResult, Felt, FunctionCall,
    MaybePreConfirmedBlockWithTxHashes, StarknetError, TransactionFinalityStatus,
};
use starknet_rust::core::utils::{get_contract_address, get_selector_from_name};
use starknet_rust::providers::jsonrpc::{HttpTransport, JsonRpcClient};
use starknet_rust::providers::{Provider, ProviderError, Url};
use starknet_rust::signers::{LocalWallet, SigningKey};
use starknet_rust_crypto::poseidon_hash_many;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{Span, debug, info, warn};

pub const STARKNET_MAINNET_RPC: &str = "https://starknet-rpc.publicnode.com";
pub const STARKNET_SEPOLIA_RPC: &str = "https://starknet-sepolia-rpc.publicnode.com";

/// The contracts of atomiq's escrows on one Starknet chain, and the WBTC
/// they hold.
#[derive(Clone, Copy, Debug)]
pub struct Contracts {
    pub escrow_manager: Felt,
    /// Claim handler of HTLCs: `poseidon(sha256(witness)) == claim_data`.
    pub hashlock: Felt,
    /// Refund handler of HTLCs: `block_timestamp > refund_data`.
    pub timelock: Felt,
    pub wbtc: Felt,
}

/// atomiq's deployment on Starknet mainnet, and StarkGate's WBTC.
pub const STARKNET_MAINNET_CONTRACTS: Contracts = Contracts {
    escrow_manager: Felt::from_hex_unchecked(
        "0x04f278e1f19e495c3b1dd35ef307c4f7510768ed95481958fbae588bd173f79a",
    ),
    hashlock: Felt::from_hex_unchecked(
        "0x07b74b50a883ebee262b6db0e3c0c697670c6f30e3d610e75faf33a89c46aa2a",
    ),
    timelock: Felt::from_hex_unchecked(
        "0x06a59659990c2aefbf7239f6d911617b3ae60b79cb3364f3bd242a6ca8f4f4f7",
    ),
    wbtc: Felt::from_hex_unchecked(
        "0x03fe2b97c1fd336e750087d68b9b867997fd64a2661ff3ca5a7c771641e8e7ac",
    ),
};

/// atomiq's deployment on Starknet Sepolia, and the test WBTC it swaps.
pub const STARKNET_SEPOLIA_CONTRACTS: Contracts = Contracts {
    escrow_manager: Felt::from_hex_unchecked(
        "0x017bf50dd28b6d823a231355bb25813d4396c8e19d2df03026038714a22f0413",
    ),
    hashlock: Felt::from_hex_unchecked(
        "0x04a57ea54d4637c352aad1bbee046868926a11702216a0aaf7eeec1568be2d7b",
    ),
    timelock: Felt::from_hex_unchecked(
        "0x034b8f28b3ca979036cb2849cfa3af7f67207459224b6ca5ce2474aa398ec3e7",
    ),
    wbtc: Felt::from_hex_unchecked(
        "0x04861ba938aed21f2cd7740acd3765ac4d2974783a3218367233de0153490cb6",
    ),
};

/// STRK, which fees are paid in, on mainnet and Sepolia alike.
pub const STRK: Felt =
    Felt::from_hex_unchecked("0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d");

/// Class of the OpenZeppelin account atomiq's keypair wallets deploy,
/// declared on mainnet and Sepolia. Its constructor takes the public key,
/// which is also the deployment salt.
pub const OZ_ACCOUNT_CLASS_HASH: Felt =
    Felt::from_hex_unchecked("0x00261c293c8084cd79086214176b33e5911677cec55104fddc8d25b0b736dcad");

/// Escrow flags: pay the claimer out of the contract (not into its LP
/// vault), and take the funds from the offerer (not from its vault).
const FLAG_PAY_OUT: u128 = 0x01;
const FLAG_PAY_IN: u128 = 0x02;

/// Escrow manager states.
const STATE_NOT_COMMITTED: u64 = 0;
const STATE_COMMITTED: u64 = 1;
const STATE_CLAIMED: u64 = 2;
const STATE_REFUNDED: u64 = 3;

/// STRK (in fri, 10^-18 STRK) kept for fees before committing to a
/// route: a lock, claim or refund costs a small fraction of it.
pub const FEE_RESERVE_FRI: u128 = 2_000_000_000_000_000_000;
/// How long a sent transaction is waited for. One that takes longer is
/// reported as failed, and found (or sent again) by the next attempt.
const RECEIPT_TIMEOUT: Duration = Duration::from_secs(180);
const RECEIPT_POLL: Duration = Duration::from_secs(3);

type Rpc = JsonRpcClient<HttpTransport>;

/// The public node, chain id and atomiq's contracts of `starknet-wbtc`
/// or `starknet-wbtc::sepolia`.
pub fn deployment(id: &NetworkId) -> Result<(&'static str, Felt, Contracts), String> {
    match id.param() {
        None => Ok((
            STARKNET_MAINNET_RPC,
            chain_id::MAINNET,
            STARKNET_MAINNET_CONTRACTS,
        )),
        Some("sepolia") => Ok((
            STARKNET_SEPOLIA_RPC,
            chain_id::SEPOLIA,
            STARKNET_SEPOLIA_CONTRACTS,
        )),
        Some(other) => Err(format!("unknown starknet-wbtc network '{other}'")),
    }
}

fn rpc_error(context: &str) -> impl Fn(ProviderError) -> NetworkError + '_ {
    move |e| NetworkError::network(format!("{context}: {e}"))
}

fn selector(name: &str) -> Felt {
    get_selector_from_name(name).expect("ASCII entry point name")
}

fn felt(address: &StarknetAddress) -> Felt {
    Felt::from_bytes_be(address.as_bytes())
}

fn address(felt: Felt) -> StarknetAddress {
    StarknetAddress::from_bytes(felt.to_bytes_be()).expect("a felt is below the prime")
}

/// 32 bytes as the eight big-endian `u32` words Cairo's SHA-256 works on.
pub fn words(bytes: &Bytes32) -> [Felt; 8] {
    std::array::from_fn(|i| {
        Felt::from(u32::from_be_bytes(
            bytes.0[4 * i..4 * i + 4].try_into().expect("4 bytes"),
        ))
    })
}

/// The 32 bytes of eight `u32` words, if they are that.
fn from_words(words: &[Felt]) -> Option<Bytes32> {
    if words.len() != 8 {
        return None;
    }
    let mut bytes = [0u8; 32];
    for (chunk, word) in bytes.chunks_mut(4).zip(words) {
        chunk.copy_from_slice(&u32::try_from(*word).ok()?.to_be_bytes());
    }
    Some(Bytes32(bytes))
}

/// The claim data of an HTLC for `payment_hash`: the Poseidon hash of its
/// words, which the hashlock claim handler checks the preimage against.
pub fn claim_data(payment_hash: &Bytes32) -> Felt {
    poseidon_hash_many(&words(payment_hash))
}

/// A `u256` as Cairo serializes it: low half, then high half.
fn u256(value: u128) -> [Felt; 2] {
    [Felt::from(value), Felt::ZERO]
}

/// The escrow of an [`Htlc`]: everything but the payment hash, which
/// the escrow's claim data commits to. A wallet that funds or claims
/// HTLCs without a [`StarknetWbtcAdapter`] builds this from an
/// [`HtlcRequest`](cassis_core::HtlcRequest) or an [`Htlc`], and sends the
/// calls below.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Escrow {
    pub amount_sat: u64,
    pub claimer: Felt,
    pub offerer: Felt,
    /// Salts the escrow, so that two with the same terms differ.
    pub sequence: u64,
    /// Unix seconds after which a block can refund the escrow.
    pub refund_after: u64,
}

impl Escrow {
    /// The escrow to make for a payment claimable by `claim` (the address
    /// of an [`InvoiceTarget::StarknetWbtc`]): `amount_msat`, rounded up
    /// to sats, locked from `offerer`, refundable after `expiry`.
    pub fn for_lock(amount_msat: u64, expiry: u64, claim: &StarknetAddress, offerer: Felt) -> Self {
        Self {
            amount_sat: sats_for_msat(amount_msat),
            claimer: felt(claim),
            offerer,
            sequence: rand::random(),
            refund_after: expiry,
        }
    }

    pub fn of(htlc: &Htlc) -> Result<Self, NetworkError> {
        let HtlcDescriptor::StarknetWbtc {
            amount_sat,
            refund_address,
            sequence,
            refund_after,
            target,
        } = &htlc.descriptor
        else {
            return Err(NetworkError::invalid("not a starknet-wbtc HTLC"));
        };
        Ok(Self {
            amount_sat: *amount_sat,
            claimer: felt(target),
            offerer: felt(refund_address),
            sequence: *sequence,
            refund_after: *refund_after,
        })
    }

    /// The descriptor of this escrow, claimable by its claimer.
    pub fn descriptor(&self) -> HtlcDescriptor {
        HtlcDescriptor::StarknetWbtc {
            amount_sat: self.amount_sat,
            refund_address: address(self.offerer),
            sequence: self.sequence,
            refund_after: self.refund_after,
            target: address(self.claimer),
        }
    }

    /// The escrow's `EscrowData` as calldata: a WBTC HTLC on `contracts`'
    /// handlers, with no deposit, bounty or action on claim.
    pub fn data(&self, payment_hash: &Bytes32, contracts: &Contracts) -> Vec<Felt> {
        let mut data = vec![
            self.offerer,
            self.claimer,
            contracts.wbtc,
            contracts.timelock,
            contracts.hashlock,
            Felt::from((u128::from(self.sequence) << 64) | FLAG_PAY_IN | FLAG_PAY_OUT),
            claim_data(payment_hash),
            Felt::from(self.refund_after),
        ];
        data.extend(u256(self.amount_sat.into()));
        // Fee token, security deposit and claimer bounty.
        data.push(STRK);
        data.extend(u256(0));
        data.extend(u256(0));
        // No success action: `Option::None`.
        data.push(Felt::ONE);
        data
    }
}

/// The calls that lock `escrow` from its offerer: approving the escrow
/// manager for the WBTC, then initializing the escrow. The offerer needs
/// no signature, so the authorization never expires.
pub fn lock_calls(escrow: &Escrow, payment_hash: &Bytes32, contracts: &Contracts) -> Vec<Call> {
    let mut approve = vec![contracts.escrow_manager];
    approve.extend(u256(escrow.amount_sat.into()));
    let mut initialize = escrow.data(payment_hash, contracts);
    // No signature, the timeout, no extra data.
    initialize.extend([Felt::ZERO, Felt::from(u64::MAX), Felt::ZERO]);
    vec![
        Call {
            to: contracts.wbtc,
            selector: selector("approve"),
            calldata: approve,
        },
        Call {
            to: contracts.escrow_manager,
            selector: selector("initialize"),
            calldata: initialize,
        },
    ]
}

/// The call that claims `escrow` with `preimage`, from any account.
pub fn claim_call(
    escrow: &Escrow,
    payment_hash: &Bytes32,
    preimage: &Bytes32,
    contracts: &Contracts,
) -> Call {
    let mut calldata = escrow.data(payment_hash, contracts);
    calldata.push(Felt::from(8u8));
    calldata.extend(words(preimage));
    Call {
        to: contracts.escrow_manager,
        selector: selector("claim"),
        calldata,
    }
}

/// The call that refunds `escrow`, from any account once a block's
/// timestamp is past its `refund_after`.
pub fn refund_call(escrow: &Escrow, payment_hash: &Bytes32, contracts: &Contracts) -> Call {
    let mut calldata = escrow.data(payment_hash, contracts);
    calldata.push(Felt::ZERO);
    Call {
        to: contracts.escrow_manager,
        selector: selector("refund"),
        calldata,
    }
}

/// What the escrow manager holds of an escrow: its state and the block it
/// was finished in.
#[derive(Clone, Copy, Debug)]
struct EscrowState {
    finish_block: u64,
    state: u64,
}

pub struct StarknetWbtcAdapter {
    id: NetworkId,
    span: Span,
    account: SingleOwnerAccount<Rpc, LocalWallet>,
    key: SigningKey,
    chain_id: Felt,
    rpc_url: Url,
    contracts: Contracts,
    /// Set once the account is known to be deployed.
    deployed: AtomicBool,
    /// Held while a transaction is sent, so that two never take the
    /// same nonce.
    sending: Mutex<()>,
}

impl StarknetWbtcAdapter {
    /// Connect to `starknet-wbtc` or `starknet-wbtc::sepolia` through a
    /// public node. All state is on chain.
    pub fn open(id: NetworkId, mnemonic: &Mnemonic, span: &Span) -> Result<Self, String> {
        let (rpc_url, chain_id, contracts) = deployment(&id)?;
        let rpc_url = Url::parse(rpc_url).map_err(|e| e.to_string())?;
        let key = SigningKey::from_secret_scalar(account_key(mnemonic)?);
        let address = account_address(key.verifying_key().scalar());
        let account = SingleOwnerAccount::new(
            JsonRpcClient::new(HttpTransport::new(rpc_url.clone())),
            LocalWallet::from(key.clone()),
            address,
            chain_id,
            ExecutionEncoding::New,
        );
        let span = cassis_core::network_span(span, &id);
        debug!(parent: &span, "starknet wallet ready: address={address:#066x} rpc={rpc_url}");
        Ok(Self {
            id,
            span,
            account,
            key,
            chain_id,
            rpc_url,
            contracts,
            deployed: AtomicBool::new(false),
            sending: Mutex::new(()),
        })
    }

    /// The account HTLCs to this node pay out to, and that funds its own.
    pub fn address(&self) -> StarknetAddress {
        address(self.account.address())
    }

    fn provider(&self) -> &Rpc {
        self.account.provider()
    }

    /// WBTC balance, in msat.
    pub async fn balance_msat(&self) -> Result<u64, String> {
        let sats = self
            .token_balance(self.contracts.wbtc)
            .await
            .map_err(|e| e.to_string())?;
        u64::try_from(sats)
            .map(|sats| sats.saturating_mul(MSAT_PER_SAT))
            .map_err(|e| e.to_string())
    }

    /// STRK balance, in fri, which pays the account's fees.
    pub async fn fee_balance_fri(&self) -> Result<u128, String> {
        self.token_balance(STRK).await.map_err(|e| e.to_string())
    }

    /// Plain WBTC transfer of `amount_msat`, in whole sats, to `to`.
    /// Returns the tx hash.
    pub async fn transfer(&self, to: &str, amount_msat: u64) -> Result<String, String> {
        let to: StarknetAddress = to.parse()?;
        let mut calldata = vec![felt(&to)];
        calldata.extend(u256((amount_msat / MSAT_PER_SAT).into()));
        let tx = self
            .transact(
                vec![Call {
                    to: self.contracts.wbtc,
                    selector: selector("transfer"),
                    calldata,
                }],
                "transfer",
            )
            .await
            .map_err(|e| e.to_string())?;
        Ok(format!("{tx:#066x}"))
    }

    fn claim_target(&self) -> InvoiceTarget {
        InvoiceTarget::StarknetWbtc {
            network: self.id.clone(),
            target: self.address(),
        }
    }

    async fn call(
        &self,
        contract: Felt,
        entry_point: &str,
        calldata: Vec<Felt>,
    ) -> Result<Vec<Felt>, NetworkError> {
        self.provider()
            .call(
                FunctionCall {
                    contract_address: contract,
                    entry_point_selector: selector(entry_point),
                    calldata,
                },
                BlockId::Tag(BlockTag::Latest),
            )
            .await
            .map_err(rpc_error(entry_point))
    }

    /// Balance of the account in `token`, in its smallest unit.
    async fn token_balance(&self, token: Felt) -> Result<u128, NetworkError> {
        let balance = self
            .call(token, "balance_of", vec![self.account.address()])
            .await?;
        match balance.as_slice() {
            [low, high] if *high == Felt::ZERO => {
                u128::try_from(*low).map_err(NetworkError::network)
            }
            _ => Err(NetworkError::network("balance does not fit 128 bits")),
        }
    }

    async fn escrow_state(
        &self,
        escrow: &Escrow,
        payment_hash: &Bytes32,
    ) -> Result<EscrowState, NetworkError> {
        let state = self
            .call(
                self.contracts.escrow_manager,
                "get_state",
                escrow.data(payment_hash, &self.contracts),
            )
            .await?;
        let [_, finish_block, state] = state.as_slice() else {
            return Err(NetworkError::network("get_state returned no escrow state"));
        };
        Ok(EscrowState {
            finish_block: u64::try_from(*finish_block).map_err(NetworkError::network)?,
            state: u64::try_from(*state).map_err(NetworkError::network)?,
        })
    }

    /// What became of `escrow`, locked for `payment_hash`: pending while
    /// committed, claimed with the preimage its claim revealed, or
    /// refunded.
    async fn outcome(
        &self,
        escrow: &Escrow,
        payment_hash: &Bytes32,
    ) -> Result<OutgoingState, NetworkError> {
        let state = self.escrow_state(escrow, payment_hash).await?;
        match state.state {
            STATE_COMMITTED => Ok(OutgoingState::Pending),
            STATE_REFUNDED => Ok(OutgoingState::Refunded),
            STATE_CLAIMED => self
                .claimed_preimage(escrow, payment_hash, state.finish_block)
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

    /// The preimage the claim of `escrow` revealed in `block`, from its
    /// `Claim` event: `[8, preimage words, claim handler]`.
    async fn claimed_preimage(
        &self,
        escrow: &Escrow,
        payment_hash: &Bytes32,
        block: u64,
    ) -> Result<Bytes32, NetworkError> {
        let filter = EventFilter {
            from_block: Some(BlockId::Number(block)),
            to_block: Some(BlockId::Number(block)),
            address: Some(AddressFilter::Single(self.contracts.escrow_manager)),
            keys: Some(vec![
                vec![selector("Claim")],
                vec![escrow.offerer],
                vec![escrow.claimer],
                vec![claim_data(payment_hash)],
            ]),
        };
        let mut continuation = None;
        loop {
            let page = self
                .provider()
                .get_events(filter.clone(), continuation, 100)
                .await
                .map_err(rpc_error("events"))?;
            for event in page.events {
                let preimage = event.data.get(1..9).and_then(from_words);
                if let Some(preimage) = preimage.filter(|p| payment_hash.matches_preimage(p)) {
                    return Ok(preimage);
                }
            }
            match page.continuation_token {
                Some(token) => continuation = Some(token),
                None => break,
            }
        }
        Err(NetworkError::network(format!(
            "escrow of {} was claimed in block {block}, but the node shows no claim there",
            payment_hash.short()
        )))
    }

    /// Timestamp of the chain tip, what refunds are held against.
    async fn tip_timestamp(&self) -> Result<u64, NetworkError> {
        match self
            .provider()
            .get_block_with_tx_hashes(BlockId::Tag(BlockTag::Latest))
            .await
            .map_err(rpc_error("tip"))?
        {
            MaybePreConfirmedBlockWithTxHashes::Block(block) => Ok(block.timestamp),
            MaybePreConfirmedBlockWithTxHashes::PreConfirmedBlock(block) => Ok(block.timestamp),
        }
    }

    /// Deploy the account, from the STRK sent to its address, unless it
    /// already is.
    async fn ensure_deployed(&self) -> Result<(), NetworkError> {
        if self.deployed.load(Ordering::Relaxed) {
            return Ok(());
        }
        match self
            .provider()
            .get_class_hash_at(BlockId::Tag(BlockTag::Latest), self.account.address())
            .await
        {
            Ok(_) => {
                self.deployed.store(true, Ordering::Relaxed);
                return Ok(());
            }
            Err(ProviderError::StarknetError(StarknetError::ContractNotFound)) => {}
            Err(error) => return Err(rpc_error("account class")(error)),
        }
        let factory = OpenZeppelinAccountFactory::new(
            OZ_ACCOUNT_CLASS_HASH,
            self.chain_id,
            LocalWallet::from(self.key.clone()),
            JsonRpcClient::new(HttpTransport::new(self.rpc_url.clone())),
        )
        .await
        .map_err(NetworkError::network)?;
        let deployment = factory
            .deploy_v3(self.key.verifying_key().scalar())
            .send()
            .await
            .map_err(|e| NetworkError::network(format!("deploying the account: {e}")))?;
        self.wait_for(deployment.transaction_hash, "deploy account")
            .await?;
        info!(
            parent: &self.span,
            "deployed account {:#066x}: tx {:#066x}",
            deployment.contract_address,
            deployment.transaction_hash
        );
        self.deployed.store(true, Ordering::Relaxed);
        Ok(())
    }

    /// Send `calls` from the account, deploying it first if need be, and
    /// wait for them to succeed.
    async fn transact(&self, calls: Vec<Call>, what: &str) -> Result<Felt, NetworkError> {
        let tx_hash = {
            let _sending = self.sending.lock().await;
            self.ensure_deployed().await?;
            self.account
                .execute_v3(calls)
                .send()
                .await
                .map_err(|e| NetworkError::network(format!("{what}: {e}")))?
                .transaction_hash
        };
        self.wait_for(tx_hash, what).await?;
        Ok(tx_hash)
    }

    /// Wait for `tx_hash` to be accepted on L2 and to have succeeded.
    async fn wait_for(&self, tx_hash: Felt, what: &str) -> Result<(), NetworkError> {
        let deadline = tokio::time::Instant::now() + RECEIPT_TIMEOUT;
        loop {
            match self.provider().get_transaction_receipt(tx_hash).await {
                Ok(receipt) => {
                    if let ExecutionResult::Reverted { reason } = receipt.receipt.execution_result()
                    {
                        return Err(NetworkError::network(format!(
                            "{what} {tx_hash:#066x} reverted: {reason}"
                        )));
                    }
                    if *receipt.receipt.finality_status() != TransactionFinalityStatus::PreConfirmed
                    {
                        return Ok(());
                    }
                }
                Err(ProviderError::StarknetError(StarknetError::TransactionHashNotFound)) => {}
                Err(error) => return Err(rpc_error(what)(error)),
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(NetworkError::network(format!(
                    "{what} {tx_hash:#066x}: not accepted yet"
                )));
            }
            tokio::time::sleep(RECEIPT_POLL).await;
        }
    }

    /// Whether the account holds enough STRK for its fees.
    async fn check_fees(&self) -> Result<(), NetworkError> {
        let balance = self.token_balance(STRK).await?;
        if balance < FEE_RESERVE_FRI {
            warn!(parent: &self.span, "cannot afford fees: {balance} < {FEE_RESERVE_FRI} fri");
            return Err(NetworkError::invalid(format!(
                "fees need {FEE_RESERVE_FRI} fri of STRK, account has {balance} fri"
            )));
        }
        Ok(())
    }
}

#[async_trait]
impl Network for StarknetWbtcAdapter {
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
        if escrow.amount_sat < sats_for_msat(htlc.amount_msat) {
            return Err(NetworkError::invalid("escrow is worth less than the HTLC"));
        }
        if escrow.refund_after < htlc.expiry {
            return Err(NetworkError::invalid("refund opens before the expiry"));
        }
        // The escrow's hash commits to every term above, the payment
        // hash, WBTC, and atomiq's hashlock and timelock handlers: one that
        // is committed is this HTLC. A node behind the sender's may not
        // have it yet.
        match self.escrow_state(&escrow, &htlc.payment_hash).await?.state {
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
        let escrow = Escrow::of(htlc)?;
        // An earlier attempt may have gone through after it was given
        // up on.
        match self.outcome(&escrow, &htlc.payment_hash).await {
            Ok(OutgoingState::Claimed(_)) => return Ok(()),
            Ok(OutgoingState::Refunded) => {
                return Err(NetworkError::invalid("the escrow was refunded"));
            }
            Ok(OutgoingState::Pending) | Err(_) => {}
        }
        let call = claim_call(&escrow, &htlc.payment_hash, &preimage, &self.contracts);
        let tx = self.transact(vec![call], "claim").await?;
        info!(parent: &self.span, "claimed {}: tx {tx:#066x}", htlc.payment_hash.short());
        Ok(())
    }

    async fn create_outgoing_htlc(
        &self,
        payment_hash: Bytes32,
        amount_msat: u64,
        expiry: u64,
        target: &InvoiceTarget,
    ) -> Result<HtlcDescriptor, NetworkError> {
        let InvoiceTarget::StarknetWbtc { target: claim, .. } = target else {
            return Err(NetworkError::invalid(
                "starknet-wbtc HTLCs are locked to a Starknet address",
            ));
        };
        let escrow = Escrow::for_lock(amount_msat, expiry, claim, self.account.address());
        let calls = lock_calls(&escrow, &payment_hash, &self.contracts);
        let tx = self.transact(calls, "lock").await?;
        info!(
            parent: &self.span,
            "locked {} sat for {} until {}: tx {tx:#066x}",
            escrow.amount_sat,
            payment_hash.short(),
            escrow.refund_after
        );
        Ok(escrow.descriptor())
    }

    async fn check_outgoing_htlc(&self, htlc: &Htlc) -> Result<OutgoingState, NetworkError> {
        self.outcome(&Escrow::of(htlc)?, &htlc.payment_hash).await
    }

    async fn refund_outgoing_htlc(&self, htlc: &Htlc) -> Result<(), NetworkError> {
        let escrow = Escrow::of(htlc)?;
        match self.outcome(&escrow, &htlc.payment_hash).await {
            Ok(OutgoingState::Refunded) => return Ok(()),
            Ok(OutgoingState::Claimed(_)) => {
                return Err(NetworkError::invalid("the escrow was claimed"));
            }
            Ok(OutgoingState::Pending) | Err(_) => {}
        }
        let tip = self.tip_timestamp().await?;
        if tip <= escrow.refund_after {
            return Err(NetworkError::network(format!(
                "refund opens after {}, tip is at {tip}",
                escrow.refund_after
            )));
        }
        let call = refund_call(&escrow, &htlc.payment_hash, &self.contracts);
        let tx = self.transact(vec![call], "refund").await?;
        info!(parent: &self.span, "refunded {}: tx {tx:#066x}", htlc.payment_hash.short());
        Ok(())
    }

    async fn can_send(&self, amount_msat: u64) -> Result<(), NetworkError> {
        let needed = u128::from(sats_for_msat(amount_msat));
        let balance = self.token_balance(self.contracts.wbtc).await?;
        if balance < needed {
            return Err(NetworkError::invalid(format!(
                "need {needed} sat of WBTC, account has {balance} sat"
            )));
        }
        self.check_fees().await
    }

    /// Claims pay fees from the account.
    async fn can_receive(&self, _amount_msat: u64) -> Result<(), NetworkError> {
        self.check_fees().await
    }
}

/// SLIP-44 coin type of Starknet.
const STARKNET_COIN_TYPE: u32 = 9004;

/// The order of the Stark curve, below which private keys lie.
const STARK_CURVE_ORDER: &str = "800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f";

/// The Stark key of the account of `mnemonic`: the BIP44 key
/// `m/44'/9004'/0'/0/0`, ground into the curve's order as EIP-2645 and
/// Starknet's wallets do.
pub fn account_key(mnemonic: &Mnemonic) -> Result<Felt, String> {
    let seed = bip44_key(&mnemonic.to_seed(""), STARKNET_COIN_TYPE, 0)
        .map_err(|e| format!("starknet key: {e}"))?;
    Ok(grind_key(&seed))
}

/// EIP-2645's `grind_key`: the first `sha256(seed || index)` below the
/// largest multiple of the curve order that fits 256 bits, reduced
/// modulo the order. The seed and the index are written in as few bytes
/// as hold them, like the reference implementation does.
pub fn grind_key(seed: &[u8; 32]) -> Felt {
    let order = BigUint::parse_bytes(STARK_CURVE_ORDER.as_bytes(), 16).expect("hex order");
    let limit = (BigUint::from(1u8) << 256u32) / &order * &order;
    let seed = BigUint::from_bytes_be(seed).to_bytes_be();
    for index in 0u32.. {
        let mut hash = Sha256::new();
        hash.update(&seed);
        hash.update(BigUint::from(index).to_bytes_be());
        let key = BigUint::from_bytes_be(&hash.finalize());
        if key < limit {
            return Felt::from_bytes_be_slice(&(key % &order).to_bytes_be());
        }
    }
    unreachable!("some index grinds a key below the limit")
}

/// The address of the OpenZeppelin account of the Stark public key
/// `public_key`, deployed by itself with the key as its salt.
pub fn account_address(public_key: Felt) -> Felt {
    get_contract_address(public_key, OZ_ACCOUNT_CLASS_HASH, &[public_key], Felt::ZERO)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reference implementation's `grind_key` of the EIP-2645 test
    /// vector.
    #[test]
    fn grinds_keys_like_eip_2645() {
        let seed: [u8; 32] = Felt::from_hex_unchecked(
            "0x86F3E7293141F20A8BAFF320E8EE4ACCB9D4A4BF2B4D295E8CEE784DB46E0519",
        )
        .to_bytes_be();
        assert_eq!(
            grind_key(&seed),
            Felt::from_hex_unchecked(
                "0x5c8c8683596c732541a59e03007b2d30dbbbb873556fe65b5fb63c16688f941"
            )
        );
    }

    #[test]
    fn words_round_trip() {
        let bytes = Bytes32(std::array::from_fn(|i| i as u8));
        assert_eq!(words(&bytes)[0], Felt::from(0x00010203u32));
        assert_eq!(from_words(&words(&bytes)), Some(bytes));
    }

    /// The escrow serializes in `EscrowData`'s field order, 16 felts with
    /// no success action.
    #[test]
    fn escrow_data_layout() {
        let escrow = Escrow {
            amount_sat: 1_000,
            claimer: Felt::from(2u8),
            offerer: Felt::from(1u8),
            sequence: 7,
            refund_after: 99,
        };
        let data = escrow.data(&Bytes32([0; 32]), &STARKNET_MAINNET_CONTRACTS);
        assert_eq!(data.len(), 16);
        assert_eq!(data[5], Felt::from((7u128 << 64) | 3));
        assert_eq!(data[7], Felt::from(99u8));
        assert_eq!(data[8], Felt::from(1_000u16));
        assert_eq!(data[15], Felt::ONE);
    }
}
