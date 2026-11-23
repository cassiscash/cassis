//! WBTC on Solana: HTLCs are WBTC escrows in atomiq's swap program (v2).
//!
//! An escrow is an account of the program at the address derived from
//! `["state", payment hash]`, holding the swap's terms while its tokens
//! sit in the program's vault. Every escrow here is of kind `Htlc`:
//! claimable with the SHA-256 preimage of the payment hash, refundable
//! once the cluster's clock is past its expiry.
//!
//! * **Lock**: `offerer_initialize_pay_in(swap data, 0, 0, [0; 32],
//!   auth expiry)` from the offerer, paying out to the claimer's WBTC
//!   account. No signature of the claimer is needed when paying out.
//! * **Claim**: `claimer_claim_pay_out(preimage)`, from anyone: the
//!   program pays the WBTC account the escrow names, whoever sends it. It
//!   emits `ClaimEvent { hash, secret, sequence }`, where the sender
//!   reads the preimage, and closes the escrow account.
//! * **Refund**: `offerer_refund_pay_in(0)` once the clock is past the
//!   expiry, paid to the offerer's WBTC account. It emits `RefundEvent`.
//!
//! Since the address is derived from the payment hash alone, only one
//! escrow per payment hash can be open at a time, and once closed, what
//! became of it is read from the events of the transactions that
//! touched the address.
//!
//! Transactions are built by hand: legacy messages, Anchor instruction
//! discriminators and Borsh arguments. The adapter's account is the
//! first Solana address of its mnemonic (see [`account_key`]), paying
//! fees and rent in SOL.

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use cassis_core::keys::Mnemonic;
use cassis_core::{
    Bytes32, Ed25519PubKey, Htlc, HtlcDescriptor, InvoiceTarget, MSAT_PER_SAT, Network,
    NetworkError, NetworkId, OutgoingState, sats_for_msat,
};
use ed25519_dalek::{Signer as _, SigningKey};
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::{Digest, Sha256, Sha512};
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{Span, debug, info, warn};

type Pubkey = Ed25519PubKey;

pub const SOLANA_MAINNET_RPC: &str = "https://api.mainnet-beta.solana.com";

/// atomiq's swap program, v2, whose source is atomiq-contracts-solana.
/// Its upgrade authority is revoked.
pub const SWAP_PROGRAM: &str = "atq2FYuvww5EF6qeB28gj9tkao6Ld9mEGUzF4M93cCC";
/// Wrapped BTC (Wormhole), 8 decimals.
pub const WBTC_MINT: &str = "3NZ9JMVBmGAqocybic2c7LQCJScmgsAZ6vQqTDzcqmJh";
pub const WBTC_DECIMALS: u8 = 8;
const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const ASSOCIATED_TOKEN_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";
const COMPUTE_BUDGET_PROGRAM: &str = "ComputeBudget111111111111111111111111111111";
const INSTRUCTIONS_SYSVAR: &str = "Sysvar1nstructions1111111111111111111111111";

/// Compute units each transaction asks for, and the price it offers
/// per unit, in micro-lamports.
const COMPUTE_UNITS: u32 = 200_000;
const COMPUTE_UNIT_PRICE: u64 = 50_000;
/// SOL (in lamports) kept for fees and rent before committing to a
/// route: an escrow account's rent while it is open, a WBTC account's
/// rent the first time one is claimed into, and fees.
pub const LAMPORTS_RESERVE: u64 = 10_000_000;
/// How long a sent transaction is waited for, about as long as its
/// blockhash is valid. One that takes longer is reported as failed, and
/// found (or sent again) by the next attempt.
const CONFIRM_TIMEOUT: Duration = Duration::from_secs(90);
const CONFIRM_POLL: Duration = Duration::from_secs(2);
/// The most transactions read back when looking for what became of an
/// escrow.
const MAX_HISTORY: usize = 1_000;

/// Bytes of an escrow account: Anchor's discriminator, the swap data,
/// then offerer, offerer's token account, claimer, claimer's token
/// account, mint, claimer bounty, security deposit, who initialized it.
const ESCROW_ACCOUNT_LEN: usize = 254;
const SWAP_TYPE_HTLC: u8 = 0;

fn pubkey(base58: &str) -> Pubkey {
    base58.parse().expect("valid base58 address constant")
}

/// The accounts a `solana-wbtc` network works with.
#[derive(Clone, Copy, Debug)]
pub struct Deployment {
    pub program: Pubkey,
    pub mint: Pubkey,
}

/// The public node and accounts of `solana-wbtc`.
pub fn deployment(id: &NetworkId) -> Result<(&'static str, Deployment), String> {
    match id.param() {
        None => Ok((
            SOLANA_MAINNET_RPC,
            Deployment {
                program: pubkey(SWAP_PROGRAM),
                mint: pubkey(WBTC_MINT),
            },
        )),
        Some(other) => Err(format!("unknown solana-wbtc network '{other}'")),
    }
}

/// Whether `bytes` is a point on the Ed25519 curve, which a program
/// derived address must not be.
fn on_curve(bytes: &[u8; 32]) -> bool {
    curve25519_dalek::edwards::CompressedEdwardsY(*bytes)
        .decompress()
        .is_some()
}

/// The program derived address of `seeds` under `program`: the first
/// bump from 255 down whose hash is off the curve.
pub fn find_program_address(seeds: &[&[u8]], program: &Pubkey) -> Pubkey {
    for bump in (0..=255u8).rev() {
        let mut hash = Sha256::new();
        for seed in seeds {
            hash.update(seed);
        }
        hash.update([bump]);
        hash.update(program.as_bytes());
        hash.update(b"ProgramDerivedAddress");
        let address: [u8; 32] = hash.finalize().into();
        if !on_curve(&address) {
            return Ed25519PubKey(address);
        }
    }
    unreachable!("some bump gives an address off the curve")
}

/// The associated token account of `owner` for `mint`.
pub fn token_account(owner: &Pubkey, mint: &Pubkey) -> Pubkey {
    find_program_address(
        &[
            owner.as_bytes(),
            pubkey(TOKEN_PROGRAM).as_bytes(),
            mint.as_bytes(),
        ],
        &pubkey(ASSOCIATED_TOKEN_PROGRAM),
    )
}

/// The escrow account of `payment_hash`.
pub fn escrow_address(payment_hash: &Bytes32, program: &Pubkey) -> Pubkey {
    find_program_address(&[b"state", &payment_hash.0], program)
}

/// The program's vault of `mint`.
pub fn vault_address(mint: &Pubkey, program: &Pubkey) -> Pubkey {
    find_program_address(&[b"vault", mint.as_bytes()], program)
}

/// The first 8 bytes of `sha256(preimage)`: Anchor's discriminators of
/// instructions (`global:<name>`), accounts (`account:<Name>`) and
/// events (`event:<Name>`).
fn discriminator(preimage: &str) -> [u8; 8] {
    Sha256::digest(preimage.as_bytes())[..8]
        .try_into()
        .expect("8 bytes")
}

/// One account an instruction uses.
#[derive(Clone, Copy, Debug)]
struct AccountMeta {
    key: Pubkey,
    signer: bool,
    writable: bool,
}

fn writable(key: Pubkey) -> AccountMeta {
    AccountMeta {
        key,
        signer: false,
        writable: true,
    }
}

fn readonly(key: Pubkey) -> AccountMeta {
    AccountMeta {
        key,
        signer: false,
        writable: false,
    }
}

fn signer(key: Pubkey) -> AccountMeta {
    AccountMeta {
        key,
        signer: true,
        writable: true,
    }
}

#[derive(Clone, Debug)]
struct Instruction {
    program: Pubkey,
    accounts: Vec<AccountMeta>,
    data: Vec<u8>,
}

/// Solana's compact-u16 length.
fn short_vec_len(out: &mut Vec<u8>, mut len: usize) {
    loop {
        let byte = (len & 0x7f) as u8;
        len >>= 7;
        if len == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// A legacy transaction of `instructions`, paid for and signed by
/// `payer`, its only signer.
fn transaction(payer: &SigningKey, instructions: &[Instruction], blockhash: [u8; 32]) -> Vec<u8> {
    let payer_key = Ed25519PubKey(payer.verifying_key().to_bytes());
    // Every account once, with the strongest role it has anywhere;
    // programs are read-only non-signers.
    let mut accounts: Vec<AccountMeta> = vec![signer(payer_key)];
    let mut add = |meta: AccountMeta| match accounts.iter_mut().find(|a| a.key == meta.key) {
        Some(account) => {
            account.signer |= meta.signer;
            account.writable |= meta.writable;
        }
        None => accounts.push(meta),
    };
    for instruction in instructions {
        for meta in &instruction.accounts {
            add(*meta);
        }
        add(readonly(instruction.program));
    }
    // Writable signers, read-only signers, writable non-signers, then
    // read-only non-signers, the payer first.
    let rank = |a: &AccountMeta| match (a.signer, a.writable) {
        (true, true) => 0,
        (true, false) => 1,
        (false, true) => 2,
        (false, false) => 3,
    };
    let payer_entry = accounts.remove(0);
    accounts.sort_by_key(rank);
    accounts.insert(0, payer_entry);
    let index = |key: &Pubkey| {
        accounts
            .iter()
            .position(|a| a.key == *key)
            .expect("every account is listed") as u8
    };

    let mut message = vec![
        accounts.iter().filter(|a| a.signer).count() as u8,
        accounts.iter().filter(|a| a.signer && !a.writable).count() as u8,
        accounts.iter().filter(|a| !a.signer && !a.writable).count() as u8,
    ];
    short_vec_len(&mut message, accounts.len());
    for account in &accounts {
        message.extend_from_slice(account.key.as_bytes());
    }
    message.extend_from_slice(&blockhash);
    short_vec_len(&mut message, instructions.len());
    for instruction in instructions {
        message.push(index(&instruction.program));
        short_vec_len(&mut message, instruction.accounts.len());
        for meta in &instruction.accounts {
            message.push(index(&meta.key));
        }
        short_vec_len(&mut message, instruction.data.len());
        message.extend_from_slice(&instruction.data);
    }

    let mut transaction = Vec::with_capacity(1 + 64 + message.len());
    short_vec_len(&mut transaction, 1);
    transaction.extend_from_slice(&payer.sign(&message).to_bytes());
    transaction.extend_from_slice(&message);
    transaction
}

/// The compute budget every transaction sets first.
fn compute_budget() -> [Instruction; 2] {
    let program = pubkey(COMPUTE_BUDGET_PROGRAM);
    let mut limit = vec![2];
    limit.extend_from_slice(&COMPUTE_UNITS.to_le_bytes());
    let mut price = vec![3];
    price.extend_from_slice(&COMPUTE_UNIT_PRICE.to_le_bytes());
    [
        Instruction {
            program,
            accounts: vec![],
            data: limit,
        },
        Instruction {
            program,
            accounts: vec![],
            data: price,
        },
    ]
}

/// Create `owner`'s token account of `mint`, paid by `payer`, unless it
/// exists.
fn create_token_account(payer: &Pubkey, owner: &Pubkey, mint: &Pubkey) -> Instruction {
    Instruction {
        program: pubkey(ASSOCIATED_TOKEN_PROGRAM),
        accounts: vec![
            signer(*payer),
            writable(token_account(owner, mint)),
            readonly(*owner),
            readonly(*mint),
            readonly(pubkey(SYSTEM_PROGRAM)),
            readonly(pubkey(TOKEN_PROGRAM)),
        ],
        // `CreateIdempotent`.
        data: vec![1],
    }
}

/// The escrow of an [`Htlc`]: everything but the payment hash, which is
/// the escrow's hash and address. A wallet that funds or claims HTLCs
/// without a [`SolanaWbtcAdapter`] builds this from an
/// [`HtlcRequest`](cassis_core::HtlcRequest) or an [`Htlc`], and sends the
/// instructions below.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Escrow {
    pub amount_sat: u64,
    pub claimer: Pubkey,
    pub offerer: Pubkey,
    /// Tells escrows of one payment hash apart.
    pub sequence: u64,
    /// Unix seconds after which the escrow can be refunded.
    pub refund_after: u64,
}

impl Escrow {
    /// The escrow to make for a payment claimable by `claim` (the key of
    /// an [`InvoiceTarget::SolanaWbtc`]): `amount_msat`, rounded up to
    /// sats, locked from `offerer`, refundable after `expiry`.
    pub fn for_lock(amount_msat: u64, expiry: u64, claim: &Pubkey, offerer: Pubkey) -> Self {
        Self {
            amount_sat: sats_for_msat(amount_msat),
            claimer: *claim,
            offerer,
            sequence: rand::random(),
            refund_after: expiry,
        }
    }

    pub fn of(htlc: &Htlc) -> Result<Self, NetworkError> {
        let HtlcDescriptor::SolanaWbtc {
            amount_sat,
            refund_address,
            sequence,
            refund_after,
            target,
        } = &htlc.descriptor
        else {
            return Err(NetworkError::invalid("not a solana-wbtc HTLC"));
        };
        Ok(Self {
            amount_sat: *amount_sat,
            claimer: *target,
            offerer: *refund_address,
            sequence: *sequence,
            refund_after: *refund_after,
        })
    }

    /// The descriptor of this escrow, claimable by its claimer.
    pub fn descriptor(&self) -> HtlcDescriptor {
        HtlcDescriptor::SolanaWbtc {
            amount_sat: self.amount_sat,
            refund_address: self.offerer,
            sequence: self.sequence,
            refund_after: self.refund_after,
            target: self.claimer,
        }
    }

    /// The program's `SwapData` of this escrow, Borsh-encoded: an HTLC
    /// paid in from the offerer's and out to the claimer's token account.
    fn swap_data(&self, payment_hash: &Bytes32) -> Vec<u8> {
        let mut data = vec![SWAP_TYPE_HTLC];
        // No confirmations, no nonce: those are for on-chain swaps.
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u64.to_le_bytes());
        data.extend_from_slice(&payment_hash.0);
        // Paid in, paid out.
        data.extend_from_slice(&[1, 1]);
        data.extend_from_slice(&self.amount_sat.to_le_bytes());
        data.extend_from_slice(&self.refund_after.to_le_bytes());
        data.extend_from_slice(&self.sequence.to_le_bytes());
        data
    }

    /// `offerer_initialize_pay_in`, from the offerer, with no deposit or
    /// bounty. The offerer needs no authorization, so it never expires.
    fn lock(&self, payment_hash: &Bytes32, deployment: &Deployment) -> Instruction {
        let mut data = discriminator("global:offerer_initialize_pay_in").to_vec();
        data.extend(self.swap_data(payment_hash));
        // Security deposit, claimer bounty, the transaction output hash
        // of on-chain swaps, authorization expiry.
        data.extend_from_slice(&0u64.to_le_bytes());
        data.extend_from_slice(&0u64.to_le_bytes());
        data.extend_from_slice(&[0; 32]);
        data.extend_from_slice(&u64::MAX.to_le_bytes());
        Instruction {
            program: deployment.program,
            accounts: vec![
                signer(self.offerer),
                readonly(self.claimer),
                signer(self.offerer),
                writable(token_account(&self.offerer, &deployment.mint)),
                writable(escrow_address(payment_hash, &deployment.program)),
                writable(vault_address(&deployment.mint, &deployment.program)),
                readonly(deployment.mint),
                readonly(pubkey(SYSTEM_PROGRAM)),
                readonly(pubkey(TOKEN_PROGRAM)),
                // No claimer vault: the escrow pays out.
                readonly(deployment.program),
                readonly(token_account(&self.claimer, &deployment.mint)),
            ],
            data,
        }
    }

    /// `claimer_claim_pay_out`, from `sender`, paying the claimer's token
    /// account, which must exist.
    fn claim(
        &self,
        payment_hash: &Bytes32,
        preimage: &Bytes32,
        sender: Pubkey,
        deployment: &Deployment,
    ) -> Instruction {
        let mut data = discriminator("global:claimer_claim_pay_out").to_vec();
        data.extend_from_slice(&32u32.to_le_bytes());
        data.extend_from_slice(&preimage.0);
        Instruction {
            program: deployment.program,
            accounts: vec![
                signer(sender),
                writable(self.offerer),
                writable(self.claimer),
                writable(escrow_address(payment_hash, &deployment.program)),
                readonly(pubkey(INSTRUCTIONS_SYSVAR)),
                writable(token_account(&self.claimer, &deployment.mint)),
                writable(vault_address(&deployment.mint, &deployment.program)),
                readonly(pubkey(TOKEN_PROGRAM)),
                // No data account: the preimage is in the instruction.
                readonly(deployment.program),
            ],
            data,
        }
    }

    /// `offerer_refund_pay_in` without the claimer's signature, from any
    /// account once the clock is past the expiry.
    fn refund(&self, payment_hash: &Bytes32, deployment: &Deployment) -> Instruction {
        let mut data = discriminator("global:offerer_refund_pay_in").to_vec();
        data.extend_from_slice(&0u64.to_le_bytes());
        Instruction {
            program: deployment.program,
            accounts: vec![
                writable(self.offerer),
                writable(self.claimer),
                writable(token_account(&self.offerer, &deployment.mint)),
                writable(escrow_address(payment_hash, &deployment.program)),
                writable(vault_address(&deployment.mint, &deployment.program)),
                readonly(pubkey(TOKEN_PROGRAM)),
                // No claimer vault and no instructions sysvar: neither a
                // vault nor a signature is involved.
                readonly(deployment.program),
                readonly(deployment.program),
            ],
            data,
        }
    }
}

/// An open escrow account, as far as the adapter reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct EscrowAccount {
    kind: u8,
    hash: Bytes32,
    pay_out: bool,
    amount_sat: u64,
    expiry: u64,
    sequence: u64,
    offerer: Pubkey,
    claimer: Pubkey,
    claimer_token_account: Pubkey,
    mint: Pubkey,
}

impl EscrowAccount {
    fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < ESCROW_ACCOUNT_LEN || data[..8] != discriminator("account:EscrowState") {
            return None;
        }
        let bytes32 = |at: usize| -> [u8; 32] { data[at..at + 32].try_into().expect("32 bytes") };
        let u64_at = |at: usize| u64::from_le_bytes(data[at..at + 8].try_into().expect("8 bytes"));
        Some(Self {
            kind: data[8],
            hash: Bytes32(bytes32(19)),
            pay_out: data[52] == 1,
            amount_sat: u64_at(53),
            expiry: u64_at(61),
            sequence: u64_at(69),
            offerer: Ed25519PubKey(bytes32(77)),
            claimer: Ed25519PubKey(bytes32(141)),
            claimer_token_account: Ed25519PubKey(bytes32(173)),
            mint: Ed25519PubKey(bytes32(205)),
        })
    }

    /// Whether this is `escrow`, locked for `payment_hash` in `mint`.
    fn is(&self, escrow: &Escrow, payment_hash: &Bytes32, mint: &Pubkey) -> bool {
        self.kind == SWAP_TYPE_HTLC
            && self.hash == *payment_hash
            && self.pay_out
            && self.amount_sat == escrow.amount_sat
            && self.expiry == escrow.refund_after
            && self.sequence == escrow.sequence
            && self.offerer == escrow.offerer
            && self.claimer == escrow.claimer
            && self.claimer_token_account == token_account(&escrow.claimer, mint)
            && self.mint == *mint
    }
}

/// What the program logged of one escrow in one transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
enum EscrowEvent {
    Claimed(Bytes32),
    Refunded,
}

/// The events `program` emitted for `payment_hash` and `sequence`, from a
/// transaction's log: the `Program data:` lines logged while `program`
/// was the innermost one running, which no other program can forge.
fn escrow_events(
    logs: &[String],
    program: &Pubkey,
    payment_hash: &Bytes32,
    sequence: u64,
) -> Vec<EscrowEvent> {
    let program = program.to_string();
    let claim = discriminator("event:ClaimEvent");
    let refund = discriminator("event:RefundEvent");
    let mut running: Vec<&str> = Vec::new();
    let mut events = Vec::new();
    for line in logs {
        let Some(rest) = line.strip_prefix("Program ") else {
            continue;
        };
        if let Some(data) = rest.strip_prefix("data: ") {
            if running.last() != Some(&program.as_str()) {
                continue;
            }
            let Ok(data) = BASE64.decode(data.trim()) else {
                continue;
            };
            let sequence_at = |at: usize| {
                data.get(at..at + 8)
                    .map(|bytes| u64::from_le_bytes(bytes.try_into().expect("8 bytes")))
            };
            let hash = data.get(8..40);
            if data.get(..8) == Some(&claim)
                && hash == Some(&payment_hash.0)
                && sequence_at(72) == Some(sequence)
            {
                let secret = Bytes32(data[40..72].try_into().expect("32 bytes"));
                events.push(EscrowEvent::Claimed(secret));
            } else if data.get(..8) == Some(&refund)
                && hash == Some(&payment_hash.0)
                && sequence_at(40) == Some(sequence)
            {
                events.push(EscrowEvent::Refunded);
            }
        } else if let Some((id, _)) = rest.split_once(" invoke [") {
            running.push(id);
        } else if rest.ends_with(" success") || rest.contains(" failed") {
            running.pop();
        }
    }
    events
}

/// A Solana JSON-RPC node.
struct Rpc {
    url: String,
    http: reqwest::Client,
}

/// JSON-RPC "invalid params", what nodes answer for the balance of a
/// token account that does not exist.
const INVALID_PARAMS: i64 = -32602;

impl Rpc {
    async fn call(&self, method: &str, params: Value) -> Result<Value, NetworkError> {
        Ok(self.call_raw(method, params).await??)
    }

    /// `call`, keeping JSON-RPC errors apart from failures to reach the
    /// node.
    async fn call_raw(
        &self,
        method: &str,
        params: Value,
    ) -> Result<Result<Value, RpcError>, NetworkError> {
        let response: Value = self
            .http
            .post(&self.url)
            .json(&json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}))
            .send()
            .await
            .map_err(|e| NetworkError::network(format!("{method}: {e}")))?
            .json()
            .await
            .map_err(|e| NetworkError::network(format!("{method}: {e}")))?;
        Ok(match response.get("error") {
            Some(error) => Err(RpcError {
                code: error["code"].as_i64().unwrap_or(0),
                message: format!("{method}: {error}"),
            }),
            None => Ok(response["result"].clone()),
        })
    }

    /// The account at `address`, if it exists: its owner and data.
    async fn account(&self, address: &Pubkey) -> Result<Option<(Pubkey, Vec<u8>)>, NetworkError> {
        let value = &self
            .call(
                "getAccountInfo",
                json!([address.to_string(), {"encoding": "base64", "commitment": "confirmed"}]),
            )
            .await?["value"];
        if value.is_null() {
            return Ok(None);
        }
        let owner = value["owner"]
            .as_str()
            .ok_or_else(|| NetworkError::network("account has no owner"))?
            .parse()
            .map_err(NetworkError::network)?;
        let data = BASE64
            .decode(value["data"][0].as_str().unwrap_or_default())
            .map_err(NetworkError::network)?;
        Ok(Some((owner, data)))
    }

    async fn lamports(&self, address: &Pubkey) -> Result<u64, NetworkError> {
        self.call(
            "getBalance",
            json!([address.to_string(), {"commitment": "confirmed"}]),
        )
        .await?["value"]
            .as_u64()
            .ok_or_else(|| NetworkError::network("balance is not a number"))
    }

    /// Balance of a token account, 0 if it does not exist.
    async fn token_balance(&self, account: &Pubkey) -> Result<u64, NetworkError> {
        match self
            .call_raw(
                "getTokenAccountBalance",
                json!([account.to_string(), {"commitment": "confirmed"}]),
            )
            .await?
        {
            Ok(result) => result["value"]["amount"]
                .as_str()
                .and_then(|amount| amount.parse().ok())
                .ok_or_else(|| NetworkError::network("token balance is not a number")),
            Err(error) if error.code == INVALID_PARAMS => Ok(0),
            Err(error) => Err(error.into()),
        }
    }

    async fn blockhash(&self) -> Result<[u8; 32], NetworkError> {
        let blockhash = self
            .call("getLatestBlockhash", json!([{"commitment": "confirmed"}]))
            .await?["value"]["blockhash"]
            .as_str()
            .ok_or_else(|| NetworkError::network("no blockhash"))?
            .parse::<Pubkey>()
            .map_err(NetworkError::network)?;
        Ok(blockhash.0)
    }

    /// The cluster's clock at its latest confirmed slot.
    async fn time(&self) -> Result<u64, NetworkError> {
        let slot = self
            .call("getSlot", json!([{"commitment": "confirmed"}]))
            .await?;
        self.call("getBlockTime", json!([slot]))
            .await?
            .as_u64()
            .ok_or_else(|| NetworkError::network("block has no time"))
    }

    /// Signatures of the successful transactions that touched `address`,
    /// newest first, up to [`MAX_HISTORY`].
    async fn history(&self, address: &Pubkey) -> Result<Vec<String>, NetworkError> {
        let mut signatures = Vec::new();
        let mut before: Option<String> = None;
        loop {
            let mut options = json!({"limit": 100, "commitment": "confirmed"});
            if let Some(before) = &before {
                options["before"] = json!(before);
            }
            let page = self
                .call(
                    "getSignaturesForAddress",
                    json!([address.to_string(), options]),
                )
                .await?;
            let page = page.as_array().cloned().unwrap_or_default();
            for entry in &page {
                if let (Some(signature), true) =
                    (entry["signature"].as_str(), entry["err"].is_null())
                {
                    signatures.push(signature.to_string());
                }
            }
            before = page
                .last()
                .and_then(|entry| entry["signature"].as_str())
                .map(str::to_string);
            if page.len() < 100 || signatures.len() >= MAX_HISTORY || before.is_none() {
                return Ok(signatures);
            }
        }
    }

    /// The log of the successful transaction `signature`.
    async fn logs(&self, signature: &str) -> Result<Vec<String>, NetworkError> {
        let result = self
            .call(
                "getTransaction",
                json!([signature, {
                    "encoding": "json",
                    "commitment": "confirmed",
                    "maxSupportedTransactionVersion": 0,
                }]),
            )
            .await?;
        if !result["meta"]["err"].is_null() {
            return Ok(Vec::new());
        }
        Ok(result["meta"]["logMessages"]
            .as_array()
            .map(|lines| {
                lines
                    .iter()
                    .filter_map(|line| line.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default())
    }
}

/// A JSON-RPC error answer.
struct RpcError {
    code: i64,
    message: String,
}

impl From<RpcError> for NetworkError {
    fn from(error: RpcError) -> Self {
        NetworkError::network(error.message)
    }
}

pub struct SolanaWbtcAdapter {
    id: NetworkId,
    span: Span,
    key: SigningKey,
    address: Pubkey,
    deployment: Deployment,
    rpc: Rpc,
    /// Held while a transaction is sent, so that two are never built on
    /// one stale view of the account.
    sending: Mutex<()>,
}

impl SolanaWbtcAdapter {
    /// Connect to `solana-wbtc` through a public node. All state is on
    /// chain.
    pub fn open(id: NetworkId, mnemonic: &Mnemonic, span: &Span) -> Result<Self, String> {
        let (rpc_url, deployment) = deployment(&id)?;
        let key = SigningKey::from_bytes(&account_key(mnemonic)?);
        let address = Ed25519PubKey(key.verifying_key().to_bytes());
        let span = cassis_core::network_span(span, &id);
        debug!(parent: &span, "solana wallet ready: address={address} rpc={rpc_url}");
        Ok(Self {
            id,
            span,
            key,
            address,
            deployment,
            rpc: Rpc {
                url: rpc_url.to_string(),
                http: reqwest::Client::new(),
            },
            sending: Mutex::new(()),
        })
    }

    /// The account that funds this node's HTLCs and pays its fees. HTLCs
    /// to this node pay out to its WBTC account.
    pub fn address(&self) -> Pubkey {
        self.address
    }

    fn wbtc_account(&self) -> Pubkey {
        token_account(&self.address, &self.deployment.mint)
    }

    /// WBTC balance, in msat.
    pub async fn balance_msat(&self) -> Result<u64, String> {
        let sats = self
            .rpc
            .token_balance(&self.wbtc_account())
            .await
            .map_err(|e| e.to_string())?;
        Ok(sats.saturating_mul(MSAT_PER_SAT))
    }

    /// SOL balance, in lamports, which pays the account's fees and rent.
    pub async fn fee_balance_lamports(&self) -> Result<u64, String> {
        self.rpc
            .lamports(&self.address)
            .await
            .map_err(|e| e.to_string())
    }

    /// Plain WBTC transfer of `amount_msat`, in whole sats, to the WBTC
    /// account of the Solana address `to`, created if need be. Returns
    /// the transaction signature.
    pub async fn transfer(&self, to: &str, amount_msat: u64) -> Result<String, String> {
        let to: Pubkey = to.parse()?;
        let mint = self.deployment.mint;
        let mut data = vec![12];
        data.extend_from_slice(&(amount_msat / MSAT_PER_SAT).to_le_bytes());
        data.push(WBTC_DECIMALS);
        let transfer = Instruction {
            program: pubkey(TOKEN_PROGRAM),
            accounts: vec![
                writable(self.wbtc_account()),
                readonly(mint),
                writable(token_account(&to, &mint)),
                signer(self.address),
            ],
            // `TransferChecked`.
            data,
        };
        self.transact(
            vec![create_token_account(&self.address, &to, &mint), transfer],
            "transfer",
        )
        .await
        .map_err(|e| e.to_string())
    }

    fn claim_target(&self) -> InvoiceTarget {
        InvoiceTarget::SolanaWbtc {
            network: self.id.clone(),
            target: self.address,
        }
    }

    /// The escrow account open for `payment_hash`, if any.
    async fn open_escrow(
        &self,
        payment_hash: &Bytes32,
    ) -> Result<Option<EscrowAccount>, NetworkError> {
        let address = escrow_address(payment_hash, &self.deployment.program);
        Ok(match self.rpc.account(&address).await? {
            Some((owner, data)) if owner == self.deployment.program => EscrowAccount::decode(&data),
            _ => None,
        })
    }

    /// What became of `escrow`, locked for `payment_hash`: pending while
    /// its account is open, else claimed or refunded as the events of
    /// the transactions that touched the account say.
    async fn outcome(
        &self,
        escrow: &Escrow,
        payment_hash: &Bytes32,
    ) -> Result<OutgoingState, NetworkError> {
        if let Some(account) = self.open_escrow(payment_hash).await?
            && account.is(escrow, payment_hash, &self.deployment.mint)
        {
            return Ok(OutgoingState::Pending);
        }
        // Gone, or another escrow of the same payment hash took the
        // address after it closed.
        let address = escrow_address(payment_hash, &self.deployment.program);
        let mut refunded = false;
        for signature in self.rpc.history(&address).await? {
            let logs = self.rpc.logs(&signature).await?;
            for event in escrow_events(
                &logs,
                &self.deployment.program,
                payment_hash,
                escrow.sequence,
            ) {
                match event {
                    EscrowEvent::Claimed(preimage) if payment_hash.matches_preimage(&preimage) => {
                        return Ok(OutgoingState::Claimed(preimage));
                    }
                    EscrowEvent::Claimed(_) => {}
                    EscrowEvent::Refunded => refunded = true,
                }
            }
        }
        if refunded {
            return Ok(OutgoingState::Refunded);
        }
        Err(NetworkError::network(format!(
            "no escrow of {} is open, and none was claimed or refunded",
            payment_hash.short()
        )))
    }

    /// Send `instructions` after the compute budget, and wait for them
    /// to be confirmed. Returns the transaction signature.
    async fn transact(
        &self,
        instructions: Vec<Instruction>,
        what: &str,
    ) -> Result<String, NetworkError> {
        let signature = {
            let _sending = self.sending.lock().await;
            let mut all = compute_budget().to_vec();
            all.extend(instructions);
            let transaction = transaction(&self.key, &all, self.rpc.blockhash().await?);
            self.rpc
                .call(
                    "sendTransaction",
                    json!([BASE64.encode(transaction), {
                        "encoding": "base64",
                        "preflightCommitment": "confirmed",
                    }]),
                )
                .await
                .map_err(|e| NetworkError::network(format!("{what}: {e}")))?
                .as_str()
                .ok_or_else(|| NetworkError::network(format!("{what}: no signature")))?
                .to_string()
        };
        let deadline = tokio::time::Instant::now() + CONFIRM_TIMEOUT;
        loop {
            let status = &self
                .rpc
                .call(
                    "getSignatureStatuses",
                    json!([[signature], {"searchTransactionHistory": true}]),
                )
                .await?["value"][0];
            if !status.is_null() {
                if !status["err"].is_null() {
                    return Err(NetworkError::network(format!(
                        "{what} {signature} failed: {}",
                        status["err"]
                    )));
                }
                if matches!(
                    status["confirmationStatus"].as_str(),
                    Some("confirmed" | "finalized")
                ) {
                    return Ok(signature);
                }
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(NetworkError::network(format!(
                    "{what} {signature}: not confirmed yet"
                )));
            }
            tokio::time::sleep(CONFIRM_POLL).await;
        }
    }

    /// Whether the account holds enough SOL for fees and rent.
    async fn check_fees(&self) -> Result<(), NetworkError> {
        let balance = self.rpc.lamports(&self.address).await?;
        if balance < LAMPORTS_RESERVE {
            warn!(parent: &self.span, "cannot afford fees: {balance} < {LAMPORTS_RESERVE} lamports");
            return Err(NetworkError::invalid(format!(
                "fees and rent need {LAMPORTS_RESERVE} lamports, account has {balance}"
            )));
        }
        Ok(())
    }
}

#[async_trait]
impl Network for SolanaWbtcAdapter {
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
        // The program stores whatever token account the offerer named,
        // so it must be checked to be the claimer's own WBTC account. A
        // node behind the sender's may not have the escrow yet.
        match self.open_escrow(&htlc.payment_hash).await? {
            Some(account) if account.is(&escrow, &htlc.payment_hash, &self.deployment.mint) => {
                Ok(())
            }
            Some(_) => Err(NetworkError::invalid(
                "the escrow of this payment hash has other terms",
            )),
            None => Err(NetworkError::not_yet("no escrow of this payment hash")),
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
        // The WBTC account the escrow pays must exist by now.
        let instructions = vec![
            create_token_account(&self.address, &escrow.claimer, &self.deployment.mint),
            escrow.claim(
                &htlc.payment_hash,
                &preimage,
                self.address,
                &self.deployment,
            ),
        ];
        let tx = self.transact(instructions, "claim").await?;
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
        let InvoiceTarget::SolanaWbtc { target: claim, .. } = target else {
            return Err(NetworkError::invalid(
                "solana-wbtc HTLCs are locked to a Solana address",
            ));
        };
        if self.open_escrow(&payment_hash).await?.is_some() {
            return Err(NetworkError::network(format!(
                "an escrow of {} is already open",
                payment_hash.short()
            )));
        }
        let escrow = Escrow::for_lock(amount_msat, expiry, claim, self.address);
        let tx = self
            .transact(vec![escrow.lock(&payment_hash, &self.deployment)], "lock")
            .await?;
        info!(
            parent: &self.span,
            "locked {} sat for {} until {}: tx {tx}",
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
        let now = self.rpc.time().await?;
        if now <= escrow.refund_after {
            return Err(NetworkError::network(format!(
                "refund opens after {}, the cluster's clock is at {now}",
                escrow.refund_after
            )));
        }
        let tx = self
            .transact(
                vec![escrow.refund(&htlc.payment_hash, &self.deployment)],
                "refund",
            )
            .await?;
        info!(parent: &self.span, "refunded {}: tx {tx}", htlc.payment_hash.short());
        Ok(())
    }

    async fn can_send(&self, amount_msat: u64) -> Result<(), NetworkError> {
        let needed = sats_for_msat(amount_msat);
        let balance = self.rpc.token_balance(&self.wbtc_account()).await?;
        if balance < needed {
            return Err(NetworkError::invalid(format!(
                "need {needed} sat of WBTC, account has {balance} sat"
            )));
        }
        self.check_fees().await
    }

    /// Claims pay fees, and the first one the rent of the WBTC account,
    /// from the account.
    async fn can_receive(&self, _amount_msat: u64) -> Result<(), NetworkError> {
        self.check_fees().await
    }
}

/// The key of the account of `mnemonic`: SLIP-0010 Ed25519
/// `m/44'/501'/0'/0'`, the first address Phantom, Solflare and the
/// Solana CLI list under the same mnemonic.
pub fn account_key(mnemonic: &Mnemonic) -> Result<[u8; 32], String> {
    Ok(slip10_ed25519(&mnemonic.to_seed(""), &[44, 501, 0, 0]))
}

/// SLIP-0010 Ed25519 derivation of `seed` along `path`, every index
/// hardened (Ed25519 has no other kind).
pub fn slip10_ed25519(seed: &[u8], path: &[u32]) -> [u8; 32] {
    let hmac = |key: &[u8], data: &[u8]| -> [u8; 64] {
        let mut mac = Hmac::<Sha512>::new_from_slice(key).expect("HMAC takes any key");
        mac.update(data);
        mac.finalize().into_bytes().into()
    };
    let mut node = hmac(b"ed25519 seed", seed);
    for index in path {
        let mut data = vec![0u8];
        data.extend_from_slice(&node[..32]);
        data.extend_from_slice(&(index | 0x8000_0000).to_be_bytes());
        node = hmac(&node[32..], &data);
    }
    node[..32].try_into().expect("32 bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SLIP-0010's first Ed25519 test vector, at `m/0'`.
    #[test]
    fn derives_like_slip_0010() {
        let seed = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        assert_eq!(
            Bytes32(slip10_ed25519(&seed, &[0])).to_string(),
            "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3"
        );
    }

    /// The account is the first address of Phantom and the Solana CLI
    /// under the same mnemonic.
    #[test]
    fn account_is_the_first_phantom_address() {
        let mnemonic = Mnemonic::parse(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap();
        let key = SigningKey::from_bytes(&account_key(&mnemonic).unwrap());
        assert_eq!(
            Ed25519PubKey(key.verifying_key().to_bytes()).to_string(),
            "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk"
        );
    }

    #[test]
    fn program_addresses_are_off_the_curve() {
        let vault = vault_address(&pubkey(WBTC_MINT), &pubkey(SWAP_PROGRAM));
        assert!(!on_curve(vault.as_bytes()));
    }

    #[test]
    fn short_vec_lengths() {
        let encode = |len| {
            let mut out = Vec::new();
            short_vec_len(&mut out, len);
            out
        };
        assert_eq!(encode(0), [0]);
        assert_eq!(encode(127), [0x7f]);
        assert_eq!(encode(128), [0x80, 0x01]);
        assert_eq!(encode(16_384), [0x80, 0x80, 0x01]);
    }

    /// Events count only inside the program's own invocation.
    #[test]
    fn events_are_read_from_the_program_only() {
        let program = pubkey(SWAP_PROGRAM);
        let hash = Bytes32([1; 32]);
        let mut claim = discriminator("event:ClaimEvent").to_vec();
        claim.extend_from_slice(&hash.0);
        claim.extend_from_slice(&[2; 32]);
        claim.extend_from_slice(&9u64.to_le_bytes());
        let data = format!("Program data: {}", BASE64.encode(&claim));
        let logs = |inner: &str| {
            vec![
                format!("Program {inner} invoke [1]"),
                data.clone(),
                format!("Program {inner} success"),
            ]
        };
        assert_eq!(
            escrow_events(&logs(SWAP_PROGRAM), &program, &hash, 9),
            vec![EscrowEvent::Claimed(Bytes32([2; 32]))]
        );
        assert!(escrow_events(&logs(SYSTEM_PROGRAM), &program, &hash, 9).is_empty());
        assert!(escrow_events(&logs(SWAP_PROGRAM), &program, &hash, 8).is_empty());
    }
}
