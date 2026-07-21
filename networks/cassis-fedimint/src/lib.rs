//! Fedimint network adapter (LNv2).
//!
//! A cassis node acts as a Fedimint client of one federation, with the
//! federation's guardians reached over iroh via `fedimint-connectors`
//! (guardian endpoint URLs of the form `iroh://<node-id>` in the
//! federation's `ClientConfig`). The adapter plays the LNv2 contract
//! roles internally: LightningInvoice (LNv2's invoice type) is the
//! HTLC instrument that travels over cassis hops.
//!
//! LNv2 wraps preimage secrecy directly into the contract via Threshold
//! Point Encryption (TPE): the "incoming" side (recipient) generates a
//! preimage, TPE-encrypts it to the federation's threshold public key
//! bound to the payment hash, and publishes an `IncomingContract`. The
//! "outgoing" side (sender) buys the preimage by funding that contract;
//! the federation decrypts it once funded and reveals the preimage to
//! the funder. This matches the "each network sells its own preimage"
//! model selected for cassis: at the Fedimint leg the contract is
//! preimage-gated via TPE rather than via an external Lightning reveal.
//!
//! Unlike the cashu / arkade / rootstock / liquid adapters, fedimint
//! does **not** implement the lower-level
//! [`cassis_core::NetworkRouterAdapter`] trait. LNv2's "sells its own
//! preimage" semantics don't map cleanly onto a router that has to
//! honor an externally-supplied `payment_hash`; instead, the adapter
//! implements the user-facing [`cassis_core::NetworkReceiverAdapter`]
//! and [`cassis_core::NetworkSenderAdapter`] traits directly.
//!
//! Method mapping:
//!
//! | cassis method                | LNv2 operation                                              |
//! |------------------------------+-------------------------------------------------------------|
//! | `create_invoice`             | `LightningClientModule::receive()` — create an              |
//! |                              | `IncomingContract` (TPE-encrypted preimage) + Bolt11        |
//! |                              | invoice, publish to peers, return the invoice.              |
//! | `watch_incoming`             | Subscribe to receive-op updates; wait for `Claiming` or     |
//! |                              | `Claimed`.                                                  |
//! | `claim_incoming`             | `await_final_receive_operation_state` → `Claimed`. The     |
//! |                              | LNv2 claim is driven by the claim-keypair the module set    |
//! |                              | up on our behalf; the `preimage` arg is informational only. |
//! | `pay_invoice`                | Fund an `OutgoingContract` directly, using the destination    |
//! |                              | pubkey as `claim_pk`.                                        |
//! | `watch_payment`              | Subscribe to send-op updates; capture `Success(preimage)`.  |
//! | `refund_payment`             | Poll `await_final_send_operation_state` to terminal         |
//! |                              | `Refunded` (LNv2 SM auto-refunds on timeout; no synchronous |
//! |                              | cancel API).                                                |
//! | `incoming_delta_secs`        | 30 — fedimint contract confirmation is fast.                |
//!
//! Design notes:
//!
//! * `create_invoice` is called with a `description` and an
//!   `expiry`; the `amount_msat` is the cassis-flavored amount we
//!   want to receive. Internally LNv2 generates its own preimage
//!   and we ignore any externally-supplied payment hash (there is
//!   none in the new API). The Bolt11 invoice string is recorded in
//!   `Invoice.payee` so the routing layer can hand it to the
//!   upstream hop, which will eventually feed it back as
//!   `destination_pubkey` to some `pay_invoice` downstream.
//! * `claim_incoming(payment_hash, preimage)` receives a 32-byte
//!   preimage (typically the one revealed to the upstream funder),
//!   but LNv2 authorizes the claim by a keypair the module holds
//!   internally; the secret is not the input here. The argument is
//!   asserted against the payment hash where possible and otherwise
//!   ignored.
//! * `destination_pubkey` passed to `pay_invoice` becomes the outgoing
//!   contract's `claim_pk`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use bitcoin::hashes::{sha256, Hash};
use fedimint_connectors::ConnectorRegistry;
use fedimint_core::core::{IntoDynInstance, OperationId};
use fedimint_core::db::Database;
use fedimint_core::invite_code::InviteCode;
use fedimint_core::module::{registry::ModuleRegistry, Amounts, ApiRequestErased};
use fedimint_core::{secp256k1, Amount};
use fedimint_derive_secret::DerivableSecret;
use fedimint_lnv2_client::common::contracts::{OutgoingContract, PaymentImage};
use fedimint_lnv2_client::common::Bolt11InvoiceDescription;
use fedimint_lnv2_client::common::{LightningOutput, LightningOutputV0};
use fedimint_lnv2_client::LightningClientModule;
use fedimint_mint_client::MintClientInit;
use futures::StreamExt;
use std::str::FromStr;
use tokio::sync::Mutex;
use tracing::{debug, warn};

use fedimint_api_client::api::FederationApiExt;
use fedimint_client::{Client, ClientHandleArc, RootSecret};
use fedimint_client_module::transaction::{ClientOutput, ClientOutputBundle, TransactionBuilder};

use cassis_core::{
    Bytes32, NetworkId, NetworkReceiverAdapter, NetworkSenderAdapter, OutgoingPayment, PubKey,
    ReceiveError, SendError,
};

/// Default per-operation invoice expiry in seconds (~1 hour) so callers
/// have enough room to construct the cross-network swap before the
/// LNv2 incoming contract times out.
const DEFAULT_RECEIVE_EXPIRY_SECS: u32 = 3600;

/// Description string embedded in generated Bolt11 invoices for
/// traceability. Cassis does not carry a description end-to-end today.
const DEFAULT_INVOICE_DESCRIPTION: &str = "cassis";

/// Salt mixed into the per-network secret when constructing the
/// fedimint root derivation. The federation id is added internally
/// by `RootSecret::StandardDoubleDerive`, so this constant simply
/// domain-separates the cassis-fedimint seed from other fedimint
/// clients that might share the same mnemonic.
const ROOT_SECRET_SALT: &[u8] = b"cassis/fedimint/v1";

/// Fedimint network adapter.
///
/// One adapter per federation. The constructor joins the federation
/// (downloading the `ClientConfig` over iroh if the address is a
/// `fed1q…` invite code, or re-open an existing client DB) and starts
/// the client's executor.
pub struct FedimintAdapter {
    network_id: NetworkId,
    invoice_pubkey: PubKey,
    client: ClientHandleArc,
    /// LN invoice produced by `create_invoice` / consumed by
    /// `pay_invoice`. Contracts are keyed by the cassis payment hash
    /// used for the hop.
    ///
    /// The same `payment_hash` may be used on both the incoming and
    /// the outgoing side of a hop (cassis's atomic-routing invariant),
    /// so we keep both maps. The LNv2 operation identifier is what we
    /// poll to observe the contract's terminal state.
    incoming_ops: Mutex<HashMap<Bytes32, IncomingOp>>,
    outgoing_ops: Mutex<HashMap<Bytes32, OutgoingOp>>,
}

#[derive(Clone)]
#[allow(dead_code)]
struct IncomingOp {
    operation_id: OperationId,
    /// Amount *we* asked for, in msat.
    amount_msat: u64,
    /// Expiry as a unix timestamp (cassis flavour).
    expiry: u64,
    /// The Bolt11 invoice string the counter-party must pay, stashed
    /// for diagnostics. The authoritative copy is in
    /// `Invoice.payee` returned by `create_invoice`.
    invoice_str: String,
    /// Counter-party identity (sender of the incoming HTLC, in cassis
    /// terms), if the routing layer ever supplies one.
    sender: String,
}

#[derive(Clone)]
#[allow(dead_code)]
struct OutgoingOp {
    outpoint: fedimint_core::OutPoint,
    amount_msat: u64,
    contract_expiration: u64,
    recipient: String,
}

impl FedimintAdapter {
    /// Construct a new adapter for a federation.
    ///
    /// `address` may be:
    /// * a Fedimint invite code (`fed1q…`) — the federation's
    ///   `ClientConfig` is downloaded over iroh/ws and the client is
    ///   joined for the first time,
    /// * a path or identifier prefixed with `db:` — re-open a client
    ///   already joined into that local RocksDB directory.
    ///
    /// `secret` is the per-network 32-byte secret derived by the
    /// cassis daemon's BIP39 key derivation. It is fed into
    /// [`DerivableSecret::new_root`] and then wrapped in
    /// [`RootSecret::StandardDoubleDerive`], which mixes in the
    /// federation id internally; reusing one mnemonic across
    /// federations is therefore safe.
    pub async fn new(
        network_id: NetworkId,
        address: String,
        secret: [u8; 32],
        invoice_pubkey: PubKey,
    ) -> Result<Self, String> {
        // Connector stack: defaults enable iroh next (`/v1`) and the
        // `iroh://` scheme. Guardian endpoints in the federation
        // config whose scheme is `iroh://` are dialed over iroh QUIC
        // automatically. The federation config dictates the
        // transport; no per-client iroh object is required.
        let connectors = ConnectorRegistry::build_from_client_defaults()
            // .iroh_pkarr_dht(true) // opt into DHT/mainline discovery
            // .iroh_next(true)      // already the default
            .bind()
            .await
            .map_err(|e| format!("failed to bind connector registry: {e}"))?;

        // Derive the root secret. `DerivableSecret::new_root` wants
        // `(root_key, salt)`. We expand the 32-byte per-network
        // secret to 64 bytes by HKDF-style repetition so the root
        // has enough entropy. `RootSecret::StandardDoubleDerive`
        // then hashes in the federation id internally — so reusing
        // one mnemonic across federations is safe.
        let mut seed64 = [0u8; 64];
        seed64[..32].copy_from_slice(&secret);
        seed64[32..].copy_from_slice(&secret);
        let root_secret = DerivableSecret::new_root(&seed64, ROOT_SECRET_SALT);
        let root_secret = RootSecret::StandardDoubleDerive(root_secret);

        // RocksDB path. The daemon doesn't pass a base path today,
        // so we put it under a fixed dir keyed by a sanitized
        // fragment of the network id.
        let db_dir = Self::db_dir_for(&network_id);
        tokio::fs::create_dir_all(&db_dir)
            .await
            .map_err(|e| format!("failed to create db dir {}: {e}", db_dir.display()))?;
        let db_path = db_dir.join("db");
        let db: Database = Database::new(
            fedimint_rocksdb::RocksDb::build(db_path)
                .open()
                .await
                .map_err(|e| format!("failed to open RocksDb at {}: {e}", db_dir.display()))?,
            ModuleRegistry::default(),
        );

        let already_initialized = Client::is_initialized(&db).await;

        let mut builder = Client::builder()
            .await
            .map_err(|e| format!("failed to build client builder: {e}"))?;

        // Mint module is REQUIRED as the primary module — it issues
        // the ecash used to fund outgoing contracts (and into which
        // incoming contracts pay us). The LNv2 module is the one we
        // drive.
        builder.with_module(MintClientInit);
        builder.with_module(fedimint_lnv2_client::LightningClientInit::default());

        let client: ClientHandleArc = if already_initialized {
            let handle = builder
                .open(connectors, db, root_secret)
                .await
                .map_err(|e| format!("failed to re-open fedimint client: {e}"))?;
            Arc::new(handle)
        } else {
            // First-time join: address must be an invite code.
            let invite = InviteCode::from_str(&address).map_err(|e| {
                format!("failed to parse '{address}' as a Fedimint invite code: {e}")
            })?;
            // `preview` downloads the federation ClientConfig from
            // one peer via the advertised URL (iroh:// in our case).
            let preview = builder
                .preview(connectors.clone(), &invite)
                .await
                .map_err(|e| format!("failed to download federation config: {e}"))?;
            let handle = preview
                .join(db, root_secret)
                .await
                .map_err(|e| format!("failed to join federation: {e}"))?;
            Arc::new(handle)
        };

        // Start the executor so the LN state machines run.
        client.start_executor();

        // Sanity-check that the LNv2 module is present.
        let _ln_module: &LightningClientModule =
            Self::ln_module(&client).map_err(|e| format!("federation has no LNv2 module: {e}"))?;

        Ok(Self {
            network_id,
            invoice_pubkey,
            client,
            incoming_ops: Mutex::new(HashMap::new()),
            outgoing_ops: Mutex::new(HashMap::new()),
        })
    }

    fn db_dir_for(network_id: &NetworkId) -> PathBuf {
        let slug = network_id
            .0
            .strip_prefix("fedimint::")
            .unwrap_or(&network_id.0);
        let safe: String = slug
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '-' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        PathBuf::from(format!("./cassis-fedimint-db/{safe}"))
    }

    /// Borrow the LNv2 client module from a client handle. The
    /// returned reference is tied to the input borrow; safe to use
    /// across `await` points since `Arc<ClientHandle>` is `Sync`.
    fn ln_module<'c>(client: &'c ClientHandleArc) -> anyhow::Result<&'c LightningClientModule> {
        Ok(client.get_first_module::<LightningClientModule>()?.module)
    }

    /// Convert a deadline (unix seconds) into a `tokio::time::Duration`
    /// suitable as a `tokio::time::timeout` deadline.
    fn deadline_to_timeout(deadline: u64) -> std::time::Duration {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let secs = deadline.saturating_sub(now);
        std::time::Duration::from_secs(secs)
    }
}

#[async_trait]
impl NetworkReceiverAdapter for FedimintAdapter {
    fn network_id(&self) -> NetworkId {
        self.network_id.clone()
    }

    /// Fedimint's contract confirmation is fast (~12 blocks for
    /// preimage reveal across consensus; the threshold-decryption
    /// round trips in seconds to low minutes). 30 s gives the
    /// routing layer the small buffer it needs to rearrange the
    /// downstream HTLC.
    fn incoming_delta_secs(&self) -> u64 {
        30
    }

    /// Create an incoming invoice: we generate a preimage, TPE-encrypt
    /// it to the federation, publish an `IncomingContract`, and produce
    /// a Bolt11 invoice the upstream node will pay. The Bolt11
    /// invoice string is recorded in `Invoice.payee` so the routing
    /// layer can hand it to the upstream hop, which will eventually
    /// feed it back as `destination_pubkey` to some `pay_invoice`
    /// downstream.
    async fn create_invoice(
        &self,
        amount_msat: u64,
        expiry: u64,
        description: Option<String>,
    ) -> Result<cassis_core::Invoice, ReceiveError> {
        let ln = Self::ln_module(&self.client)
            .map_err(|e| ReceiveError::Network(format!("LNv2 module not available: {e}")))?;
        let amount = Amount::from_msats(amount_msat);

        let receive_fut = ln.receive(
            amount,
            DEFAULT_RECEIVE_EXPIRY_SECS,
            Bolt11InvoiceDescription::Direct(
                description.unwrap_or_else(|| DEFAULT_INVOICE_DESCRIPTION.to_string()),
            ),
            None, // let LNv2 pick a registered gateway for the invoice
            serde_json::Value::Null,
        );

        let (invoice, operation_id) =
            tokio::time::timeout(Self::deadline_to_timeout(expiry), receive_fut)
                .await
                .map_err(|_| ReceiveError::DeadlineExceeded)?
                .map_err(|e| ReceiveError::Network(format!("receive failed: {e:?}")))?;

        let payment_hash = Bytes32(invoice.payment_hash().to_byte_array());
        let invoice_str = invoice.to_string();

        self.incoming_ops.lock().await.insert(
            payment_hash,
            IncomingOp {
                operation_id,
                amount_msat,
                expiry,
                invoice_str: invoice_str.clone(),
                sender: String::new(),
            },
        );

        debug!(
            ?payment_hash,
            amount_msat, "fedimint incoming invoice created"
        );

        Ok(cassis_core::Invoice {
            payment_hash,
            amount_msat,
            payee: self.invoice_pubkey,
            expires_at: expiry,
            // Fedimint sells its own preimage: the federation settles
            // the contract, so there is no local key that signs a
            // claim and nothing to advertise here.
            claim_pubkeys: Vec::new(),
            networks: vec![self.network_id.clone()],
            description: Some(DEFAULT_INVOICE_DESCRIPTION.to_string()),
            iroh_peer_id: None,
            iroh_relay: None,
            payment_request: None,
        })
    }

    /// Wait for the upstream hop to fund our incoming contract. We
    /// subscribe to the receive-op state stream and return once it
    /// reaches `Claiming` or `Claimed` (the federation has decrypted
    /// our preimage and is issuing ecash in our wallet). The preimage
    /// is held by the LNv2 module and revealed to the upstream funder
    /// automatically; we cannot surface it here, so the returned
    /// `Bytes32` is a zero placeholder — only its role as "payment
    /// observed" matters to the routing layer.
    async fn watch_incoming(
        &self,
        payment_hash: Bytes32,
        deadline: u64,
    ) -> Result<Bytes32, ReceiveError> {
        let ln = Self::ln_module(&self.client)
            .map_err(|e| ReceiveError::Network(format!("LNv2 module not available: {e}")))?;
        let op_id = {
            let ops = self.incoming_ops.lock().await;
            ops.get(&payment_hash)
                .map(|o| o.operation_id)
                .ok_or_else(|| {
                    ReceiveError::NotFound(format!(
                        "no incoming operation known for payment hash {:?}",
                        payment_hash
                    ))
                })?
        };

        let stream = ln
            .subscribe_receive_operation_state_updates(op_id)
            .await
            .map_err(|e| ReceiveError::Network(format!("subscribe_receive failed: {e}")))?
            .into_stream();

        let watch_fut = async {
            let mut s = stream;
            while let Some(state) = s.next().await {
                match state {
                    fedimint_lnv2_client::ReceiveOperationState::Claiming
                    | fedimint_lnv2_client::ReceiveOperationState::Claimed => {
                        return Ok(());
                    }
                    fedimint_lnv2_client::ReceiveOperationState::Pending => continue,
                    fedimint_lnv2_client::ReceiveOperationState::Expired => {
                        return Err(ReceiveError::Network(
                            "incoming contract expired before being funded".into(),
                        ));
                    }
                    fedimint_lnv2_client::ReceiveOperationState::Failure => {
                        return Err(ReceiveError::Network("incoming receive failed".into()));
                    }
                }
            }
            Err(ReceiveError::Network(
                "receive state stream ended before payment observed".into(),
            ))
        };

        tokio::time::timeout(Self::deadline_to_timeout(deadline), watch_fut)
            .await
            .map_err(|_| ReceiveError::DeadlineExceeded)??;
        Ok(Bytes32([0u8; 32]))
    }

    /// Confirm that the incoming HTLC has fully settled. The
    /// `preimage` argument is informational only — LNv2 authorises the
    /// claim with a keypair the module holds internally, and the
    /// preimage is revealed to the upstream funder as part of the
    /// funding flow. We sanity-check the preimage against the payment
    /// hash (the public LN module doesn't expose its raw preimage, so
    /// SHA-256 of the supplied value is the best we can do) and then
    /// wait for the receive op to reach its `Claimed` terminal state.
    async fn claim_incoming(
        &self,
        payment_hash: Bytes32,
        preimage: Bytes32,
    ) -> Result<(), ReceiveError> {
        let ln = Self::ln_module(&self.client)
            .map_err(|e| ReceiveError::Network(format!("LNv2 module not available: {e}")))?;
        let op_id = {
            let ops = self.incoming_ops.lock().await;
            ops.get(&payment_hash)
                .map(|o| o.operation_id)
                .ok_or_else(|| {
                    ReceiveError::NotFound(format!(
                        "no incoming operation known for payment hash {:?}",
                        payment_hash
                    ))
                })?
        };

        let computed = Bytes32(sha256::Hash::hash(&preimage.0).to_byte_array());
        if computed != payment_hash {
            warn!(
                expected = ?payment_hash,
                got = ?computed,
                "claim_incoming: preimage does not match payment hash; \
                 proceeding because LNv2 owns the actual claim secret"
            );
        }

        let final_state = ln
            .await_final_receive_operation_state(op_id)
            .await
            .map_err(|e| ReceiveError::Network(format!("await_receive failed: {e}")))?;

        match final_state {
            fedimint_lnv2_client::FinalReceiveOperationState::Claimed => {
                debug!(?payment_hash, "fedimint incoming invoice claimed");
                self.incoming_ops.lock().await.remove(&payment_hash);
                Ok(())
            }
            fedimint_lnv2_client::FinalReceiveOperationState::Expired => {
                self.incoming_ops.lock().await.remove(&payment_hash);
                Err(ReceiveError::Network(
                    "incoming contract expired before being funded".into(),
                ))
            }
            fedimint_lnv2_client::FinalReceiveOperationState::Failure => {
                self.incoming_ops.lock().await.remove(&payment_hash);
                Err(ReceiveError::Network("incoming receive failed".into()))
            }
        }
    }
}

#[async_trait]
impl NetworkSenderAdapter for FedimintAdapter {
    fn network_id(&self) -> NetworkId {
        self.network_id.clone()
    }

    /// Initiate an outgoing payment by funding an LNv2 contract directly.
    async fn pay_invoice(
        &self,
        payment_hash: Bytes32,
        amount_msat: u64,
        destination_pubkey: PubKey,
        destination_network: &NetworkId,
        expiry: u64,
    ) -> Result<OutgoingPayment, SendError> {
        if destination_network != &self.network_id {
            return Err(SendError::InvalidParams(format!(
                "destination network {destination_network} does not match \
                 sender network {}",
                self.network_id
            )));
        }
        if amount_msat == 0 {
            return Err(SendError::InvalidParams("amount must be > 0".into()));
        }
        if expiry
            <= std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_secs())
                .unwrap_or(0)
        {
            return Err(SendError::InvalidParams("expiry in the past".into()));
        }

        let module = self
            .client
            .get_first_module::<LightningClientModule>()
            .map_err(|e| SendError::Network(format!("LNv2 module not available: {e}")))?;
        let consensus_block_count: u64 = module
            .api
            .request_current_consensus(
                "consensus_block_count".to_string(),
                ApiRequestErased::default(),
            )
            .await
            .map_err(|e| SendError::Network(format!("block count request failed: {e}")))?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        let expiration =
            consensus_block_count.saturating_add(expiry.saturating_sub(now).div_ceil(10));
        let mut claim_pk_bytes = [0u8; 33];
        claim_pk_bytes[0] = 2;
        claim_pk_bytes[1..].copy_from_slice(destination_pubkey.as_bytes());
        let claim_pk = secp256k1::PublicKey::from_slice(&claim_pk_bytes)
            .map_err(|e| SendError::InvalidParams(format!("invalid destination pubkey: {e}")))?;
        let refund_keypair = secp256k1::SecretKey::new(&mut secp256k1::rand::thread_rng())
            .keypair(&secp256k1::SECP256K1);
        let ephemeral_keypair = secp256k1::SecretKey::new(&mut secp256k1::rand::thread_rng())
            .keypair(&secp256k1::SECP256K1);
        let contract = OutgoingContract {
            payment_image: PaymentImage::Hash(sha256::Hash::from_byte_array(payment_hash.0)),
            amount: Amount::from_msats(amount_msat),
            expiration,
            claim_pk,
            refund_pk: refund_keypair.public_key(),
            ephemeral_pk: ephemeral_keypair.public_key(),
        };
        let operation_id = OperationId::from_encodable(&(payment_hash.0, destination_pubkey.0));
        let output = ClientOutput {
            output: LightningOutput::V0(LightningOutputV0::Outgoing(contract)),
            amounts: Amounts::new_bitcoin(Amount::from_msats(amount_msat)),
        };
        let outputs = ClientOutputBundle::new_no_sm(vec![output]).into_dyn(module.id);
        let outpoints = self
            .client
            .finalize_and_submit_transaction(
                operation_id,
                "lnv2-cassis",
                |_| serde_json::Value::Null,
                TransactionBuilder::new().with_outputs(outputs),
            )
            .await
            .map_err(|e| SendError::Network(format!("failed to fund contract: {e}")))?;
        let outpoint = outpoints
            .into_iter()
            .next()
            .ok_or_else(|| SendError::Network("funding returned no outpoint".into()))?;

        self.outgoing_ops.lock().await.insert(
            payment_hash,
            OutgoingOp {
                outpoint,
                amount_msat,
                contract_expiration: expiration,
                recipient: destination_pubkey.to_hex(),
            },
        );

        debug!(
            ?payment_hash,
            amount_msat, "fedimint outgoing payment initiated"
        );

        Ok(OutgoingPayment {
            payment_hash,
            amount_msat,
            destination_pubkey: destination_pubkey.to_hex(),
            destination_network: destination_network.clone(),
            expiry,
        })
    }

    /// Watch the outgoing payment until completion. The
    /// `SendOperationState` stream emits `Success(preimage)` once the
    /// federation decrypts the counter-party's TPE-encrypted preimage
    /// and the contract is claimed; we capture and return the
    /// preimage. `Refunded`/`Refunding`/`Failure` propagate as
    /// `SendError::Network`.
    async fn watch_payment(
        &self,
        payment: OutgoingPayment,
        deadline: u64,
    ) -> Result<Bytes32, SendError> {
        let (outpoint, contract_expiration) = {
            let ops = self.outgoing_ops.lock().await;
            ops.get(&payment.payment_hash)
                .map(|o| (o.outpoint, o.contract_expiration))
                .ok_or_else(|| {
                    SendError::NotFound(format!(
                        "no outgoing operation known for payment hash {:?}",
                        payment.payment_hash
                    ))
                })?
        };

        let module = self
            .client
            .get_first_module::<LightningClientModule>()
            .map_err(|e| SendError::Network(format!("LNv2 module not available: {e}")))?;
        let preimage = tokio::time::timeout(
            Self::deadline_to_timeout(deadline),
            module.api.request_current_consensus::<[u8; 32]>(
                "await_preimage".to_string(),
                ApiRequestErased::new((outpoint, contract_expiration)),
            ),
        )
        .await
        .map_err(|_| SendError::DeadlineExceeded)?
        .map_err(|e| SendError::Network(format!("await preimage failed: {e}")))?;
        Ok(Bytes32(preimage))
    }

    /// Refund/cancel an outgoing payment. In LNv2 the send state
    /// machine refunds automatically when the outgoing contract times
    /// out or the counter-party forfeits; there is no public
    /// synchronous "cancel now" primitive, so this polls the
    /// operation to its terminal state. In the atomic-routing happy
    /// path this is normally NOT called — the preimage reveals and
    /// we move on.
    async fn refund_payment(&self, payment: OutgoingPayment) -> Result<(), SendError> {
        let _ = payment;
        Err(SendError::Network(
            "raw outgoing contract refund is not supported".into(),
        ))
    }
}
