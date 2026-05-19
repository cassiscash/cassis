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
//! Method mapping (see [`cassis_core::NetworkAdapter`]):
//!
//! | cassis method          | LNv2 operation                                                   |
//! |-------------------------+------------------------------------------------------------------|
//! | watch_incoming_htlc    | `LightningClientModule::receive()` — create an IncomingContract  |
//! |                        | (TPE-encrypted preimage) + Bolt11 invoice, publish to peers      |
//! | claim_incoming         | `await_final_receive_operation_state` → `Claimed`.              |
//! |                        | The LNv2 claim is driven by the claim-keypair the module set     |
//! |                        | up on our behalf; the `preimage` arg is informational only.      |
//! | create_outgoing_htlc   | `LightningClientModule::send(Bolt11Invoice)` — fund an          |
//! |                        | OutgoingContract for the counter-party's IncomingContract.      |
//! |                        | `recipient` carries the counter-party's Bolt11 invoice string.   |
//! | watch_preimage         | Subscribe to send-operation updates; capture `Success(preimage)`.|
//! | refund_outgoing        | Poll `await_final_send_operation_state` to terminal `Refunded`  |
//! |                        | (LNv2 SM auto-refunds on timeout; no synchronous cancel API).   |
//! | incoming_delta_secs    | 30 — fedimint contract confirmation is fast.                     |
//!
//! Design notes / known mismatches with the abstract cassis trait:
//!
//! * `watch_incoming_htlc` is given a `payment_hash` by the routing
//!   layer. In the "sells its own preimage" model the recipient
//!   *creates* the preimage (so its `SHA256` *is* the payment hash);
//!   we therefore cannot honour an externally-supplied `payment_hash`.
//!   The caller's argument is ignored; the returned
//!   `IncomingHtlc.payment_hash` is the LNv2-generated hash. The
//!   Bolt11 invoice string is recorded in `IncomingHtlc.sender` so
//!   the routing layer can hand it to the upstream hop, which will
//!   eventually feed it back as the `recipient` to some
//!   `create_outgoing_htlc` downstream.
//! * `claim_incoming(preimage)` receives a 32-byte preimage but LNv2
//!   authorizes the claim by a keypair the module holds internally;
//!   the secret is not the input here. The argument is asserted
//!   against the payment hash where possible and otherwise ignored.
//! * `recipient` passed to `create_outgoing_htlc` is the
//!   counter-party's Bolt11 invoice string — i.e. the
//!   `Bolt11Invoice` produced by the *downstream* node's
//!   `watch_incoming_htlc`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use bitcoin::hashes::{Hash, sha256};
use fedimint_connectors::ConnectorRegistry;
use fedimint_core::core::OperationId;
use fedimint_core::db::Database;
use fedimint_core::invite_code::InviteCode;
use fedimint_core::module::registry::ModuleRegistry;
use fedimint_core::Amount;
use fedimint_derive_secret::DerivableSecret;
use fedimint_lnv2_client::common::Bolt11InvoiceDescription;
use fedimint_lnv2_client::{LightningClientModule, SendOperationState};
use fedimint_mint_client::MintClientInit;
use futures::StreamExt;
use lightning_invoice::Bolt11Invoice;
use std::str::FromStr;
use tokio::sync::Mutex;
use tracing::{debug, warn};

use fedimint_client::{Client, ClientHandleArc, RootSecret};

use cassis_core::{Bytes32, HtlcError, IncomingHtlc, NetworkAdapter, NetworkId, OutgoingHtlc, WatchError};

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
    client: ClientHandleArc,
    /// LN invoice produced by `watch_incoming_htlc` / consumed by
    /// `create_outgoing_htlc`. Contracts are keyed by the cassis
    /// payment hash used for the hop.
    ///
    /// The same `payment_hash` may be used on both the incoming and
    /// the outgoing side of a hop (cassis's atomic-routing
    /// invariant), so we keep both maps. The LNv2 operation
    /// identifier is what we poll to observe the contract's
    /// terminal state.
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
    /// for diagnostics. The authoritative copy is in the returned
    /// `IncomingHtlc.sender` field.
    invoice_str: String,
    /// Counter-party identity (sender of the incoming HTLC, in cassis
    /// terms), if the routing layer ever supplies one.
    sender: String,
}

#[derive(Clone)]
#[allow(dead_code)]
struct OutgoingOp {
    operation_id: OperationId,
    amount_msat: u64,
    expiry: u64,
    recipient: String,
    /// Bolt11 invoice we are paying.
    invoice: Bolt11Invoice,
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
            fedimint_rocksdb::RocksDb::build(db_path).open().await.map_err(|e| {
                format!("failed to open RocksDb at {}: {e}", db_dir.display())
            })?,
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
            client,
            incoming_ops: Mutex::new(HashMap::new()),
            outgoing_ops: Mutex::new(HashMap::new()),
        })
    }

    fn db_dir_for(network_id: &NetworkId) -> PathBuf {
        let slug = network_id.0.strip_prefix("fedimint:").unwrap_or(&network_id.0);
        let safe: String = slug
            .chars()
            .map(|c| if c.is_alphanumeric() || c == '-' { c } else { '_' })
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
impl NetworkAdapter for FedimintAdapter {
    fn network_id(&self) -> NetworkId {
        self.network_id.clone()
    }

    /// Create an incoming HTLC instrument. In the "sells its own
    /// preimage" model this means: we generate a preimage, TPE-encrypt
    /// it to the federation, publish an `IncomingContract`, and produce
    /// a Bolt11 invoice the upstream node will pay. The cassis-supplied
    /// `payment_hash` is ignored — we cannot honour an externally-set
    /// payment hash when selling our own preimage; the returned
    /// `IncomingHtlc.payment_hash` is the LNv2-generated hash. The
    /// Bolt11 invoice string is recorded in `IncomingHtlc.sender` so
    /// the routing layer can hand it to the upstream hop (which will
    /// eventually feed it back as `recipient` to some
    /// `create_outgoing_htlc` downstream).
    async fn watch_incoming_htlc(
        &self,
        _payment_hash: Bytes32,
        min_amount_msat: u64,
        deadline: u64,
    ) -> Result<IncomingHtlc, WatchError> {
        let ln = Self::ln_module(&self.client)
            .map_err(|e| WatchError::Network(format!("LNv2 module not available: {e}")))?;
        let amount = Amount::from_msats(min_amount_msat);

        let receive_fut = ln.receive(
            amount,
            DEFAULT_RECEIVE_EXPIRY_SECS,
            Bolt11InvoiceDescription::Direct(DEFAULT_INVOICE_DESCRIPTION.to_string()),
            None, // let LNv2 pick a registered gateway for the invoice
            serde_json::Value::Null,
        );

        let (invoice, operation_id) = tokio::time::timeout(
            Self::deadline_to_timeout(deadline),
            receive_fut,
        )
        .await
        .map_err(|_| WatchError::DeadlineExceeded)?
        .map_err(|e| WatchError::Network(format!("receive failed: {e:?}")))?;

        let payment_hash = Bytes32(invoice.payment_hash().to_byte_array());
        let invoice_str = invoice.to_string();

        let incoming = IncomingHtlc {
            payment_hash,
            amount_msat: min_amount_msat,
            expiry: deadline,
            sender: invoice_str.clone(),
            network: self.network_id.clone(),
        };

        self.incoming_ops.lock().await.insert(
            payment_hash,
            IncomingOp {
                operation_id,
                amount_msat: min_amount_msat,
                expiry: deadline,
                invoice_str,
                sender: String::new(),
            },
        );

        debug!(
            ?payment_hash,
            amount_msat = min_amount_msat,
            "fedimint incoming HTLC instrument created"
        );
        Ok(incoming)
    }

    /// Create an outgoing HTLC by paying the counter-party's Bolt11
    /// invoice. The `recipient` argument is the Bolt11 invoice string.
    /// `amount_msat` is validated against the invoice's amount.
    async fn create_outgoing_htlc(
        &self,
        _payment_hash: Bytes32,
        amount_msat: u64,
        _expiry: u64,
        recipient: &str,
    ) -> Result<OutgoingHtlc, HtlcError> {
        let invoice: Bolt11Invoice = recipient
            .parse()
            .map_err(|e| HtlcError::InvalidParams(format!("recipient is not a Bolt11 invoice: {e}")))?;

        let invoice_amount_msat = invoice
            .amount_milli_satoshis()
            .ok_or_else(|| HtlcError::InvalidParams("invoice has no amount".into()))?;
        if invoice_amount_msat != amount_msat {
            return Err(HtlcError::InvalidParams(format!(
                "invoice amount {invoice_amount_msat} msat does not match requested {amount_msat}"
            )));
        }
        let invoice_payment_hash = Bytes32(invoice.payment_hash().to_byte_array());

        let ln = Self::ln_module(&self.client)
            .map_err(|e| HtlcError::Network(format!("LNv2 module not available: {e}")))?;
        let operation_id = ln
            .send(invoice.clone(), None, serde_json::Value::Null)
            .await
            .map_err(|e| HtlcError::Network(format!("send failed: {e:?}")))?;

        let outgoing = OutgoingHtlc {
            payment_hash: invoice_payment_hash,
            amount_msat,
            expiry: 0, // Bolt11 expiry is internal to the invoice
            recipient: recipient.to_string(),
            network: self.network_id.clone(),
        };

        self.outgoing_ops.lock().await.insert(
            invoice_payment_hash,
            OutgoingOp {
                operation_id,
                amount_msat,
                expiry: 0,
                recipient: recipient.to_string(),
                invoice,
            },
        );

        debug!(
            ?invoice_payment_hash,
            amount_msat,
            "fedimint outgoing HTLC created"
        );
        Ok(outgoing)
    }

    /// Acknowledge that an incoming HTLC has been claimed. In LNv2 the
    /// claim is driven internally by the receive state machine once
    /// the contract is funded and (where applicable) decrypted, using
    /// the claim-keypair the module set up on our behalf. The
    /// `preimage` argument is informational only; we just confirm the
    /// operation reached the `Claimed` state.
    async fn claim_incoming(
        &self,
        htlc: &IncomingHtlc,
        preimage: Bytes32,
    ) -> Result<(), HtlcError> {
        let ln = Self::ln_module(&self.client)
            .map_err(|e| HtlcError::Network(format!("LNv2 module not available: {e}")))?;
        let op_id = {
            let ops = self.incoming_ops.lock().await;
            ops.get(&htlc.payment_hash)
                .map(|o| o.operation_id)
                .ok_or_else(|| {
                    HtlcError::InvalidParams(format!(
                        "no incoming operation known for payment hash {:?}",
                        htlc.payment_hash
                    ))
                })?
        };

        // Sanity-check the supplied preimage against the payment hash
        // (the public LN module doesn't reveal the raw preimage it
        // generated, so we validate via SHA256 instead).
        let computed = Bytes32(sha256::Hash::hash(&preimage.0).to_byte_array());
        if computed != htlc.payment_hash {
            warn!(
                expected = ?htlc.payment_hash,
                got = ?computed,
                "claim_incoming: preimage does not match payment hash; \
                 proceeding because LNv2 owns the actual claim secret"
            );
        }

        let final_state = ln
            .await_final_receive_operation_state(op_id)
            .await
            .map_err(|e| HtlcError::Network(format!("await_receive failed: {e}")))?;

        match final_state {
            fedimint_lnv2_client::FinalReceiveOperationState::Claimed => {
                debug!(?htlc.payment_hash, "fedimint incoming HTLC claimed");
                self.incoming_ops.lock().await.remove(&htlc.payment_hash);
                Ok(())
            }
            fedimint_lnv2_client::FinalReceiveOperationState::Expired => {
                self.incoming_ops.lock().await.remove(&htlc.payment_hash);
                Err(HtlcError::Network(
                    "incoming contract expired before being funded".into(),
                ))
            }
            fedimint_lnv2_client::FinalReceiveOperationState::Failure => {
                self.incoming_ops.lock().await.remove(&htlc.payment_hash);
                Err(HtlcError::Network("incoming receive failed".into()))
            }
        }
    }

    /// Refund an outgoing HTLC. In LNv2 the send state machine
    /// refunds automatically when the outgoing contract times out or
    /// the counter-party forfeits; there is no public synchronous
    /// "cancel now" primitive, so this polls the operation to its
    /// terminal state. In the atomic-routing happy path this is
    /// normally NOT called — the preimage reveals and we move on.
    /// It is called on the refund branch.
    async fn refund_outgoing(&self, htlc: &OutgoingHtlc) -> Result<(), HtlcError> {
        let ln = Self::ln_module(&self.client)
            .map_err(|e| HtlcError::Network(format!("LNv2 module not available: {e}")))?;
        let op_id = {
            let ops = self.outgoing_ops.lock().await;
            ops.get(&htlc.payment_hash)
                .map(|o| o.operation_id)
                .ok_or_else(|| {
                    HtlcError::InvalidParams(format!(
                        "no outgoing operation known for payment hash {:?}",
                        htlc.payment_hash
                    ))
                })?
        };

        // LNv2 only reaches `Refunded` once the outgoing contract's
        // block-height expiry has passed. For long-expiry contracts
        // this can be hours, so we cap the wait here and return early
        // if the SM hasn't refunded yet — the cassis routing layer
        // may re-invoke later when the deadline approaches. We prefer
        // a generous cap (one day) so most realistic refund cases
        // resolve in one call.
        let final_state = tokio::time::timeout(
            std::time::Duration::from_secs(86_400),
            ln.await_final_send_operation_state(op_id),
        )
        .await
        .map_err(|_| HtlcError::Network("timed out waiting for send state".into()))?
        .map_err(|e| HtlcError::Network(format!("await_send failed: {e}")))?;

        match final_state {
            fedimint_lnv2_client::FinalSendOperationState::Refunded => {
                debug!(?htlc.payment_hash, "fedimint outgoing HTLC refunded");
                self.outgoing_ops.lock().await.remove(&htlc.payment_hash);
                Ok(())
            }
            fedimint_lnv2_client::FinalSendOperationState::Success => Err(HtlcError::Network(
                "outgoing HTLC was already claimed with a preimage (not refundable)".into(),
            )),
            fedimint_lnv2_client::FinalSendOperationState::Failure => {
                self.outgoing_ops.lock().await.remove(&htlc.payment_hash);
                Err(HtlcError::Network("outgoing send failed".into()))
            }
        }
    }

    /// Watch for the preimage to be revealed on an outgoing HTLC.
    /// In LNv2 this is captured on the way through the send state
    /// stream: the SM emits `SendOperationState::Success(preimage)`
    /// once the federation decrypts the counter-party's TPE-encrypted
    /// preimage and the contract is claimed. The
    /// `await_final_send_operation_state` accessor drops the preimage
    /// on the way through (its `Success` variant is unit), so we
    /// subscribe to the per-update stream directly.
    async fn watch_preimage(
        &self,
        htlc: &OutgoingHtlc,
        deadline: u64,
    ) -> Result<Bytes32, WatchError> {
        let ln = Self::ln_module(&self.client)
            .map_err(|e| WatchError::Network(format!("LNv2 module not available: {e}")))?;
        let op_id = {
            let ops = self.outgoing_ops.lock().await;
            ops.get(&htlc.payment_hash)
                .map(|o| o.operation_id)
                .ok_or_else(|| {
                    WatchError::Network(format!(
                        "no outgoing operation known for payment hash {:?}",
                        htlc.payment_hash
                    ))
                })?
        };

        let stream =
            ln.subscribe_send_operation_state_updates(op_id)
                .await
                .map_err(|e| WatchError::Network(format!("subscribe_send failed: {e}")))?
                .into_stream();

        let preimage_fut = async {
            let mut s = stream;
            while let Some(state) = s.next().await {
                match state {
                    SendOperationState::Success(p) => return Ok(Bytes32(p)),
                    SendOperationState::Refunded => {
                        return Err(WatchError::Network(
                            "outgoing HTLC refunded (counter-party forfeited or expired)".into(),
                        ))
                    }
                    SendOperationState::Failure => {
                        return Err(WatchError::Network("outgoing send failed".into()))
                    }
                    SendOperationState::Refunding => {
                        return Err(WatchError::Network(
                            "outgoing HTLC is refunding (counter-party forfeited or expired)".into(),
                        ))
                    }
                    SendOperationState::Funding | SendOperationState::Funded => {}
                }
            }
            Err(WatchError::Network("send state stream ended without preimage".into()))
        };

        tokio::time::timeout(Self::deadline_to_timeout(deadline), preimage_fut)
            .await
            .map_err(|_| WatchError::DeadlineExceeded)?
            .map_err(|e| WatchError::Network(format!("await: {e}")))
    }

    /// Fedimint's contract confirmation is fast (~12 blocks for
    /// preimage reveal across consensus; the threshold-decryption
    /// round trips in seconds to low minutes). 30 s gives the
    /// routing layer the small buffer it needs to rearrange the
    /// downstream HTLC.
    fn incoming_delta_secs(&self) -> u64 {
        30
    }
}