//! Payer -> gateway -> offline payee, with a preimage server, over real
//! iroh endpoints and an in-memory mock chain every party shares: the
//! payee issues an invoice through the gateway (or lets the gateway
//! issue one alone) and goes offline, the payer pays the gateway, the
//! gateway pays the payee on and the preimage server releases the
//! preimage, and the payee comes back to redeem.
//!
//! Needs internet access (iroh relays), so it is ignored by default:
//! `cargo test -p cassis-gateway --test e2e -- --ignored`

use async_trait::async_trait;
use cassis_core::keys::{generate_mnemonic, NodeKeys};
use cassis_core::node::{
    authorize_gateway, create_gateway_invoice, redeem_offline_payments, GatewayInvoiceRecord,
    InvoiceStatus, Node, NodeConfig, OfflineEndpoints, GATEWAY_INVOICES,
};
use cassis_core::offline::{endpoint_public_key, DEFAULT_MIN_FINAL_TIMEOUT_SECS};
use cassis_core::protocol::{
    GatewayInvoiceFor, Invoice, InvoiceReceiver, Metadata, PreimageRelease, ReceivedPayment,
    Request, Response,
};
use cassis_core::store::Store;
use cassis_core::transport::{PeerAddr, Transport};
use cassis_core::{
    unix_now, Bytes32, Htlc, HtlcDescriptor, HtlcTarget, Network, NetworkError, NetworkId,
    OutgoingState, XOnlyPubKey,
};
use cassis_gateway::{Gateway, GatewayConfig, GatewayPolicy};
use cassis_preimage_server::{Db, PreimageServer, ServerConfig};
use iroh_base::PublicKey;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tracing::Span;

const NETWORK: &str = "mock::chain";

#[derive(Clone, Debug, PartialEq)]
enum LockState {
    Locked,
    Claimed(Bytes32),
    Refunded,
}

#[derive(Clone)]
struct Lock {
    payment_hash: Bytes32,
    amount_msat: u64,
    expiry: u64,
    target: HtlcTarget,
    state: LockState,
}

/// One mock chain shared by every party on it.
#[derive(Clone, Default)]
struct Ledger(Arc<Mutex<HashMap<String, Lock>>>);

impl Ledger {
    fn locks(&self) -> Vec<Lock> {
        self.0.lock().unwrap().values().cloned().collect()
    }
}

struct MockNetwork {
    key: XOnlyPubKey,
    ledger: Ledger,
}

impl MockNetwork {
    fn new(key: u8, ledger: &Ledger) -> Arc<Self> {
        Arc::new(Self {
            key: ritualistic::SecretKey::from_bytes([key; 32])
                .unwrap()
                .pubkey(),
            ledger: ledger.clone(),
        })
    }

    fn lock_id(htlc: &Htlc) -> Result<String, NetworkError> {
        match &htlc.descriptor {
            HtlcDescriptor::Cashu { proofs_b64 } if proofs_b64.len() == 1 => {
                Ok(proofs_b64[0].clone())
            }
            _ => Err(NetworkError::invalid("not a mock HTLC")),
        }
    }
}

#[async_trait]
impl Network for MockNetwork {
    fn id(&self) -> NetworkId {
        NetworkId(NETWORK.into())
    }

    fn incoming_delta_secs(&self) -> u64 {
        5
    }

    async fn receive_target(&self, _: Bytes32, _: u64, _: u64) -> Result<HtlcTarget, NetworkError> {
        Ok(HtlcTarget::XOnlyPubKey(self.key))
    }

    async fn cancel_receive(&self, _: Bytes32) -> Result<(), NetworkError> {
        Ok(())
    }

    async fn verify_incoming_htlc(&self, htlc: &Htlc) -> Result<(), NetworkError> {
        if htlc.target != HtlcTarget::XOnlyPubKey(self.key) {
            return Err(NetworkError::invalid("HTLC is not addressed to this node"));
        }
        self.verify_htlc(htlc).await
    }

    async fn verify_htlc(&self, htlc: &Htlc) -> Result<(), NetworkError> {
        let ledger = self.ledger.0.lock().unwrap();
        let lock = ledger
            .get(&Self::lock_id(htlc)?)
            .ok_or_else(|| NetworkError::invalid("no such lock"))?;
        let ok = lock.target == htlc.target
            && lock.payment_hash == htlc.payment_hash
            && lock.amount_msat >= htlc.amount_msat
            && lock.expiry >= htlc.expiry
            && lock.state == LockState::Locked;
        ok.then_some(())
            .ok_or_else(|| NetworkError::invalid("lock does not match"))
    }

    async fn claim_incoming_htlc(
        &self,
        htlc: &Htlc,
        preimage: Bytes32,
    ) -> Result<(), NetworkError> {
        let mut ledger = self.ledger.0.lock().unwrap();
        let lock = ledger.get_mut(&Self::lock_id(htlc)?).unwrap();
        assert!(lock.payment_hash.matches_preimage(&preimage));
        assert_eq!(lock.target, HtlcTarget::XOnlyPubKey(self.key));
        lock.state = LockState::Claimed(preimage);
        Ok(())
    }

    async fn create_outgoing_htlc(
        &self,
        payment_hash: Bytes32,
        amount_msat: u64,
        expiry: u64,
        target: &HtlcTarget,
    ) -> Result<HtlcDescriptor, NetworkError> {
        let id = Bytes32::random().to_string();
        self.ledger.0.lock().unwrap().insert(
            id.clone(),
            Lock {
                payment_hash,
                amount_msat,
                expiry,
                target: target.clone(),
                state: LockState::Locked,
            },
        );
        Ok(HtlcDescriptor::Cashu {
            proofs_b64: vec![id],
        })
    }

    async fn check_outgoing_htlc(&self, htlc: &Htlc) -> Result<OutgoingState, NetworkError> {
        let ledger = self.ledger.0.lock().unwrap();
        Ok(match ledger[&Self::lock_id(htlc)?].state {
            LockState::Locked => OutgoingState::Pending,
            LockState::Claimed(preimage) => OutgoingState::Claimed(preimage),
            LockState::Refunded => OutgoingState::Refunded,
        })
    }

    async fn refund_outgoing_htlc(&self, htlc: &Htlc) -> Result<(), NetworkError> {
        let mut ledger = self.ledger.0.lock().unwrap();
        ledger.get_mut(&Self::lock_id(htlc)?).unwrap().state = LockState::Refunded;
        Ok(())
    }

    async fn can_send(&self, _: u64) -> Result<(), NetworkError> {
        Ok(())
    }

    async fn can_receive(&self, _: u64) -> Result<(), NetworkError> {
        Ok(())
    }
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "cassis-gateway-{name}-{}",
        Bytes32::random().short()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

struct Payee {
    keys: NodeKeys,
    store: Store,
    network: Arc<dyn Network>,
    /// Client endpoint with the payee's identity, its iroh key.
    transport: Transport,
}

impl Payee {
    async fn new(key: u8, ledger: &Ledger) -> Self {
        let keys = NodeKeys::from_mnemonic(&generate_mnemonic()).unwrap();
        let transport = Transport::bind_client(keys.iroh).await.unwrap();
        Self {
            keys,
            store: Store::open(&temp_dir("payee").join("store.db")).unwrap(),
            network: MockNetwork::new(key, ledger),
            transport,
        }
    }

    fn key(&self) -> PublicKey {
        endpoint_public_key(&self.keys.iroh)
    }

    async fn invoice(
        &self,
        endpoints: &OfflineEndpoints,
        amount_msat: u64,
        min_final_timeout_secs: u64,
    ) -> Result<Invoice, String> {
        create_gateway_invoice(
            &self.store,
            &self.keys,
            &self.transport,
            endpoints.clone(),
            std::slice::from_ref(&self.network),
            amount_msat,
            unix_now() + 600,
            Some("coffee".into()),
            Some(metadata("order 42")),
            min_final_timeout_secs,
        )
        .await
    }

    async fn redeem(&self, server: &PeerAddr) -> cassis_core::node::RedeemReport {
        redeem_offline_payments(
            &self.store,
            &self.keys,
            &self.transport,
            server,
            std::slice::from_ref(&self.network),
            0,
        )
        .await
        .unwrap()
    }
}

fn metadata(text: &str) -> Metadata {
    Metadata::new(text.as_bytes().to_vec()).unwrap()
}

async fn request(transport: &Transport, peer: &PeerAddr, request: Request) -> Response {
    transport.request(peer, &request).await.unwrap()
}

struct Setup {
    ledger: Ledger,
    server: PreimageServer,
    gateway: Gateway,
    endpoints: OfflineEndpoints,
    payer: Node,
}

async fn setup() -> Setup {
    let ledger = Ledger::default();
    let server_keys = NodeKeys::from_mnemonic(&generate_mnemonic()).unwrap();
    let server = PreimageServer::start(ServerConfig {
        endpoint_secret: server_keys.iroh,
        preimage_secret: server_keys.preimage_server_secret(),
        db: Arc::new(Db::open(temp_dir("server").join("releases.redb")).unwrap()),
        networks: vec![MockNetwork::new(9, &ledger)],
        span: Span::none(),
    })
    .await
    .unwrap();
    let gateway_keys = NodeKeys::from_mnemonic(&generate_mnemonic()).unwrap();
    let gateway = Gateway::start(GatewayConfig {
        endpoint_secret: gateway_keys.iroh,
        store: Arc::new(Store::open(&temp_dir("gateway").join("store.db")).unwrap()),
        networks: vec![MockNetwork::new(8, &ledger)],
        policy: GatewayPolicy {
            forward_slack_secs: 60,
            final_slack_secs: 60,
            ..GatewayPolicy::default()
        },
        span: Span::none(),
    })
    .await
    .unwrap();
    let endpoints = OfflineEndpoints {
        gateway: PeerAddr {
            id: gateway.peer_id(),
            relay: gateway.home_relay().await,
        },
        preimage_server: PeerAddr {
            id: server.peer_id(),
            relay: server.home_relay().await,
        },
    };
    let payer = Node::start(
        NodeConfig {
            keys: NodeKeys::from_mnemonic(&generate_mnemonic()).unwrap(),
            store: Arc::new(Store::open(&temp_dir("payer").join("store.db")).unwrap()),
            span: Span::none(),
            serve: false,
        },
        vec![MockNetwork::new(1, &ledger)],
    )
    .await
    .unwrap();
    Setup {
        ledger,
        server,
        gateway,
        endpoints,
        payer,
    }
}

impl Setup {
    async fn shutdown(self) {
        self.payer.shutdown().await;
        self.gateway.shutdown().await;
        self.server.shutdown().await;
    }

    /// The locks paying `hash`: the payer's to the gateway, and the
    /// gateway's to `payee`.
    fn locks(&self, hash: Bytes32, payee: u8) -> (Lock, Lock) {
        let payee = HtlcTarget::XOnlyPubKey(MockNetwork::new(payee, &self.ledger).key);
        let locks: Vec<Lock> = self
            .ledger
            .locks()
            .into_iter()
            .filter(|lock| lock.payment_hash == hash)
            .collect();
        assert_eq!(locks.len(), 2, "one lock to the gateway, one to the payee");
        let (to_payee, to_gateway): (Vec<Lock>, Vec<Lock>) =
            locks.into_iter().partition(|lock| lock.target == payee);
        (to_gateway[0].clone(), to_payee[0].clone())
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs internet access for iroh relays"]
async fn payee_offline_behind_a_gateway() {
    let setup = setup().await;
    let network = NetworkId(NETWORK.into());

    // The payee has the gateway issue an invoice and goes offline.
    let payee = Payee::new(2, &setup.ledger).await;
    let invoice = payee
        .invoice(&setup.endpoints, 50_000, DEFAULT_MIN_FINAL_TIMEOUT_SECS)
        .await
        .unwrap();
    invoice.verify().unwrap();
    assert!(matches!(invoice.receiver, InvoiceReceiver::Gateway(_)));
    assert_eq!(*invoice.payee(), payee.key());
    assert_eq!(invoice.body.metadata, Some(metadata("order 42")));
    assert_eq!(invoice.gateway().copied(), Some(setup.gateway.key()));
    assert_eq!(invoice.iroh_peer_id().to_string(), setup.gateway.peer_id());

    let preimage = setup.payer.pay(&invoice, &network, &[]).await.unwrap();
    assert!(invoice.body.payment_hash.matches_preimage(&preimage));

    // The payer's HTLC runs as for any payee and the gateway claimed it;
    // the gateway's own to the payee runs a week, still unclaimed.
    let (to_gateway, to_payee) = setup.locks(invoice.body.payment_hash, 2);
    assert_eq!(to_gateway.state, LockState::Claimed(preimage));
    assert!(to_gateway.expiry < unix_now() + 3600);
    assert_eq!(to_payee.state, LockState::Locked);
    assert!(to_payee.expiry >= unix_now() + DEFAULT_MIN_FINAL_TIMEOUT_SECS);
    assert!(to_payee.amount_msat >= 50_000);

    // Paying again gets the same preimage without new HTLCs.
    assert_eq!(
        setup.payer.pay(&invoice, &network, &[]).await.unwrap(),
        preimage
    );
    setup.locks(invoice.body.payment_hash, 2);

    // The payee comes back and redeems, once.
    let report = payee.redeem(&setup.endpoints.preimage_server).await;
    assert_eq!(
        report.claimed,
        vec![(
            invoice.body.payment_hash,
            network.clone(),
            to_payee.amount_msat
        )]
    );
    assert_eq!(
        report.metadata,
        vec![(invoice.body.payment_hash, metadata("order 42"))]
    );
    assert!(report.pending.is_empty() && report.failed.is_empty());
    assert_eq!(
        setup.locks(invoice.body.payment_hash, 2).1.state,
        LockState::Claimed(preimage)
    );
    let record: GatewayInvoiceRecord = payee
        .store
        .get(GATEWAY_INVOICES, &invoice.body.payment_hash.to_string())
        .unwrap()
        .unwrap();
    assert_eq!(record.status, InvoiceStatus::Claimed);
    let again = payee.redeem(&setup.endpoints.preimage_server).await;
    assert!(again.claimed.is_empty() && again.failed.is_empty());

    // The gateway refuses to lock its funds longer than it wants to.
    let error = payee
        .invoice(&setup.endpoints, 1_000, 60 * 24 * 3600)
        .await
        .unwrap_err();
    assert!(error.contains("gateway refused"), "{error}");

    // Nobody but the gateway gets preimages released, and nobody but
    // the payee sees its log.
    let intruder = Transport::bind_client([7; 32]).await.unwrap();
    let record: cassis_gateway::InvoiceRecord = setup
        .gateway
        .store()
        .get(
            cassis_gateway::INVOICES,
            &invoice.body.payment_hash.to_string(),
        )
        .unwrap()
        .unwrap();
    let release = Request::PreimageRelease(PreimageRelease {
        authorization: record.authorization,
        issuance: record.issuance,
        metadata: record.invoice.body.metadata,
        network: network.clone(),
        htlc: Htlc {
            payment_hash: invoice.body.payment_hash,
            amount_msat: to_payee.amount_msat,
            expiry: to_payee.expiry,
            target: to_payee.target.clone(),
            descriptor: HtlcDescriptor::Cashu {
                proofs_b64: vec!["none".into()],
            },
        },
    });
    assert!(matches!(
        request(&intruder, &setup.endpoints.preimage_server, release).await,
        Response::PreimageReleased(Err(reason)) if reason.contains("only the authorized gateway")
    ));
    let Response::PreimagePayments(Ok(payments)) = request(
        &intruder,
        &setup.endpoints.preimage_server,
        Request::PreimagePayments { since: 0 },
    )
    .await
    else {
        panic!("expected a payment log");
    };
    assert!(payments.is_empty());
    let Response::PreimagePayments(Ok(payments)) = request(
        &payee.transport,
        &setup.endpoints.preimage_server,
        Request::PreimagePayments { since: 0 },
    )
    .await
    else {
        panic!("expected a payment log");
    };
    assert!(matches!(
        payments.as_slice(),
        [ReceivedPayment::Received { payment_hash, .. }] if *payment_hash == invoice.body.payment_hash
    ));

    intruder.close().await;
    payee.transport.close().await;
    setup.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs internet access for iroh relays"]
async fn gateway_issues_invoices_for_an_offline_payee() {
    let setup = setup().await;
    let network = NetworkId(NETWORK.into());
    let payee = Payee::new(3, &setup.ledger).await;
    let now = unix_now();
    authorize_gateway(
        &payee.store,
        &payee.keys,
        &payee.transport,
        setup.endpoints.clone(),
        std::slice::from_ref(&payee.network),
        now,
        now + 24 * 3600,
        1_000,
        100_000,
        DEFAULT_MIN_FINAL_TIMEOUT_SECS,
    )
    .await
    .unwrap();

    // Anyone asks the gateway for an invoice paying the payee, which
    // stays offline.
    let asker = Transport::bind(None).await.unwrap();
    let ask = |amount_msat| {
        Request::GatewayInvoiceFor(GatewayInvoiceFor {
            payee: payee.key(),
            amount_msat,
            expires_at: None,
            description: Some("tip".into()),
            metadata: Some(metadata("tip jar")),
        })
    };
    let Response::GatewayInvoice(Ok(invoice)) =
        request(&asker, &setup.endpoints.gateway, ask(20_000)).await
    else {
        panic!("expected an invoice");
    };
    invoice.verify().unwrap();
    assert!(matches!(invoice.receiver, InvoiceReceiver::Delegated(_)));
    assert_eq!(*invoice.payee(), payee.key());

    // Outside the authorized amounts, or for a payee that authorized
    // nothing, there is none.
    assert!(matches!(
        request(&asker, &setup.endpoints.gateway, ask(200_000)).await,
        Response::GatewayInvoice(Err(_))
    ));
    let mut stranger = ask(20_000);
    if let Request::GatewayInvoiceFor(ref mut ask) = stranger {
        ask.payee = endpoint_public_key(&[5; 32]);
    }
    assert!(matches!(
        request(&asker, &setup.endpoints.gateway, stranger).await,
        Response::GatewayInvoice(Err(_))
    ));

    let preimage = setup.payer.pay(&invoice, &network, &[]).await.unwrap();
    assert!(invoice.body.payment_hash.matches_preimage(&preimage));
    let (to_gateway, to_payee) = setup.locks(invoice.body.payment_hash, 3);
    assert_eq!(to_gateway.state, LockState::Claimed(preimage));
    assert_eq!(to_payee.state, LockState::Locked);
    assert!(to_payee.expiry >= unix_now() + DEFAULT_MIN_FINAL_TIMEOUT_SECS);

    let report = payee.redeem(&setup.endpoints.preimage_server).await;
    assert_eq!(
        report.claimed,
        vec![(invoice.body.payment_hash, network, to_payee.amount_msat)]
    );
    assert_eq!(
        report.metadata,
        vec![(invoice.body.payment_hash, metadata("tip jar"))]
    );
    assert_eq!(
        setup.locks(invoice.body.payment_hash, 3).1.state,
        LockState::Claimed(preimage)
    );

    asker.close().await;
    payee.transport.close().await;
    setup.shutdown().await;
}
