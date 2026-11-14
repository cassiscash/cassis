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
use cassis_admin::networks::{NetworkConfig, Networks, Opened, Opener, Status};
use cassis_admin::{App, Args, ConfigFile, Refresh};
use cassis_core::keys::{generate_mnemonic, NodeKeys};
use cassis_core::offline::{
    endpoint_public_key, GatewayMetadata, GatewayTerms, ReceiveAuthorization,
    DEFAULT_MIN_FINAL_TIMEOUT_SECS,
};
use cassis_core::protocol::{
    GatewayInvoiceFor, Invoice, InvoiceReceiver, Metadata, PreimageRelease, ReceivedPayment,
    Request, Response,
};
use cassis_core::transport::{PeerAddr, Transport};
use cassis_core::{
    unix_now, Bytes32, Htlc, HtlcDescriptor, InvoiceTarget, Network, NetworkError, NetworkId,
    OutgoingState, XOnlyPubKey,
};
use cassis_gateway::admin::GatewayAdmin;
use cassis_gateway::config as gateway_config;
use cassis_gateway::{Gateway, GatewayConfig, GatewayPolicy};
use cassis_preimage_server::admin::PreimageAdmin;
use cassis_preimage_server::config as server_config;
use cassis_preimage_server::{Db, PreimageServer, ServerConfig, Stats};
use cassis_wallet::db::{Db as WalletDb, InvoiceHash, InvoiceState};
use cassis_wallet::node::{
    authorize_gateway, create_gateway_invoice, redeem_offline_payments, OfflineEndpoints,
    RedeemReport,
};
use cassis_wallet::{open_db, Node, NodeConfig};
use futures::future::BoxFuture;
use hypereffect::json;
use hypereffect::vtree::text;
use iroh_base::PublicKey;
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tracing::Span;

const NETWORK: &str = "cashu::mock.chain";

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
    target: XOnlyPubKey,
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
            HtlcDescriptor::Cashu { proofs_b64, .. } if proofs_b64.len() == 1 => {
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

    async fn receive_target(
        &self,
        _: Bytes32,
        _: u64,
        _: u64,
    ) -> Result<InvoiceTarget, NetworkError> {
        Ok(InvoiceTarget::Cashu {
            network: self.id(),
            target: self.key,
        })
    }

    async fn cancel_receive(&self, _: Bytes32) -> Result<(), NetworkError> {
        Ok(())
    }

    async fn verify_incoming_htlc(&self, htlc: &Htlc) -> Result<(), NetworkError> {
        if !htlc
            .descriptor
            .pays(&self.receive_target(htlc.payment_hash, 0, 0).await?)
        {
            return Err(NetworkError::invalid("HTLC is not addressed to this node"));
        }
        self.verify_htlc(htlc).await
    }

    async fn verify_htlc(&self, htlc: &Htlc) -> Result<(), NetworkError> {
        let ledger = self.ledger.0.lock().unwrap();
        let lock = ledger
            .get(&Self::lock_id(htlc)?)
            .ok_or_else(|| NetworkError::invalid("no such lock"))?;
        let paid: InvoiceTarget = InvoiceTarget::Cashu {
            network: self.id(),
            target: lock.target,
        };
        let ok = htlc.descriptor.pays(&paid)
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
        assert_eq!(lock.target, self.key);
        lock.state = LockState::Claimed(preimage);
        Ok(())
    }

    async fn create_outgoing_htlc(
        &self,
        payment_hash: Bytes32,
        amount_msat: u64,
        expiry: u64,
        target: &InvoiceTarget,
    ) -> Result<HtlcDescriptor, NetworkError> {
        let InvoiceTarget::Cashu { target: key, .. } = target else {
            return Err(NetworkError::invalid(
                "mock HTLCs are locked to an x-only key",
            ));
        };
        let id = Bytes32::random().to_string();
        self.ledger.0.lock().unwrap().insert(
            id.clone(),
            Lock {
                payment_hash,
                amount_msat,
                expiry,
                target: *key,
                state: LockState::Locked,
            },
        );
        Ok(HtlcDescriptor::Cashu {
            proofs_b64: vec![id],
            target: *key,
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

/// Opens the gateway's side of the mock chain.
struct MockOpener(Ledger);

impl Opener<NetworkConfig> for MockOpener {
    fn open<'a>(
        &'a self,
        _: &'a NetworkId,
        _: &'a NetworkConfig,
    ) -> BoxFuture<'a, Result<Opened, String>> {
        Box::pin(async move {
            let network: Arc<dyn Network> = MockNetwork::new(8, &self.0);
            Ok(Opened {
                network,
                wallet: None,
            })
        })
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
    db: Arc<WalletDb>,
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
            db: open_db(&temp_dir("payee")).unwrap(),
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
            &self.db,
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

    async fn redeem(&self, server: &PeerAddr) -> RedeemReport {
        redeem_offline_payments(
            &self.db,
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

fn gateway_db(name: &str) -> Arc<cassis_gateway::db::Db> {
    Arc::new(cassis_gateway::db::Db::open(temp_dir(name).join("gateway.redb")).unwrap())
}

/// What a gateway's invoice carries in its metadata, opened.
fn carried(invoice: &Invoice, secret: &[u8; 32]) -> (GatewayMetadata, GatewayTerms) {
    let metadata = GatewayMetadata::from_metadata(invoice.body.metadata.as_ref().unwrap()).unwrap();
    let terms = metadata.open(secret, &invoice.body.payment_hash).unwrap();
    (metadata, terms)
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
    gateway_secret: [u8; 32],
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
    let gateway_secret = gateway_keys.iroh;
    let gateway = Gateway::start(GatewayConfig {
        endpoint_secret: gateway_secret,
        db: gateway_db("gateway"),
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
            db: open_db(&temp_dir("payer")).unwrap(),
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
        gateway_secret,
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

    fn networks(&self) -> Arc<Networks<NetworkConfig>> {
        let networks = Networks::new(MockOpener(self.ledger.clone()), Span::none(), false);
        networks.attach(Arc::new(self.gateway.clone()));
        networks
    }

    fn gateway_admin(&self, networks: Arc<Networks<NetworkConfig>>) -> Arc<GatewayAdmin> {
        let template = format!(
            "mnemonic = \"{}\"\n[networks.\"{NETWORK}\"]\n",
            generate_mnemonic()
        );
        let file = ConfigFile::<gateway_config::Config>::load_or_create(
            &temp_dir("gateway-admin"),
            &template,
        );
        GatewayAdmin::new(
            self.gateway.clone(),
            file.unwrap(),
            networks,
            None,
            Refresh::default(),
        )
    }

    /// The tabs of the admin pages of the gateway and the server.
    fn pages(&self) -> (String, String) {
        let gateway = self.gateway_admin(self.networks());
        let file = ConfigFile::load_or_create(&temp_dir("server-admin"), server_config::TEMPLATE);
        let server = PreimageAdmin::new(
            self.server.clone(),
            file.unwrap(),
            self.networks(),
            None,
            Refresh::default(),
        );
        (
            format!("{:?}", gateway.tabs(text("access"))),
            format!("{:?}", server.tabs(text("access"))),
        )
    }

    /// The locks paying `hash`: the payer's to the gateway, and the
    /// gateway's to `payee`.
    fn locks(&self, hash: Bytes32, payee: u8) -> (Lock, Lock) {
        let payee = MockNetwork::new(payee, &self.ledger).key;
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
    // The gateway carries the invoice's terms in its metadata, signed,
    // around the payee's.
    let (carried, terms) = carried(&invoice, &setup.gateway_secret);
    carried.verify(&setup.gateway.key()).unwrap();
    assert_eq!(terms.payee_metadata, Some(metadata("order 42")));
    assert_eq!(terms.payment_hash, invoice.body.payment_hash);
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
    let record = payee
        .db
        .invoices()
        .get(InvoiceHash(invoice.body.payment_hash.to_string()))
        .unwrap()
        .unwrap();
    assert_eq!(record.state, InvoiceState::Settled);
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
    let release = Request::PreimageRelease(PreimageRelease {
        authorization: terms.authorization,
        preimage_metadata: carried.preimage_metadata,
        metadata: terms.payee_metadata,
        network: network.clone(),
        htlc: Htlc {
            payment_hash: invoice.body.payment_hash,
            amount_msat: to_payee.amount_msat,
            expiry: to_payee.expiry,
            descriptor: HtlcDescriptor::Cashu {
                proofs_b64: vec!["none".into()],
                target: to_payee.target,
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
        &payee.db,
        &payee.keys,
        &payee.transport,
        setup.endpoints.clone(),
        std::slice::from_ref(&payee.network),
        now,
        now + 24 * 3600,
        1_000,
        100_000,
        DEFAULT_MIN_FINAL_TIMEOUT_SECS,
        Some("tip".into()),
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
    let invoice = match request(&asker, &setup.endpoints.gateway, ask(20_000)).await {
        Response::GatewayInvoice(Ok(invoice)) => invoice,
        other => panic!("expected an invoice, got {other:?}"),
    };
    invoice.verify().unwrap();
    assert!(matches!(invoice.receiver, InvoiceReceiver::Delegated(_)));
    assert_eq!(*invoice.payee(), payee.key());
    assert_eq!(invoice.body.description.as_deref(), Some("tip"));

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
    // The payee pinned what its invoices say: another description is
    // refused.
    let mut misdescribed = ask(20_000);
    if let Request::GatewayInvoiceFor(ref mut ask) = misdescribed {
        ask.description = Some("tea".into());
    }
    assert!(matches!(
        request(&asker, &setup.endpoints.gateway, misdescribed).await,
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

    // The admin pages show the payment, and neither gives its preimage
    // away.
    let (gateway_page, server_page) = setup.pages();
    for page in [&gateway_page, &server_page] {
        assert!(page.contains(&invoice.body.payment_hash.to_string()));
        assert!(page.contains(&payee.key().to_string()));
        assert!(page.contains("20 sat"), "{page}");
        assert!(!page.contains(&preimage.to_string()));
    }
    assert!(gateway_page.contains("1 settled"), "{gateway_page}");
    assert!(
        gateway_page.contains("payee claimed") || gateway_page.contains("waiting for the payee")
    );
    assert_eq!(
        setup.server.stats(),
        Stats {
            issued: 1,
            released: 1,
            refused: 0
        }
    );

    // A forgotten authorization gives no more invoices.
    let delegations = setup.gateway.delegations().unwrap();
    assert_eq!(delegations.len(), 1);
    let id = ReceiveAuthorization::try_from(&delegations[0].authorization)
        .unwrap()
        .id()
        .unwrap();
    setup.gateway.forget_delegation(&id).unwrap();
    assert!(matches!(
        request(&asker, &setup.endpoints.gateway, ask(20_000)).await,
        Response::GatewayInvoice(Err(_))
    ));

    asker.close().await;
    payee.transport.close().await;
    setup.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs internet access for iroh relays"]
async fn networks_and_terms_change_while_running() {
    let setup = setup().await;
    let network = NetworkId(NETWORK.into());
    let payee = Payee::new(2, &setup.ledger).await;
    let networks = setup.networks();
    let wanted = BTreeMap::from([(NETWORK.to_string(), NetworkConfig::default())]);
    let none = BTreeMap::new();
    let timeout = DEFAULT_MIN_FINAL_TIMEOUT_SECS;

    // A network removed takes effect at once, and comes back.
    assert!(networks.sync(&wanted, None, &|| {}).await);
    assert!(networks.sync(&none, None, &|| {}).await);
    assert!(setup.gateway.network_ids().is_empty());
    let error = payee.invoice(&setup.endpoints, 50_000, timeout).await;
    assert!(error.is_err());
    assert!(networks.sync(&wanted, None, &|| {}).await);
    assert_eq!(setup.gateway.network_ids(), [network.clone()]);

    // Terms apply to what comes next, through the file, which refuses
    // nonsense.
    let admin = setup.gateway_admin(networks.clone());
    let set = |payload: hypereffect::Value| {
        admin
            .clone()
            .act("terms.set", &Args(payload.as_object().unwrap().clone()))
    };
    assert!(set(json!({"forward_slack_secs": 0})).is_err());
    set(json!({"max_final_timeout_secs": 60})).unwrap();
    assert_eq!(setup.gateway.policy().max_final_timeout_secs, 60);
    let error = payee.invoice(&setup.endpoints, 50_000, timeout).await;
    assert!(error.unwrap_err().contains("gateway refused"));
    // Back to the default, and the slacks of this setup.
    set(json!({"max_final_timeout_secs": "", "forward_slack_secs": 60, "final_slack_secs": 60}))
        .unwrap();

    // A network paying a payee who has not claimed yet stays open, for
    // the refund, until the payee does.
    let invoice = payee
        .invoice(&setup.endpoints, 50_000, timeout)
        .await
        .unwrap();
    setup.payer.pay(&invoice, &network, &[]).await.unwrap();
    assert_eq!(setup.gateway.in_flight(&network), 1);
    assert!(!networks.sync(&none, None, &|| {}).await);
    assert_eq!(setup.gateway.network_ids(), [network.clone()]);
    assert_eq!(networks.slots()[NETWORK].status, Status::Waiting(1));
    let report = payee.redeem(&setup.endpoints.preimage_server).await;
    assert_eq!(report.claimed.len(), 1);
    setup.gateway.settle_once().await;
    assert_eq!(setup.gateway.in_flight(&network), 0);
    assert!(networks.sync(&none, None, &|| {}).await);
    assert!(setup.gateway.network_ids().is_empty());

    // A forward whose network is not open waits for it instead of giving
    // up on the money: here, one claiming as a gateway starts on nothing.
    let db = gateway_db("resumed");
    let mut htlc = setup.gateway.payee_htlcs().unwrap().remove(0);
    assert!(htlc.settled && htlc.preimage.is_some());
    htlc.settled = false;
    db.payee_htlcs().insert(&htlc).unwrap();
    let resumed = Gateway::start(GatewayConfig {
        endpoint_secret: [33; 32],
        db,
        networks: Vec::new(),
        policy: GatewayPolicy::default(),
        span: Span::none(),
    })
    .await
    .unwrap();
    let settled = || resumed.payee_htlcs().unwrap().remove(0).settled;
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    assert!(!settled());
    resumed.add_network(MockNetwork::new(8, &setup.ledger));
    for _ in 0..100 {
        if settled() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(settled());

    resumed.shutdown().await;
    payee.transport.close().await;
    setup.shutdown().await;
}
