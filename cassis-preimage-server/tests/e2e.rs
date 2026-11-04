//! Payer -> payee through a preimage server, over real iroh endpoints,
//! with an in-memory mock network every party shares: the payee issues
//! an invoice through the server and goes offline, the payer pays it,
//! the server verifies the HTLC and reveals the preimage, and the payee
//! comes back to redeem.
//!
//! Needs internet access (iroh relays), so it is ignored by default:
//! `cargo test -p cassis-preimage-server --test e2e -- --ignored`

use async_trait::async_trait;
use cassis_core::keys::{generate_mnemonic, NodeKeys};
use cassis_core::node::{
    create_preimage_server_invoice, redeem_preimage_server_payments, InvoiceStatus, Node,
    NodeConfig, PreimageServerInvoiceRecord, PREIMAGE_SERVER_INVOICES,
};
use cassis_core::protocol::{Commit, Invoice, ReceivedPayment, Request, Response};
use cassis_core::store::Store;
use cassis_core::transport::{PeerAddr, Transport};
use cassis_core::{
    unix_now, Bytes32, Htlc, HtlcDescriptor, HtlcTarget, Network, NetworkError, NetworkId,
    OutgoingState, XOnlyPubKey,
};
use cassis_preimage_server::{Db, PreimageServer, ServerConfig};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tracing::Span;

const NETWORK: &str = "mock::chain";
const CLAIM_WINDOW: u64 = 3600;

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
        "cassis-preimage-{name}-{}",
        Bytes32::random().short()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

struct Payee {
    keys: NodeKeys,
    store: Store,
    network: Arc<dyn Network>,
}

impl Payee {
    fn new(key: u8, ledger: &Ledger) -> Self {
        Self {
            keys: NodeKeys::from_mnemonic(&generate_mnemonic()).unwrap(),
            store: Store::open(&temp_dir("payee").join("store.db")).unwrap(),
            network: MockNetwork::new(key, ledger),
        }
    }

    async fn invoice(&self, server: &PeerAddr, amount_msat: u64) -> Result<Invoice, String> {
        create_preimage_server_invoice(
            &self.store,
            &self.keys,
            server.clone(),
            &[self.network.clone()],
            amount_msat,
            unix_now() + 600,
            Some("coffee".into()),
            CLAIM_WINDOW,
        )
        .await
    }

    fn record(&self, invoice: &Invoice) -> PreimageServerInvoiceRecord {
        self.store
            .get(PREIMAGE_SERVER_INVOICES, &invoice.payment_hash.to_string())
            .unwrap()
            .unwrap()
    }
}

async fn request(transport: &Transport, server: &PeerAddr, request: Request) -> Response {
    transport.request(server, &request).await.unwrap()
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs internet access for iroh relays"]
async fn payee_offline_behind_a_preimage_server() {
    let ledger = Ledger::default();
    let network = NetworkId(NETWORK.into());

    let server_keys = NodeKeys::from_mnemonic(&generate_mnemonic()).unwrap();
    let server = PreimageServer::start(ServerConfig {
        endpoint_secret: server_keys.iroh,
        preimage_secret: server_keys.preimage_server_secret(),
        db: Arc::new(Db::open(temp_dir("server").join("payments.redb")).unwrap()),
        networks: vec![MockNetwork::new(9, &ledger)],
        span: Span::none(),
    })
    .await
    .unwrap();
    let server_addr = PeerAddr {
        id: server.peer_id(),
        relay: server.home_relay().await,
    };

    // The payee issues an invoice through the server and goes offline:
    // nothing of it runs until it redeems.
    let payee = Payee::new(2, &ledger);
    let invoice = payee.invoice(&server_addr, 50_000).await.unwrap();
    invoice.verify_signature().unwrap();
    assert_eq!(
        invoice.iroh_peer_id.as_deref(),
        Some(server.peer_id().as_str())
    );
    assert_eq!(
        invoice.incoming_delta_for(&network),
        5 + CLAIM_WINDOW,
        "the claim window widens the payee's margin"
    );

    let payer_keys = NodeKeys::from_mnemonic(&generate_mnemonic()).unwrap();
    let payer = Node::start(
        NodeConfig {
            keys: payer_keys,
            store: Arc::new(Store::open(&temp_dir("payer").join("store.db")).unwrap()),
            span: Span::none(),
            serve: false,
        },
        vec![MockNetwork::new(1, &ledger)],
    )
    .await
    .unwrap();
    let preimage = payer.pay(&invoice, &network, &[]).await.unwrap();
    assert!(invoice.payment_hash.matches_preimage(&preimage));

    // The server revealed the preimage but could not claim: the HTLC
    // pays the payee's key, and stays locked long enough for it.
    let locks = ledger.locks();
    assert_eq!(locks.len(), 1);
    assert_eq!(locks[0].state, LockState::Locked);
    assert!(locks[0].expiry >= unix_now() + CLAIM_WINDOW);

    // Paying again gets the same preimage without a second HTLC.
    assert_eq!(payer.pay(&invoice, &network, &[]).await.unwrap(), preimage);
    assert_eq!(ledger.locks().len(), 1);

    // The payee comes back and redeems.
    let report = redeem_preimage_server_payments(
        &payee.store,
        &payee.keys,
        &server_addr,
        &[payee.network.clone()],
        0,
    )
    .await
    .unwrap();
    assert_eq!(
        report.claimed,
        vec![(invoice.payment_hash, network.clone(), 50_000)]
    );
    assert!(report.pending.is_empty() && report.failed.is_empty());
    assert_eq!(ledger.locks()[0].state, LockState::Claimed(preimage));
    assert_eq!(payee.record(&invoice).status, InvoiceStatus::Claimed);
    // Redeeming again claims nothing twice.
    let again = redeem_preimage_server_payments(
        &payee.store,
        &payee.keys,
        &server_addr,
        &[payee.network.clone()],
        0,
    )
    .await
    .unwrap();
    assert!(again.claimed.is_empty() && again.failed.is_empty());

    // Another payee sees none of it, and cannot have the first payee's
    // invoices signed.
    let intruder = Transport::bind_client([7; 32]).await.unwrap();
    let Response::PreimagePayments(Ok(payments)) = request(
        &intruder,
        &server_addr,
        Request::PreimagePayments { since: 0 },
    )
    .await
    else {
        panic!("expected a payment log");
    };
    assert!(payments.is_empty());
    let mut unsigned = payee.invoice(&server_addr, 1_000).await.unwrap();
    unsigned.signature = None;
    assert!(matches!(
        request(&intruder, &server_addr, Request::PreimageSign(unsigned.clone())).await,
        Response::PreimageSigned(Err(reason)) if reason.contains("another payee")
    ));

    // A COMMIT naming an HTLC that does not exist gets no preimage and
    // stores nothing, and the server keeps no record without the
    // invoice to check against.
    let second = payee.invoice(&server_addr, 20_000).await.unwrap();
    let bogus = Commit {
        payment_hash: second.payment_hash,
        network: network.clone(),
        expiry: unix_now() + CLAIM_WINDOW + 600,
        descriptor: HtlcDescriptor::Cashu {
            proofs_b64: vec!["no such lock".into()],
        },
        metadata: second.metadata.clone(),
        invoice: Some(second.clone()),
    };
    assert!(matches!(
        request(&intruder, &server_addr, Request::Commit(bogus.clone())).await,
        Response::Error(reason) if reason.contains("HTLC rejected")
    ));
    let without_invoice = Commit {
        invoice: None,
        ..bogus.clone()
    };
    assert!(matches!(
        request(&intruder, &server_addr, Request::Commit(without_invoice)).await,
        Response::Error(reason) if reason.contains("send the invoice")
    ));
    // Nor does one carrying an altered invoice, or an HTLC expiring
    // inside the claim window.
    let mut altered = second.clone();
    altered.amount_msat = 1;
    let tampered = Commit {
        invoice: Some(altered),
        ..bogus.clone()
    };
    assert!(matches!(
        request(&intruder, &server_addr, Request::Commit(tampered)).await,
        Response::Error(reason) if reason.contains("signature")
    ));
    let short = Commit {
        expiry: unix_now() + CLAIM_WINDOW / 2,
        ..bogus
    };
    assert!(matches!(
        request(&intruder, &server_addr, Request::Commit(short)).await,
        Response::Error(reason) if reason.contains("too soon")
    ));
    let payee_client = Transport::bind_client(payee.keys.preimage_server_client_secret())
        .await
        .unwrap();
    let Response::PreimagePayments(Ok(payments)) = request(
        &payee_client,
        &server_addr,
        Request::PreimagePayments { since: 0 },
    )
    .await
    else {
        panic!("expected a payment log");
    };
    assert!(matches!(
        payments.as_slice(),
        [ReceivedPayment::Received { payment_hash, .. }] if *payment_hash == invoice.payment_hash
    ));

    intruder.close().await;
    payee_client.close().await;
    payer.shutdown().await;
    server.shutdown().await;
}
