//! Payer -> router -> payee over real iroh endpoints and an in-process
//! Nostr relay, with an in-memory mock network on each side.
//!
//! Needs internet access (iroh relays), so it is ignored by default:
//! `cargo test -p cassis-core --test payment_flow -- --ignored`

use async_trait::async_trait;
use cassis_core::keys::{generate_mnemonic, NodeKeys};
use cassis_core::node::{
    HopRecord, HopState, Node, NodeConfig, PaymentRecord, PaymentStatus, RouteOffer, RoutingPolicy,
};
use cassis_core::protocol::Metadata;
use cassis_core::store::Store;
use cassis_core::{
    unix_now, Bytes32, Htlc, HtlcDescriptor, HtlcTarget, Network, NetworkError, NetworkId,
    OutgoingState, XOnlyPubKey,
};
use ritualistic::server::{CustomRelay, RelayInternals};
use ritualistic::{Event, Filter};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::Span;

const RELAY_ADDR: &str = "127.0.0.1:10777";
const RELAY: &str = "ws://127.0.0.1:10777";

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

/// One mock chain shared by every node on it.
#[derive(Clone, Default)]
struct Ledger(Arc<Mutex<HashMap<String, Lock>>>);

struct MockNetwork {
    id: NetworkId,
    key: XOnlyPubKey,
    ledger: Ledger,
}

impl MockNetwork {
    fn new(id: &str, key: u8, ledger: &Ledger) -> Arc<Self> {
        Arc::new(Self {
            id: NetworkId(id.into()),
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
        self.id.clone()
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
        let ledger = self.ledger.0.lock().unwrap();
        let lock = ledger
            .get(&Self::lock_id(htlc)?)
            .ok_or_else(|| NetworkError::invalid("no such lock"))?;
        let ok = htlc.target == HtlcTarget::XOnlyPubKey(self.key)
            && lock.target == htlc.target
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

#[derive(Default)]
struct MemoryRelay {
    events: Vec<Event>,
}

impl CustomRelay for MemoryRelay {
    fn handle_event(&mut self, event: &Event) -> Result<(), String> {
        self.events.push(event.clone());
        Ok(())
    }

    fn handle_request(&mut self, filter: &Filter) -> Result<Vec<Event>, String> {
        Ok(self
            .events
            .iter()
            .filter(|event| filter.matches(event))
            .cloned()
            .collect())
    }
}

/// A serving node, and its keys to sign doctored invoices with.
async fn start_node(name: &str, networks: Vec<Arc<dyn Network>>) -> (Node, NodeKeys) {
    let dir = std::env::temp_dir().join(format!("cassis-flow-{name}-{}", rand_suffix()));
    let keys = NodeKeys::from_mnemonic(&generate_mnemonic()).unwrap();
    let node = Node::start(
        NodeConfig {
            keys: keys.clone(),
            store: Arc::new(Store::open(&dir.join("store.db")).unwrap()),
            span: Span::none(),
            serve: true,
        },
        networks,
    )
    .await
    .unwrap();
    (node, keys)
}

fn rand_suffix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs internet access for iroh relays"]
async fn payment_crosses_a_router_and_failures_stay_refundable() {
    let relay = RelayInternals {
        info: Default::default(),
        custom_relay: Box::new(tokio::sync::Mutex::new(MemoryRelay::default())),
    };
    tokio::spawn(ritualistic::server::start(
        Arc::new(relay),
        RELAY_ADDR.parse().unwrap(),
    ));

    let chain_a = Ledger::default();
    let chain_b = Ledger::default();
    let a = "cashu::a.example";
    let b = "cashu::b.example";
    let (payer, _) = start_node("payer", vec![MockNetwork::new(a, 1, &chain_a)]).await;
    let (router, router_keys) = start_node(
        "router",
        vec![
            MockNetwork::new(a, 2, &chain_a),
            MockNetwork::new(b, 3, &chain_b),
        ],
    )
    .await;
    let (payee, payee_keys) = start_node("payee", vec![MockNetwork::new(b, 4, &chain_b)]).await;
    let offer = |from: &str, to: &str| RouteOffer {
        nostr_relays: vec![RELAY.into()],
        ..RouteOffer::new(NetworkId(from.into()), NetworkId(to.into()))
    };
    router.start_routing(RoutingPolicy {
        routes: vec![offer(a, b), offer(b, a)],
        ..RoutingPolicy::default()
    });
    for _ in 0..100 {
        if cassis_core::routing::fetch_announcements(&[RELAY.into()])
            .await
            .is_ok_and(|announcements| announcements.len() == 2)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Happy path: the payee claims, the router learns the preimage.
    let metadata = Metadata::new(b"order 42".to_vec()).unwrap();
    let invoice = payee
        .create_invoice(
            &[NetworkId(b.into())],
            100_000,
            unix_now() + 600,
            None,
            Some(metadata),
        )
        .await
        .unwrap();
    let preimage = payer
        .pay(&invoice, &NetworkId(a.into()), &[RELAY.into()])
        .await
        .unwrap();
    assert!(invoice.payment_hash.matches_preimage(&preimage));
    let hops: Vec<HopRecord> = router.store().list("hops").unwrap();
    assert_eq!(hops.len(), 1);
    // Fee: 1000 base + 500 ppm of 100_000.
    assert_eq!(hops[0].prepare.amount_msat, 101_050);
    // The SETTLE fanout claimed the router's incoming HTLC.
    assert_eq!(hops[0].state, HopState::Settled);
    let claimed_upstream = chain_a
        .0
        .lock()
        .unwrap()
        .values()
        .all(|lock| lock.state == LockState::Claimed(preimage));
    assert!(claimed_upstream);

    // An invoice changed after signing is refused before anything is
    // funded.
    let mut tampered = payee
        .create_invoice(&[NetworkId(b.into())], 50_000, unix_now() + 600, None, None)
        .await
        .unwrap();
    tampered.amount_msat = 40_000;
    let error = payer
        .pay(&tampered, &NetworkId(a.into()), &[RELAY.into()])
        .await
        .unwrap_err();
    assert!(error.contains("invalid invoice signature"), "{error}");
    assert!(payer
        .store()
        .get::<PaymentRecord>("payments", &tampered.payment_hash.to_string())
        .unwrap()
        .is_none());

    // The endpoint named for the payee does not know the invoice: it
    // refuses at PREPARE, before anything is funded.
    let mut misdirected = payee
        .create_invoice(&[NetworkId(b.into())], 50_000, unix_now() + 600, None, None)
        .await
        .unwrap();
    misdirected.iroh_peer_id = Some(router.iroh_peer_id());
    misdirected.sign_as_payee(&router_keys.iroh).unwrap();
    let error = payer
        .pay(&misdirected, &NetworkId(a.into()), &[RELAY.into()])
        .await
        .unwrap_err();
    assert!(error.contains("payee refused: unknown invoice"), "{error}");
    assert!(payer
        .store()
        .get::<PaymentRecord>("payments", &misdirected.payment_hash.to_string())
        .unwrap()
        .is_none());

    // The payer locks to a key the payee does not claim with: PREPARE
    // passes, COMMIT fails after funding, and both funded HTLCs stay
    // journaled for refund.
    let mut unreachable = payee
        .create_invoice(&[NetworkId(b.into())], 50_000, unix_now() + 600, None, None)
        .await
        .unwrap();
    unreachable.networks[0].target = HtlcTarget::XOnlyPubKey(
        ritualistic::SecretKey::from_bytes([9; 32])
            .unwrap()
            .pubkey(),
    );
    unreachable.sign_as_payee(&payee_keys.iroh).unwrap();
    let error = payer
        .pay(&unreachable, &NetworkId(a.into()), &[RELAY.into()])
        .await
        .unwrap_err();
    assert!(error.contains("payee did not claim"), "{error}");
    let payment: PaymentRecord = payer
        .store()
        .get("payments", &unreachable.payment_hash.to_string())
        .unwrap()
        .unwrap();
    assert_eq!(payment.status, PaymentStatus::Pending);
    let forwarded: Vec<HopRecord> = router.store().list("hops").unwrap();
    assert!(forwarded
        .iter()
        .any(|hop| hop.prepare.payment_hash == unreachable.payment_hash
            && hop.state == HopState::Forwarded));
    // Nothing is refunded before the expiry.
    router.settle_once().await;
    payer.settle_once().await;
    assert!(chain_b
        .0
        .lock()
        .unwrap()
        .values()
        .all(|lock| lock.state != LockState::Refunded));
}
