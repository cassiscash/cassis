//! Payer -> router -> payee over real iroh endpoints and an in-process
//! Nostr relay, with an in-memory mock network on each side.
//!
//! Needs internet access (iroh relays), so it is ignored by default:
//! `cargo test -p cassis-routerd --test payment_flow -- --ignored`

use async_trait::async_trait;
use cassis_core::keys::{generate_mnemonic, NodeKeys};
use cassis_core::offline::endpoint_public_key;
use cassis_core::protocol::{InvoiceReceiver, Metadata};
use cassis_core::{
    unix_now, Bytes32, Htlc, HtlcDescriptor, InvoiceTarget, Network, NetworkError, NetworkId,
    OutgoingState, XOnlyPubKey,
};
use cassis_routerd::db::{Db as RouterDb, HopState};
use cassis_routerd::router::{RouteOffer, Router, RoutingPolicy};
use cassis_wallet::db::{PendingPaymentHash, TransactionHash};
use cassis_wallet::{open_db, Node, NodeConfig};
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
    target: XOnlyPubKey,
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
        self.id.clone()
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
        let ledger = self.ledger.0.lock().unwrap();
        let lock = ledger
            .get(&Self::lock_id(htlc)?)
            .ok_or_else(|| NetworkError::invalid("no such lock"))?;
        let paid = |target| -> InvoiceTarget {
            InvoiceTarget::Cashu {
                network: self.id(),
                target,
            }
        };
        let ok = htlc.descriptor.pays(&paid(self.key))
            && htlc.descriptor.pays(&paid(lock.target))
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
    let keys = NodeKeys::from_mnemonic(&generate_mnemonic()).unwrap();
    let node = Node::start(
        NodeConfig {
            keys: keys.clone(),
            db: open_db(&dir(name)).unwrap(),
            span: Span::none(),
            serve: true,
        },
        networks,
    )
    .await
    .unwrap();
    (node, keys)
}

fn dir(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("cassis-flow-{name}-{}", rand_suffix()))
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
    let (router_node, router_keys) = start_node(
        "router",
        vec![
            MockNetwork::new(a, 2, &chain_a),
            MockNetwork::new(b, 3, &chain_b),
        ],
    )
    .await;
    let router_dir = dir("router-hops");
    std::fs::create_dir_all(&router_dir).unwrap();
    let router = Router::start(
        router_node,
        Arc::new(RouterDb::open(router_dir.join("router.redb")).unwrap()),
    )
    .unwrap();
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
    assert!(invoice.body.payment_hash.matches_preimage(&preimage));
    // The SETTLE fanout claimed the router's incoming HTLC: the hop is
    // settled, no longer in flight.
    let settled = router.db().hops().by_in_flight(false).unwrap();
    assert_eq!(settled.len(), 1);
    assert_eq!(settled[0].state, HopState::Settled);
    // Fee: 1000 base + 2000 of cashu claim cost + 500 ppm of 100_000.
    assert_eq!(settled[0].incoming.amount_msat, 103_050);
    assert_eq!(settled[0].fee_msat(), 3_050);
    assert!(router.db().hops().by_in_flight(true).unwrap().is_empty());
    // The payer and the payee each have their transaction.
    let key = TransactionHash(invoice.body.payment_hash.to_string());
    assert!(payer.db().transactions().contains(key.clone()).unwrap());
    assert!(payee.db().transactions().contains(key).unwrap());
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
    tampered.body.amount_msat = 40_000;
    let error = payer
        .pay(&tampered, &NetworkId(a.into()), &[RELAY.into()])
        .await
        .unwrap_err();
    assert!(error.contains("invalid invoice signature"), "{error}");
    assert!(!payer
        .db()
        .pending_payments()
        .contains(PendingPaymentHash(tampered.body.payment_hash.to_string()))
        .unwrap());

    // The endpoint named for the payee does not know the invoice: it
    // refuses at PREPARE, before anything is funded.
    let mut misdirected = payee
        .create_invoice(&[NetworkId(b.into())], 50_000, unix_now() + 600, None, None)
        .await
        .unwrap();
    if let InvoiceReceiver::Direct(receiver) = &mut misdirected.receiver {
        receiver.payee = endpoint_public_key(&router_keys.iroh);
    }
    misdirected.sign_as_payee(&router_keys.iroh).unwrap();
    let error = payer
        .pay(&misdirected, &NetworkId(a.into()), &[RELAY.into()])
        .await
        .unwrap_err();
    assert!(error.contains("payee refused: unknown invoice"), "{error}");
    assert!(!payer
        .db()
        .pending_payments()
        .contains(PendingPaymentHash(
            misdirected.body.payment_hash.to_string()
        ))
        .unwrap());

    // The payer locks to a key the payee does not claim with: PREPARE
    // passes, COMMIT fails after funding, and both funded HTLCs stay
    // journaled for refund.
    let mut unreachable = payee
        .create_invoice(&[NetworkId(b.into())], 50_000, unix_now() + 600, None, None)
        .await
        .unwrap();
    unreachable.body.networks[0].target = InvoiceTarget::Cashu {
        network: NetworkId(b.into()),
        target: ritualistic::SecretKey::from_bytes([9; 32])
            .unwrap()
            .pubkey(),
    };
    unreachable.sign_as_payee(&payee_keys.iroh).unwrap();
    let error = payer
        .pay(&unreachable, &NetworkId(a.into()), &[RELAY.into()])
        .await
        .unwrap_err();
    assert!(error.contains("payee did not claim"), "{error}");
    assert!(payer
        .db()
        .pending_payments()
        .contains(PendingPaymentHash(
            unreachable.body.payment_hash.to_string()
        ))
        .unwrap());
    let forwarded = router
        .db()
        .hops()
        .by_payment_hash(unreachable.body.payment_hash.to_string())
        .unwrap();
    assert!(forwarded
        .iter()
        .any(|hop| hop.state == HopState::Forwarded && hop.outgoing.is_some()));
    assert_eq!(router.db().hops().by_in_flight(true).unwrap().len(), 1);
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
