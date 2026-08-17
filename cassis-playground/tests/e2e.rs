//! End-to-end payments across real ledgers running locally: cashu mints
//! (`cdk-mintd`, fake Lightning), fedimint federations (`fedimintd`
//! on regtest bitcoin) and arkd operators (on the same regtest bitcoin,
//! funding nodes with arknotes), with routers funded with their fake
//! money.
//!
//! Each test brings up its own ledgers on free ports, so they can run in
//! parallel. They need `cdk-mintd`, `cdk-cli`, `bitcoind` and fedimintd
//! (see [`cassis_playground::local`]), so they are ignored by default:
//!
//! ```text
//! cargo test -p cassis-playground --test e2e -- --ignored
//! ```
//!
//! The arkade tests also need `go`, to build arkd on first use.

use cassis_core::node::{HopState, PaymentStatus, PrepareVeto, RoutingPolicy};
use cassis_core::NetworkId;
use cassis_playground::local::{wait_for_announcements, LocalEnv, TestNode};
use std::sync::Arc;
use std::time::Duration;

/// Funding per node and network, in msat.
const FUND_MSAT: u64 = 100_000_000;
/// Payment amount, in msat.
const PAY_MSAT: u64 = 1_000_000;

fn init_logs() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info,cassis_core=debug")
        .try_init();
}

/// Pay `PAY_MSAT` from `payer` on `from` to `payee` on `to`, and check
/// the payee got it.
async fn pay(payer: &TestNode, from: &NetworkId, payee: &TestNode, to: &NetworkId) {
    let before = payee.balance_msat(to).await.unwrap();
    let invoice = payee.invoice(to, PAY_MSAT).await.unwrap();
    let preimage = payer.pay(&invoice, from).await.unwrap();
    assert!(invoice.payment_hash.matches_preimage(&preimage));
    let after = payee.balance_msat(to).await.unwrap();
    // Ledgers may charge a small fee on the claim itself.
    assert!(
        after + 10_000 >= before + PAY_MSAT,
        "{} received {} msat, expected about {PAY_MSAT}",
        payee.name,
        after.saturating_sub(before)
    );
}

/// `alice` on `from`, `carol` on `to`, and `bob` routing between them
/// with funds on `to`.
async fn single_hop(env: &LocalEnv, from: &NetworkId, to: &NetworkId) {
    let alice = env.node("alice", std::slice::from_ref(from)).await.unwrap();
    let bob = env.node("bob", &[from.clone(), to.clone()]).await.unwrap();
    let carol = env.node("carol", std::slice::from_ref(to)).await.unwrap();
    env.fund(&alice, from, FUND_MSAT).await.unwrap();
    env.fund(&bob, to, FUND_MSAT).await.unwrap();
    bob.route(None);
    wait_for_announcements(env, 2).await.unwrap();
    pay(&alice, from, &carol, to).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns cashu mints; run with --ignored"]
async fn cashu_to_cashu() {
    init_logs();
    let env = LocalEnv::start("cashu_to_cashu").await.unwrap();
    let (a, b) = (
        env.cashu_mint().await.unwrap(),
        env.cashu_mint().await.unwrap(),
    );
    single_hop(&env, &a, &b).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns a cashu mint and a federation; run with --ignored"]
async fn cashu_to_fedimint() {
    init_logs();
    let env = LocalEnv::start("cashu_to_fedimint").await.unwrap();
    let (a, b) = (
        env.cashu_mint().await.unwrap(),
        env.federation().await.unwrap(),
    );
    single_hop(&env, &a, &b).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns a federation and a cashu mint; run with --ignored"]
async fn fedimint_to_cashu() {
    init_logs();
    let env = LocalEnv::start("fedimint_to_cashu").await.unwrap();
    let (a, b) = (
        env.federation().await.unwrap(),
        env.cashu_mint().await.unwrap(),
    );
    single_hop(&env, &a, &b).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns two federations; run with --ignored"]
async fn fedimint_to_fedimint() {
    init_logs();
    let env = LocalEnv::start("fedimint_to_fedimint").await.unwrap();
    let (a, b) = (
        env.federation().await.unwrap(),
        env.federation().await.unwrap(),
    );
    single_hop(&env, &a, &b).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns a cashu mint and arkd; run with --ignored"]
async fn cashu_to_arkade() {
    init_logs();
    let env = LocalEnv::start("cashu_to_arkade").await.unwrap();
    let (a, b) = (env.cashu_mint().await.unwrap(), env.arkd().await.unwrap());
    single_hop(&env, &a, &b).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns arkd and a federation; run with --ignored"]
async fn arkade_to_fedimint() {
    init_logs();
    let env = LocalEnv::start("arkade_to_fedimint").await.unwrap();
    let (a, b) = (env.arkd().await.unwrap(), env.federation().await.unwrap());
    single_hop(&env, &a, &b).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns arkd; run with --ignored"]
async fn arkade_to_arkade_needs_no_router() {
    init_logs();
    let env = LocalEnv::start("arkade_same_network").await.unwrap();
    let network = env.arkd().await.unwrap();
    let alice = env
        .node("alice", std::slice::from_ref(&network))
        .await
        .unwrap();
    let carol = env
        .node("carol", std::slice::from_ref(&network))
        .await
        .unwrap();
    env.fund(&alice, &network, FUND_MSAT).await.unwrap();
    pay(&alice, &network, &carol, &network).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns a federation and two cashu mints; run with --ignored"]
async fn payee_on_the_payers_network_needs_no_router() {
    init_logs();
    let env = LocalEnv::start("same_network").await.unwrap();
    for network in [
        env.cashu_mint().await.unwrap(),
        env.federation().await.unwrap(),
    ] {
        let alice = env
            .node("alice", std::slice::from_ref(&network))
            .await
            .unwrap();
        let carol = env
            .node("carol", std::slice::from_ref(&network))
            .await
            .unwrap();
        env.fund(&alice, &network, FUND_MSAT).await.unwrap();
        pay(&alice, &network, &carol, &network).await;
    }
}

/// cashu -> fedimint -> cashu over two routers.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns a federation and two cashu mints; run with --ignored"]
async fn two_hops_through_a_federation() {
    init_logs();
    let env = LocalEnv::start("two_hops").await.unwrap();
    let (a, f, c) = (
        env.cashu_mint().await.unwrap(),
        env.federation().await.unwrap(),
        env.cashu_mint().await.unwrap(),
    );
    let alice = env.node("alice", std::slice::from_ref(&a)).await.unwrap();
    let bob = env.node("bob", &[a.clone(), f.clone()]).await.unwrap();
    let derek = env.node("derek", &[f.clone(), c.clone()]).await.unwrap();
    let carol = env.node("carol", std::slice::from_ref(&c)).await.unwrap();
    env.fund(&alice, &a, FUND_MSAT).await.unwrap();
    env.fund(&bob, &f, FUND_MSAT).await.unwrap();
    env.fund(&derek, &c, FUND_MSAT).await.unwrap();
    bob.route(None);
    derek.route(None);
    wait_for_announcements(&env, 4).await.unwrap();
    pay(&alice, &a, &carol, &c).await;
}

/// A router vetoing every PREPARE makes the payment fail before
/// anything is locked.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns cashu mints; run with --ignored"]
async fn payment_fails_when_the_router_vetoes() {
    init_logs();
    let env = LocalEnv::start("veto").await.unwrap();
    let (a, b) = (
        env.cashu_mint().await.unwrap(),
        env.cashu_mint().await.unwrap(),
    );
    let alice = env.node("alice", std::slice::from_ref(&a)).await.unwrap();
    let bob = env.node("bob", &[a.clone(), b.clone()]).await.unwrap();
    let carol = env.node("carol", std::slice::from_ref(&b)).await.unwrap();
    env.fund(&alice, &a, FUND_MSAT).await.unwrap();
    env.fund(&bob, &b, FUND_MSAT).await.unwrap();
    let veto: PrepareVeto = Arc::new(|_| Some("bob is in a bad mood".into()));
    bob.route(Some(veto));
    wait_for_announcements(&env, 2).await.unwrap();

    let before = alice.balance_msat(&a).await.unwrap();
    let invoice = carol.invoice(&b, PAY_MSAT).await.unwrap();
    let error = alice.pay(&invoice, &a).await.unwrap_err();
    assert!(error.contains("bad mood"), "{error}");
    assert_eq!(alice.balance_msat(&a).await.unwrap(), before);
}

/// The second of two routers vetoes: the payer aborts after PREPARE
/// and nothing is locked on any ledger.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns cashu mints; run with --ignored"]
async fn payment_fails_when_the_second_hop_vetoes() {
    init_logs();
    let env = LocalEnv::start("veto_second_hop").await.unwrap();
    let (a, b, c) = (
        env.cashu_mint().await.unwrap(),
        env.cashu_mint().await.unwrap(),
        env.cashu_mint().await.unwrap(),
    );
    let alice = env.node("alice", std::slice::from_ref(&a)).await.unwrap();
    let bob = env.node("bob", &[a.clone(), b.clone()]).await.unwrap();
    let derek = env.node("derek", &[b.clone(), c.clone()]).await.unwrap();
    let carol = env.node("carol", std::slice::from_ref(&c)).await.unwrap();
    env.fund(&alice, &a, FUND_MSAT).await.unwrap();
    env.fund(&bob, &b, FUND_MSAT).await.unwrap();
    env.fund(&derek, &c, FUND_MSAT).await.unwrap();
    bob.route(None);
    let veto: PrepareVeto = Arc::new(|prepare| {
        (prepare.amount_msat > 100_000).then(|| format!("derek refuses {}", prepare.amount_msat))
    });
    derek.route(Some(veto));
    wait_for_announcements(&env, 4).await.unwrap();

    let before = alice.balance_msat(&a).await.unwrap();
    let invoice = carol.invoice(&c, PAY_MSAT).await.unwrap();
    let error = alice.pay(&invoice, &a).await.unwrap_err();
    assert!(error.contains("derek refuses"), "{error}");
    assert_eq!(alice.balance_msat(&a).await.unwrap(), before);
}

/// alice on arkade pays carol on a second federation through four
/// routers: arkade -> cashu 1 -> fedimint 1 -> cashu 2 -> fedimint 2.
struct LongRoute {
    env: LocalEnv,
    /// arkade, cashu 1, fedimint 1, cashu 2, fedimint 2.
    networks: [NetworkId; 5],
    alice: TestNode,
    /// Router `i` forwards from `networks[i]` to `networks[i + 1]`.
    routers: [TestNode; 4],
    carol: TestNode,
}

impl LongRoute {
    async fn start(name: &str, policy: RoutingPolicy) -> Self {
        init_logs();
        let env = LocalEnv::start(name).await.unwrap();
        let (arkade, cashu_1, fedimint_1, cashu_2, fedimint_2) = tokio::try_join!(
            env.arkd(),
            env.cashu_mint(),
            env.federation(),
            env.cashu_mint(),
            env.federation(),
        )
        .unwrap();
        let networks = [arkade, cashu_1, fedimint_1, cashu_2, fedimint_2];
        let alice = env
            .node("alice", std::slice::from_ref(&networks[0]))
            .await
            .unwrap();
        env.fund(&alice, &networks[0], FUND_MSAT).await.unwrap();
        let mut routers = Vec::new();
        for (i, name) in ["r1", "r2", "r3", "r4"].into_iter().enumerate() {
            let router = env.node(name, &networks[i..i + 2]).await.unwrap();
            env.fund(&router, &networks[i + 1], FUND_MSAT)
                .await
                .unwrap();
            router.route_with(policy.clone());
            routers.push(router);
        }
        let carol = env
            .node("carol", std::slice::from_ref(&networks[4]))
            .await
            .unwrap();
        wait_for_announcements(&env, 8).await.unwrap();
        Self {
            env,
            networks,
            alice,
            routers: routers.try_into().unwrap_or_else(|_| unreachable!()),
            carol,
        }
    }

    /// Balance of every party on the network it pays from: alice on
    /// arkade, router `i` on `networks[i + 1]`.
    async fn balances(&self) -> Vec<u64> {
        let mut balances = vec![self.alice.balance_msat(&self.networks[0]).await.unwrap()];
        for (i, router) in self.routers.iter().enumerate() {
            balances.push(router.balance_msat(&self.networks[i + 1]).await.unwrap());
        }
        balances
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns arkd, two cashu mints and two federations; run with --ignored"]
async fn four_hops_across_every_ledger() {
    let route = LongRoute::start("four_hops", RoutingPolicy::default()).await;
    pay(
        &route.alice,
        &route.networks[0],
        &route.carol,
        &route.networks[4],
    )
    .await;
}

/// The third router is down when the payer PREPAREs: the payment fails
/// before anything is locked.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns arkd, two cashu mints and two federations; run with --ignored"]
async fn payment_fails_when_a_router_misses_prepare() {
    let route = LongRoute::start("missed_prepare", RoutingPolicy::default()).await;
    route.routers[2].shutdown().await;

    let before = route.balances().await;
    let invoice = route
        .carol
        .invoice(&route.networks[4], PAY_MSAT)
        .await
        .unwrap();
    let error = route
        .alice
        .pay(&invoice, &route.networks[0])
        .await
        .unwrap_err();
    assert!(error.starts_with("hop 3:"), "{error}");
    assert_eq!(route.balances().await, before);
    assert!(route.alice.node.payments().unwrap().is_empty());
    for router in &route.routers {
        assert!(
            router.node.hops().unwrap().is_empty(),
            "{} routed",
            router.name
        );
    }
}

/// The third router answers PREPARE, then goes down before its EXECUTE:
/// alice and the first two routers have funded their HTLCs, and get
/// them back once they expire.
///
/// The routers announce a 5s transit slack (instead of 60s) so the
/// HTLCs expire within about five minutes, and blocks are mined while
/// waiting so that the chain-timed ledgers follow the wall clock.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns arkd, two cashu mints and two federations; run with --ignored"]
async fn htlcs_are_refunded_when_a_router_misses_execute() {
    let policy = RoutingPolicy {
        transit_slack_secs: 5,
        ..RoutingPolicy::default()
    };
    let route = LongRoute::start("missed_execute", policy).await;
    let [_, r2, r3, r4] = &route.routers;

    let before = route.balances().await;
    let invoice = route
        .carol
        .invoice(&route.networks[4], PAY_MSAT)
        .await
        .unwrap();
    // r2 journals its hop when its EXECUTE arrives, after every PREPARE
    // was answered and before r3 can get its EXECUTE.
    let take_r3_down = async {
        while r2.node.hops().unwrap().is_empty() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        r3.shutdown().await;
    };
    let (paid, ()) = tokio::join!(route.alice.pay(&invoice, &route.networks[0]), take_r3_down);
    let error = paid.unwrap_err();
    assert!(error.starts_with("hop 3 failed"), "{error}");

    // alice, r1 and r2 have their HTLCs locked; r3 and r4 locked nothing.
    let locked = route.balances().await;
    for i in 0..3 {
        assert!(locked[i] < before[i], "party {i} has nothing locked");
    }
    assert_eq!(locked[3..], before[3..]);
    assert!(r3.node.hops().unwrap().is_empty());
    assert!(r4.node.hops().unwrap().is_empty());

    let refunded = async {
        loop {
            let payment_refunded =
                route.alice.node.payments().unwrap()[0].status == PaymentStatus::Refunded;
            let hops_refunded = route.routers[..2].iter().all(|router| {
                let hops = router.node.hops().unwrap();
                hops.len() == 1 && hops[0].state == HopState::Refunded
            });
            if payment_refunded && hops_refunded {
                return;
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    };
    tokio::time::timeout(Duration::from_secs(600), route.env.mine_while(refunded))
        .await
        .expect("HTLCs not refunded within 10 minutes");

    let after = route.balances().await;
    for (i, (after, before)) in after.iter().zip(&before).enumerate() {
        // Ledgers may charge a small fee on the lock and the refund.
        assert!(
            after + 10_000 >= *before,
            "party {i} got {after} msat back of {before}"
        );
    }
}

/// Wait up to two minutes for `ready`.
async fn until(what: &str, ready: impl Fn() -> bool) {
    tokio::time::timeout(Duration::from_secs(120), async {
        while !ready() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {what}"));
}

/// cashu -> bitcoin -> cashu: the second router holds its EXECUTE
/// (answering PENDING) until the bitcoin lockup confirms.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns two cashu mints and bitcoind; run with --ignored"]
async fn router_waits_for_a_bitcoin_confirmation() {
    init_logs();
    let env = LocalEnv::start("bitcoin_hop").await.unwrap();
    let (c1, btc, c2) =
        tokio::try_join!(env.cashu_mint(), env.bitcoin(), env.cashu_mint()).unwrap();
    let alice = env.node("alice", std::slice::from_ref(&c1)).await.unwrap();
    let r1 = env.node("r1", &[c1.clone(), btc.clone()]).await.unwrap();
    let r2 = env.node("r2", &[btc.clone(), c2.clone()]).await.unwrap();
    let carol = env.node("carol", std::slice::from_ref(&c2)).await.unwrap();
    env.fund(&alice, &c1, FUND_MSAT).await.unwrap();
    env.fund(&r1, &btc, FUND_MSAT).await.unwrap();
    env.fund(&r2, &c2, FUND_MSAT).await.unwrap();
    r1.route(None);
    r2.route(None);
    wait_for_announcements(&env, 4).await.unwrap();

    let before = carol.balance_msat(&c2).await.unwrap();
    let invoice = carol.invoice(&c2, PAY_MSAT).await.unwrap();
    let r2_state = || r2.node.hops().unwrap().first().map(|hop| hop.state.clone());
    let confirm = async {
        until("r2 to get its EXECUTE", || r2_state().is_some()).await;
        tokio::time::sleep(Duration::from_secs(15)).await;
        assert_eq!(r2_state(), Some(HopState::Verifying), "r2 did not wait");
        env.mine(1).await.unwrap();
    };
    let (paid, ()) = tokio::join!(alice.pay(&invoice, &c1), confirm);
    assert!(invoice.payment_hash.matches_preimage(&paid.unwrap()));
    let after = carol.balance_msat(&c2).await.unwrap();
    assert!(
        after + 10_000 >= before + PAY_MSAT,
        "carol got {}",
        after - before
    );
}

/// cashu -> bitcoin: the payee holds COMMIT (answering PENDING) until
/// the bitcoin lockup confirms.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns a cashu mint and bitcoind; run with --ignored"]
async fn payee_waits_for_a_bitcoin_confirmation() {
    init_logs();
    let env = LocalEnv::start("bitcoin_payee").await.unwrap();
    let (cashu, btc) = tokio::try_join!(env.cashu_mint(), env.bitcoin()).unwrap();
    let alice = env
        .node("alice", std::slice::from_ref(&cashu))
        .await
        .unwrap();
    let bob = env
        .node("bob", &[cashu.clone(), btc.clone()])
        .await
        .unwrap();
    let carol = env.node("carol", std::slice::from_ref(&btc)).await.unwrap();
    env.fund(&alice, &cashu, FUND_MSAT).await.unwrap();
    env.fund(&bob, &btc, FUND_MSAT).await.unwrap();
    bob.route(None);
    wait_for_announcements(&env, 2).await.unwrap();

    let before = carol.balance_msat(&btc).await.unwrap();
    let invoice = carol.invoice(&btc, PAY_MSAT).await.unwrap();
    let confirm = async {
        until("bob to fund carol's HTLC", || {
            bob.node
                .hops()
                .unwrap()
                .first()
                .is_some_and(|hop| hop.state == HopState::Forwarded)
        })
        .await;
        tokio::time::sleep(Duration::from_secs(15)).await;
        assert_eq!(
            carol.balance_msat(&btc).await.unwrap(),
            before,
            "carol claimed an unconfirmed lockup"
        );
        env.mine(1).await.unwrap();
    };
    let (paid, ()) = tokio::join!(alice.pay(&invoice, &cashu), confirm);
    assert!(invoice.payment_hash.matches_preimage(&paid.unwrap()));
    // The claim transaction pays its own fee (1 sat/vB).
    let after = carol.balance_msat(&btc).await.unwrap();
    assert!(
        after + 1_000_000 >= before + PAY_MSAT,
        "carol got {}",
        after - before
    );
}
