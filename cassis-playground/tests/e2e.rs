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

use cassis_core::node::PrepareVeto;
use cassis_core::NetworkId;
use cassis_playground::local::{wait_for_announcements, LocalEnv, TestNode};
use std::sync::Arc;

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
