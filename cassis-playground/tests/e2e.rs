//! End-to-end tests driving the `cassis_playground` library directly.
//!
//! These exercise the full multi-network payment stack across the live
//! testnet networks (Liquid testnet, Arkade mutinynet, Rootstock testnet
//! RPC) plus the three local `cdk-mintd` cashu mints. They are ignored
//! by default: run them explicitly with
//!
//! ```text
//! cargo test -p cassis-playground --test e2e -- --ignored --nocapture --test-threads=1
//! ```
//!
//! `--test-threads=1` matters: the tests share fixed ports (the in-process
//! relay on 10000 and the three mints on 8091..8093) and fixed network
//! endpoints, so they must not run concurrently.
//!
//! ## Prefunding (one-time per testnet)
//!
//! The `cashu_*` networks mint freely (fake wallet), so nothing is needed
//! there. The Liquid / Arkade / Rootstock legs spend testnet coins from
//! the shared prefund wallet. The `cassis-prefund` binary prints those
//! addresses and blocks until each holds enough coin, so run it first:
//!
//! ```text
//! cargo run -p cassis-playground --bin cassis-prefund -- --min-sats 20000
//! cargo test -p cassis-playground --test e2e -- --ignored --test-threads=1
//! ```
//!
//! Each test independently re-checks the prefund balance and, once the
//! chain-network prefund wallets have coin, moves it into the node
//! wallets via `command_fund`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use cassis_playground::{
    command_fund, command_pay, command_router, command_router_with_veto, node_home, Playground,
    DEFAULT_PREFUND_SEED, E2E_ROOT,
};

/// Per-node seed phrases. Deterministic on purpose: each node's
/// Nostr / iroh / per-network identities derive from its seed, so
/// repeated runs reuse the same testnet wallets and any coins left
/// behind from a previous run are still there.
const ALICE_SEED: &str =
    "jungle stem gravity essay praise kidney rule torch photo faculty museum artefact";
const BOB_SEED: &str =
    "electric chunk together detect derive midnight age clap reward whale skull tree";
const CHARLIE_SEED: &str =
    "battle rug shy flight together bird antique suspect settle happy radar pledge";
const DEREK_SEED: &str = "kid dust fantasy pet female token dad begin kiss list caution uncle";

/// Funding per node, in msat (10k sats). Enough for several payments
/// plus network fees. Liquid requires locks of at least 1000 sats and
/// Arkade has an operator dust limit, so keep payments and funding
/// above both while keeping the prefund requirement small.
const FUND_MSAT: u64 = 10_000_000;
/// Payment amount in msat (1k sats): exactly Liquid's `MIN_LOCK_SATS`
/// and above Arkade's dust, a whole number of sats for both.
const PAY_MSAT: u64 = 1_000_000;

/// Pin a node's BIP39 seed before [`Playground::new`] initializes the
/// node home. `Playground::new` only writes a seed when none exists, so
/// pre-writing one fixes the node's identity across runs.
fn pin_seed(root: &Path, node: &str, seed: &str) {
    let home = node_home(root, node);
    std::fs::create_dir_all(&home).expect("create node home");
    let seed_path = home.join("seed");
    if !seed_path.exists() {
        std::fs::write(&seed_path, format!("{seed}\n")).expect("write seed");
    }
}

/// In-process relay URL, shared by routers and payers.
async fn wait_for_relay() {
    for _ in 0..50 {
        if tokio::net::TcpStream::connect("127.0.0.1:10000")
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
}

async fn fund_and_router(pg: &Playground, node: &str, networks: &[&str]) -> Result<(), String> {
    for network in networks {
        command_fund(pg, node, network, FUND_MSAT).await?;
    }
    command_router(pg, node, networks.iter().map(|s| s.to_string()).collect()).await
}

/// Give the routers a moment to publish route announcements and the
/// in-process relay to index them.
async fn let_routes_settle() {
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
}

/// Assert a node holds at least `min_msat` on `network` before a
/// payment is attempted, with a message naming the node and network so
/// a shortfall is diagnosable instead of surfacing as a mid-payment
/// `can_route` rejection.
async fn assert_funded(pg: &Playground, node: &str, network: &str, min_msat: u64) {
    let balance = pg.balance_msat(node, network).await.unwrap_or(0);
    assert!(
        balance >= min_msat,
        "node {node} has {balance} msat on {network}, needs at least {min_msat}"
    );
}

/// Assert the shared prefund wallet holds at least `min_msat` on a
/// chain network before a test moves coins into node wallets. Pairs
/// with the `cassis-prefund` gate: that script waits for the deposits,
/// this check turns a shortfall into a clear per-test failure instead
/// of a mid-`command_fund` error.
async fn assert_prefunded(pg: &Playground, network: &str, min_msat: u64) {
    let balance = pg.prefund_balance_msat(network).await.unwrap_or(0);
    assert!(
        balance >= min_msat,
        "prefund wallet has {balance} msat on {network}, needs at least {min_msat} \
         (run `cargo run -p cassis-playground --bin cassis-prefund` to top up)"
    );
}

#[tokio::test]
#[ignore = "requires live testnet infrastructure and local cdk-mintd"]
async fn cashu_to_liquid_payment() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let root = PathBuf::from(E2E_ROOT).join("cashu_to_liquid");
    let _ = std::fs::remove_dir_all(&root);
    pin_seed(&root, "alice", ALICE_SEED);
    pin_seed(&root, "bob", BOB_SEED);
    pin_seed(&root, "charlie", CHARLIE_SEED);
    let pg = Playground::new(DEFAULT_PREFUND_SEED.to_string(), root)
        .await
        .unwrap();
    wait_for_relay().await;

    // alice pays from cashu, charlie receives on Liquid, bob bridges.
    // The prefund wallet funds both bob and charlie on Liquid, so it
    // must hold two funding amounts before either transfer.
    assert_prefunded(&pg, "liquid_testnet", 2 * FUND_MSAT).await;
    fund_and_router(&pg, "bob", &["cashu_1", "liquid_testnet"])
        .await
        .unwrap();
    command_fund(&pg, "alice", "cashu_1", FUND_MSAT)
        .await
        .unwrap();
    command_fund(&pg, "charlie", "liquid_testnet", FUND_MSAT)
        .await
        .unwrap();

    let_routes_settle().await;

    // Verify every participant has the funds to complete the route:
    // the sender on its outgoing network and the router on its own
    // outgoing side.
    assert_funded(&pg, "alice", "cashu_1", PAY_MSAT).await;
    assert_funded(&pg, "bob", "liquid_testnet", PAY_MSAT).await;

    command_pay(&pg, "alice", "charlie", PAY_MSAT)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires live testnet infrastructure and local cdk-mintd"]
async fn cashu_to_arkade_payment() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let root = PathBuf::from(E2E_ROOT).join("cashu_to_arkade");
    let _ = std::fs::remove_dir_all(&root);
    pin_seed(&root, "alice", ALICE_SEED);
    pin_seed(&root, "bob", BOB_SEED);
    pin_seed(&root, "charlie", CHARLIE_SEED);
    let pg = Playground::new(DEFAULT_PREFUND_SEED.to_string(), root)
        .await
        .unwrap();
    wait_for_relay().await;

    // alice pays from cashu, charlie receives on Arkade, bob bridges.
    assert_prefunded(&pg, "arkade_testnet", 2 * FUND_MSAT).await;
    fund_and_router(&pg, "bob", &["cashu_1", "arkade_testnet"])
        .await
        .unwrap();
    command_fund(&pg, "alice", "cashu_1", FUND_MSAT)
        .await
        .unwrap();
    command_fund(&pg, "charlie", "arkade_testnet", FUND_MSAT)
        .await
        .unwrap();

    let_routes_settle().await;

    assert_funded(&pg, "alice", "cashu_1", PAY_MSAT).await;
    assert_funded(&pg, "bob", "arkade_testnet", PAY_MSAT).await;

    command_pay(&pg, "alice", "charlie", PAY_MSAT)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires live testnet infrastructure and local cdk-mintd"]
async fn cashu_to_rootstock_payment() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let root = PathBuf::from(E2E_ROOT).join("cashu_to_rootstock");
    let _ = std::fs::remove_dir_all(&root);
    pin_seed(&root, "alice", ALICE_SEED);
    pin_seed(&root, "bob", BOB_SEED);
    pin_seed(&root, "charlie", CHARLIE_SEED);
    let pg = Playground::new(DEFAULT_PREFUND_SEED.to_string(), root)
        .await
        .unwrap();
    wait_for_relay().await;

    // alice pays from cashu, charlie receives on Rootstock, bob bridges.
    assert_prefunded(&pg, "rootstock_testnet", 2 * FUND_MSAT).await;
    fund_and_router(&pg, "bob", &["cashu_1", "rootstock_testnet"])
        .await
        .unwrap();
    command_fund(&pg, "alice", "cashu_1", FUND_MSAT)
        .await
        .unwrap();
    command_fund(&pg, "charlie", "rootstock_testnet", FUND_MSAT)
        .await
        .unwrap();

    let_routes_settle().await;

    assert_funded(&pg, "alice", "cashu_1", PAY_MSAT).await;
    assert_funded(&pg, "bob", "rootstock_testnet", PAY_MSAT).await;

    command_pay(&pg, "alice", "charlie", PAY_MSAT)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires live testnet infrastructure and local cdk-mintd"]
async fn multi_hop_cashu_to_liquid_to_rootstock() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let root = PathBuf::from(E2E_ROOT).join("multi_hop");
    let _ = std::fs::remove_dir_all(&root);
    pin_seed(&root, "alice", ALICE_SEED);
    pin_seed(&root, "bob", BOB_SEED);
    pin_seed(&root, "derek", DEREK_SEED);
    pin_seed(&root, "charlie", CHARLIE_SEED);
    let pg = Playground::new(DEFAULT_PREFUND_SEED.to_string(), root)
        .await
        .unwrap();
    wait_for_relay().await;

    // bob: cashu_1 -> liquid_testnet ; derek: liquid_testnet -> rootstock_testnet
    // bob and derek each take FUND_MSAT from the Liquid prefund, derek
    // and charlie each from the Rootstock prefund.
    assert_prefunded(&pg, "liquid_testnet", 2 * FUND_MSAT).await;
    assert_prefunded(&pg, "rootstock_testnet", 2 * FUND_MSAT).await;
    fund_and_router(&pg, "bob", &["cashu_1", "liquid_testnet"])
        .await
        .unwrap();
    fund_and_router(&pg, "derek", &["liquid_testnet", "rootstock_testnet"])
        .await
        .unwrap();
    command_fund(&pg, "alice", "cashu_1", FUND_MSAT)
        .await
        .unwrap();
    command_fund(&pg, "charlie", "rootstock_testnet", FUND_MSAT)
        .await
        .unwrap();

    let_routes_settle().await;

    // Both hops need funds on their outgoing networks, the sender on
    // its own.
    assert_funded(&pg, "alice", "cashu_1", PAY_MSAT).await;
    assert_funded(&pg, "bob", "liquid_testnet", PAY_MSAT).await;
    assert_funded(&pg, "derek", "rootstock_testnet", PAY_MSAT).await;

    command_pay(&pg, "alice", "charlie", PAY_MSAT)
        .await
        .unwrap();
}

/// A payment is rejected when the sole router vetoes the PREPARE. The
/// veto hook runs before any reservation is recorded, so the payer
/// aborts cleanly and `command_pay` returns an error.
#[tokio::test]
#[ignore = "requires live testnet infrastructure and local cdk-mintd"]
async fn payment_fails_when_router_vetoes() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let root = PathBuf::from(E2E_ROOT).join("veto_single_hop");
    let _ = std::fs::remove_dir_all(&root);
    pin_seed(&root, "alice", ALICE_SEED);
    pin_seed(&root, "bob", BOB_SEED);
    pin_seed(&root, "charlie", CHARLIE_SEED);
    let pg = Playground::new(DEFAULT_PREFUND_SEED.to_string(), root)
        .await
        .unwrap();
    wait_for_relay().await;

    command_fund(&pg, "bob", "cashu_1", FUND_MSAT)
        .await
        .unwrap();
    command_fund(&pg, "bob", "cashu_2", FUND_MSAT)
        .await
        .unwrap();
    command_fund(&pg, "alice", "cashu_1", FUND_MSAT)
        .await
        .unwrap();
    command_fund(&pg, "charlie", "cashu_2", FUND_MSAT)
        .await
        .unwrap();

    // Bob rejects every PREPARE outright.
    let veto_all: cassis_router::PrepareVeto =
        Arc::new(|_prepare| Some("bob is in a bad mood".to_string()));
    command_router_with_veto(
        &pg,
        "bob",
        vec!["cashu_1".to_string(), "cashu_2".to_string()],
        Some(veto_all),
    )
    .await
    .unwrap();

    let_routes_settle().await;

    // Funds are present; the veto, not a shortfall, is what fails it.
    assert_funded(&pg, "alice", "cashu_1", PAY_MSAT).await;
    assert_funded(&pg, "bob", "cashu_2", PAY_MSAT).await;

    assert!(command_pay(&pg, "alice", "charlie", PAY_MSAT)
        .await
        .is_err());
}

/// A two-hop payment fails when the *second* hop vetoes: the first hop
/// accepts (and holds a reservation) but the payer aborts once the
/// second hop rejects, and the first hop's reservation is released.
#[tokio::test]
#[ignore = "requires live testnet infrastructure and local cdk-mintd"]
async fn payment_fails_when_second_hop_vetoes() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let root = PathBuf::from(E2E_ROOT).join("veto_second_hop");
    let _ = std::fs::remove_dir_all(&root);
    pin_seed(&root, "alice", ALICE_SEED);
    pin_seed(&root, "bob", BOB_SEED);
    pin_seed(&root, "derek", DEREK_SEED);
    pin_seed(&root, "charlie", CHARLIE_SEED);
    let pg = Playground::new(DEFAULT_PREFUND_SEED.to_string(), root)
        .await
        .unwrap();
    wait_for_relay().await;

    fund_and_router(&pg, "bob", &["cashu_1", "cashu_2"])
        .await
        .unwrap();
    command_fund(&pg, "derek", "cashu_2", FUND_MSAT)
        .await
        .unwrap();
    command_fund(&pg, "derek", "cashu_3", FUND_MSAT)
        .await
        .unwrap();
    command_fund(&pg, "alice", "cashu_1", FUND_MSAT)
        .await
        .unwrap();
    command_fund(&pg, "charlie", "cashu_3", FUND_MSAT)
        .await
        .unwrap();

    // Derek vetoes anything above a small threshold; the payment amount
    // is above it, so his hop rejects.
    let veto_large: cassis_router::PrepareVeto = Arc::new(|prepare| {
        (prepare.amount_msat > 100_000)
            .then(|| format!("derek refuses {} msat", prepare.amount_msat))
    });
    command_router_with_veto(
        &pg,
        "derek",
        vec!["cashu_2".to_string(), "cashu_3".to_string()],
        Some(veto_large),
    )
    .await
    .unwrap();

    let_routes_settle().await;

    // All three hops funded; derek's veto is what aborts the payment.
    assert_funded(&pg, "alice", "cashu_1", PAY_MSAT).await;
    assert_funded(&pg, "bob", "cashu_2", PAY_MSAT).await;
    assert_funded(&pg, "derek", "cashu_3", PAY_MSAT).await;

    assert!(command_pay(&pg, "alice", "charlie", PAY_MSAT)
        .await
        .is_err());
}

/// Smoke test that only checks the environment boots and nodes can be
/// funded and routed, without completing a payment. Useful as a cheap
/// first step when debugging infrastructure.
#[tokio::test]
#[ignore = "requires local cdk-mintd"]
async fn environment_boots_and_funds() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let root = PathBuf::from(E2E_ROOT).join("boots");
    let _ = std::fs::remove_dir_all(&root);
    pin_seed(&root, "alice", ALICE_SEED);
    pin_seed(&root, "bob", BOB_SEED);
    pin_seed(&root, "charlie", CHARLIE_SEED);
    let pg = Playground::new(DEFAULT_PREFUND_SEED.to_string(), root)
        .await
        .unwrap();
    wait_for_relay().await;

    command_fund(&pg, "alice", "cashu_1", FUND_MSAT)
        .await
        .unwrap();
    command_fund(&pg, "bob", "cashu_2", FUND_MSAT)
        .await
        .unwrap();
    command_router(
        &pg,
        "charlie",
        vec!["cashu_1".to_string(), "cashu_2".to_string()],
    )
    .await
    .unwrap();
}
