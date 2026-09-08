//! Wait for the chain-network prefund wallets to be funded, then exit.
//!
//! Prints the prefund deposit addresses for Liquid testnet, Arkade
//! mutinynet and Rootstock testnet, then polls their balances until
//! each meets a minimum, prompting the operator to deposit test coins
//! meanwhile. Exits 0 once funded, so a test runner can gate the e2e
//! suite on it:
//!
//! ```text
//! cargo run -p cassis-playground --bin cassis-prefund -- --min-sats 20000
//! cargo test -p cassis-playground --test e2e -- --ignored --test-threads=1
//! ```

use std::path::PathBuf;
use std::time::Duration;

use cassis_playground::{PrefundWallets, DEFAULT_PREFUND_SEED};

#[derive(Default)]
struct Args {
    seed: String,
    root: PathBuf,
    /// Minimum prefund balance per chain network, in sats.
    min_sats: u64,
    /// Poll interval between balance checks.
    interval_secs: u64,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        seed: DEFAULT_PREFUND_SEED.to_string(),
        root: PathBuf::from("target/e2e/prefund"),
        min_sats: 0,
        interval_secs: 5,
    };
    let mut iter = std::env::args().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--seed" => args.seed = iter.next().ok_or("--seed needs a value")?,
            "--root" => args.root = PathBuf::from(iter.next().ok_or("--root needs a value")?),
            "--min-sats" => {
                args.min_sats = iter
                    .next()
                    .ok_or("--min-sats needs a value")?
                    .parse()
                    .map_err(|e| format!("--min-sats: {e}"))?
            }
            "--interval-secs" => {
                args.interval_secs = iter
                    .next()
                    .ok_or("--interval-secs needs a value")?
                    .parse()
                    .map_err(|e| format!("--interval-secs: {e}"))?
            }
            other => return Err(format!("unknown argument '{other}'")),
        }
    }
    Ok(args)
}

const NETWORKS: &[&str] = &["liquid_testnet", "arkade_testnet", "rootstock_testnet"];

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args()?;
    let wallets = PrefundWallets::build(&args.root, &args.seed).await?;

    println!("prefund seed: {}", args.seed);
    println!("send test coins to the following addresses:\n");
    for (network, address) in wallets.addresses().await? {
        println!("  {network}: {address}");
    }
    println!();

    loop {
        // Arkade deposits need an onboard to settle into spendable
        // VTXOs before the balance reflects them.
        if let Err(e) = wallets.onboard_arkade().await {
            eprintln!("arkade onboard check failed: {e}");
        }

        let mut funded = true;
        let mut lines = Vec::new();
        for network in NETWORKS {
            match wallets.balance_msat(network).await {
                Ok(balance) => {
                    let sats = balance / 1000;
                    let ok = sats >= args.min_sats;
                    funded &= ok;
                    lines.push(format!(
                        "  {network}: {sats} sats{}",
                        if ok {
                            String::new()
                        } else {
                            format!(" (need {})", args.min_sats)
                        }
                    ));
                }
                Err(e) => {
                    funded = false;
                    lines.push(format!("  {network}: error ({e})"));
                }
            }
        }

        if funded {
            println!(
                "prefund wallets funded:\n{}\nready for e2e tests",
                lines.join("\n")
            );
            return Ok(());
        }
        println!(
            "waiting for deposits (min {} sats per network):\n{}\n",
            args.min_sats,
            lines.join("\n")
        );
        tokio::time::sleep(Duration::from_secs(args.interval_secs)).await;
    }
}
