//! Per-network funds management, outside of Cassis payments: balances,
//! deposits and plain sends. One subcommand per compiled-in network.
//! Opening a wallet runs its routine checks first (see
//! [`routine_checks`]).

#[allow(unused_imports)]
use cassis_core::NetworkId;
#[allow(unused_imports)]
use cassis_wallet::{routine_checks, Home};
use clap::Subcommand;
use tracing::Span;

#[derive(Subcommand)]
pub enum Command {
    /// Ecash wallet on one mint.
    #[cfg(feature = "cashu")]
    Cashu {
        /// `cashu::<mint host>`
        #[arg(long)]
        network: String,
        #[command(subcommand)]
        command: CashuCommand,
    },
    /// L-BTC wallet.
    #[cfg(feature = "liquid")]
    Liquid {
        #[arg(long, default_value = "liquid")]
        network: String,
        #[command(subcommand)]
        command: ChainCommand,
    },
    /// On-chain bitcoin wallet.
    #[cfg(feature = "bitcoin")]
    Bitcoin {
        #[arg(long, default_value = "bitcoin")]
        network: String,
        #[command(subcommand)]
        command: ChainCommand,
    },
    /// Arkade VTXO wallet.
    #[cfg(feature = "arkade")]
    Arkade {
        #[arg(long, default_value = "arkade")]
        network: String,
        #[command(subcommand)]
        command: ArkadeCommand,
    },
    /// RBTC account.
    #[cfg(feature = "rootstock")]
    Rootstock {
        #[arg(long, default_value = "rootstock")]
        network: String,
        #[command(subcommand)]
        command: ChainCommand,
    },
    /// Bark wallet of a `lightning` network enabled with `--bark`.
    #[cfg(feature = "bark-lightning")]
    Bark {
        #[arg(long, default_value = "lightning")]
        network: String,
        #[command(subcommand)]
        command: BarkCommand,
    },
    /// Ecash wallet in one federation.
    #[cfg(feature = "fedimint")]
    Fedimint {
        /// `fedimint::<invite code>`
        #[arg(long)]
        network: String,
        #[command(subcommand)]
        command: FedimintCommand,
    },
}

#[derive(Subcommand)]
pub enum ChainCommand {
    Balance,
    /// Address to deposit to.
    Address,
    Send {
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount_msat: u64,
    },
}

#[derive(Subcommand)]
pub enum CashuCommand {
    Balance,
    /// Take ecash out of the wallet as a token.
    Send {
        #[arg(long)]
        amount_sat: u64,
    },
    /// Redeem a token into the wallet.
    Receive {
        #[arg(long)]
        token: String,
    },
}

#[derive(Subcommand)]
pub enum ArkadeCommand {
    Balance,
    /// Boarding, on-chain and arkade addresses.
    Address,
    /// Settle confirmed boarding deposits into spendable VTXOs.
    Onboard,
    Send {
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount_msat: u64,
    },
    /// Redeem an arknote issued by the operator into VTXOs.
    RedeemNote {
        note: String,
    },
}

#[derive(Subcommand)]
pub enum BarkCommand {
    Balance,
    /// Ark address to receive VTXOs at.
    Address,
    /// Lightning invoice to fund the wallet with; waits until it is paid
    /// and claimed.
    Invoice {
        #[arg(long)]
        amount_sat: u64,
    },
}

#[derive(Subcommand)]
pub enum FedimintCommand {
    Balance,
    /// Spend ecash notes out of the wallet.
    Send {
        #[arg(long)]
        amount_msat: u64,
    },
    /// Reissue ecash notes into the wallet.
    Receive {
        #[arg(long)]
        notes: String,
    },
    /// Peg-in address.
    Deposit {
        #[arg(long)]
        wait: bool,
        #[arg(long, default_value_t = 3600)]
        timeout_secs: u64,
    },
    /// Peg out on-chain.
    Withdraw {
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount_sat: u64,
    },
}

// Builds with only `lightning` have no wallet subcommand: LND manages
// its own funds.
#[allow(unused_variables, unreachable_code)]
pub async fn run(home: &Home, command: Command, span: &Span) -> Result<(), String> {
    match command {
        #[cfg(feature = "cashu")]
        Command::Cashu { network, command } => {
            let wallet = home.open_cashu(&kind(&network, "cashu")?, span)?;
            routine_checks(&wallet).await;
            match command {
                CashuCommand::Balance => println!("{} msat", wallet.balance_msat()?),
                CashuCommand::Send { amount_sat } => {
                    println!("{}", wallet.send_token(amount_sat).await?)
                }
                CashuCommand::Receive { token } => {
                    println!("received {} sat", wallet.receive_token(&token).await?)
                }
            }
        }
        #[cfg(feature = "liquid")]
        Command::Liquid { network, command } => {
            let network = kind(&network, "liquid")?;
            let wallet = cassis_networks::liquid::LiquidAdapter::open(
                network.clone(),
                home.secret(&network)?,
                &home.network_dir(&network),
                span,
            )
            .await?;
            routine_checks(&wallet).await;
            let error = |e: cassis_core::NetworkError| e.to_string();
            match command {
                ChainCommand::Balance => {
                    println!("{} msat", wallet.balance_msat().await.map_err(error)?)
                }
                ChainCommand::Address => {
                    println!("{}", wallet.deposit_address().await.map_err(error)?)
                }
                ChainCommand::Send { to, amount_msat } => println!(
                    "{}",
                    wallet
                        .transfer_to_address(&to, amount_msat)
                        .await
                        .map_err(error)?
                ),
            }
        }
        #[cfg(feature = "bitcoin")]
        Command::Bitcoin { network, command } => {
            let network = kind(&network, "bitcoin")?;
            let wallet = cassis_networks::bitcoin::BitcoinAdapter::open(
                network.clone(),
                home.secret(&network)?,
                span,
            )?;
            routine_checks(&wallet).await;
            let error = |e: cassis_core::NetworkError| e.to_string();
            match command {
                ChainCommand::Balance => {
                    println!("{} msat", wallet.balance_msat().await.map_err(error)?)
                }
                ChainCommand::Address => println!("{}", wallet.deposit_address()),
                ChainCommand::Send { to, amount_msat } => println!(
                    "{}",
                    wallet
                        .transfer_to_address(&to, amount_msat)
                        .await
                        .map_err(error)?
                ),
            }
        }
        #[cfg(feature = "arkade")]
        Command::Arkade { network, command } => {
            let network = kind(&network, "arkade")?;
            let wallet = home.open_arkade(&network, span).await?;
            let error = |e: cassis_core::NetworkError| e.to_string();
            match command {
                ArkadeCommand::Balance => {
                    println!("{} msat", wallet.balance_msat().await.map_err(error)?)
                }
                ArkadeCommand::Address => {
                    let (boarding, onchain, arkade) =
                        wallet.deposit_addresses().await.map_err(error)?;
                    println!("boarding: {boarding}\nonchain:  {onchain}\narkade:   {arkade}");
                }
                ArkadeCommand::Onboard => match wallet.onboard().await.map_err(error)? {
                    Some(txid) => println!("onboarded in {txid}"),
                    None => println!("nothing to onboard"),
                },
                ArkadeCommand::Send { to, amount_msat } => println!(
                    "{}",
                    wallet
                        .transfer_to_ark_address(&to, amount_msat)
                        .await
                        .map_err(error)?
                ),
                ArkadeCommand::RedeemNote { note } => {
                    println!("{}", wallet.redeem_note(&note).await.map_err(error)?)
                }
            }
        }
        #[cfg(feature = "bark-lightning")]
        Command::Bark { network, command } => {
            let network = kind(&network, "lightning")?;
            let wallet = home.open_bark(&network, span).await?;
            let error = |e: cassis_core::NetworkError| e.to_string();
            match command {
                BarkCommand::Balance => {
                    println!("{} sat", wallet.spendable_sats().await.map_err(error)?)
                }
                BarkCommand::Address => println!(
                    "{}",
                    wallet
                        .wallet()
                        .new_address()
                        .await
                        .map_err(|e| format!("{e:#}"))?
                ),
                BarkCommand::Invoice { amount_sat } => {
                    let invoice = wallet.funding_invoice(amount_sat).await.map_err(error)?;
                    println!("{invoice}");
                    wallet.claim_funding(&invoice).await.map_err(error)?;
                    println!("claimed {amount_sat} sat");
                }
            }
        }
        #[cfg(feature = "rootstock")]
        Command::Rootstock { network, command } => {
            let network = kind(&network, "rootstock")?;
            let wallet = cassis_networks::rootstock::RootstockAdapter::open(
                network.clone(),
                home.secret(&network)?,
                span,
            )?;
            routine_checks(&wallet).await;
            match command {
                ChainCommand::Balance => println!("{} msat", wallet.balance_msat().await?),
                ChainCommand::Address => println!("{}", wallet.address()),
                ChainCommand::Send { to, amount_msat } => {
                    println!("{}", wallet.transfer(&to, amount_msat).await?)
                }
            }
        }
        #[cfg(feature = "fedimint")]
        Command::Fedimint { network, command } => {
            let network = kind(&network, "fedimint")?;
            let wallet = cassis_networks::fedimint::FedimintAdapter::open(
                network.clone(),
                home.secret(&network)?,
                &home.network_dir(&network),
                span,
            )
            .await?;
            routine_checks(&wallet).await;
            match command {
                FedimintCommand::Balance => println!("{} msat", wallet.balance_msat().await?),
                FedimintCommand::Send { amount_msat } => {
                    println!("{}", wallet.send_ecash(amount_msat).await?)
                }
                FedimintCommand::Receive { notes } => {
                    println!("received {} msat", wallet.receive_ecash(&notes).await?)
                }
                FedimintCommand::Deposit { wait, timeout_secs } => {
                    let (address, position) = wallet.deposit_address().await?;
                    println!("{address}");
                    if wait {
                        wallet.await_deposit(position, timeout_secs).await?;
                        println!("deposited");
                    }
                }
                FedimintCommand::Withdraw { to, amount_sat } => {
                    println!("{}", wallet.withdraw(&to, amount_sat).await?)
                }
            }
        }
    }
    Ok(())
}

/// Parse `spec`, which must be a network of `kind`.
#[allow(dead_code)]
fn kind(spec: &str, kind: &str) -> Result<NetworkId, String> {
    let network = NetworkId::parse(spec)?;
    if network.kind() != kind {
        return Err(format!("{spec} is not a {kind} network"));
    }
    Ok(network)
}
