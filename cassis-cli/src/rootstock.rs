use crate::{derive_for, read_or_init_mnemonic};
use cassis_client::adapters::build_rootstock_adapter;
use cassis_client::netspec::NetSpec;
use clap::Subcommand;
use tracing::info_span;

#[derive(Subcommand, Debug)]
pub enum RootstockCommands {
    Send {
        #[arg(long)]
        to: String,
        #[arg(long, default_value_t = 0)]
        amount_msat: u64,
        #[arg(long)]
        data: Option<String>,
        #[arg(long)]
        args: Option<String>,
    },
    Info,
    Read {
        #[arg(long)]
        to: String,
        #[arg(long)]
        data: String,
        #[arg(long)]
        args: String,
    },
}

pub(crate) async fn run(network: String, command: RootstockCommands) -> Result<(), String> {
    match command {
        RootstockCommands::Send {
            to,
            amount_msat,
            data: _,
            args: _,
        } => send(network, to, amount_msat).await,
        RootstockCommands::Info => info(network).await,
        RootstockCommands::Read { to, data, args } => read(network, to, data, args).await,
    }
}

async fn send(network: String, to: String, amount_msat: u64) -> Result<(), String> {
    let testnet = network == "rootstock::testnet";
    let spec = NetSpec::Rootstock { testnet };
    let mnemonic = read_or_init_mnemonic()?;
    let derived = derive_for(&mnemonic, std::slice::from_ref(&spec))?;
    let adapter =
        build_rootstock_adapter(&spec, &derived, info_span!("node", node = "cassis-cli")).await?;
    let tx_hash = adapter
        .transfer(&to, amount_msat)
        .await
        .map_err(|e| format!("rootstock send: {e}"))?;
    println!("status:      ok");
    println!("network:     {network}");
    println!("tx_hash:     {tx_hash}");
    Ok(())
}

async fn info(_network: String) -> Result<(), String> {
    Err("'cassis-cli rootstock info' is implemented in `cassis-gui`.".to_string())
}

async fn read(_network: String, _to: String, _data: String, _args: String) -> Result<(), String> {
    Err("'cassis-cli rootstock read' is implemented in `cassis-gui`.".to_string())
}
