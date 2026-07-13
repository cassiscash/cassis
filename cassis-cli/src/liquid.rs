use clap::Subcommand;

#[cfg(feature = "liquid")]
use crate::{derive_for, node_home, node_store_path, read_or_init_mnemonic};
#[cfg(feature = "liquid")]
use cassis_client::adapters::build_liquid_adapter;
#[cfg(feature = "liquid")]
use cassis_client::netspec::NetSpec;
#[cfg(feature = "liquid")]
use tracing::info_span;

#[derive(Subcommand, Debug)]
pub enum LiquidCommands {
    Balance,
    Deposit,
    Send {
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount_msat: u64,
    },
}

#[cfg(feature = "liquid")]
pub(crate) async fn run(network: String, command: LiquidCommands) -> Result<(), String> {
    match command {
        LiquidCommands::Balance => balance(network).await,
        LiquidCommands::Deposit => deposit(network).await,
        LiquidCommands::Send { to, amount_msat } => send(network, to, amount_msat).await,
    }
}

#[cfg(feature = "liquid")]
async fn adapter(
    network: &str,
) -> Result<(NetSpec, std::sync::Arc<cassis_liquid::LiquidAdapter>), String> {
    let testnet = network == "liquid::testnet";
    if !testnet && network != "liquid" {
        return Err(format!(
            "network 'liquid' only accepts no parameter or 'testnet', got '{network}'"
        ));
    }
    let spec = NetSpec::Liquid { testnet };
    let mnemonic = read_or_init_mnemonic()?;
    let derived = derive_for(&mnemonic, std::slice::from_ref(&spec))?;
    let adapter = build_liquid_adapter(
        &spec,
        &derived,
        &node_store_path(&node_home()),
        info_span!("node", node = "cassis-cli"),
    )
    .await
    .map_err(|e| format!("liquid adapter init failed: {e}"))?;
    Ok((spec, adapter))
}

#[cfg(feature = "liquid")]
async fn balance(network: String) -> Result<(), String> {
    let (spec, adapter) = adapter(&network).await?;
    let balance_msat = adapter.balance_msat().await.map_err(|e| e.to_string())?;
    println!("status:      ok");
    println!("network:     {}", spec.network_id());
    println!("balance_msat:{balance_msat:>13}");
    Ok(())
}

#[cfg(feature = "liquid")]
async fn deposit(network: String) -> Result<(), String> {
    let (spec, adapter) = adapter(&network).await?;
    let address = adapter.deposit_address().await.map_err(|e| e.to_string())?;
    println!("status:      ok");
    println!("network:     {}", spec.network_id());
    println!("address:     {address}");
    Ok(())
}

#[cfg(feature = "liquid")]
async fn send(network: String, to: String, amount_msat: u64) -> Result<(), String> {
    let (spec, adapter) = adapter(&network).await?;
    let txid = adapter
        .transfer_to_address(&to, amount_msat)
        .await
        .map_err(|e| format!("liquid send: {e}"))?;
    println!("status:      ok");
    println!("network:     {}", spec.network_id());
    println!("to:          {to}");
    println!("amount_msat: {amount_msat}");
    println!("txid:        {txid}");
    Ok(())
}
