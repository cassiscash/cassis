use clap::Subcommand;

#[cfg(feature = "arkade")]
use crate::{derive_for, read_or_init_mnemonic};
#[cfg(feature = "arkade")]
use cassis_client::adapters::build_arkade_adapter;
#[cfg(feature = "arkade")]
use cassis_client::netspec::NetSpec;
#[cfg(feature = "arkade")]
use tracing::info_span;

#[derive(Subcommand, Debug)]
pub enum ArkadeCommands {
    Balance,
    Onboard,
    Deposit,
    Send {
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount_msat: u64,
    },
}

#[cfg(feature = "arkade")]
pub(crate) async fn run(network: String, command: ArkadeCommands) -> Result<(), String> {
    match command {
        ArkadeCommands::Balance => balance(network).await,
        ArkadeCommands::Onboard => onboard(network).await,
        ArkadeCommands::Deposit => deposit(network).await,
        ArkadeCommands::Send { to, amount_msat } => send(network, to, amount_msat).await,
    }
}

#[cfg(feature = "arkade")]
async fn adapter(
    network: &str,
) -> Result<(NetSpec, std::sync::Arc<cassis_arkade::ArkadeAdapter>), String> {
    let testnet = network == "arkade::testnet";
    if !testnet && network != "arkade" {
        return Err(format!(
            "network 'arkade' only accepts no parameter or 'testnet', got '{network}'"
        ));
    }
    let spec = NetSpec::Arkade { testnet };
    let mnemonic = read_or_init_mnemonic()?;
    let derived = derive_for(&mnemonic, std::slice::from_ref(&spec))?;
    let adapter = build_arkade_adapter(&spec, &derived, info_span!("node", node = "cassis-cli"))
        .await
        .map_err(|e| format!("arkade adapter init failed: {e}"))?;
    Ok((spec, adapter))
}

#[cfg(feature = "arkade")]
async fn balance(network: String) -> Result<(), String> {
    let (spec, adapter) = adapter(&network).await?;
    let balance_msat = adapter.balance_msat().await.map_err(|e| e.to_string())?;
    println!("status:      ok");
    println!("network:     {}", spec.network_id());
    println!("balance_msat:{balance_msat:>13}");
    Ok(())
}

#[cfg(feature = "arkade")]
async fn onboard(network: String) -> Result<(), String> {
    let (spec, adapter) = adapter(&network).await?;
    let commitment_txid = adapter.onboard().await.map_err(|e| e.to_string())?;
    println!("status:      ok");
    println!("network:     {}", spec.network_id());
    match commitment_txid {
        Some(txid) => println!("commitment_txid: {txid}"),
        None => println!("message:     no boarding outputs ready"),
    }
    Ok(())
}

#[cfg(feature = "arkade")]
async fn deposit(network: String) -> Result<(), String> {
    let (spec, adapter) = adapter(&network).await?;
    let (boarding, onchain, arkade) = adapter
        .deposit_addresses()
        .await
        .map_err(|e| e.to_string())?;
    println!("status:      ok");
    println!("network:     {}", spec.network_id());
    println!("boarding:    {boarding}");
    println!("onchain:     {onchain}");
    println!("arkade:      {arkade}");
    Ok(())
}

#[cfg(feature = "arkade")]
async fn send(network: String, to: String, amount_msat: u64) -> Result<(), String> {
    let (spec, adapter) = adapter(&network).await?;
    let txid = adapter
        .transfer_to_ark_address(&to, amount_msat)
        .await
        .map_err(|e| format!("arkade send: {e}"))?;
    println!("status:      ok");
    println!("network:     {}", spec.network_id());
    println!("to:          {to}");
    println!("amount_msat: {amount_msat}");
    println!("txid:        {txid}");
    Ok(())
}
