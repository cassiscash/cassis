use clap::Subcommand;

#[cfg(feature = "fedimint")]
use crate::{derive_for, read_or_init_mnemonic};
#[cfg(feature = "fedimint")]
use cassis_client::adapters::build_fedimint_adapter;
#[cfg(feature = "fedimint")]
use cassis_client::netspec::NetSpec;
#[cfg(feature = "fedimint")]
use cassis_core::NetworkRouterAdapter;

#[derive(Subcommand, Debug)]
pub enum FedimintCommands {
    /// Print federation info, connection state and the user's balance.
    Info,
    /// Spend raw ecash notes (base64) from the wallet.
    Send {
        #[arg(long)]
        amount_msat: u64,
        /// Seconds after which the notes auto-cancel back to our
        /// wallet if the recipient hasn't reissued them.
        #[arg(long, default_value_t = 86400)]
        try_cancel_after_secs: u64,
    },
    /// Reissue a raw ecash note (base64) into our wallet.
    Receive {
        #[arg(long)]
        note: String,
        #[arg(long)]
        wait: bool,
    },
    /// Get an on-chain deposit (peg-in) address.
    Deposit {
        #[arg(long)]
        wait: bool,
        #[arg(long, default_value_t = 3600)]
        timeout_secs: u64,
    },
    /// Withdraw on-chain (peg-out).
    Withdraw {
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount_sat: u64,
    },
}

#[cfg(feature = "fedimint")]
pub(crate) async fn run(network: String, command: FedimintCommands) -> Result<(), String> {
    match command {
        FedimintCommands::Info => info(&network).await,
        FedimintCommands::Send {
            amount_msat,
            try_cancel_after_secs,
        } => send(network, amount_msat, try_cancel_after_secs).await,
        FedimintCommands::Receive { note, wait } => receive(network, note, wait).await,
        FedimintCommands::Deposit { wait, timeout_secs } => {
            deposit(network, wait, timeout_secs).await
        }
        FedimintCommands::Withdraw { to, amount_sat } => withdraw(network, to, amount_sat).await,
    }
}

#[cfg(not(feature = "fedimint"))]
pub(crate) async fn run(_network: String, _command: FedimintCommands) -> Result<(), String> {
    Err("'cassis-cli fedimint' requires building with the 'fedimint' feature".to_string())
}

#[cfg(feature = "fedimint")]
async fn adapter(
    network: &str,
) -> Result<(NetSpec, std::sync::Arc<cassis_fedimint::FedimintAdapter>), String> {
    let spec = NetSpec::parse(network)?;
    if !matches!(spec, NetSpec::Fedimint { .. }) {
        return Err(format!(
            "expected a fedimint spec ('fedimint::<invite-code>'), got '{network}'"
        ));
    }
    let mnemonic = read_or_init_mnemonic()?;
    let derived = derive_for(&mnemonic, std::slice::from_ref(&spec))?;
    let adapter = build_fedimint_adapter(&spec, &derived).await?;
    Ok((spec, adapter))
}

/// Print federation info, connection state and the user's balance.
/// Building the adapter joins (or opens) the federation client, so
/// success here means the wallet is usable.
#[cfg(feature = "fedimint")]
async fn info(network: &str) -> Result<(), String> {
    let (spec, adapter) = adapter(network).await?;
    println!("status:       ok");
    println!("network:      {}", spec.network_id());
    println!("claim_pubkey: {}", adapter.invoice_pubkey().to_hex());
    println!("db_dir:       {}", adapter.db_dir().display());
    println!("balance_msat: {}", adapter.balance_msat().await?);
    Ok(())
}

#[cfg(feature = "fedimint")]
async fn send(network: String, amount_msat: u64, try_cancel_after_secs: u64) -> Result<(), String> {
    let (_spec, adapter) = adapter(&network).await?;
    let note = adapter
        .send_ecash(amount_msat, try_cancel_after_secs)
        .await?;
    println!("status:       ok");
    println!("note: {note}");
    Ok(())
}

#[cfg(feature = "fedimint")]
async fn receive(network: String, note: String, wait: bool) -> Result<(), String> {
    let (_spec, adapter) = adapter(&network).await?;
    let amount_msat = adapter.receive_ecash(&note, wait).await?;
    println!("status:       ok");
    if wait {
        println!("message:      reissued");
    }
    println!("amount_msat:  {amount_msat}");
    Ok(())
}

#[cfg(feature = "fedimint")]
async fn deposit(network: String, wait: bool, timeout_secs: u64) -> Result<(), String> {
    let (_spec, adapter) = adapter(&network).await?;
    let (address, operation_id) = adapter.deposit_address().await?;
    println!("status:        ok");
    println!("deposit_addr:  {address}");
    println!("operation_id:  {}", lowercase_hex::encode(operation_id.0));
    if !wait {
        println!("message:       run again with --wait to follow (need in-process handle)");
        return Ok(());
    }
    let claimed_sat = adapter.await_deposit(operation_id, timeout_secs).await?;
    println!("status:        claimed");
    println!("amount_sat:    {claimed_sat}");
    Ok(())
}

#[cfg(feature = "fedimint")]
async fn withdraw(network: String, to: String, amount_sat: u64) -> Result<(), String> {
    let (_spec, adapter) = adapter(&network).await?;
    let txid = adapter.withdraw(&to, amount_sat).await?;
    println!("status:       ok");
    println!("to:           {to}");
    println!("amount_sat:   {amount_sat}");
    println!("txid:         {txid}");
    Ok(())
}
