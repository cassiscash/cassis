use crate::{load_registered_networks, open_store};
use cassis_client::netspec::NetSpec;
use clap::Subcommand;

#[derive(Subcommand, Debug)]
pub enum CashuCommands {
    Send {
        #[arg(long)]
        network: String,
        #[arg(long)]
        amount: u64,
    },
    Receive {
        #[arg(long = "proof")]
        proof: String,
    },
    Balance {
        #[arg(long)]
        network: Option<String>,
    },
}

pub(crate) fn run(command: CashuCommands) -> Result<(), String> {
    match command {
        CashuCommands::Send { network, amount } => send_stub(network, amount),
        CashuCommands::Receive { proof } => receive_stub(proof),
        CashuCommands::Balance { network } => balance(network),
    }
}

fn send_stub(_network: String, _amount: u64) -> Result<(), String> {
    Err("'cassis-cli cashu send' is implemented in `cassis-gui`.".to_string())
}

fn receive_stub(_proof: String) -> Result<(), String> {
    Err("'cassis-cli cashu receive' is implemented in `cassis-gui`.".to_string())
}

fn balance(network: Option<String>) -> Result<(), String> {
    let mut store = open_store()?;
    match network {
        Some(spec_str) => {
            let net_id = NetSpec::parse(&spec_str)?.network_id();
            let mint_url = cassis_core::cashu_mint_url(&net_id).map_err(|e| e.to_string())?;
            let total = store.cashu_balance(&mint_url).map_err(|e| e.to_string())?;
            let rows = store
                .list_cashu_proofs(&mint_url)
                .map_err(|e| e.to_string())?;
            println!("mint:        {mint_url}");
            println!("balance_sat: {total}");
            println!("proofs:      {}", rows.len());
        }
        None => {
            let registered = load_registered_networks(&mut store)?;
            let mut any = false;
            for raw in &registered {
                let spec = match NetSpec::parse(raw) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                if let NetSpec::Cashu { mint_url, .. } = &spec {
                    let total = store.cashu_balance(mint_url).map_err(|e| e.to_string())?;
                    let rows = store
                        .list_cashu_proofs(mint_url)
                        .map_err(|e| e.to_string())?;
                    println!("{mint_url}  {total} sat ({} proof(s))", rows.len());
                    any = true;
                }
            }
            if !any {
                println!("(no registered cashu mints)");
            }
        }
    }
    Ok(())
}
