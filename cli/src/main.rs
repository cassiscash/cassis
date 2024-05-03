use cassis::operation::{Operation, Trust};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = clap::Command::new("cassis")
        .version("1.0")
        .about("talks to cassis servers")
        .arg(
            clap::Arg::new("registry_address")
                .long("host")
                .value_name("DOMAIN")
                .help("domain name of the cassis registry")
                .default_value("registry.cassis.cash"),
        )
        .arg(
            clap::Arg::new("secret_key")
                .long("key")
                .value_name("HEX-PRIVATE-KEY")
                .help("private key to use in the operation")
                .required(true),
        )
        .subcommand(
            clap::Command::new("trust")
                .about("makes it so the receiver of the trust can send payments through you")
                .arg(
                    clap::Arg::new("trustee")
                        .value_name("HEX-PUBLIC-KEY")
                        .required(true)
                        .index(1),
                )
                .arg(
                    clap::Arg::new("amount")
                        .value_name("SATOSHIS")
                        .required(true)
                        .index(2),
                ),
        )
        .get_matches();

    let host = matches.get_one::<String>("registry_address").unwrap();
    let base = if host.starts_with("localhost") {
        format!("http://{}", host)
    } else {
        format!("https://{}", host)
    };
    let sk = cassis::SecretKey::from_hex(matches.get_one::<String>("secret_key").unwrap())
        .expect("invalid private key");

    let client = reqwest::Client::new();

    if let Some(matches) = matches.subcommand_matches("trust") {
        let to = cassis::PublicKey::from_hex(matches.get_one("trustee").unwrap())
            .expect("invalid trustee public key");
        let amount = matches
            .get_one::<String>("amount")
            .unwrap()
            .parse::<u32>()
            .expect("amount is not a valid integer");

        // get our key index from server
        let from = client
            .get(format!("{}/idx/{}", base, sk.public()))
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?
            .parse::<u32>()
            .expect("response from /key call is not a valid integer");

        // build trust operation
        let data = Operation::Trust(Trust::new(sk, from, to, amount));

        // send to server
        let _ = client
            .post(format!("{}/append", base))
            .body(serde_json::to_string(&data)?)
            .header("Content-Type", "application/json")
            .send()
            .await?
            .error_for_status()?;

        println!("success!");
    }

    Ok(())
}
