use cassis::operation;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = clap::Command::new("cassis")
        .version("1.0")
        .about("talks to cassis servers")
        .arg(
            clap::Arg::new("registry_address")
                .short('h')
                .long("host")
                .value_name("DOMAIN")
                .help("domain name of the cassis registry")
                .default_value("registry.cassis.cash"),
        )
        .arg(
            clap::Arg::new("secret_key")
                .long("sk")
                .value_name("HEX-PRIVATE-KEY")
                .help("private key to use in the operation"),
        )
        .subcommand(
            clap::Command::new("trust")
                .about("makes it so the receiver of the trust can send payments through you")
                .arg(
                    clap::Arg::new("trustee")
                        .short('t')
                        .long("trustee")
                        .value_name("HEX-PUBLIC-KEY")
                        .required(true),
                )
                .arg(
                    clap::Arg::new("amount")
                        .short('a')
                        .long("amount")
                        .value_name("SATOSHIS")
                        .required(true),
                ),
        )
        .get_matches();

    let host = matches.get_one("registry_address").unwrap();
    let sk = matches
        .get_one::<&str>("secret_key")
        .unwrap()
        .parse::<u32>()?;

    let client = reqwest::Client::new();

    if let Some(matches) = matches.subcommand_matches("trust") {
        let trustee = matches.get_one("trustee").unwrap();
        let amount = matches.get_one("amount").unwrap();

        let data = operation::Trust {};

        let response = client
            .post(format!("https://{}/append", host))
            .body(&data)
            .send()
            .await?;

        println!("{}", response.text().await?);
    }

    Ok(())
}
