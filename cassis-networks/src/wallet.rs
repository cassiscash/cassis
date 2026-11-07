//! The funds a node holds on each network, outside of Cassis payments:
//! what it has, where to send it more, and moving it in and out. Every
//! adapter opened by [`crate::open_wallet`] comes with its [`Wallet`],
//! which says what it can do ([`Wallet::can`]) so that a UI shows the
//! controls of its network.

#[allow(unused_imports)]
use cassis_core::MSAT_PER_SAT;
use std::future::Future;
use std::pin::Pin;
#[allow(unused_imports)]
use std::sync::Arc;

/// The longest a fedimint peg-in is waited for.
#[cfg(feature = "fedimint")]
const DEPOSIT_WAIT_SECS: u64 = 24 * 3600;

/// The wallet of one open network, sharing the adapter that routes on it.
#[derive(Clone)]
pub enum Wallet {
    #[cfg(feature = "arkade")]
    Arkade(Arc<cassis_arkade::ArkadeAdapter>),
    #[cfg(feature = "bark-lightning")]
    Bark(Arc<cassis_bark_lightning::BarkLightningAdapter>),
    #[cfg(feature = "bitcoin")]
    Bitcoin(Arc<cassis_bitcoin::BitcoinAdapter>),
    #[cfg(feature = "cashu")]
    Cashu(Arc<cassis_cashu::CashuAdapter>),
    #[cfg(feature = "fedimint")]
    Fedimint(Arc<cassis_fedimint::FedimintAdapter>),
    #[cfg(feature = "liquid")]
    Liquid(Arc<cassis_liquid::LiquidAdapter>),
    #[cfg(feature = "lightning")]
    Lnd(Arc<cassis_lnd::LndAdapter>),
    #[cfg(feature = "rootstock")]
    Rootstock(Arc<cassis_rootstock::RootstockAdapter>),
}

/// An amount the wallet holds.
#[derive(Clone, Debug, PartialEq)]
pub struct Balance {
    pub label: &'static str,
    pub msat: u64,
}

/// Where funds can be sent to the wallet.
#[derive(Clone, Debug, PartialEq)]
pub struct Address {
    pub label: &'static str,
    pub address: String,
}

/// What a wallet can do, each with what the UI asks for it. The amounts
/// of every [`Op`] are in sats.
#[derive(Clone, Debug, Default)]
pub struct Can {
    /// [`Op::Send`], to what (`"Bitcoin address"`).
    pub send: Option<&'static str>,
    /// [`Op::Issue`], of what (`"Cashu token"`).
    pub issue: Option<&'static str>,
    /// [`Op::Redeem`], of what.
    pub redeem: Option<&'static str>,
    /// [`Op::Onboard`].
    pub onboard: bool,
    /// [`Op::Invoice`] and [`Op::Pay`].
    pub lightning: bool,
    /// [`Op::Deposit`], of what (`"Peg-in address"`).
    pub deposit: Option<&'static str>,
    /// Whether [`Wallet::addresses`] gives new addresses every time.
    pub new_addresses: bool,
    /// What else to know about the wallet's funds.
    pub note: Option<&'static str>,
}

/// Something to do with the funds.
#[derive(Clone, Debug)]
pub enum Op {
    /// Send to an address.
    Send { to: String, amount_sat: u64 },
    /// Take funds out of the wallet as a bearer token.
    Issue { amount_sat: u64 },
    /// Take a token into the wallet.
    Redeem { token: String },
    /// Turn confirmed deposits into spendable funds.
    Onboard,
    /// A Lightning invoice paying the wallet.
    Invoice { amount_sat: u64 },
    /// Pay a Lightning invoice.
    Pay { invoice: String },
    /// A one-time address paying the wallet.
    Deposit,
}

/// A future that finishes an [`Op`].
pub type Then = Pin<Box<dyn Future<Output = Result<String, String>> + Send>>;

/// What an [`Op`] did.
pub struct Done {
    /// What happened.
    pub message: String,
    /// Something to hand out, which only this has: a token, an invoice,
    /// an address.
    pub output: Option<Address>,
    /// What is left to wait for, like an invoice to be paid, saying what
    /// happened once it is done.
    pub then: Option<Then>,
}

// Unused in builds with no network.
#[allow(dead_code)]
impl Done {
    fn said(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            output: None,
            then: None,
        }
    }

    fn with(mut self, label: &'static str, output: impl Into<String>) -> Self {
        self.output = Some(Address {
            label,
            address: output.into(),
        });
        self
    }

    fn then(mut self, then: impl Future<Output = Result<String, String>> + Send + 'static) -> Self {
        self.then = Some(Box::pin(then));
        self
    }
}

#[allow(dead_code)]
fn sats(msat_or_sat: impl std::fmt::Display) -> String {
    format!("{msat_or_sat} sat")
}

#[allow(dead_code)]
fn spendable(msat: u64) -> Vec<Balance> {
    vec![Balance {
        label: "Spendable",
        msat,
    }]
}

#[allow(dead_code)]
fn address(label: &'static str, address: impl Into<String>) -> Address {
    Address {
        label,
        address: address.into(),
    }
}

#[allow(unused_variables, unreachable_code, unreachable_patterns)]
impl Wallet {
    /// What the wallet can do.
    pub fn can(&self) -> Can {
        match *self {
            #[cfg(feature = "arkade")]
            Wallet::Arkade(_) => Can {
                send: Some("Arkade address"),
                redeem: Some("Arknote"),
                onboard: true,
                note: Some(
                    "Coins sent to the boarding address are spendable once confirmed and \
                     onboarded.",
                ),
                ..Can::default()
            },
            #[cfg(feature = "bark-lightning")]
            Wallet::Bark(_) => Can {
                send: Some("Ark or bitcoin address"),
                lightning: true,
                new_addresses: true,
                ..Can::default()
            },
            #[cfg(feature = "bitcoin")]
            Wallet::Bitcoin(_) => Can {
                send: Some("Bitcoin address"),
                ..Can::default()
            },
            #[cfg(feature = "cashu")]
            Wallet::Cashu(_) => Can {
                issue: Some("Cashu token"),
                redeem: Some("Cashu token"),
                note: Some("A token is money: whoever has it can redeem it."),
                ..Can::default()
            },
            #[cfg(feature = "fedimint")]
            Wallet::Fedimint(_) => Can {
                send: Some("Bitcoin address (peg-out)"),
                issue: Some("Ecash notes"),
                redeem: Some("Ecash notes"),
                deposit: Some("Peg-in address"),
                note: Some("Ecash notes are money: whoever has them can redeem them."),
                ..Can::default()
            },
            #[cfg(feature = "liquid")]
            Wallet::Liquid(_) => Can {
                send: Some("Liquid address"),
                new_addresses: true,
                ..Can::default()
            },
            #[cfg(feature = "lightning")]
            Wallet::Lnd(_) => Can {
                send: Some("Bitcoin address (from the on-chain wallet)"),
                lightning: true,
                new_addresses: true,
                note: Some(
                    "The funds of the LND node, which opens and closes its channels itself.",
                ),
                ..Can::default()
            },
            #[cfg(feature = "rootstock")]
            Wallet::Rootstock(_) => Can {
                send: Some("Rootstock address"),
                ..Can::default()
            },
        }
    }

    /// What the wallet holds, the first entry being what it can spend.
    pub async fn balances(&self) -> Result<Vec<Balance>, String> {
        Ok(match *self {
            #[cfg(feature = "arkade")]
            Wallet::Arkade(ref w) => spendable(w.balance_msat().await.map_err(|e| e.to_string())?),
            #[cfg(feature = "bark-lightning")]
            Wallet::Bark(ref w) => {
                let (spendable, other) = w.balance_sats().await.map_err(|e| e.to_string())?;
                vec![
                    Balance {
                        label: "Spendable",
                        msat: spendable * MSAT_PER_SAT,
                    },
                    Balance {
                        label: "Refreshing or in flight",
                        msat: other * MSAT_PER_SAT,
                    },
                ]
            }
            #[cfg(feature = "bitcoin")]
            Wallet::Bitcoin(ref w) => spendable(w.balance_msat().await.map_err(|e| e.to_string())?),
            #[cfg(feature = "cashu")]
            Wallet::Cashu(ref w) => spendable(w.balance_msat()?),
            #[cfg(feature = "fedimint")]
            Wallet::Fedimint(ref w) => spendable(w.balance_msat().await?),
            #[cfg(feature = "liquid")]
            Wallet::Liquid(ref w) => spendable(w.balance_msat().await.map_err(|e| e.to_string())?),
            #[cfg(feature = "lightning")]
            Wallet::Lnd(ref w) => vec![
                Balance {
                    label: "In channels",
                    msat: w.channel_balance_msat().await.map_err(|e| e.to_string())?,
                },
                Balance {
                    label: "On chain",
                    msat: w.onchain_balance_msat().await.map_err(|e| e.to_string())?,
                },
            ],
            #[cfg(feature = "rootstock")]
            Wallet::Rootstock(ref w) => spendable(w.balance_msat().await?),
        })
    }

    /// Where to send funds to the wallet; new ones every time if
    /// [`Can::new_addresses`].
    pub async fn addresses(&self) -> Result<Vec<Address>, String> {
        Ok(match *self {
            #[cfg(feature = "arkade")]
            Wallet::Arkade(ref w) => {
                let (boarding, onchain, arkade) =
                    w.deposit_addresses().await.map_err(|e| e.to_string())?;
                vec![
                    address("Boarding (on-chain, then onboard)", boarding),
                    address("Arkade", arkade),
                    address("On-chain", onchain),
                ]
            }
            #[cfg(feature = "bark-lightning")]
            Wallet::Bark(ref w) => {
                vec![address(
                    "Ark",
                    w.new_address().await.map_err(|e| e.to_string())?,
                )]
            }
            #[cfg(feature = "bitcoin")]
            Wallet::Bitcoin(ref w) => vec![address("Bitcoin", w.deposit_address())],
            #[cfg(feature = "cashu")]
            Wallet::Cashu(_) => Vec::new(),
            #[cfg(feature = "fedimint")]
            Wallet::Fedimint(_) => Vec::new(),
            #[cfg(feature = "liquid")]
            Wallet::Liquid(ref w) => vec![address(
                "Liquid",
                w.deposit_address().await.map_err(|e| e.to_string())?,
            )],
            #[cfg(feature = "lightning")]
            Wallet::Lnd(ref w) => vec![address(
                "On-chain",
                w.new_address().await.map_err(|e| e.to_string())?,
            )],
            #[cfg(feature = "rootstock")]
            Wallet::Rootstock(ref w) => vec![address("Rootstock", w.address().to_string())],
        })
    }

    /// Do `op`, if the wallet [`Can`].
    pub async fn run(&self, op: Op) -> Result<Done, String> {
        let unsupported = || Err("this network's wallet cannot do that".to_string());
        let msat = |amount_sat: u64| amount_sat.saturating_mul(MSAT_PER_SAT);
        match (self, op) {
            #[cfg(feature = "arkade")]
            (Wallet::Arkade(w), op) => {
                let error = |e: cassis_core::NetworkError| e.to_string();
                match op {
                    Op::Send { to, amount_sat } => {
                        let txid = w
                            .transfer_to_ark_address(&to, msat(amount_sat))
                            .await
                            .map_err(error)?;
                        Ok(Done::said(format!("Sent {} in {txid}", sats(amount_sat))))
                    }
                    Op::Redeem { token } => {
                        let txid = w.redeem_note(&token).await.map_err(error)?;
                        Ok(Done::said(format!("Redeemed the arknote in {txid}")))
                    }
                    Op::Onboard => Ok(Done::said(match w.onboard().await.map_err(error)? {
                        Some(txid) => format!("Onboarded in {txid}"),
                        None => "Nothing to onboard".to_string(),
                    })),
                    _ => unsupported(),
                }
            }
            #[cfg(feature = "bark-lightning")]
            (Wallet::Bark(w), op) => {
                let error = |e: cassis_core::NetworkError| e.to_string();
                match op {
                    Op::Send { to, amount_sat } => Ok(Done::said(
                        match w.send(&to, amount_sat).await.map_err(error)? {
                            Some(txid) => format!("Sent {} on-chain in {txid}", sats(amount_sat)),
                            None => format!("Sent {}", sats(amount_sat)),
                        },
                    )),
                    Op::Invoice { amount_sat } => {
                        let invoice = w.funding_invoice(amount_sat).await.map_err(error)?;
                        let w = w.clone();
                        let claimed = invoice.clone();
                        Ok(Done::said("Invoice created: waiting for it to be paid")
                            .with("Lightning invoice", invoice)
                            .then(async move {
                                w.claim_funding(&claimed).await.map_err(error)?;
                                Ok(format!("Received {}", sats(amount_sat)))
                            }))
                    }
                    Op::Pay { invoice } => {
                        w.pay_invoice(&invoice).await.map_err(error)?;
                        Ok(Done::said("Paid the invoice"))
                    }
                    _ => unsupported(),
                }
            }
            #[cfg(feature = "bitcoin")]
            (Wallet::Bitcoin(w), Op::Send { to, amount_sat }) => {
                let txid = w
                    .transfer_to_address(&to, msat(amount_sat))
                    .await
                    .map_err(|e| e.to_string())?;
                Ok(Done::said(format!("Sent {} in {txid}", sats(amount_sat))))
            }
            #[cfg(feature = "cashu")]
            (Wallet::Cashu(w), op) => match op {
                Op::Issue { amount_sat } => Ok(Done::said(format!(
                    "Took {} out as a token",
                    sats(amount_sat)
                ))
                .with("Cashu token", w.send_token(amount_sat).await?)),
                Op::Redeem { token } => Ok(Done::said(format!(
                    "Received {}",
                    sats(w.receive_token(&token).await?)
                ))),
                _ => unsupported(),
            },
            #[cfg(feature = "fedimint")]
            (Wallet::Fedimint(w), op) => match op {
                Op::Send { to, amount_sat } => {
                    let txid = w.withdraw(&to, amount_sat).await?;
                    Ok(Done::said(format!(
                        "Pegged out {} in {txid}",
                        sats(amount_sat)
                    )))
                }
                Op::Issue { amount_sat } => Ok(Done::said(format!(
                    "Took {} out as ecash notes",
                    sats(amount_sat)
                ))
                .with("Ecash notes", w.send_ecash(msat(amount_sat)).await?)),
                Op::Redeem { token } => {
                    let received = w.receive_ecash(&token).await?;
                    Ok(Done::said(format!("Received {received} msat")))
                }
                Op::Deposit => {
                    let (address, position) = w.deposit_address().await?;
                    let w = w.clone();
                    Ok(
                        Done::said("Peg-in address created: waiting for a deposit to it")
                            .with("Peg-in address", address)
                            .then(async move {
                                w.await_deposit(position, DEPOSIT_WAIT_SECS).await?;
                                Ok("Deposit received".to_string())
                            }),
                    )
                }
                _ => unsupported(),
            },
            #[cfg(feature = "liquid")]
            (Wallet::Liquid(w), Op::Send { to, amount_sat }) => {
                let txid = w
                    .transfer_to_address(&to, msat(amount_sat))
                    .await
                    .map_err(|e| e.to_string())?;
                Ok(Done::said(format!("Sent {} in {txid}", sats(amount_sat))))
            }
            #[cfg(feature = "lightning")]
            (Wallet::Lnd(w), op) => {
                let error = |e: cassis_core::NetworkError| e.to_string();
                match op {
                    Op::Send { to, amount_sat } => {
                        let txid = w.send_onchain(&to, amount_sat).await.map_err(error)?;
                        Ok(Done::said(format!("Sent {} in {txid}", sats(amount_sat))))
                    }
                    Op::Invoice { amount_sat } => Ok(Done::said("Invoice created").with(
                        "Lightning invoice",
                        w.add_invoice(msat(amount_sat)).await.map_err(error)?,
                    )),
                    Op::Pay { invoice } => {
                        w.pay_invoice(&invoice).await.map_err(error)?;
                        Ok(Done::said("Paid the invoice"))
                    }
                    _ => unsupported(),
                }
            }
            #[cfg(feature = "rootstock")]
            (Wallet::Rootstock(w), Op::Send { to, amount_sat }) => {
                let txid = w.transfer(&to, msat(amount_sat)).await?;
                Ok(Done::said(format!("Sent {} in {txid}", sats(amount_sat))))
            }
            _ => unsupported(),
        }
    }
}
