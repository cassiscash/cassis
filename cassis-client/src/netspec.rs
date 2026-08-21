use cassis_core::{cashu_mint_url, cashu_network_id, NetworkId};

/// A parsed `--network` spec, mirroring the router/CLI format:
/// `cashu::host`, `rootstock`, or `rootstock::testnet`.
#[derive(Clone, Debug)]
pub enum NetSpec {
    Cashu { mint_url: String, host: String },
    Rootstock { testnet: bool },
}

impl NetSpec {
    pub fn parse(spec: &str) -> Result<Self, String> {
        let (kind, param) = split_canonical_spec(spec);
        match kind {
            "cashu" => {
                let host = param.ok_or_else(|| {
                    "network 'cashu' requires a host, e.g. cashu::mint.example.com".to_string()
                })?;
                if host.is_empty() {
                    return Err(
                        "network 'cashu' requires a non-empty host, e.g. cashu::mint.example.com"
                            .to_string(),
                    );
                }
                let network_id = cashu_network_id(host);
                let mint_url = cashu_mint_url(&network_id).map_err(|e| e.to_string())?;
                Ok(NetSpec::Cashu {
                    mint_url,
                    host: host.to_string(),
                })
            }
            "rootstock" => match param {
                None => Ok(NetSpec::Rootstock { testnet: false }),
                Some("testnet") => Ok(NetSpec::Rootstock { testnet: true }),
                Some(other) => Err(format!(
                    "network 'rootstock' only accepts no parameter or 'testnet', got '{other}'"
                )),
            },
            other => Err(format!(
                "unsupported network kind '{other}' (compile cassis-client with the matching feature)"
            )),
        }
    }

    pub fn kind_name(&self) -> &'static str {
        match self {
            NetSpec::Cashu { .. } => "cashu",
            NetSpec::Rootstock { .. } => "rootstock",
        }
    }

    pub fn network_id(&self) -> NetworkId {
        match self {
            NetSpec::Cashu { host, .. } => cashu_network_id(host),
            NetSpec::Rootstock { testnet } => NetworkId(if *testnet {
                "rootstock::testnet".to_string()
            } else {
                "rootstock".to_string()
            }),
        }
    }
}

fn split_canonical_spec(spec: &str) -> (&str, Option<&str>) {
    match spec.split_once("::") {
        Some((kind, param)) => (kind, Some(param)),
        None => (spec, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_canonical_cashu_spec() {
        let s = NetSpec::parse("cashu::mint.example.com").unwrap();
        assert_eq!(s.network_id().0, "cashu::mint.example.com");
        let NetSpec::Cashu { mint_url, host } = s else {
            panic!("expected Cashu");
        };
        assert_eq!(host, "mint.example.com");
        assert_eq!(mint_url, "https://mint.example.com");
    }

    #[test]
    fn parse_canonical_cashu_loopback() {
        let s = NetSpec::parse("cashu::localhost:3338").unwrap();
        assert_eq!(s.network_id().0, "cashu::localhost:3338");
        let NetSpec::Cashu { mint_url, host } = s else {
            panic!("expected Cashu");
        };
        assert_eq!(host, "localhost:3338");
        assert_eq!(mint_url, "http://localhost:3338");
    }

    #[test]
    fn parse_rejects_empty_cashu() {
        assert!(NetSpec::parse("cashu::").is_err());
    }

    #[test]
    fn parse_rootstock_default_and_testnet() {
        assert!(matches!(
            NetSpec::parse("rootstock").unwrap(),
            NetSpec::Rootstock { testnet: false }
        ));
        assert!(matches!(
            NetSpec::parse("rootstock::testnet").unwrap(),
            NetSpec::Rootstock { testnet: true }
        ));
    }
}
