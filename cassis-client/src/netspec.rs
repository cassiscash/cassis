use cassis_core::{cashu_mint_url, cashu_network_id, NetworkId};

/// A parsed `--network` spec, mirroring the router/CLI format:
/// `cashu::host`, `arkade`, `arkade::mutinynet`, `liquid`,
/// `liquid::testnet`, `rootstock`, or `rootstock::testnet`.
#[derive(Clone, Debug)]
pub enum NetSpec {
    Cashu { mint_url: String, host: String },
    Arkade { mutinynet: bool },
    Liquid { testnet: bool },
    Rootstock { testnet: bool },
    Lightning,
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
            "lightning" => match param {
                None => Ok(NetSpec::Lightning),
                Some(other) => Err(format!(
                    "network 'lightning' does not accept a parameter, got '{other}'"
                )),
            },
            "arkade" => match param {
                None => Ok(NetSpec::Arkade { mutinynet: false }),
                Some("mutinynet") => Ok(NetSpec::Arkade { mutinynet: true }),
                Some(other) => Err(format!(
                    "network 'arkade' only accepts no parameter or 'mutinynet', got '{other}'"
                )),
            },
            "liquid" => match param {
                None => Ok(NetSpec::Liquid { testnet: false }),
                Some("testnet") => Ok(NetSpec::Liquid { testnet: true }),
                Some(other) => Err(format!(
                    "network 'liquid' only accepts no parameter or 'testnet', got '{other}'"
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
            NetSpec::Arkade { .. } => "arkade",
            NetSpec::Liquid { .. } => "liquid",
            NetSpec::Rootstock { .. } => "rootstock",
            NetSpec::Lightning => "lightning",
        }
    }

    pub fn network_id(&self) -> NetworkId {
        match self {
            NetSpec::Cashu { host, .. } => cashu_network_id(host),
            NetSpec::Arkade { mutinynet } => NetworkId(if *mutinynet {
                "arkade::mutinynet".to_string()
            } else {
                "arkade".to_string()
            }),
            NetSpec::Liquid { testnet } => NetworkId(if *testnet {
                "liquid::testnet".to_string()
            } else {
                "liquid".to_string()
            }),
            NetSpec::Rootstock { testnet } => NetworkId(if *testnet {
                "rootstock::testnet".to_string()
            } else {
                "rootstock".to_string()
            }),
            NetSpec::Lightning => NetworkId("lightning".to_string()),
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

    #[test]
    fn parse_liquid_default_and_testnet() {
        let s = NetSpec::parse("liquid").unwrap();
        assert_eq!(s.network_id().0, "liquid");
        assert_eq!(s.kind_name(), "liquid");
        let s = NetSpec::parse("liquid::testnet").unwrap();
        assert_eq!(s.network_id().0, "liquid::testnet");
        assert!(matches!(NetSpec::parse("liquid::foo"), Err(_)));
    }

    #[test]
    fn parse_lightning_has_no_parameter() {
        let s = NetSpec::parse("lightning").unwrap();
        assert_eq!(s.network_id().0, "lightning");
        assert_eq!(s.kind_name(), "lightning");
        assert!(matches!(NetSpec::parse("lightning::testnet"), Err(_)));
    }

    #[test]
    fn parse_arkade_default_and_testnet() {
        let s = NetSpec::parse("arkade").unwrap();
        assert_eq!(s.network_id().0, "arkade");
        assert_eq!(s.kind_name(), "arkade");
        let s = NetSpec::parse("arkade::mutinynet").unwrap();
        assert_eq!(s.network_id().0, "arkade::mutinynet");
        assert!(matches!(NetSpec::parse("arkade::foo"), Err(_)));
    }
}
