//! How the router opens its networks, kept in step with the config by
//! [`cassis_admin::networks::Networks`], and what it tells them.

use crate::config::NetworkConfig;
use cassis_admin::networks::{Daemon, Opened, Opener};
use cassis_core::{Network, NetworkId};
use cassis_routerd::router::Router;
use futures::future::BoxFuture;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::Span;

pub type Networks = cassis_admin::networks::Networks<NetworkConfig>;

/// Opens a network, its wallet under `dir`.
pub struct RouterOpener {
    pub dir: PathBuf,
    pub span: Span,
}

impl Opener<NetworkConfig> for RouterOpener {
    fn open<'a>(
        &'a self,
        id: &'a NetworkId,
        config: &'a NetworkConfig,
    ) -> BoxFuture<'a, Result<Opened, String>> {
        Box::pin(async move {
            let settings = config.settings(id, &self.dir)?;
            let (network, wallet) = cassis_networks::open_wallet(id, &settings, &self.span).await?;
            Ok(Opened {
                network,
                wallet: Some(wallet),
            })
        })
    }
}

/// The router, as what uses the networks.
pub struct RouterDaemon(pub Router);

impl Daemon for RouterDaemon {
    /// The hops in flight through `id`, and the router's own payments.
    fn in_flight(&self, id: &NetworkId) -> usize {
        let payments = self
            .0
            .node()
            .db()
            .pending_payments()
            .all()
            .map(|payments| payments.iter().filter(|p| p.network == id.0).count())
            // Unable to tell: do not let go of the network.
            .unwrap_or(1);
        self.0.in_flight(id) + payments
    }

    fn add_network(&self, network: Arc<dyn Network>) {
        self.0.node().add_network(network);
    }

    fn remove_network(&self, id: &NetworkId) {
        self.0.node().remove_network(id);
    }
}
