//! How the router opens its networks, kept in step with the config by
//! [`cassis_admin::networks::Networks`], and what it tells them.

use crate::config::NetworkConfig;
use cassis_admin::networks::{Daemon, Opened, Opener};
use cassis_core::keys::NodeKeys;
use cassis_core::node::{HopState, Node};
use cassis_core::{Network, NetworkId};
use futures::future::BoxFuture;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::Span;

pub type Networks = cassis_admin::networks::Networks<NetworkConfig>;

/// Opens a network, its wallet under `dir`.
pub struct RouterOpener {
    pub keys: NodeKeys,
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
            let settings = config.settings(id, &self.keys, &self.dir)?;
            let (network, wallet) = cassis_networks::open_wallet(id, &settings, &self.span).await?;
            Ok(Opened {
                network,
                wallet: Some(wallet),
            })
        })
    }
}

/// The node, as what uses the networks.
pub struct RouterDaemon(pub Node);

impl Daemon for RouterDaemon {
    /// The hops in flight through `id`.
    fn in_flight(&self, id: &NetworkId) -> usize {
        self.0
            .hops()
            .unwrap_or_default()
            .iter()
            .filter(|hop| {
                matches!(
                    hop.state,
                    HopState::Verifying | HopState::Funding | HopState::Forwarded
                ) && (hop.prepare.incoming_network == *id || hop.prepare.outgoing_network == *id)
            })
            .count()
    }

    fn add_network(&self, network: Arc<dyn Network>) {
        self.0.add_network(network);
    }

    fn remove_network(&self, id: &NetworkId) {
        self.0.remove_network(id);
    }
}
