//! What the router tells the networks its wallets open and close (see
//! [`hyperb_cassis_wallet`]), which keeps them as the config says.

use cassis_core::{Network, NetworkId};
use cassis_routerd::router::Router;
use hyperb_cassis_wallet::Host;
use std::sync::Arc;
use tokio::sync::Notify;

/// The router, as what uses the networks.
pub struct RouterHost {
    pub router: Router,
    /// Notified when a network opens or closes, for the routes to be
    /// announced again.
    pub changed: Arc<Notify>,
}

impl Host for RouterHost {
    fn opened(&self, network: Arc<dyn Network>) {
        self.router.node().add_network(network);
        self.changed.notify_one();
    }

    fn closed(&self, id: &NetworkId) {
        self.router.node().remove_network(id);
        self.changed.notify_one();
    }

    /// The hops in flight through `id`, and the router's own payments.
    fn in_flight(&self, id: &NetworkId) -> usize {
        let payments = self
            .router
            .node()
            .db()
            .pending_payments()
            .all()
            .map(|payments| payments.iter().filter(|p| p.network == id.0).count())
            // Unable to tell: do not let go of the network.
            .unwrap_or(1);
        self.router.in_flight(id) + payments
    }
}
