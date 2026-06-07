use async_trait::async_trait;
use cassis_core::{
    Bytes32, HtlcError, IncomingHtlc, NetworkId, NetworkRouterAdapter, OutgoingHtlc, WatchError,
};

#[derive(Clone, Debug)]
pub struct ArkAdapter {
    network_id: NetworkId,
}

impl ArkAdapter {
    pub fn new(network_id: NetworkId) -> Self {
        Self { network_id }
    }
}

#[async_trait]
impl NetworkRouterAdapter for ArkAdapter {
    fn network_id(&self) -> NetworkId {
        self.network_id.clone()
    }

    async fn watch_incoming_htlc(
        &self,
        _payment_hash: Bytes32,
        _min_amount_msat: u64,
        _deadline: u64,
    ) -> Result<IncomingHtlc, WatchError> {
        Err(WatchError::Unimplemented)
    }

    async fn create_outgoing_htlc(
        &self,
        _payment_hash: Bytes32,
        _amount_msat: u64,
        _expiry: u64,
        _recipient: &str,
    ) -> Result<OutgoingHtlc, HtlcError> {
        Err(HtlcError::Unimplemented)
    }

    async fn claim_incoming(
        &self,
        _payment_hash: Bytes32,
        _preimage: Bytes32,
    ) -> Result<(), HtlcError> {
        Err(HtlcError::Unimplemented)
    }

    async fn refund_outgoing(&self, _payment_hash: Bytes32) -> Result<(), HtlcError> {
        Err(HtlcError::Unimplemented)
    }

    async fn watch_preimage(
        &self,
        _payment_hash: Bytes32,
        _deadline: u64,
    ) -> Result<Bytes32, WatchError> {
        Err(WatchError::Unimplemented)
    }

    async fn can_route(&self, _amount_msat: u64) -> Result<(), HtlcError> {
        Err(HtlcError::Unimplemented)
    }

    async fn verify_incoming_htlc(
        &self,
        _descriptor: &cassis_core::HtlcDescriptor,
        _payment_hash: Bytes32,
    ) -> Result<(), HtlcError> {
        Err(HtlcError::Unimplemented)
    }

    async fn accept_incoming_htlc(
        &self,
        _payment_hash: Bytes32,
        _descriptor: &cassis_core::HtlcDescriptor,
        _deadline: u64,
    ) -> Result<(), HtlcError> {
        Err(HtlcError::Unimplemented)
    }

    async fn outgoing_htlc_descriptor(
        &self,
        _payment_hash: Bytes32,
    ) -> Result<cassis_core::HtlcDescriptor, HtlcError> {
        Err(HtlcError::Unimplemented)
    }

    fn incoming_delta_secs(&self) -> u64 {
        10
    }
}
