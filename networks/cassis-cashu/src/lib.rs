use async_trait::async_trait;
use cashu::nuts::{
    nut01::KeysResponse,
    nut02::{Id as KeysetId, KeySetInfo, KeysetResponse},
    nut03::{SwapRequest, SwapResponse},
    nut07::{CheckStateRequest, CheckStateResponse},
    nut23::{
        MeltQuoteBolt11Request, MeltQuoteBolt11Response, MintQuoteBolt11Request,
        MintQuoteBolt11Response,
    },
    nut04::{MintRequest, MintResponse},
    nut05,
    CurrencyUnit,
};
use cashu::MintUrl;
use cassis_core::{Bytes32, HtlcError, IncomingHtlc, NetworkAdapter, NetworkId, OutgoingHtlc, WatchError};
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::RwLock;

mod errors;
mod htlc;
mod mint_client;

use errors::{CashuError, CashuResult};
use mint_client::MintClient;

pub use errors::CashuError as Error;

pub struct CashuAdapter {
    network_id: NetworkId,
    #[allow(dead_code)]
    mint_url: MintUrl,
    client: MintClient,
    secret_key: [u8; 32],
    keysets: Arc<RwLock<Vec<KeySetInfo>>>,
}

impl CashuAdapter {
    pub fn new(network_id: NetworkId, mint_url: String, secret_key: [u8; 32]) -> Self {
        let mint_url = MintUrl::from_str(&mint_url).unwrap_or_else(|_| {
            MintUrl::from_str("https://unknown.mint").expect("valid fallback mint url")
        });
        let client = MintClient::new(mint_url.clone(), None);
        Self {
            network_id,
            mint_url,
            client,
            secret_key,
            keysets: Arc::new(RwLock::new(Vec::new())),
        }
    }

    async fn ensure_keysets(&self) -> CashuResult<Vec<KeySetInfo>> {
        {
            let cached = self.keysets.read().await;
            if !cached.is_empty() {
                return Ok(cached.clone());
            }
        }
        let resp = self.client.get_keysets().await?;
        let active: Vec<KeySetInfo> = resp
            .keysets
            .into_iter()
            .filter(|k| k.active)
            .collect();
        let mut guard = self.keysets.write().await;
        *guard = active.clone();
        Ok(active)
    }

    async fn active_keyset_id(&self) -> CashuResult<KeysetId> {
        let keysets = self.ensure_keysets().await?;
        keysets
            .clone()
            .into_iter()
            .find(|k| k.unit == CurrencyUnit::Sat)
            .or_else(|| keysets.into_iter().next())
            .map(|k| k.id)
            .ok_or(CashuError::NoKeyset)
    }

    async fn get_keys(&self, keyset_id: &KeysetId) -> CashuResult<cashu::nuts::nut01::Keys> {
        let resp = self.client.get_keys(keyset_id).await?;
        resp.keysets
            .into_iter()
            .find(|ks| &ks.id == keyset_id)
            .map(|ks| ks.keys)
            .ok_or(CashuError::NoKeyset)
    }
}

#[async_trait]
impl NetworkAdapter for CashuAdapter {
    fn network_id(&self) -> NetworkId {
        self.network_id.clone()
    }

    async fn create_outgoing_htlc(
        &self,
        payment_hash: Bytes32,
        amount_msat: u64,
        _expiry: u64,
        _recipient: &str,
    ) -> Result<OutgoingHtlc, HtlcError> {
        let keyset_id = self
            .active_keyset_id()
            .await
            .map_err(|e| HtlcError::Network(e.to_string()))?;

        let _ = self
            .get_keys(&keyset_id)
            .await
            .map_err(|e| HtlcError::Network(e.to_string()))?;

        let _ = (payment_hash, amount_msat);

        Err(HtlcError::Unimplemented)
    }

    async fn watch_incoming_htlc(
        &self,
        _payment_hash: Bytes32,
        _min_amount_msat: u64,
        _deadline: u64,
    ) -> Result<IncomingHtlc, WatchError> {
        let keysets = self
            .ensure_keysets()
            .await
            .map_err(|e| WatchError::Network(e.to_string()))?;
        if keysets.is_empty() {
            return Err(WatchError::Network("mint has no active keysets".into()));
        }
        Err(WatchError::Unimplemented)
    }

    async fn claim_incoming(
        &self,
        _htlc: &IncomingHtlc,
        _preimage: Bytes32,
    ) -> Result<(), HtlcError> {
        Err(HtlcError::Unimplemented)
    }

    async fn refund_outgoing(&self, _htlc: &OutgoingHtlc) -> Result<(), HtlcError> {
        Err(HtlcError::Unimplemented)
    }

    async fn watch_preimage(
        &self,
        _htlc: &OutgoingHtlc,
        _deadline: u64,
    ) -> Result<Bytes32, WatchError> {
        Err(WatchError::Unimplemented)
    }

    fn incoming_delta_secs(&self) -> u64 {
        30
    }
}