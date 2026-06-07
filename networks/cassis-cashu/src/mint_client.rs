//! HTTP client for a Cashu mint.
//!
//! This module wraps a [`reqwest::Client`] and exposes typed methods for the
//! Cashu mint REST endpoints the cassis wallet actually needs: reading
//! keyset metadata, swapping proofs (NUT-03), and checking proof state
//! (NUT-07). Minting (NUT-04) and melting (NUT-05/23) are out of scope
//! for the local wallet — funds come in via the cross-network hop layer
//! or by redeeming proofs, and go out by spending proofs.

use cashu::nuts::{
    nut01::KeysResponse,
    nut02::{Id as KeysetId, KeysetResponse},
    nut03::{SwapRequest, SwapResponse},
    nut07::{CheckStateRequest, CheckStateResponse},
};
use cashu::MintUrl;
use reqwest::Client;
use std::time::Duration;

use crate::errors::{CashuError, CashuResult};

/// HTTP client for a Cashu mint.
#[derive(Clone)]
pub struct MintClient {
    mint_url: MintUrl,
    http: Client,
}

impl MintClient {
    /// Create a new mint client.
    ///
    /// Pass `None` for `timeout` to use the default of 30 seconds.
    pub fn new(mint_url: MintUrl, timeout: Option<Duration>) -> Self {
        let http = Client::builder()
            .timeout(timeout.unwrap_or(Duration::from_secs(30)))
            .build()
            .expect("failed to build reqwest client");
        Self { mint_url, http }
    }

    /// `GET /v1/keysets` — list the mint's keysets (NUT-02).
    pub async fn get_keysets(&self) -> CashuResult<KeysetResponse> {
        self.get("/v1/keysets").await
    }

    /// `GET /v1/keys/{keyset_id}` — get public keys for a specific keyset (NUT-01).
    pub async fn get_keys(&self, keyset_id: &KeysetId) -> CashuResult<KeysResponse> {
        let path = format!("/v1/keys/{}", keyset_id);
        self.get(&path).await
    }

    /// `POST /v1/swap` — swap proofs for new blinded signatures (NUT-03).
    pub async fn swap(&self, request: &SwapRequest) -> CashuResult<SwapResponse> {
        self.post("/v1/swap", request).await
    }

    /// `POST /v1/checkstate` — check whether proofs are spent (NUT-07).
    pub async fn check_state(
        &self,
        request: &CheckStateRequest,
    ) -> CashuResult<CheckStateResponse> {
        self.post("/v1/checkstate", request).await
    }

    async fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> CashuResult<T> {
        let url = self
            .mint_url
            .join(path)
            .map_err(|e| self.http_err(e.to_string()))?;
        let resp = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| self.http_err(e.to_string()))?;
        self.parse_response(resp).await
    }

    async fn post<T: serde::de::DeserializeOwned, B: serde::Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> CashuResult<T> {
        let url = self
            .mint_url
            .join(path)
            .map_err(|e| self.http_err(e.to_string()))?;
        let resp = self
            .http
            .post(url)
            .json(body)
            .send()
            .await
            .map_err(|e| self.http_err(e.to_string()))?;
        self.parse_response(resp).await
    }

    fn http_err(&self, detail: String) -> CashuError {
        CashuError::Http(format!("mint {}: {detail}", self.mint_url))
    }

    async fn parse_response<T: serde::de::DeserializeOwned>(
        &self,
        resp: reqwest::Response,
    ) -> CashuResult<T> {
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(CashuError::Mint(format!(
                "mint {}: HTTP {status}: {text}",
                self.mint_url
            )));
        }
        resp.json::<T>()
            .await
            .map_err(|e| CashuError::Deserialize(format!("mint {}: {e}", self.mint_url)))
    }
}
