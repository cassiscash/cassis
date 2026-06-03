//! HTTP client for a Cashu mint.
//!
//! This module wraps a [`reqwest::Client`] and exposes typed methods for each
//! Cashu mint REST endpoint, using types from the `cashu` crate for
//! serialization and deserialization.

use cashu::nuts::{
    nut01::KeysResponse,
    nut02::{Id as KeysetId, KeysetResponse},
    nut03::{SwapRequest, SwapResponse},
    nut04::{MintRequest, MintResponse},
    nut05::MeltRequest,
    nut07::{CheckStateRequest, CheckStateResponse},
    nut23::{
        MeltQuoteBolt11Request, MeltQuoteBolt11Response, MintQuoteBolt11Request,
        MintQuoteBolt11Response,
    },
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

    /// `GET /v1/keys` — get all active keysets' public keys (NUT-01).
    pub async fn get_all_keys(&self) -> CashuResult<KeysResponse> {
        self.get("/v1/keys").await
    }

    /// `POST /v1/swap` — swap proofs for new blinded signatures (NUT-03).
    pub async fn swap(&self, request: &SwapRequest) -> CashuResult<SwapResponse> {
        self.post("/v1/swap", request).await
    }

    /// `POST /v1/mint/quote/bolt11` — create a BOLT11 mint quote (NUT-04/23).
    pub async fn mint_quote_bolt11(
        &self,
        request: &MintQuoteBolt11Request,
    ) -> CashuResult<MintQuoteBolt11Response<String>> {
        self.post("/v1/mint/quote/bolt11", request).await
    }

    /// `POST /v1/mint/bolt11` — mint tokens from a BOLT11 quote (NUT-04).
    pub async fn mint_bolt11(
        &self,
        request: &MintRequest<String>,
    ) -> CashuResult<MintResponse> {
        self.post("/v1/mint/bolt11", request).await
    }

    /// `POST /v1/melt/quote/bolt11` — create a BOLT11 melt quote (NUT-05/23).
    pub async fn melt_quote_bolt11(
        &self,
        request: &MeltQuoteBolt11Request,
    ) -> CashuResult<MeltQuoteBolt11Response<String>> {
        self.post("/v1/melt/quote/bolt11", request).await
    }

    /// `POST /v1/melt/bolt11` — melt tokens for a BOLT11 payment (NUT-05).
    pub async fn melt_bolt11(
        &self,
        request: &MeltRequest<String>,
    ) -> CashuResult<MeltQuoteBolt11Response<String>> {
        self.post("/v1/melt/bolt11", request).await
    }

    /// `GET /v1/melt/quote/bolt11/{quote_id}` — check a melt quote's state.
    pub async fn check_melt_quote(
        &self,
        quote_id: &str,
    ) -> CashuResult<MeltQuoteBolt11Response<String>> {
        let path = format!("/v1/melt/quote/bolt11/{quote_id}");
        self.get(&path).await
    }

    /// `GET /v1/mint/quote/bolt11/{quote_id}` — check a mint quote's state.
    pub async fn check_mint_quote(
        &self,
        quote_id: &str,
    ) -> CashuResult<MintQuoteBolt11Response<String>> {
        let path = format!("/v1/mint/quote/bolt11/{quote_id}");
        self.get(&path).await
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