//! A minimal Esplora REST API over a regtest `bitcoind`, for software
//! that only talks Esplora (arkd's wallet, the arkade SDK) in local
//! tests. bitcoind has no address index, so this keeps one in memory:
//! every block and mempool transaction, brought up to date on each
//! request. Fine for regtest-sized chains, nothing more.
//!
//! Serves the subset of <https://github.com/Blockstream/esplora/blob/master/API.md>
//! those clients use; anything else answers 404 and is logged.

use crate::local::Bitcoind;
use axum::body::Bytes;
use axum::http::{Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::hex::DisplayHex;
use bitcoin::{Address, Block, BlockHash, OutPoint, ScriptBuf, Transaction, TxOut, Txid};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::warn;

/// Start serving on a free local port; returns the API's base URL.
pub(crate) async fn serve(bitcoind: Bitcoind) -> Result<String, String> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| e.to_string())?;
    let url = format!(
        "http://{}",
        listener.local_addr().map_err(|e| e.to_string())?
    );
    let state = Arc::new(State {
        bitcoind,
        index: Mutex::new(Index::default()),
    });
    let app = axum::Router::new().fallback(move |method: Method, uri: Uri, body: Bytes| {
        let state = state.clone();
        async move { state.handle(method, uri, body).await }
    });
    tokio::spawn(async move {
        if let Err(error) = axum::serve(listener, app).await {
            warn!("esplora server stopped: {error}");
        }
    });
    Ok(url)
}

struct State {
    bitcoind: Bitcoind,
    index: Mutex<Index>,
}

#[derive(Default)]
struct Index {
    /// Indexed blocks, by height.
    blocks: Vec<BlockInfo>,
    txs: HashMap<Txid, Entry>,
    /// Transactions paying to a script, in index order.
    funding: HashMap<ScriptBuf, Vec<Txid>>,
    /// Spending input of each spent outpoint.
    spends: HashMap<OutPoint, (Txid, u32)>,
    mempool: HashSet<Txid>,
}

struct BlockInfo {
    hash: BlockHash,
    header: bitcoin::block::Header,
    txids: Vec<Txid>,
    size: usize,
    weight: u64,
}

struct Entry {
    tx: Transaction,
    /// Confirming block height, `None` while in the mempool.
    height: Option<u32>,
}

enum Reply {
    Json(Value),
    Text(String),
    Bytes(Vec<u8>),
    NotFound,
    Error(StatusCode, String),
}

impl IntoResponse for Reply {
    fn into_response(self) -> Response {
        match self {
            Reply::Json(value) => axum::Json(value).into_response(),
            Reply::Text(text) => text.into_response(),
            Reply::Bytes(bytes) => bytes.into_response(),
            Reply::NotFound => (StatusCode::NOT_FOUND, "not found").into_response(),
            Reply::Error(status, message) => (status, message).into_response(),
        }
    }
}

fn bad_request(error: impl ToString) -> Reply {
    Reply::Error(StatusCode::BAD_REQUEST, error.to_string())
}

impl State {
    async fn handle(&self, method: Method, uri: Uri, body: Bytes) -> Reply {
        let path: Vec<&str> = uri.path().trim_matches('/').split('/').collect();
        // Writes go straight to bitcoind.
        if method == Method::POST {
            return match path.as_slice() {
                ["tx"] => self.broadcast(&body).await,
                ["txs", "package"] => self.broadcast_package(&body).await,
                _ => self.unknown(&method, &uri),
            };
        }
        let mut index = self.index.lock().await;
        if let Err(error) = index.sync(&self.bitcoind).await {
            return Reply::Error(StatusCode::SERVICE_UNAVAILABLE, error);
        }
        let reply = match path.as_slice() {
            ["blocks", "tip", "height"] => index
                .tip()
                .map(|(height, _)| Reply::Text(height.to_string())),
            ["blocks", "tip", "hash"] => index
                .tip()
                .map(|(_, info)| Reply::Text(info.hash.to_string())),
            ["blocks"] => Some(index.blocks_from(None)),
            ["blocks", height] => height.parse().ok().map(|h| index.blocks_from(Some(h))),
            ["block-height", height] => height
                .parse::<usize>()
                .ok()
                .and_then(|h| index.blocks.get(h))
                .map(|info| Reply::Text(info.hash.to_string())),
            ["block", hash, rest @ ..] => index.block(hash, rest),
            ["tx", txid, rest @ ..] => match Txid::from_str(txid) {
                Ok(txid) => index.tx(&txid, rest),
                Err(error) => Some(bad_request(error)),
            },
            ["address", address, rest @ ..] => {
                match Address::from_str(address).map(|a| a.assume_checked().script_pubkey()) {
                    Ok(script) => index.script(&script, json!({ "address": address }), rest),
                    Err(error) => Some(bad_request(error)),
                }
            }
            ["scripthash", hash, rest @ ..] => {
                let script = index
                    .funding
                    .keys()
                    .find(|script| sha256::Hash::hash(script.as_bytes()).to_string() == *hash)
                    .cloned()
                    .unwrap_or_default();
                index.script(&script, json!({ "scripthash": hash }), rest)
            }
            ["fee-estimates"] => Some(Reply::Json(fee_estimates())),
            ["mempool", "txids"] => {
                Some(Reply::Json(json!(index.mempool.iter().collect::<Vec<_>>())))
            }
            _ => return self.unknown(&method, &uri),
        };
        reply.unwrap_or(Reply::NotFound)
    }

    fn unknown(&self, method: &Method, uri: &Uri) -> Reply {
        warn!("esplora: unsupported {method} {uri}");
        Reply::NotFound
    }

    async fn broadcast(&self, body: &[u8]) -> Reply {
        let hex = String::from_utf8_lossy(body).trim().to_string();
        match self.bitcoind.rpc("sendrawtransaction", json!([hex])).await {
            Ok(txid) => Reply::Text(txid.as_str().unwrap_or_default().to_string()),
            Err(error) => bad_request(error),
        }
    }

    async fn broadcast_package(&self, body: &[u8]) -> Reply {
        let txs: Vec<String> = match serde_json::from_slice(body) {
            Ok(txs) => txs,
            Err(error) => return bad_request(error),
        };
        match self.bitcoind.rpc("submitpackage", json!([txs])).await {
            Ok(result) => Reply::Json(result),
            Err(error) => bad_request(error),
        }
    }
}

fn fee_estimates() -> Value {
    // Regtest has no fee market; the floor everywhere.
    let targets = [1, 2, 3, 6, 12, 25, 144, 504, 1008];
    Value::Object(
        targets
            .iter()
            .map(|target| (target.to_string(), json!(1.0)))
            .collect(),
    )
}

impl Index {
    /// Catch up with bitcoind's chain and mempool.
    async fn sync(&mut self, bitcoind: &Bitcoind) -> Result<(), String> {
        let count = bitcoind
            .rpc("getblockcount", json!([]))
            .await?
            .as_u64()
            .ok_or("getblockcount: not a number")? as usize;
        // A reorg (or a reset chain) invalidates everything.
        if let Some(last) = self.blocks.last() {
            let height = self.blocks.len() - 1;
            let hash = if height <= count {
                bitcoind.rpc("getblockhash", json!([height])).await.ok()
            } else {
                None
            };
            if hash.as_ref().and_then(Value::as_str) != Some(last.hash.to_string().as_str()) {
                *self = Index::default();
            }
        }
        for height in self.blocks.len()..=count {
            let hash = bitcoind.rpc("getblockhash", json!([height])).await?;
            let raw = bitcoind.rpc("getblock", json!([hash, 0])).await?;
            let block: Block = deserialize_hex(raw.as_str().unwrap_or_default())
                .map_err(|e| format!("block {height}: {e}"))?;
            let mut info = BlockInfo {
                hash: block.block_hash(),
                header: block.header,
                txids: Vec::with_capacity(block.txdata.len()),
                size: bitcoin::consensus::serialize(&block).len(),
                weight: block.weight().to_wu(),
            };
            for tx in block.txdata {
                info.txids.push(tx.compute_txid());
                self.add(tx, Some(height as u32));
            }
            self.blocks.push(info);
        }

        let mempool: HashSet<Txid> =
            serde_json::from_value(bitcoind.rpc("getrawmempool", json!([])).await?)
                .map_err(|e| format!("getrawmempool: {e}"))?;
        // Evicted or replaced transactions.
        for txid in self.mempool.clone() {
            if !mempool.contains(&txid) {
                self.mempool.remove(&txid);
                if self
                    .txs
                    .get(&txid)
                    .is_some_and(|entry| entry.height.is_none())
                {
                    self.remove(&txid);
                }
            }
        }
        for txid in mempool {
            if self.txs.contains_key(&txid) {
                continue;
            }
            let Ok(raw) = bitcoind.rpc("getrawtransaction", json!([txid])).await else {
                continue; // Left the mempool meanwhile.
            };
            let tx: Transaction = deserialize_hex(raw.as_str().unwrap_or_default())
                .map_err(|e| format!("tx {txid}: {e}"))?;
            self.add(tx, None);
            self.mempool.insert(txid);
        }
        Ok(())
    }

    fn add(&mut self, tx: Transaction, height: Option<u32>) {
        let txid = tx.compute_txid();
        if let Some(entry) = self.txs.get_mut(&txid) {
            // Confirmed from the mempool.
            entry.height = height;
            self.mempool.remove(&txid);
            return;
        }
        if !tx.is_coinbase() {
            for (vin, input) in tx.input.iter().enumerate() {
                self.spends
                    .insert(input.previous_output, (txid, vin as u32));
            }
        }
        for output in &tx.output {
            let funding = self
                .funding
                .entry(output.script_pubkey.clone())
                .or_default();
            if funding.last() != Some(&txid) {
                funding.push(txid);
            }
        }
        self.txs.insert(txid, Entry { tx, height });
    }

    fn remove(&mut self, txid: &Txid) {
        let Some(entry) = self.txs.remove(txid) else {
            return;
        };
        for input in &entry.tx.input {
            if self.spends.get(&input.previous_output).map(|(t, _)| t) == Some(txid) {
                self.spends.remove(&input.previous_output);
            }
        }
        for output in &entry.tx.output {
            if let Some(funding) = self.funding.get_mut(&output.script_pubkey) {
                funding.retain(|t| t != txid);
            }
        }
    }

    fn tip(&self) -> Option<(usize, &BlockInfo)> {
        self.blocks.last().map(|info| (self.blocks.len() - 1, info))
    }

    fn prevout(&self, outpoint: &OutPoint) -> Option<&TxOut> {
        self.txs
            .get(&outpoint.txid)
            .and_then(|entry| entry.tx.output.get(outpoint.vout as usize))
    }

    /// Median time past at `height`.
    fn median_time(&self, height: usize) -> u32 {
        let mut times: Vec<u32> = self.blocks[height.saturating_sub(10)..=height]
            .iter()
            .map(|info| info.header.time)
            .collect();
        times.sort_unstable();
        times[times.len() / 2]
    }

    fn status(&self, height: Option<u32>) -> Value {
        match height.and_then(|h| self.blocks.get(h as usize).map(|info| (h, info))) {
            Some((height, info)) => json!({
                "confirmed": true,
                "block_height": height,
                "block_hash": info.hash,
                "block_time": info.header.time,
            }),
            None => json!({ "confirmed": false }),
        }
    }

    fn block_json(&self, height: usize) -> Value {
        let info = &self.blocks[height];
        json!({
            "id": info.hash,
            "height": height,
            "version": info.header.version.to_consensus(),
            "timestamp": info.header.time,
            "mediantime": self.median_time(height),
            "bits": info.header.bits.to_consensus(),
            "nonce": info.header.nonce,
            "merkle_root": info.header.merkle_root,
            "previousblockhash": (height > 0).then(|| info.header.prev_blockhash),
            "tx_count": info.txids.len(),
            "size": info.size,
            "weight": info.weight,
        })
    }

    /// Ten blocks down from `height` (default: the tip).
    fn blocks_from(&self, height: Option<usize>) -> Reply {
        let top = height.unwrap_or(self.blocks.len().saturating_sub(1));
        let blocks: Vec<Value> = (0..self.blocks.len().min(top + 1))
            .rev()
            .take(10)
            .map(|h| self.block_json(h))
            .collect();
        Reply::Json(json!(blocks))
    }

    fn block(&self, hash: &str, rest: &[&str]) -> Option<Reply> {
        let height = self
            .blocks
            .iter()
            .position(|info| info.hash.to_string() == hash)?;
        let info = &self.blocks[height];
        Some(match rest {
            [] => Reply::Json(self.block_json(height)),
            ["header"] => Reply::Text(serialize_hex(&info.header)),
            ["status"] => Reply::Json(json!({
                "in_best_chain": true,
                "height": height,
                "next_best": self.blocks.get(height + 1).map(|next| next.hash),
            })),
            ["txids"] => Reply::Json(json!(info.txids)),
            _ => return None,
        })
    }

    fn tx_json(&self, txid: &Txid) -> Option<Value> {
        let entry = self.txs.get(txid)?;
        let tx = &entry.tx;
        let mut input_value = 0;
        let vin: Vec<Value> = tx
            .input
            .iter()
            .map(|input| {
                let prevout = (!tx.is_coinbase())
                    .then(|| self.prevout(&input.previous_output))
                    .flatten();
                input_value += prevout.map_or(0, |out| out.value.to_sat());
                json!({
                    "txid": input.previous_output.txid,
                    "vout": input.previous_output.vout,
                    "prevout": prevout.map(|out| json!({
                        "scriptpubkey": out.script_pubkey,
                        "value": out.value.to_sat(),
                    })),
                    "scriptsig": input.script_sig,
                    "witness": input.witness.iter().map(|item| item.to_lower_hex_string()).collect::<Vec<_>>(),
                    "sequence": input.sequence.to_consensus_u32(),
                    "is_coinbase": tx.is_coinbase(),
                })
            })
            .collect();
        let output_value: u64 = tx.output.iter().map(|out| out.value.to_sat()).sum();
        Some(json!({
            "txid": txid,
            "version": tx.version.0,
            "locktime": tx.lock_time.to_consensus_u32(),
            "vin": vin,
            "vout": tx.output.iter().map(|out| json!({
                "scriptpubkey": out.script_pubkey,
                "value": out.value.to_sat(),
            })).collect::<Vec<_>>(),
            "size": tx.total_size(),
            "weight": tx.weight().to_wu(),
            "fee": if tx.is_coinbase() { 0 } else { input_value.saturating_sub(output_value) },
            "status": self.status(entry.height),
        }))
    }

    fn outspend(&self, outpoint: &OutPoint) -> Value {
        match self.spends.get(outpoint) {
            Some((txid, vin)) => json!({
                "spent": true,
                "txid": txid,
                "vin": vin,
                "status": self.status(self.txs.get(txid).and_then(|entry| entry.height)),
            }),
            None => json!({ "spent": false }),
        }
    }

    fn tx(&self, txid: &Txid, rest: &[&str]) -> Option<Reply> {
        let entry = self.txs.get(txid)?;
        Some(match rest {
            [] => Reply::Json(self.tx_json(txid)?),
            ["hex"] => Reply::Text(serialize_hex(&entry.tx)),
            ["raw"] => Reply::Bytes(bitcoin::consensus::serialize(&entry.tx)),
            ["status"] => Reply::Json(self.status(entry.height)),
            ["outspend", vout] => {
                Reply::Json(self.outspend(&OutPoint::new(*txid, vout.parse().ok()?)))
            }
            ["outspends"] => Reply::Json(json!((0..entry.tx.output.len())
                .map(|vout| self.outspend(&OutPoint::new(*txid, vout as u32)))
                .collect::<Vec<_>>())),
            _ => return None,
        })
    }

    /// Outputs paying to `script`, and the transactions creating or
    /// spending them, newest first.
    fn script_history(
        &self,
        script: &ScriptBuf,
    ) -> (Vec<(OutPoint, &TxOut, Option<u32>)>, Vec<Txid>) {
        let mut outputs = Vec::new();
        let mut txids = Vec::new();
        for txid in self.funding.get(script).into_iter().flatten() {
            let entry = &self.txs[txid];
            txids.push(*txid);
            for (vout, out) in entry.tx.output.iter().enumerate() {
                if out.script_pubkey == *script {
                    let outpoint = OutPoint::new(*txid, vout as u32);
                    if let Some((spender, _)) = self.spends.get(&outpoint) {
                        txids.push(*spender);
                    }
                    outputs.push((outpoint, out, entry.height));
                }
            }
        }
        let height = |txid: &Txid| self.txs[txid].height.unwrap_or(u32::MAX);
        txids.sort_by_key(|txid| std::cmp::Reverse(height(txid)));
        txids.dedup();
        (outputs, txids)
    }

    fn script(&self, script: &ScriptBuf, id: Value, rest: &[&str]) -> Option<Reply> {
        let (outputs, txids) = self.script_history(script);
        let confirmed = |txid: &Txid| self.txs[txid].height.is_some();
        let txs = |filter: &dyn Fn(&Txid) -> bool| {
            Reply::Json(json!(txids
                .iter()
                .filter(|txid| filter(txid))
                .filter_map(|txid| self.tx_json(txid))
                .collect::<Vec<_>>()))
        };
        Some(match rest {
            [] => {
                let stats = |in_chain: bool| {
                    let funded: Vec<_> = outputs
                        .iter()
                        .filter(|(_, _, height)| height.is_some() == in_chain)
                        .collect();
                    let spent: Vec<_> = outputs
                        .iter()
                        .filter(|(outpoint, _, _)| {
                            self.spends
                                .get(outpoint)
                                .is_some_and(|(txid, _)| confirmed(txid) == in_chain)
                        })
                        .collect();
                    json!({
                        "funded_txo_count": funded.len(),
                        "funded_txo_sum": funded.iter().map(|(_, out, _)| out.value.to_sat()).sum::<u64>(),
                        "spent_txo_count": spent.len(),
                        "spent_txo_sum": spent.iter().map(|(_, out, _)| out.value.to_sat()).sum::<u64>(),
                        "tx_count": txids.iter().filter(|txid| confirmed(txid) == in_chain).count(),
                    })
                };
                let mut summary = id;
                summary["chain_stats"] = stats(true);
                summary["mempool_stats"] = stats(false);
                Reply::Json(summary)
            }
            ["utxo"] => Reply::Json(json!(outputs
                .iter()
                .filter(|(outpoint, _, _)| !self.spends.contains_key(outpoint))
                .map(|(outpoint, out, height)| json!({
                    "txid": outpoint.txid,
                    "vout": outpoint.vout,
                    "value": out.value.to_sat(),
                    "status": self.status(*height),
                }))
                .collect::<Vec<_>>())),
            ["txs"] => txs(&|_| true),
            ["txs", "mempool"] => txs(&|txid| !confirmed(txid)),
            ["txs", "chain"] => txs(&|txid| confirmed(txid)),
            ["txs", "chain", last_seen] => {
                let last_seen = Txid::from_str(last_seen).ok()?;
                let after = txids.iter().position(|txid| *txid == last_seen)?;
                let rest: HashSet<Txid> = txids[after + 1..].iter().copied().collect();
                txs(&|txid| confirmed(txid) && rest.contains(txid))
            }
            _ => return None,
        })
    }
}
