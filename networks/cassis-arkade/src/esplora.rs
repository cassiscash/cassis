//! Minimal [`ark_client::Blockchain`] implementation over an Esplora
//! REST endpoint, used by the arkade adapter to satisfy the
//! `ark_client::Client` type bounds (blockchain lookups only matter
//! for boarding/onchain flows; the offchain HTLC paths never touch
//! it).

use ark_client::Blockchain;
use ark_client::Error;
use ark_client::SpendStatus;
use ark_client::TxStatus;
use ark_core::ExplorerUtxo;
use bitcoin::Address;
use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoin::Transaction;
use bitcoin::Txid;

pub struct EsploraBlockchain {
    client: esplora_client::AsyncClient,
}

impl Blockchain for EsploraBlockchain {
    async fn find_outpoints(&self, address: &Address) -> Result<Vec<ExplorerUtxo>, Error> {
        let current_block_height = self.client.get_height().await.map_err(Error::consumer)?;

        let script_pubkey = address.script_pubkey();
        let txs = self
            .client
            .scripthash_txs(&script_pubkey, None)
            .await
            .map_err(Error::consumer)?;

        let spent_outpoints: std::collections::HashSet<OutPoint> = txs
            .iter()
            .flat_map(|tx| {
                tx.vin
                    .iter()
                    .filter(|input| {
                        input
                            .prevout
                            .as_ref()
                            .is_some_and(|prevout| prevout.scriptpubkey == script_pubkey)
                    })
                    .map(|input| OutPoint {
                        txid: input.txid,
                        vout: input.vout,
                    })
            })
            .collect();

        let utxos = txs
            .into_iter()
            .flat_map(|tx| {
                let txid = tx.txid;
                tx.vout
                    .iter()
                    .enumerate()
                    .filter(|(_, v)| v.scriptpubkey == script_pubkey)
                    .map(|(i, v)| {
                        let outpoint = OutPoint {
                            txid,
                            vout: i as u32,
                        };
                        let confirmations = match tx.status.block_height {
                            Some(confirmation_block_height) => current_block_height
                                .checked_sub(confirmation_block_height)
                                .and_then(|diff| diff.checked_add(1))
                                .unwrap_or(0),
                            None => 0,
                        };

                        ExplorerUtxo {
                            outpoint,
                            amount: Amount::from_sat(v.value),
                            confirmation_blocktime: tx.status.block_time,
                            confirmations: confirmations as u64,
                            is_spent: spent_outpoints.contains(&outpoint),
                        }
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        Ok(utxos)
    }

    async fn find_tx(&self, txid: &Txid) -> Result<Option<Transaction>, Error> {
        let option = self.client.get_tx(txid).await.map_err(Error::consumer)?;
        Ok(option)
    }

    async fn get_tx_status(&self, txid: &Txid) -> Result<TxStatus, Error> {
        let info = self
            .client
            .get_tx_info(txid)
            .await
            .map_err(Error::consumer)?;

        Ok(TxStatus {
            confirmed_at: info.and_then(|s| s.status.block_time.map(|t| t as i64)),
        })
    }

    async fn get_output_status(&self, txid: &Txid, vout: u32) -> Result<SpendStatus, Error> {
        let status = self
            .client
            .get_output_status(txid, vout as u64)
            .await
            .map_err(Error::consumer)?;

        Ok(SpendStatus {
            spend_txid: status.as_ref().and_then(|s| s.txid),
        })
    }

    async fn broadcast(&self, tx: &Transaction) -> Result<(), Error> {
        self.client.broadcast(tx).await.map_err(Error::consumer)?;
        Ok(())
    }

    async fn get_fee_rate(&self) -> Result<f64, Error> {
        Ok(1.0)
    }

    async fn broadcast_package(&self, _txs: &[&Transaction]) -> Result<(), Error> {
        unimplemented!("broadcast_package is not implemented for cassis-arkade")
    }
}

impl EsploraBlockchain {
    pub fn new(url: &str) -> Result<Self, String> {
        let client = esplora_client::Builder::new(url)
            .build_async()
            .map_err(|e| format!("esplora client init ({url}): {e}"))?;
        Ok(Self { client })
    }
}

impl EsploraBlockchain {
    /// Timestamp of the current chain tip block. The operator
    /// validates timestamp CLTVs against this, not the wall clock.
    pub async fn tip_time(&self) -> Result<u64, String> {
        let tip_hash = self
            .client
            .get_tip_hash()
            .await
            .map_err(|e| format!("get_tip_hash: {e}"))?;
        let header = self
            .client
            .get_header_by_hash(&tip_hash)
            .await
            .map_err(|e| format!("get_header_by_hash: {e}"))?;
        Ok(u64::from(header.time))
    }
}
