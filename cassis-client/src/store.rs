use cassis_core::{Bytes32, HtlcDescriptor, Invoice, NetworkId, OutgoingPayment};
use minisqlite::{Connection, Error as SqlError, Value};

/// Re-export of `minisqlite::Value` so callers can pattern-match SQL
/// rows without depending on `minisqlite` directly.
pub use minisqlite::Value as SqlValue;
use std::path::Path;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS invoices (
    payment_hash TEXT PRIMARY KEY,
    preimage     BLOB NOT NULL,
    amount_msat  INTEGER NOT NULL,
    network_id   TEXT NOT NULL,
    payee        TEXT,
    description  TEXT,
    expires_at   INTEGER NOT NULL,
    status       TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    claimed_at   INTEGER
);
CREATE INDEX IF NOT EXISTS invoices_status_idx ON invoices(status);

CREATE TABLE IF NOT EXISTS outgoing_payments (
    payment_hash       TEXT PRIMARY KEY,
    invoice_json       TEXT NOT NULL,
    sender_network     TEXT NOT NULL,
    amount_msat        INTEGER NOT NULL,
    destination_pubkey TEXT NOT NULL,
    destination_network TEXT NOT NULL,
    expiry             INTEGER NOT NULL,
    descriptor_json    TEXT,
    status             TEXT NOT NULL,
    created_at         INTEGER NOT NULL,
    resolved_at        INTEGER
);
CREATE INDEX IF NOT EXISTS outgoing_payments_status_idx
    ON outgoing_payments(status);

CREATE TABLE IF NOT EXISTS payment_proofs (
    payment_hash TEXT PRIMARY KEY,
    invoice_json TEXT NOT NULL,
    preimage     BLOB NOT NULL,
    paid_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS cashu_proofs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    mint_url     TEXT NOT NULL,
    amount_sat   INTEGER NOT NULL,
    proof_blob   BLOB NOT NULL,
    created_at   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS cashu_proofs_mint_idx ON cashu_proofs(mint_url);
";

/// Lifecycle of an invoice row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvoiceStatus {
    Pending,
    Claimed,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutgoingPaymentStatus {
    Pending,
    Completed,
    Refunded,
    Failed,
}

impl OutgoingPaymentStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Completed => "completed",
            Self::Refunded => "refunded",
            Self::Failed => "failed",
        }
    }
}

impl InvoiceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            InvoiceStatus::Pending => "pending",
            InvoiceStatus::Claimed => "claimed",
            InvoiceStatus::Failed => "failed",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(InvoiceStatus::Pending),
            "claimed" => Some(InvoiceStatus::Claimed),
            "failed" => Some(InvoiceStatus::Failed),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct InvoiceRow {
    pub payment_hash: Bytes32,
    pub preimage: [u8; 32],
    pub amount_msat: u64,
    pub network_id: NetworkId,
    pub payee: Option<String>,
    pub description: Option<String>,
    pub expires_at: u64,
    pub status: InvoiceStatus,
    pub created_at: u64,
    pub claimed_at: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct PendingOutgoingPayment {
    pub invoice: Invoice,
    pub payment: OutgoingPayment,
    pub sender_network: NetworkId,
    pub descriptor: Option<HtlcDescriptor>,
    pub created_at: u64,
}

#[derive(Clone, Debug)]
pub struct PaymentProof {
    pub invoice: Invoice,
    pub preimage: Bytes32,
    pub paid_at: u64,
}

#[derive(thiserror::Error, Debug)]
pub enum StoreError {
    #[error("sqlite: {0}")]
    Sqlite(String),
    #[error("invalid row: {0}")]
    Invalid(String),
    #[error("not found: {0}")]
    NotFound(String),
}

impl From<SqlError> for StoreError {
    fn from(e: SqlError) -> Self {
        StoreError::Sqlite(e.to_string())
    }
}

pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let mut conn = Connection::open(path)?;
        conn.execute(SCHEMA)?;
        Ok(Self { conn })
    }

    #[allow(dead_code)]
    pub fn in_memory() -> Result<Self, StoreError> {
        let mut conn = Connection::open_in_memory()?;
        conn.execute(SCHEMA)?;
        Ok(Self { conn })
    }

    /// Direct access to the underlying connection for callers that
    /// need ad-hoc tables or PRAGMAs (e.g. the `meta` table used by
    /// `register`). Most callers should not need this.
    pub fn conn(&mut self) -> &mut Connection {
        &mut self.conn
    }

    pub fn insert_invoice(&mut self, row: &InvoiceRow) -> Result<(), StoreError> {
        let sql = format!(
            "INSERT INTO invoices \
             (payment_hash, preimage, amount_msat, network_id, payee, description, \
              expires_at, status, created_at, claimed_at) \
             VALUES ('{}', X'{}', {}, {}, {}, {}, {}, '{}', {}, {});",
            row.payment_hash,
            hex::encode(row.preimage),
            row.amount_msat,
            escape_sql_string(&row.network_id.0),
            option_sql_string(&row.payee),
            option_sql_string(&row.description),
            row.expires_at,
            row.status.as_str(),
            row.created_at,
            row.claimed_at.map_or("NULL".to_string(), |v| v.to_string()),
        );
        self.conn.execute(&sql)?;
        Ok(())
    }

    pub fn mark_status(
        &mut self,
        payment_hash: &Bytes32,
        status: InvoiceStatus,
    ) -> Result<(), StoreError> {
        let claimed_at = match status {
            InvoiceStatus::Claimed => Some(unix_now()),
            _ => None,
        };
        let claimed_at_sql = claimed_at
            .map(|v| v.to_string())
            .unwrap_or_else(|| "NULL".to_string());
        self.conn.execute(&format!(
            "UPDATE invoices SET status='{}', claimed_at={} WHERE payment_hash='{}';",
            status.as_str(),
            claimed_at_sql,
            payment_hash
        ))?;
        Ok(())
    }

    pub fn insert_outgoing_payment(
        &mut self,
        invoice: &Invoice,
        payment: &OutgoingPayment,
        sender_network: &NetworkId,
        descriptor: Option<&HtlcDescriptor>,
    ) -> Result<(), StoreError> {
        let invoice_json = serde_json::to_string(invoice)
            .map_err(|e| StoreError::Invalid(format!("encode invoice: {e}")))?;
        let descriptor_json = descriptor
            .map(serde_json::to_string)
            .transpose()
            .map_err(|e| StoreError::Invalid(format!("encode descriptor: {e}")))?;
        self.conn.execute(&format!(
            "INSERT OR REPLACE INTO outgoing_payments \
             (payment_hash, invoice_json, sender_network, amount_msat, destination_pubkey, \
              destination_network, expiry, descriptor_json, status, created_at, resolved_at) \
             VALUES ('{}', {}, {}, {}, {}, {}, {}, {}, '{}', {}, NULL);",
            payment.payment_hash,
            escape_sql_string(&invoice_json),
            escape_sql_string(&sender_network.0),
            payment.amount_msat,
            escape_sql_string(&payment.destination_pubkey),
            escape_sql_string(&payment.destination_network.0),
            payment.expiry,
            option_sql_string(&descriptor_json),
            OutgoingPaymentStatus::Pending.as_str(),
            unix_now(),
        ))?;
        Ok(())
    }

    pub fn update_outgoing_descriptor(
        &mut self,
        payment_hash: &Bytes32,
        descriptor: &HtlcDescriptor,
    ) -> Result<(), StoreError> {
        let descriptor_json = serde_json::to_string(descriptor)
            .map_err(|e| StoreError::Invalid(format!("encode descriptor: {e}")))?;
        self.conn.execute(&format!(
            "UPDATE outgoing_payments SET descriptor_json={} WHERE payment_hash='{}';",
            escape_sql_string(&descriptor_json),
            payment_hash,
        ))?;
        Ok(())
    }

    pub fn list_pending_outgoing(&mut self) -> Result<Vec<PendingOutgoingPayment>, StoreError> {
        let result = self.conn.query(
            "SELECT invoice_json, payment_hash, sender_network, amount_msat, \
                    destination_pubkey, destination_network, expiry, descriptor_json, created_at \
             FROM outgoing_payments WHERE status='pending' ORDER BY created_at ASC;",
        )?;
        result
            .rows
            .iter()
            .map(|row| pending_outgoing_from_values(row.as_slice()))
            .collect()
    }

    pub fn mark_outgoing_status(
        &mut self,
        payment_hash: &Bytes32,
        status: OutgoingPaymentStatus,
    ) -> Result<(), StoreError> {
        self.conn.execute(&format!(
            "UPDATE outgoing_payments SET status='{}', resolved_at={} WHERE payment_hash='{}';",
            status.as_str(),
            unix_now(),
            payment_hash,
        ))?;
        Ok(())
    }

    pub fn record_payment_proof(
        &mut self,
        invoice: &Invoice,
        preimage: Bytes32,
    ) -> Result<(), StoreError> {
        let invoice_json = serde_json::to_string(invoice)
            .map_err(|e| StoreError::Invalid(format!("encode invoice: {e}")))?;
        self.conn.execute(&format!(
            "INSERT OR REPLACE INTO payment_proofs \
             (payment_hash, invoice_json, preimage, paid_at) \
             VALUES ('{}', {}, X'{}', {});",
            invoice.payment_hash,
            escape_sql_string(&invoice_json),
            hex::encode(preimage.0),
            unix_now(),
        ))?;
        Ok(())
    }

    pub fn get_payment_proof(
        &mut self,
        payment_hash: &Bytes32,
    ) -> Result<PaymentProof, StoreError> {
        let result = self.conn.query(&format!(
            "SELECT invoice_json, preimage, paid_at FROM payment_proofs \
             WHERE payment_hash='{}';",
            payment_hash,
        ))?;
        let row = result
            .rows
            .first()
            .ok_or_else(|| StoreError::NotFound(payment_hash.to_string()))?;
        let invoice = serde_json::from_str(&text_at(row, 0, "invoice_json")?)
            .map_err(|e| StoreError::Invalid(format!("invoice_json: {e}")))?;
        Ok(PaymentProof {
            invoice,
            preimage: Bytes32(blob_at(row, 1, "preimage")?),
            paid_at: int_at(row, 2, "paid_at")? as u64,
        })
    }

    pub fn get(&mut self, payment_hash: &Bytes32) -> Result<InvoiceRow, StoreError> {
        let result = self.conn.query(&format!(
            "SELECT payment_hash, preimage, amount_msat, network_id, payee, description, \
                    expires_at, status, created_at, claimed_at \
             FROM invoices WHERE payment_hash='{}';",
            payment_hash
        ))?;
        let row = result
            .rows
            .first()
            .ok_or_else(|| StoreError::NotFound(payment_hash.to_string()))?;
        row_from_values(row)
    }

    pub fn list(&mut self, status: Option<InvoiceStatus>) -> Result<Vec<InvoiceRow>, StoreError> {
        let where_clause = match status {
            Some(s) => format!("WHERE status='{}'", s.as_str()),
            None => String::new(),
        };
        let result = self.conn.query(&format!(
            "SELECT payment_hash, preimage, amount_msat, network_id, payee, description, \
                    expires_at, status, created_at, claimed_at \
             FROM invoices {} ORDER BY created_at DESC;",
            where_clause
        ))?;
        result
            .rows
            .iter()
            .map(|r| row_from_values(r.as_slice()))
            .collect()
    }
}

fn row_from_values(row: &[Value]) -> Result<InvoiceRow, StoreError> {
    let payment_hash_str = text_at(row, 0, "payment_hash")?;
    let payment_hash = parse_payment_hash_bytes(&payment_hash_str)
        .ok_or_else(|| StoreError::Invalid(format!("payment_hash: {payment_hash_str}")))?;
    let preimage = blob_at(row, 1, "preimage")?;
    let amount_msat = int_at(row, 2, "amount_msat")? as u64;
    let network_id = NetworkId(text_at(row, 3, "network_id")?);
    let payee = optional_text_at(row, 4, "payee")?;
    let description = optional_text_at(row, 5, "description")?;
    let expires_at = int_at(row, 6, "expires_at")? as u64;
    let status_str = text_at(row, 7, "status")?;
    let status = InvoiceStatus::parse(&status_str)
        .ok_or_else(|| StoreError::Invalid(format!("status: {status_str}")))?;
    let created_at = int_at(row, 8, "created_at")? as u64;
    let claimed_at = if matches!(row.get(9), Some(Value::Null) | None) {
        None
    } else {
        Some(int_at(row, 9, "claimed_at")? as u64)
    };
    Ok(InvoiceRow {
        payment_hash,
        preimage,
        amount_msat,
        network_id,
        payee,
        description,
        expires_at,
        status,
        created_at,
        claimed_at,
    })
}

fn pending_outgoing_from_values(row: &[Value]) -> Result<PendingOutgoingPayment, StoreError> {
    let invoice: Invoice = serde_json::from_str(&text_at(row, 0, "invoice_json")?)
        .map_err(|e| StoreError::Invalid(format!("invoice_json: {e}")))?;
    let payment_hash = parse_payment_hash_bytes(&text_at(row, 1, "payment_hash")?)
        .ok_or_else(|| StoreError::Invalid("payment_hash".into()))?;
    let sender_network = NetworkId(text_at(row, 2, "sender_network")?);
    let amount_msat = int_at(row, 3, "amount_msat")? as u64;
    let destination_pubkey = text_at(row, 4, "destination_pubkey")?;
    let destination_network = NetworkId(text_at(row, 5, "destination_network")?);
    let expiry = int_at(row, 6, "expiry")? as u64;
    let descriptor = match row.get(7) {
        Some(Value::Null) | None => None,
        Some(Value::Text(value)) => Some(
            serde_json::from_str(value)
                .map_err(|e| StoreError::Invalid(format!("descriptor_json: {e}")))?,
        ),
        other => {
            return Err(StoreError::Invalid(format!(
                "descriptor_json: expected nullable text, got {other:?}"
            )))
        }
    };
    let created_at = int_at(row, 8, "created_at")? as u64;
    Ok(PendingOutgoingPayment {
        invoice,
        payment: OutgoingPayment {
            payment_hash,
            amount_msat,
            destination_pubkey,
            destination_network,
            expiry,
        },
        sender_network,
        descriptor,
        created_at,
    })
}

fn text_at(row: &[Value], idx: usize, field: &str) -> Result<String, StoreError> {
    match row.get(idx) {
        Some(Value::Text(s)) => Ok(s.clone()),
        other => Err(StoreError::Invalid(format!(
            "{field}: expected text, got {other:?}"
        ))),
    }
}

fn optional_text_at(row: &[Value], idx: usize, field: &str) -> Result<Option<String>, StoreError> {
    match row.get(idx) {
        Some(Value::Null) | None => Ok(None),
        Some(Value::Text(s)) => Ok(Some(s.clone())),
        other => Err(StoreError::Invalid(format!(
            "{field}: expected nullable text, got {other:?}"
        ))),
    }
}

fn int_at(row: &[Value], idx: usize, field: &str) -> Result<i64, StoreError> {
    match row.get(idx) {
        Some(Value::Integer(i)) => Ok(*i),
        other => Err(StoreError::Invalid(format!(
            "{field}: expected integer, got {other:?}"
        ))),
    }
}

fn blob_at(row: &[Value], idx: usize, field: &str) -> Result<[u8; 32], StoreError> {
    match row.get(idx) {
        Some(Value::Blob(b)) if b.len() == 32 => {
            let mut out = [0u8; 32];
            out.copy_from_slice(b);
            Ok(out)
        }
        Some(Value::Blob(b)) => Err(StoreError::Invalid(format!(
            "{field}: expected 32-byte blob, got {} bytes",
            b.len()
        ))),
        other => Err(StoreError::Invalid(format!(
            "{field}: expected blob, got {other:?}"
        ))),
    }
}

fn escape_sql_string(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

fn option_sql_string(opt: &Option<String>) -> String {
    match opt {
        Some(s) => escape_sql_string(s),
        None => "NULL".to_string(),
    }
}

fn parse_payment_hash_bytes(s: &str) -> Option<Bytes32> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    let bytes = s.as_bytes();
    for i in 0..32 {
        let hi = hex_nibble(bytes[2 * i])?;
        let lo = hex_nibble(bytes[2 * i + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(Bytes32(out))
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Cashu proofs (only with the `cashu` feature)
//
// The wallet stores NUT-00 `Proof` objects as JSON blobs in a
// dedicated `cashu_proofs` table. Each row carries its own
// `mint_url` and `amount_sat` so we can list / sum without
// deserializing the blob. The `id` is a local synthetic; it
// is NOT a cashu protocol concept and is only used by the
// wallet to mark specific rows as spent.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct CashuProofRow {
    pub id: i64,
    pub mint_url: String,
    pub amount_sat: u64,
    /// JSON-serialized cashu `Proof`.
    pub proof_blob: Vec<u8>,
    pub created_at: u64,
}

impl Store {
    /// Append a batch of proofs to the wallet for `mint_url`.
    /// Each proof is its own row so the wallet can delete
    /// individual proofs when sending.
    pub fn insert_cashu_proofs(
        &mut self,
        mint_url: &str,
        proofs: &[cassis_cashu::Proof],
    ) -> Result<(), StoreError> {
        let now = unix_now();
        for proof in proofs {
            let amount_sat = u64::from(proof.amount);
            let blob = serde_json::to_vec(proof)
                .map_err(|e| StoreError::Invalid(format!("encode proof: {e}")))?;
            self.conn.execute(&format!(
                "INSERT INTO cashu_proofs (mint_url, amount_sat, proof_blob, created_at) \
                 VALUES ('{}', {}, X'{}', {});",
                mint_url.replace('\'', "''"),
                amount_sat,
                hex::encode(&blob),
                now,
            ))?;
        }
        Ok(())
    }

    /// List every proof for `mint_url` in insertion order. The
    /// wallet's `send` flow uses this to build the input set
    /// for [`crate::cmd_cashu_send`].
    pub fn list_cashu_proofs(&mut self, mint_url: &str) -> Result<Vec<CashuProofRow>, StoreError> {
        let result = self.conn.query(&format!(
            "SELECT id, mint_url, amount_sat, proof_blob, created_at \
             FROM cashu_proofs WHERE mint_url='{}' \
             ORDER BY id ASC;",
            mint_url.replace('\'', "''"),
        ))?;
        let mut out = Vec::with_capacity(result.rows.len());
        for row in result.rows.iter() {
            out.push(cashu_proof_row_from_values(row.as_slice())?);
        }
        Ok(out)
    }

    /// Delete proofs by their local row ids. Used after a
    /// successful `swap_proofs_for_amount` to mark the inputs
    /// spent (the mint already burned them at the swap).
    pub fn delete_cashu_proofs(&mut self, ids: &[i64]) -> Result<(), StoreError> {
        if ids.is_empty() {
            return Ok(());
        }
        let list = ids
            .iter()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(",");
        self.conn
            .execute(&format!("DELETE FROM cashu_proofs WHERE id IN ({list});"))?;
        Ok(())
    }

    /// Total balance (in sats) for `mint_url`. Convenience
    /// wrapper around [`Store::list_cashu_proofs`] for CLI
    /// status output.
    pub fn cashu_balance(&mut self, mint_url: &str) -> Result<u64, StoreError> {
        let result = self.conn.query(&format!(
            "SELECT COALESCE(SUM(amount_sat), 0) AS total FROM cashu_proofs WHERE mint_url='{}';",
            mint_url.replace('\'', "''"),
        ))?;
        let total = result
            .rows
            .first()
            .and_then(|r| r.first())
            .and_then(|v| match v {
                Value::Integer(i) => Some(*i as u64),
                _ => None,
            })
            .unwrap_or(0);
        Ok(total)
    }
}

/// A `CashuProofStore` implementation backed by the sqlite store
/// file. Holds only the path, not a connection — minisqlite's
/// `Connection` is not `Send`, so each operation opens a fresh,
/// short-lived [`Store`] (same pattern the COMMIT handler uses).
/// This keeps the adapter (which must be `Send + Sync`) free to
/// share the store across threads.
#[derive(Clone)]
pub struct CashuProofDb {
    path: PathBuf,
}

impl CashuProofDb {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl cassis_cashu::CashuProofStore for CashuProofDb {
    fn insert_proofs(
        &self,
        mint_url: &str,
        proofs: &[cassis_cashu::Proof],
    ) -> Result<(), cassis_cashu::Error> {
        let mut store = Store::open(&self.path)?;
        store.insert_cashu_proofs(mint_url, proofs)?;
        Ok(())
    }

    fn list_proofs(&self, mint_url: &str) -> Result<Vec<cassis_cashu::Proof>, cassis_cashu::Error> {
        let mut store = Store::open(&self.path)?;
        let rows = store.list_cashu_proofs(mint_url)?;
        rows.iter()
            .map(|r| {
                serde_json::from_slice(&r.proof_blob)
                    .map_err(|e| cassis_cashu::Error::Store(format!("decode proof: {e}")))
            })
            .collect()
    }

    fn remove_proofs(
        &self,
        mint_url: &str,
        proofs: &[cassis_cashu::Proof],
    ) -> Result<(), cassis_cashu::Error> {
        let mut store = Store::open(&self.path)?;
        let rows = store.list_cashu_proofs(mint_url)?;
        let drop_ids: Vec<i64> = rows
            .iter()
            .filter(|r| {
                proofs.iter().any(|p| {
                    r.amount_sat == u64::from(p.amount)
                        && r.proof_blob == serde_json::to_vec(p).unwrap_or_default().as_slice()
                })
            })
            .map(|r| r.id)
            .collect();
        store.delete_cashu_proofs(&drop_ids)?;
        Ok(())
    }
}

impl From<StoreError> for cassis_cashu::Error {
    fn from(e: StoreError) -> Self {
        cassis_cashu::Error::Store(e.to_string())
    }
}

fn cashu_proof_row_from_values(row: &[Value]) -> Result<CashuProofRow, StoreError> {
    let id = int_at(row, 0, "id")?;
    let mint_url = text_at(row, 1, "mint_url")?;
    let amount_sat = int_at(row, 2, "amount_sat")? as u64;
    let proof_blob = blob_at_var(row, 3, "proof_blob")?;
    let created_at = int_at(row, 4, "created_at")? as u64;
    Ok(CashuProofRow {
        id,
        mint_url,
        amount_sat,
        proof_blob,
        created_at,
    })
}

fn blob_at_var(row: &[Value], idx: usize, field: &str) -> Result<Vec<u8>, StoreError> {
    match row.get(idx) {
        Some(Value::Blob(b)) => Ok(b.clone()),
        other => Err(StoreError::Invalid(format!(
            "{field}: expected blob, got {other:?}"
        ))),
    }
}

mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        let mut s = String::with_capacity(bytes.as_ref().len() * 2);
        for b in bytes.as_ref() {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}

#[cfg(all(test, feature = "cashu"))]
mod cashu_tests {
    use super::*;
    // Via cassis-cashu's re-exports: this crate has no direct cashu/cdk
    // dependency of its own.
    use cassis_cashu::{Amount, KeysetId, Proof, PublicKey, Secret};
    use std::str::FromStr;

    fn fake_proof(amount_sat: u64, secret_seed: &str) -> Proof {
        // Hand-rolled so the test doesn't need a mint: a real
        // `Proof` carries a mint signature on `C`, but the
        // store layer only needs the JSON shape to round-trip.
        Proof {
            amount: Amount::from(amount_sat),
            keyset_id: KeysetId::from_str("009a1f293253e41e").unwrap(),
            secret: Secret::new(secret_seed),
            c: PublicKey::from_str(
                "02bc9097997d81afb2cc7346b5e4345a9346bd2a506eb7958598a72f0cf85163ea",
            )
            .unwrap(),
            witness: None,
            dleq: None,
            p2pk_e: None,
        }
    }

    fn open_in_memory() -> Store {
        Store::in_memory().expect("open in-memory store")
    }

    #[test]
    fn cashu_proofs_round_trip_through_store() {
        let mut store = open_in_memory();
        let proofs = vec![fake_proof(2, "a"), fake_proof(1, "b")];
        store
            .insert_cashu_proofs("cashu::mint.example.com", &proofs)
            .expect("insert");
        let rows = store
            .list_cashu_proofs("cashu::mint.example.com")
            .expect("list");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].amount_sat, 2);
        assert_eq!(rows[1].amount_sat, 1);
        let total = store
            .cashu_balance("cashu::mint.example.com")
            .expect("balance");
        assert_eq!(total, 3);
    }

    #[test]
    fn cashu_proofs_are_partitioned_by_mint() {
        let mut store = open_in_memory();
        let a = vec![fake_proof(2, "a")];
        let b = vec![fake_proof(4, "b"), fake_proof(8, "c")];
        store
            .insert_cashu_proofs("https://a.example.com", &a)
            .expect("insert a");
        store
            .insert_cashu_proofs("https://b.example.com", &b)
            .expect("insert b");
        assert_eq!(
            store
                .list_cashu_proofs("https://a.example.com")
                .expect("list a")
                .len(),
            1
        );
        assert_eq!(
            store
                .list_cashu_proofs("https://b.example.com")
                .expect("list b")
                .len(),
            2
        );
        assert_eq!(
            store.cashu_balance("https://a.example.com").expect("bal a"),
            2
        );
        assert_eq!(
            store.cashu_balance("https://b.example.com").expect("bal b"),
            12
        );
    }

    #[test]
    fn cashu_proofs_can_be_deleted_by_id() {
        let mut store = open_in_memory();
        let proofs = vec![fake_proof(1, "a"), fake_proof(2, "b"), fake_proof(4, "c")];
        store
            .insert_cashu_proofs("https://mint.example.com", &proofs)
            .expect("insert");
        let rows = store
            .list_cashu_proofs("https://mint.example.com")
            .expect("list");
        let drop: Vec<i64> = rows.iter().take(2).map(|r| r.id).collect();
        store.delete_cashu_proofs(&drop).expect("delete");
        let remaining = store
            .list_cashu_proofs("https://mint.example.com")
            .expect("list again");
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].amount_sat, 4);
    }

    #[test]
    fn delete_cashu_proofs_with_empty_ids_is_noop() {
        let mut store = open_in_memory();
        let proofs = vec![fake_proof(1, "a")];
        store
            .insert_cashu_proofs("https://mint.example.com", &proofs)
            .expect("insert");
        store.delete_cashu_proofs(&[]).expect("empty delete");
        assert_eq!(
            store
                .list_cashu_proofs("https://mint.example.com")
                .expect("list")
                .len(),
            1
        );
    }
}
