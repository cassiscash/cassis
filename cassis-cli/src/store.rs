use cassis_core::{Bytes32, NetworkId};
use minisqlite::{Connection, Error as SqlError, Value};
use std::path::Path;
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
";

/// Lifecycle of an invoice row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvoiceStatus {
    Pending,
    Claimed,
    Failed,
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

mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        let mut s = String::with_capacity(bytes.as_ref().len() * 2);
        for b in bytes.as_ref() {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}
