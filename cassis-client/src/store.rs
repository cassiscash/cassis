use cassis_core::{
    Bytes32, HtlcDescriptor, HtlcTarget, Invoice, InvoiceHandle, NetworkId, OperationId,
    OutgoingPayment,
};
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

-- One row per payment *attempt*. `operation_id` identifies a single
-- protocol attempt and is the primary key; `payment_hash` identifies
-- the payment intent and is deliberately non-unique so a retried or
-- re-routed payment can keep several attempts alive side by side.
CREATE TABLE IF NOT EXISTS outgoing_payments (
    operation_id       TEXT PRIMARY KEY,
    payment_hash       TEXT NOT NULL,
    invoice_json       TEXT NOT NULL,
    sender_network     TEXT NOT NULL,
    amount_msat        INTEGER NOT NULL,
    destination_pubkey TEXT NOT NULL,
    destination_network TEXT NOT NULL,
    expiry             INTEGER NOT NULL,
    descriptor_json    TEXT NOT NULL,
    status             TEXT NOT NULL,
    created_at         INTEGER NOT NULL,
    resolved_at        INTEGER
);
CREATE INDEX IF NOT EXISTS outgoing_payments_status_idx
    ON outgoing_payments(status);
CREATE INDEX IF NOT EXISTS outgoing_payments_hash_idx
    ON outgoing_payments(payment_hash);

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

CREATE TABLE IF NOT EXISTS invoice_handles (
    payment_hash   TEXT PRIMARY KEY,
    operation_id   TEXT NOT NULL,
    invoice_json   TEXT NOT NULL,
    reservation_json TEXT NOT NULL,
    preimage       BLOB NOT NULL,
    created_at     INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS commit_attempts (
    operation_id TEXT PRIMARY KEY,
    payment_hash TEXT NOT NULL,
    preimage     BLOB NOT NULL,
    created_at   INTEGER NOT NULL
);
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
        #[cfg(unix)]
        if path.exists() {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = std::fs::metadata(path)
                .map_err(|error| StoreError::Sqlite(error.to_string()))?
                .permissions();
            permissions.set_mode(0o600);
            std::fs::set_permissions(path, permissions)
                .map_err(|error| StoreError::Sqlite(error.to_string()))?;
        }
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

    /// Persist one outgoing attempt keyed by its `operation_id`. Two
    /// attempts for the same `payment_hash` coexist: the primary key is
    /// the attempt identifier, so a retry with a fresh operation id
    /// becomes its own row instead of clobbering the previous one.
    pub fn insert_outgoing_payment(
        &mut self,
        invoice: &Invoice,
        payment: &OutgoingPayment,
        sender_network: &NetworkId,
    ) -> Result<(), StoreError> {
        validate_operation_id(&payment.operation_id)?;
        if invoice.payment_hash != payment.payment_hash {
            return Err(StoreError::Invalid(
                "invoice payment hash does not match outgoing payment".into(),
            ));
        }
        let invoice_json = serde_json::to_string(invoice)
            .map_err(|e| StoreError::Invalid(format!("encode invoice: {e}")))?;
        let descriptor = &payment.descriptor;
        let descriptor_json = serde_json::to_string(descriptor)
            .map_err(|e| StoreError::Invalid(format!("encode descriptor: {e}")))?;
        let destination_json = serde_json::to_string(&payment.destination)
            .map_err(|e| StoreError::Invalid(format!("encode destination: {e}")))?;
        let existing = self.conn.query(&format!(
            "SELECT payment_hash, invoice_json, amount_msat, destination_pubkey, \
                    destination_network, expiry, descriptor_json \
             FROM outgoing_payments WHERE operation_id={};",
            escape_sql_string(payment.operation_id.as_str())
        ))?;
        if let Some(row) = existing.rows.first() {
            let existing_hash = parse_payment_hash_bytes(&text_at(row, 0, "payment_hash")?)
                .ok_or_else(|| StoreError::Invalid("payment_hash".into()))?;
            let same = existing_hash == payment.payment_hash
                && text_at(row, 1, "invoice_json")?.as_str() == invoice_json.as_str()
                && int_at(row, 2, "amount_msat")? as u64 == payment.amount_msat
                && text_at(row, 3, "destination_pubkey")?.as_str() == destination_json.as_str()
                && text_at(row, 4, "destination_network")?.as_str()
                    == payment.destination_network.0.as_str()
                && int_at(row, 5, "expiry")? as u64 == payment.expiry
                && text_at(row, 6, "descriptor_json")?.as_str() == descriptor_json.as_str();
            if same {
                return Ok(());
            }
            return Err(StoreError::Invalid(format!(
                "operation_id {} is already bound to different outgoing state",
                payment.operation_id
            )));
        }
        self.conn.execute(&format!(
            "INSERT INTO outgoing_payments \
             (operation_id, payment_hash, invoice_json, sender_network, amount_msat, destination_pubkey, \
              destination_network, expiry, descriptor_json, status, created_at, resolved_at) \
             VALUES ({}, '{}', {}, {}, {}, {}, {}, {}, {}, '{}', {}, NULL);",
            escape_sql_string(payment.operation_id.as_str()),
            payment.payment_hash,
            escape_sql_string(&invoice_json),
            escape_sql_string(&sender_network.0),
            payment.amount_msat,
            escape_sql_string(&destination_json),
            escape_sql_string(&payment.destination_network.0),
            payment.expiry,
            escape_sql_string(&descriptor_json),
            OutgoingPaymentStatus::Pending.as_str(),
            unix_now(),
        ))?;
        Ok(())
    }

    pub fn get_commit_attempt(
        &mut self,
        operation_id: &OperationId,
    ) -> Result<Option<(Bytes32, [u8; 32])>, StoreError> {
        let result = self.conn.query(&format!(
            "SELECT payment_hash, preimage FROM commit_attempts WHERE operation_id={};",
            escape_sql_string(operation_id.as_str())
        ))?;
        let Some(row) = result.rows.first() else {
            return Ok(None);
        };
        let payment_hash = parse_payment_hash_bytes(&text_at(row, 0, "payment_hash")?)
            .ok_or_else(|| StoreError::Invalid("commit payment_hash".into()))?;
        let bytes = lowercase_hex::decode(&text_at(row, 1, "preimage")?)
            .map_err(|e| StoreError::Invalid(format!("commit preimage: {e}")))?;
        let preimage = bytes
            .try_into()
            .map_err(|_| StoreError::Invalid("commit preimage must be 32 bytes".into()))?;
        Ok(Some((payment_hash, preimage)))
    }

    pub fn insert_commit_attempt(
        &mut self,
        operation_id: &OperationId,
        payment_hash: Bytes32,
        preimage: [u8; 32],
    ) -> Result<(), StoreError> {
        validate_operation_id(operation_id)?;
        self.conn.execute(&format!(
            "INSERT OR REPLACE INTO commit_attempts \
             (operation_id, payment_hash, preimage, created_at) VALUES ({}, '{}', '{}', {});",
            escape_sql_string(operation_id.as_str()),
            payment_hash,
            lowercase_hex::encode(preimage),
            unix_now(),
        ))?;
        Ok(())
    }

    pub fn insert_invoice_handle(&mut self, handle: &InvoiceHandle) -> Result<(), StoreError> {
        if !handle.reservation.operation_id.is_valid() {
            return Err(StoreError::Invalid(
                "invoice reservation operation_id must be 32 hexadecimal characters".into(),
            ));
        }
        if handle.invoice.networks.len() != 1
            || handle.reservation.payment_hash != handle.invoice.payment_hash
            || handle.reservation.network != handle.invoice.networks[0]
        {
            return Err(StoreError::Invalid(
                "invoice handle reservation does not match invoice".into(),
            ));
        }
        let invoice_json = serde_json::to_string(&handle.invoice)
            .map_err(|e| StoreError::Invalid(format!("encode invoice handle: {e}")))?;
        let reservation_json = serde_json::to_string(&handle.reservation)
            .map_err(|e| StoreError::Invalid(format!("encode invoice reservation: {e}")))?;
        let preimage = lowercase_hex::encode(handle.preimage.0);
        self.conn.execute(&format!(
            "INSERT OR REPLACE INTO invoice_handles \
             (payment_hash, operation_id, invoice_json, reservation_json, preimage, created_at) \
             VALUES ('{}', {}, {}, {}, '{}', {});",
            handle.invoice.payment_hash,
            escape_sql_string(handle.reservation.operation_id.as_str()),
            escape_sql_string(&invoice_json),
            escape_sql_string(&reservation_json),
            preimage,
            unix_now(),
        ))?;
        Ok(())
    }

    pub fn list_invoice_handles(&mut self) -> Result<Vec<InvoiceHandle>, StoreError> {
        let result = self.conn.query(
            "SELECT invoice_json, reservation_json, preimage FROM invoice_handles ORDER BY created_at ASC;",
        )?;
        result
            .rows
            .iter()
            .map(|row| {
                let invoice: Invoice = serde_json::from_str(&text_at(row, 0, "invoice_json")?)
                    .map_err(|e| StoreError::Invalid(format!("invoice_json: {e}")))?;
                let reservation = serde_json::from_str(&text_at(row, 1, "reservation_json")?)
                    .map_err(|e| StoreError::Invalid(format!("reservation_json: {e}")))?;
                let preimage_hex = text_at(row, 2, "preimage")?;
                let bytes = lowercase_hex::decode(&preimage_hex)
                    .map_err(|e| StoreError::Invalid(format!("preimage: {e}")))?;
                let preimage: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| StoreError::Invalid("preimage must be 32 bytes".into()))?;
                Ok(InvoiceHandle {
                    invoice,
                    reservation,
                    preimage: Bytes32(preimage),
                })
            })
            .collect()
    }

    /// Every attempt still in `pending`, oldest first. The returned
    /// `operation_id` is the row key, so callers mark or restore the
    /// exact attempt they resumed.
    pub fn list_pending_outgoing(&mut self) -> Result<Vec<PendingOutgoingPayment>, StoreError> {
        let result = self.conn.query(
            "SELECT operation_id, payment_hash, invoice_json, sender_network, amount_msat, \
                    destination_pubkey, destination_network, expiry, descriptor_json, created_at \
             FROM outgoing_payments WHERE status='pending' ORDER BY created_at ASC;",
        )?;
        result
            .rows
            .iter()
            .map(|row| pending_outgoing_from_values(row.as_slice()))
            .collect()
    }

    /// Resolve one attempt by its `operation_id`. Attempts sharing a
    /// `payment_hash` are left untouched.
    pub fn mark_outgoing_status(
        &mut self,
        operation_id: &OperationId,
        status: OutgoingPaymentStatus,
    ) -> Result<(), StoreError> {
        validate_operation_id(operation_id)?;
        self.conn.execute(&format!(
            "UPDATE outgoing_payments SET status='{}', resolved_at={} WHERE operation_id={};",
            status.as_str(),
            unix_now(),
            escape_sql_string(operation_id.as_str()),
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
    let operation_id = OperationId(text_at(row, 0, "operation_id")?);
    if !operation_id.is_valid() {
        return Err(StoreError::Invalid(
            "operation_id must be 32 hexadecimal characters".into(),
        ));
    }
    let payment_hash = parse_payment_hash_bytes(&text_at(row, 1, "payment_hash")?)
        .ok_or_else(|| StoreError::Invalid("payment_hash".into()))?;
    let invoice: Invoice = serde_json::from_str(&text_at(row, 2, "invoice_json")?)
        .map_err(|e| StoreError::Invalid(format!("invoice_json: {e}")))?;
    let sender_network = NetworkId(text_at(row, 3, "sender_network")?);
    let amount_msat = int_at(row, 4, "amount_msat")? as u64;
    let destination = serde_json::from_str::<HtlcTarget>(&text_at(row, 5, "destination_pubkey")?)
        .map_err(|e| StoreError::Invalid(format!("destination_pubkey: {e}")))?;
    let destination_network = NetworkId(text_at(row, 6, "destination_network")?);
    let expiry = int_at(row, 7, "expiry")? as u64;
    let descriptor: HtlcDescriptor = serde_json::from_str(&text_at(row, 8, "descriptor_json")?)
        .map_err(|e| StoreError::Invalid(format!("descriptor_json: {e}")))?;
    let created_at = int_at(row, 9, "created_at")? as u64;
    Ok(PendingOutgoingPayment {
        invoice,
        payment: OutgoingPayment {
            operation_id,
            payment_hash,
            amount_msat,
            destination,
            destination_network,
            expiry,
            descriptor,
        },
        sender_network,
        created_at,
    })
}

/// Reject operation ids that could not round-trip through the store's
/// primary key column.
fn validate_operation_id(operation_id: &OperationId) -> Result<(), StoreError> {
    if !operation_id.is_valid() {
        return Err(StoreError::Invalid(
            "operation_id must be 32 hexadecimal characters".into(),
        ));
    }
    Ok(())
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

#[cfg(test)]
mod store_tests {
    use super::*;
    use cassis_core::{IncomingReservation, XOnlyPubKey};

    fn test_key() -> XOnlyPubKey {
        XOnlyPubKey::from_bytes([
            0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
            0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b,
            0x16, 0xf8, 0x17, 0x98,
        ])
        .expect("valid test x-only key")
    }

    fn fixture_invoice() -> Invoice {
        Invoice {
            payment_hash: Bytes32([7u8; 32]),
            amount_msat: 1_000,
            payee: test_key(),
            expires_at: 2_000,
            networks: vec![NetworkId("cashu".into())],
            address: HtlcTarget::XOnlyPubKey(test_key()),
            description: None,
            iroh_peer_id: None,
            iroh_relay: None,
        }
    }

    fn fixture_payment(invoice: &Invoice, operation_id: &str) -> OutgoingPayment {
        OutgoingPayment {
            operation_id: OperationId(operation_id.into()),
            payment_hash: invoice.payment_hash,
            amount_msat: invoice.amount_msat,
            destination: HtlcTarget::XOnlyPubKey(test_key()),
            destination_network: NetworkId("cashu".into()),
            expiry: 2_000,
            descriptor: HtlcDescriptor::Cashu {
                proofs_b64: vec!["descriptor".into()],
            },
        }
    }

    #[test]
    fn outgoing_attempts_are_keyed_by_operation_id() {
        let mut store = Store::in_memory().expect("open store");
        let invoice = fixture_invoice();
        let first = fixture_payment(&invoice, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let second = fixture_payment(&invoice, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        store
            .insert_outgoing_payment(&invoice, &first, &NetworkId("cashu".into()))
            .expect("insert first");
        store
            .insert_outgoing_payment(&invoice, &second, &NetworkId("cashu".into()))
            .expect("insert second");

        let pending = store.list_pending_outgoing().expect("list pending");
        assert_eq!(pending.len(), 2);
        assert!(pending
            .iter()
            .any(|row| row.payment.operation_id == first.operation_id));
        assert!(pending
            .iter()
            .any(|row| row.payment.operation_id == second.operation_id));

        store
            .mark_outgoing_status(&first.operation_id, OutgoingPaymentStatus::Completed)
            .expect("mark first");
        let pending = store.list_pending_outgoing().expect("list after mark");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].payment.operation_id, second.operation_id);
    }

    #[test]
    fn operation_keyed_auxiliary_rows_round_trip() {
        let mut store = Store::in_memory().expect("open store");
        let operation_id = OperationId("cccccccccccccccccccccccccccccccc".into());
        let payment_hash = Bytes32([4u8; 32]);
        store
            .insert_commit_attempt(&operation_id, payment_hash, [3u8; 32])
            .expect("insert commit attempt");
        assert_eq!(
            store
                .get_commit_attempt(&operation_id)
                .expect("get commit attempt"),
            Some((payment_hash, [3u8; 32]))
        );

        let invoice = fixture_invoice();
        let reservation_payment_hash = invoice.payment_hash;
        let handle = InvoiceHandle {
            invoice,
            reservation: IncomingReservation {
                operation_id: OperationId("dddddddddddddddddddddddddddddddd".into()),
                payment_hash: reservation_payment_hash,
                network: NetworkId("cashu".into()),
                amount_msat: 1_000,
                deadline: 2_000,
                target: HtlcTarget::XOnlyPubKey(test_key()),
            },
            preimage: Bytes32([6u8; 32]),
        };
        store.insert_invoice_handle(&handle).expect("insert handle");
        let handles = store.list_invoice_handles().expect("list handles");
        assert_eq!(handles.len(), 1);
        assert_eq!(handles[0].reservation, handle.reservation);
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
