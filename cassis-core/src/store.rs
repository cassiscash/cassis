//! The node's database: one sqlite file of JSON records grouped in
//! tables (`invoices`, `payments`, `hops`, ...), keyed by string.

use minisqlite::{Connection, Value};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS records (
    tbl   TEXT NOT NULL,
    key   TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (tbl, key)
);";

pub struct Store {
    path: PathBuf,
    /// minisqlite connections are not `Send`, so each call opens its
    /// own; this serializes them within the process.
    lock: Mutex<()>,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("create {parent:?}: {e}"))?;
        }
        let store = Self {
            path: path.to_path_buf(),
            lock: Mutex::new(()),
        };
        store.with(|conn| conn.execute(SCHEMA))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("restrict {path:?}: {e}"))?;
        }
        Ok(store)
    }

    fn with<T>(
        &self,
        f: impl FnOnce(&mut Connection) -> Result<T, minisqlite::Error>,
    ) -> Result<T, String> {
        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut conn = Connection::open(&self.path)
            .map_err(|e| format!("open {}: {e}", self.path.display()))?;
        f(&mut conn).map_err(|e| format!("store: {e}"))
    }

    pub fn put<T: Serialize>(&self, table: &str, key: &str, value: &T) -> Result<(), String> {
        let json = serde_json::to_string(value).map_err(|e| format!("encode record: {e}"))?;
        self.with(|conn| {
            conn.execute(&format!(
                "INSERT OR REPLACE INTO records (tbl, key, value) VALUES ({}, {}, {});",
                quote(table),
                quote(key),
                quote(&json)
            ))
        })
    }

    pub fn get<T: DeserializeOwned>(&self, table: &str, key: &str) -> Result<Option<T>, String> {
        let rows = self.with(|conn| {
            conn.query(&format!(
                "SELECT value FROM records WHERE tbl = {} AND key = {};",
                quote(table),
                quote(key)
            ))
        })?;
        rows.rows.first().map(|row| decode(&row[0])).transpose()
    }

    pub fn list<T: DeserializeOwned>(&self, table: &str) -> Result<Vec<T>, String> {
        let rows = self.with(|conn| {
            conn.query(&format!(
                "SELECT value FROM records WHERE tbl = {} ORDER BY key;",
                quote(table)
            ))
        })?;
        rows.rows.iter().map(|row| decode(&row[0])).collect()
    }

    pub fn delete(&self, table: &str, key: &str) -> Result<(), String> {
        self.with(|conn| {
            conn.execute(&format!(
                "DELETE FROM records WHERE tbl = {} AND key = {};",
                quote(table),
                quote(key)
            ))
        })
    }
}

/// SQL string literal. minisqlite has no bound parameters.
fn quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "''"))
}

fn decode<T: DeserializeOwned>(value: &Value) -> Result<T, String> {
    match value {
        Value::Text(json) => serde_json::from_str(json).map_err(|e| format!("decode record: {e}")),
        other => Err(format!("record is not text: {other:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_round_trip_with_quotes() {
        let dir = std::env::temp_dir().join(format!("cassis-store-{}", rand::random::<u64>()));
        let store = Store::open(&dir.join("store.db")).unwrap();
        store.put("t", "a'b", &vec!["it's".to_string()]).unwrap();
        store.put("t", "c", &vec!["x".to_string()]).unwrap();
        assert_eq!(
            store.get::<Vec<String>>("t", "a'b").unwrap(),
            Some(vec!["it's".to_string()])
        );
        assert_eq!(store.list::<Vec<String>>("t").unwrap().len(), 2);
        store.delete("t", "c").unwrap();
        assert_eq!(store.get::<Vec<String>>("t", "c").unwrap(), None);
        assert!(store.list::<Vec<String>>("other").unwrap().is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }
}
