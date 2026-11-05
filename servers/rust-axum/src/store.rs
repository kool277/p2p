//! The four Host SPI stores, in SQLite, using the reference migration. The core owns
//! each record's fields, so this only files JSON documents.

use qalqon_sdk::{ErrorKind, api};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::Value;

const MIGRATION: &str = include_str!("../../../core/server-core/migrations/0001_init.sql");

pub struct Stores {
    db: Connection,
}

impl Stores {
    pub fn open(path: &str) -> rusqlite::Result<Self> {
        let db = Connection::open(path)?;
        db.pragma_update(None, "journal_mode", "WAL")?;
        let applied: i64 = db.query_row(
            "SELECT count(*) FROM sqlite_master WHERE name = 'qalqon_users'",
            [],
            |row| row.get(0),
        )?;
        if applied == 0 {
            db.execute_batch(MIGRATION)?;
        }
        Ok(Stores { db })
    }

    pub fn perform(
        &mut self,
        store: api::StoreKind,
        operation: api::StoreOperation,
        key: Option<String>,
        record: Option<Vec<u8>>,
    ) -> (u32, Option<Vec<u8>>) {
        match self.run(store, operation, key, record) {
            Ok(record) => (0, record),
            Err(e) => {
                eprintln!("a store operation failed: {e}");
                let code = if store == api::StoreKind::Audit { ErrorKind::AuditUnavailable } else { ErrorKind::Internal };
                (code.code(), None)
            }
        }
    }

    fn run(
        &mut self,
        store: api::StoreKind,
        operation: api::StoreOperation,
        key: Option<String>,
        record: Option<Vec<u8>>,
    ) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
        use api::StoreKind as K;
        use api::StoreOperation as O;
        let key_or_err = |k: Option<String>| k.ok_or("this operation needs a key");
        let text = |r: Option<Vec<u8>>| -> Result<String, Box<dyn std::error::Error>> {
            Ok(String::from_utf8(r.ok_or("this operation needs a record")?)?)
        };
        Ok(match (store, operation) {
            (K::User, O::Get) => self.get("SELECT record FROM qalqon_users WHERE user_id = ?1", &key_or_err(key)?)?,
            (K::Device, O::Get) => self.get("SELECT record FROM qalqon_devices WHERE device_id = ?1", &key_or_err(key)?)?,
            (K::Policy, O::Get) => self.get("SELECT record FROM qalqon_policies WHERE name = ?1", &key_or_err(key)?)?,
            (K::User, O::Put) => {
                self.db.execute(
                    "INSERT INTO qalqon_users (user_id, record) VALUES (?1, ?2)
                     ON CONFLICT (user_id) DO UPDATE SET record = excluded.record",
                    params![key_or_err(key)?, text(record)?],
                )?;
                None
            }
            (K::Device, O::Put) => {
                let document = text(record)?;
                let parsed: Value = serde_json::from_str(&document)?;
                let user = parsed["user_id"].as_str().ok_or("a device record has no user_id")?.to_string();
                self.db.execute(
                    "INSERT INTO qalqon_devices (device_id, user_id, record) VALUES (?1, ?2, ?3)
                     ON CONFLICT (device_id) DO UPDATE SET user_id = excluded.user_id, record = excluded.record",
                    params![key_or_err(key)?, user, document],
                )?;
                None
            }
            (K::Policy, O::Put) => {
                self.db.execute(
                    "INSERT INTO qalqon_policies (name, record) VALUES (?1, ?2)
                     ON CONFLICT (name) DO UPDATE SET record = excluded.record",
                    params![key_or_err(key)?, text(record)?],
                )?;
                None
            }
            (K::User, O::List) => Some(self.list("SELECT record FROM qalqon_users ORDER BY user_id", None)?),
            (K::Device, O::List) => match key.as_deref().and_then(|k| k.strip_prefix("user:")) {
                Some(user) => Some(self.list(
                    "SELECT record FROM qalqon_devices WHERE user_id = ?1 ORDER BY device_id",
                    Some(user),
                )?),
                None => Some(self.list("SELECT record FROM qalqon_devices ORDER BY device_id", None)?),
            },
            (K::Audit, O::Append) => {
                let document = text(record)?;
                let parsed: Value = serde_json::from_str(&document)?;
                let at = parsed["at"].as_i64().ok_or("an audit row has no time")?;
                let seq: i64 = key_or_err(key)?.parse()?;
                self.db.execute(
                    "INSERT INTO qalqon_audit (seq, at, record) VALUES (?1, ?2, ?3)",
                    params![seq, at, document],
                )?;
                None
            }
            (K::Audit, O::Head) => self
                .db
                .query_row("SELECT record FROM qalqon_audit ORDER BY seq DESC LIMIT 1", [], |row| row.get::<_, String>(0))
                .optional()?
                .map(String::into_bytes),
            (K::Audit, O::Range) => {
                let key = key_or_err(key)?;
                let (from, to) = key.split_once(',').ok_or("a range looks like from,to")?;
                let from: u64 = from.parse()?;
                let to: u64 = to.parse()?;
                let to = i64::try_from(to).unwrap_or(i64::MAX);
                let mut statement = self.db.prepare("SELECT record FROM qalqon_audit WHERE seq BETWEEN ?1 AND ?2 ORDER BY seq")?;
                let rows = statement.query_map(params![from as i64, to], |row| row.get::<_, String>(0))?;
                let mut values = Vec::new();
                for row in rows {
                    values.push(serde_json::from_str::<Value>(&row?)?);
                }
                Some(serde_json::to_vec(&values)?)
            }
            _ => return Err(format!("{store:?} does not support {operation:?}").into()),
        })
    }

    fn get(&self, sql: &str, key: &str) -> rusqlite::Result<Option<Vec<u8>>> {
        Ok(self.db.query_row(sql, [key], |row| row.get::<_, String>(0)).optional()?.map(String::into_bytes))
    }

    fn list(&self, sql: &str, parameter: Option<&str>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut statement = self.db.prepare(sql)?;
        let collect = |row: &rusqlite::Row<'_>| row.get::<_, String>(0);
        let rows: Vec<String> = match parameter {
            Some(p) => statement.query_map([p], collect)?.collect::<Result<_, _>>()?,
            None => statement.query_map([], collect)?.collect::<Result<_, _>>()?,
        };
        let values: Vec<Value> = rows.iter().map(|r| serde_json::from_str(r)).collect::<Result<_, _>>()?;
        Ok(serde_json::to_vec(&values)?)
    }
}
