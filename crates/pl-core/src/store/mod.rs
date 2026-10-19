//! The append-only local event store (SPEC §5.6): SQLite through the system library, WAL
//! mode, forward-only migrations, a thin typed layer and no ORM.

use std::fmt;
use std::path::{Path, PathBuf};

use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};

use crate::schema::{DropReason, Event, Kind};

/// Version of the SQL schema in this build. Bumped with every migration appended.
pub const STORE_SCHEMA_VERSION: u32 = 2;

const MIGRATIONS: &[(u32, &str)] = &[(1, include_str!("v1.sql")), (2, include_str!("v2.sql"))];

const META_SCHEMA_VERSION: &str = "schema_version";
const META_HIGH_WATER: &str = "event_high_water";
const MAX_DATABASE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_BATCH_BYTES: usize = 4 * 1024 * 1024;
const MAX_STORED_JSON_BYTES: i64 = 64 * 1024 * 1024;
const MAX_STORED_EVENTS: i64 = 100_000;
const RETENTION_SECONDS: i64 = 7 * 24 * 60 * 60;
const MIN_FREE_BYTES: u64 = 512 * 1024 * 1024;
const META_RETENTION_FLOOR: &str = "retention_floor";

#[derive(Debug)]
pub enum StoreError {
    Sqlite(rusqlite::Error),
    Json(serde_json::Error),
    Migration(String),
    Capacity(String),
    /// An I/O error raised by a caller's callback, e.g. a closed pipe while dumping.
    Io(std::io::Error),
    /// Ids must be contiguous and strictly increasing from the persisted high-water mark.
    IdOrder {
        expected: u64,
        got: u64,
    },
    /// A `u64` that does not fit SQLite's signed 64-bit INTEGER.
    Range(u64),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Sqlite(e) => write!(f, "sqlite: {e}"),
            StoreError::Json(e) => write!(f, "json: {e}"),
            StoreError::Migration(m) => write!(f, "migration: {m}"),
            StoreError::Capacity(m) => write!(f, "telemetry capacity: {m}"),
            StoreError::Io(e) => write!(f, "io: {e}"),
            StoreError::IdOrder { expected, got } => {
                write!(f, "event id order: expected {expected}, got {got}")
            }
            StoreError::Range(n) => write!(f, "value {n} exceeds the SQLite INTEGER range"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        StoreError::Sqlite(e)
    }
}

impl From<std::io::Error> for StoreError {
    fn from(e: std::io::Error) -> Self {
        StoreError::Io(e)
    }
}

impl From<serde_json::Error> for StoreError {
    fn from(e: serde_json::Error) -> Self {
        StoreError::Json(e)
    }
}

pub type Result<T> = std::result::Result<T, StoreError>;

/// Outcome of [`EventStore::verify`].
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    pub schema_version: u32,
    pub events: u64,
    pub high_water: u64,
    /// SQLite's `PRAGMA integrity_check` result; `ok` when clean.
    pub integrity: String,
    /// Human-readable problems, capped at [`VerifyReport::MAX_PROBLEMS`].
    pub problems: Vec<String>,
}

impl VerifyReport {
    pub const MAX_PROBLEMS: usize = 50;

    pub fn is_ok(&self) -> bool {
        self.integrity == "ok" && self.problems.is_empty()
    }
}

/// SQLite INTEGER is signed 64-bit; rusqlite 0.40 does not convert `u64` for us.
fn to_db(n: u64) -> Result<i64> {
    i64::try_from(n).map_err(|_| StoreError::Range(n))
}

/// Inverse of [`to_db`]. A negative value cannot come from this store; it maps to `0`,
/// which [`EventStore::verify`] then reports as a mismatch.
fn from_db(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

fn drop_reason_str(reason: DropReason) -> &'static str {
    match reason {
        DropReason::SequenceGap => "sequence_gap",
        DropReason::RingFull => "ring_full",
        DropReason::AppDisconnected => "app_disconnected",
    }
}

pub struct EventStore {
    conn: Connection,
    path: Option<PathBuf>,
}

impl EventStore {
    /// Opens or creates a store, applying pending migrations.
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")?;
        let mut store = Self::init(conn)?;
        store.path = Some(path.canonicalize()?);
        Ok(store)
    }

    /// Opens an existing store read-only. Fails if its schema is not this build's version.
    pub fn open_read_only(path: &Path) -> Result<Self> {
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        let store = Self { conn, path: None };
        let version = store.schema_version()?;
        if version != STORE_SCHEMA_VERSION {
            return Err(StoreError::Migration(format!(
                "read-only open of schema version {version}; this build is {STORE_SCHEMA_VERSION}"
            )));
        }
        Ok(store)
    }

    /// An in-memory store for tests and headless replay.
    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        let mut store = Self { conn, path: None };
        let page_size: i64 = store.conn.query_row("PRAGMA page_size", [], |r| r.get(0))?;
        let pages = MAX_DATABASE_BYTES as i64 / page_size;
        let actual: i64 =
            store
                .conn
                .query_row(&format!("PRAGMA max_page_count = {pages}"), [], |r| {
                    r.get(0)
                })?;
        if actual > pages {
            return Err(StoreError::Capacity(
                "existing database exceeds byte budget; retain it for offline recovery".into(),
            ));
        }
        store
            .conn
            .execute_batch("PRAGMA journal_size_limit = 0; PRAGMA wal_autocheckpoint = 256;")?;
        store.migrate()?;
        Ok(store)
    }

    fn meta_get(conn: &Connection, key: &str) -> Result<Option<String>> {
        let has_meta: u32 = conn.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'meta'",
            [],
            |r| r.get(0),
        )?;
        if has_meta == 0 {
            return Ok(None);
        }
        Ok(conn
            .query_row("SELECT value FROM meta WHERE key = ?1", params![key], |r| {
                r.get(0)
            })
            .optional()?)
    }

    fn meta_set(tx: &Transaction<'_>, key: &str, value: &str) -> Result<()> {
        tx.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2) \
             ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    fn migrate(&mut self) -> Result<()> {
        let current = self.schema_version()?;
        if current > STORE_SCHEMA_VERSION {
            return Err(StoreError::Migration(format!(
                "store is schema version {current}; this build only knows {STORE_SCHEMA_VERSION}"
            )));
        }
        for (version, sql) in MIGRATIONS {
            if *version > current {
                let tx = self.conn.transaction()?;
                tx.execute_batch(sql)?;
                Self::meta_set(&tx, META_SCHEMA_VERSION, &version.to_string())?;
                tx.commit()?;
            }
        }
        Ok(())
    }

    /// The SQL schema version of the open store (`0` for an empty database).
    pub fn schema_version(&self) -> Result<u32> {
        Ok(Self::meta_get(&self.conn, META_SCHEMA_VERSION)?
            .and_then(|v| v.parse().ok())
            .unwrap_or(0))
    }

    /// Highest event id ever appended, persisted so ids survive restarts.
    pub fn high_water(&self) -> Result<u64> {
        Ok(Self::meta_get(&self.conn, META_HIGH_WATER)?
            .and_then(|v| v.parse().ok())
            .unwrap_or(0))
    }

    fn available_bytes(&self) -> Result<u64> {
        let Some(path) = &self.path else {
            return Ok(u64::MAX);
        };
        // Fixed system executable, no shell or caller-selected arguments/environment.
        let output = std::process::Command::new("/bin/df")
            .args(["-Pk"])
            .arg(path)
            .env_clear()
            .env("LC_ALL", "C")
            .output()?;
        if !output.status.success() {
            return Err(StoreError::Capacity(
                "cannot establish free disk space".into(),
            ));
        }
        let text = String::from_utf8_lossy(&output.stdout);
        text.lines()
            .last()
            .and_then(|line| line.split_whitespace().nth(3))
            .and_then(|value| value.parse::<u64>().ok())
            .and_then(|blocks| blocks.checked_mul(1024))
            .ok_or_else(|| StoreError::Capacity("invalid free-space report".into()))
    }

    fn admit_space(available: u64) -> Result<()> {
        if available < MIN_FREE_BYTES + MAX_BATCH_BYTES as u64 * 4 {
            return Err(StoreError::Capacity(
                "low disk: collection batch not saved".into(),
            ));
        }
        Ok(())
    }

    fn checkpoint(&self) -> Result<()> {
        let busy: i64 = self
            .conn
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| r.get(0))?;
        if busy != 0 {
            return Err(StoreError::Capacity(
                "WAL checkpoint blocked by reader; collection paused".into(),
            ));
        }
        Ok(())
    }

    /// Cumulative prefix eviction count; IDs are never recycled or hidden as contiguous history.
    pub fn retention_floor(&self) -> Result<u64> {
        Ok(Self::meta_get(&self.conn, META_RETENTION_FLOOR)?
            .and_then(|v| v.parse().ok())
            .unwrap_or(0))
    }

    fn retain(tx: &Transaction<'_>, now: i64, max_events: i64, max_bytes: i64) -> Result<()> {
        let mut floor: i64 = tx.query_row(
            "SELECT coalesce(max(id), 0) FROM events WHERE stored_at < ?1",
            [now.saturating_sub(RETENTION_SECONDS)],
            |r| r.get(0),
        )?;
        let count_floor: i64 = tx.query_row(
            "SELECT coalesce((SELECT id FROM events ORDER BY id DESC LIMIT 1 OFFSET ?1), 0)",
            [max_events],
            |r| r.get(0),
        )?;
        floor = floor.max(count_floor);
        let mut total: i64 = tx.query_row(
            "SELECT coalesce(sum(length(CAST(json AS BLOB))), 0) FROM events WHERE id > ?1",
            [floor],
            |r| r.get(0),
        )?;
        if total > max_bytes {
            let mut stmt = tx.prepare(
                "SELECT id, length(CAST(json AS BLOB)) FROM events WHERE id > ?1 ORDER BY id",
            )?;
            let rows =
                stmt.query_map([floor], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)))?;
            for row in rows {
                let (id, bytes) = row?;
                floor = id;
                total -= bytes;
                if total <= max_bytes {
                    break;
                }
            }
        }
        if floor > 0 {
            tx.execute("DELETE FROM drops WHERE event_id <= ?1", [floor])?;
            tx.execute("DELETE FROM events WHERE id <= ?1", [floor])?;
            let previous = Self::meta_get(tx, META_RETENTION_FLOOR)?
                .and_then(|v| v.parse::<i64>().ok())
                .unwrap_or(0);
            Self::meta_set(tx, META_RETENTION_FLOOR, &floor.max(previous).to_string())?;
        }
        Ok(())
    }

    /// Appends a batch in one transaction. Ids must already be assigned and continue the
    /// high-water mark contiguously; anything else is rejected and nothing is written.
    pub fn append(&mut self, events: &[Event]) -> Result<()> {
        if events.is_empty() {
            return Ok(());
        }
        if events.len() > 1024 {
            return Err(StoreError::Capacity("batch exceeds 1024 events".into()));
        }
        Self::admit_space(self.available_bytes()?)?;
        self.checkpoint()?;
        let mut jsons = Vec::new();
        let mut bytes = 0usize;
        for event in events {
            let json = event.to_json_line()?;
            bytes = bytes.saturating_add(json.len());
            if bytes > MAX_BATCH_BYTES {
                return Err(StoreError::Capacity(
                    "batch exceeds serialized byte budget".into(),
                ));
            }
            jsons.push(json);
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| StoreError::Capacity("invalid retention clock".into()))?
            .as_secs() as i64;
        // IMMEDIATE takes the write lock before reading the high-water mark, so a second
        // writer waits on the busy handler instead of failing with BUSY_SNAPSHOT.
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut high_water = Self::meta_get(&tx, META_HIGH_WATER)?
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        {
            let mut insert = tx.prepare_cached(
                "INSERT INTO events (id, mach_time, wall_time, seq_num, global_seq_num, source, \
                 kind, process_token, parent_token, json, stored_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            )?;
            let mut insert_drop = tx.prepare_cached(
                "INSERT INTO drops (event_id, event_type, expected_seq, got_seq, count, reason) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )?;
            for (event, json) in events.iter().zip(&jsons) {
                let expected = high_water + 1;
                if event.id != expected {
                    return Err(StoreError::IdOrder {
                        expected,
                        got: event.id,
                    });
                }
                insert.execute(params![
                    to_db(event.id)?,
                    to_db(event.mach_time.0)?,
                    event.wall_time.0,
                    to_db(event.seq_num)?,
                    to_db(event.global_seq_num)?,
                    event.source.as_str(),
                    event.kind.discriminator(),
                    event.process.token.key(),
                    event.process.parent_token.key(),
                    json,
                    now,
                ])?;
                if let Kind::Drop {
                    event_type,
                    expected_seq,
                    got_seq,
                    count,
                    reason,
                } = &event.kind
                {
                    insert_drop.execute(params![
                        to_db(event.id)?,
                        event_type,
                        to_db(*expected_seq)?,
                        to_db(*got_seq)?,
                        to_db(*count)?,
                        drop_reason_str(*reason),
                    ])?;
                }
                high_water = event.id;
            }
        }
        Self::meta_set(&tx, META_HIGH_WATER, &high_water.to_string())?;
        Self::retain(&tx, now, MAX_STORED_EVENTS, MAX_STORED_JSON_BYTES)?;
        tx.commit()?;
        Ok(())
    }

    pub fn count(&self) -> Result<u64> {
        Ok(self
            .conn
            .query_row("SELECT count(*) FROM events", [], |r| r.get::<_, i64>(0))
            .map(from_db)?)
    }

    /// Streams events with `from <= id <= to` in id order.
    pub fn for_each_event<F>(&self, from: u64, to: Option<u64>, mut f: F) -> Result<()>
    where
        F: FnMut(Event) -> Result<()>,
    {
        let from = to_db(from)?;
        let to = to.map(to_db).transpose()?.unwrap_or(i64::MAX);
        let mut stmt = self
            .conn
            .prepare_cached("SELECT json FROM events WHERE id >= ?1 AND id <= ?2 ORDER BY id")?;
        let rows = stmt.query_map(params![from, to], |r| r.get::<_, String>(0))?;
        for row in rows {
            let event: Event = serde_json::from_str(&row?)?;
            f(event)?;
        }
        Ok(())
    }

    /// Collects a range of events. Prefer [`for_each_event`](Self::for_each_event) for large
    /// ranges.
    pub fn events(&self, from: u64, to: Option<u64>) -> Result<Vec<Event>> {
        let mut out = Vec::new();
        self.for_each_event(from, to, |e| {
            out.push(e);
            Ok(())
        })?;
        Ok(out)
    }

    /// Integrity check plus a full scan: ids contiguous from 1, every row's JSON parses, and
    /// the indexed columns agree with the JSON.
    pub fn verify(&self) -> Result<VerifyReport> {
        let integrity: String = self
            .conn
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
        let mut report = VerifyReport {
            schema_version: self.schema_version()?,
            events: self.count()?,
            high_water: self.high_water()?,
            integrity,
            problems: Vec::new(),
        };
        let push = |report: &mut VerifyReport, msg: String| {
            if report.problems.len() < VerifyReport::MAX_PROBLEMS {
                report.problems.push(msg);
            }
        };
        let mut stmt = self.conn.prepare(
            "SELECT id, kind, process_token, parent_token, mach_time, wall_time, json \
             FROM events ORDER BY id",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                from_db(r.get::<_, i64>(0)?),
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                from_db(r.get::<_, i64>(4)?),
                r.get::<_, i64>(5)?,
                r.get::<_, String>(6)?,
            ))
        })?;
        let floor = self.retention_floor()?;
        let mut expected = floor + 1;
        let mut last_id = floor;
        for row in rows {
            let (id, kind, process_token, parent_token, mach_time, wall_time, json) = row?;
            if id != expected {
                push(
                    &mut report,
                    format!("id gap: expected {expected}, found {id}"),
                );
            }
            expected = id + 1;
            last_id = id;
            match serde_json::from_str::<Event>(&json) {
                Ok(event) => {
                    if event.wall_time.0 != wall_time {
                        push(
                            &mut report,
                            format!("event {id}: wall_time column mismatch"),
                        );
                    }
                    if event.id != id {
                        push(&mut report, format!("event {id}: json id is {}", event.id));
                    }
                    if event.kind.discriminator() != kind {
                        push(
                            &mut report,
                            format!(
                                "event {id}: kind column {kind} vs json {}",
                                event.kind.discriminator()
                            ),
                        );
                    }
                    if event.process.token.key() != process_token {
                        push(
                            &mut report,
                            format!("event {id}: process_token column mismatch"),
                        );
                    }
                    if event.process.parent_token.key() != parent_token {
                        push(
                            &mut report,
                            format!("event {id}: parent_token column mismatch"),
                        );
                    }
                    if event.mach_time.0 != mach_time {
                        push(
                            &mut report,
                            format!("event {id}: mach_time column mismatch"),
                        );
                    }
                }
                Err(e) => push(&mut report, format!("event {id}: json does not parse: {e}")),
            }
        }
        if last_id != report.high_water {
            let high_water = report.high_water;
            push(
                &mut report,
                format!("high water {high_water} but last id is {last_id}"),
            );
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::kind::samples;
    use crate::schema::{MachTime, SCHEMA_VERSION, Source, WallTime};

    fn event(id: u64, kind: Kind) -> Event {
        Event {
            schema_version: SCHEMA_VERSION,
            capture: None,
            id,
            mach_time: MachTime(id * 10),
            wall_time: WallTime(1_700_000_000_000_000_000 + id as i64),
            seq_num: id,
            global_seq_num: id,
            source: Source::Synthetic,
            process: samples::process(5, "/usr/bin/x"),
            kind,
        }
    }

    fn temp_db(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("porchlight-store-{}-{name}", std::process::id()));
        // Remove stale -wal/-shm siblings from an aborted earlier run with the same pid.
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("events.db")
    }

    #[test]
    fn retention_evicts_prefix_by_count_bytes_and_age_without_reusing_ids() {
        let mut store = EventStore::open_in_memory().unwrap();
        let events: Vec<_> = (1..=5)
            .map(|id| event(id, Kind::Exit { status: 0 }))
            .collect();
        store.append(&events).unwrap();
        let tx = store.conn.transaction().unwrap();
        EventStore::retain(&tx, 0, 3, i64::MAX).unwrap();
        tx.commit().unwrap();
        assert_eq!(store.retention_floor().unwrap(), 2);
        assert_eq!(store.count().unwrap(), 3);
        assert!(store.verify().unwrap().is_ok());
        let one = events[4].to_json_line().unwrap().len() as i64;
        let tx = store.conn.transaction().unwrap();
        EventStore::retain(&tx, 0, 100, one).unwrap();
        tx.commit().unwrap();
        assert_eq!(store.count().unwrap(), 1);
        assert_eq!(store.retention_floor().unwrap(), 4);
        store
            .conn
            .execute("UPDATE events SET stored_at = 1", [])
            .unwrap();
        let tx = store.conn.transaction().unwrap();
        EventStore::retain(&tx, RETENTION_SECONDS + 2, 100, i64::MAX).unwrap();
        tx.commit().unwrap();
        assert_eq!(store.count().unwrap(), 0);
        assert_eq!(store.high_water().unwrap(), 5);
        assert_eq!(store.retention_floor().unwrap(), 5);
        assert!(store.verify().unwrap().is_ok());
        store.append(&[event(6, Kind::Exit { status: 0 })]).unwrap();
        assert!(store.verify().unwrap().is_ok());
    }

    #[test]
    fn excessive_batch_count_is_rejected_without_advancing_ids() {
        let mut store = EventStore::open_in_memory().unwrap();
        let batch: Vec<_> = (1..=1025)
            .map(|id| event(id, Kind::Exit { status: 0 }))
            .collect();
        assert!(matches!(store.append(&batch), Err(StoreError::Capacity(_))));
        assert_eq!(store.high_water().unwrap(), 0);
        assert_eq!(store.count().unwrap(), 0);
    }

    #[test]
    fn low_disk_admission_and_byte_budget_fail_closed() {
        assert!(matches!(
            EventStore::admit_space(MIN_FREE_BYTES),
            Err(StoreError::Capacity(_))
        ));
        assert!(EventStore::admit_space(u64::MAX).is_ok());
        let mut store = EventStore::open_in_memory().unwrap();
        let mut large = event(1, Kind::Exit { status: 0 });
        large.process.executable_path = "x".repeat(MAX_BATCH_BYTES);
        assert!(matches!(
            store.append(&[large]),
            Err(StoreError::Capacity(_))
        ));
        assert_eq!(store.high_water().unwrap(), 0);
        assert_eq!(store.count().unwrap(), 0);
    }

    #[test]
    fn disk_store_caps_pages_and_checkpoints_wal() {
        let path = temp_db("bounded-wal");
        let mut store = EventStore::open(&path).unwrap();
        let pages: i64 = store
            .conn
            .query_row("PRAGMA max_page_count", [], |r| r.get(0))
            .unwrap();
        let page_size: i64 = store
            .conn
            .query_row("PRAGMA page_size", [], |r| r.get(0))
            .unwrap();
        assert!(pages * page_size <= MAX_DATABASE_BYTES as i64);
        for id in 1..=20 {
            store
                .append(&[event(id, Kind::Exit { status: 0 })])
                .unwrap();
        }
        store.checkpoint().unwrap();
        assert_eq!(
            std::fs::metadata(path.with_file_name("events.db-wal"))
                .unwrap()
                .len(),
            0
        );
        assert!(store.verify().unwrap().is_ok());
    }

    #[test]
    fn legacy_migration_preserves_unknown_completeness() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(include_str!("v1.sql")).unwrap();
        conn.execute("INSERT INTO meta VALUES ('schema_version', '1')", [])
            .unwrap();
        let mut old = event(1, Kind::Exit { status: 0 });
        old.schema_version = 1;
        let mut json = serde_json::to_value(old).unwrap();
        json.as_object_mut().unwrap().remove("capture");
        conn.execute(
            "INSERT INTO events VALUES (1, 10, 1, 1, 1, 'synthetic', 'exit', '5:1', '1:1', ?1)",
            [json.to_string()],
        )
        .unwrap();
        let store = EventStore::init(conn).unwrap();
        let events = store.events(1, None).unwrap();
        assert_eq!(events[0].schema_version, 2);
        assert_eq!(events[0].capture, None);
        assert_eq!(store.schema_version().unwrap(), 2);
    }

    #[test]
    fn migrates_fresh_db_and_is_idempotent() {
        let store = EventStore::open_in_memory().unwrap();
        assert_eq!(store.schema_version().unwrap(), STORE_SCHEMA_VERSION);
        assert_eq!(store.high_water().unwrap(), 0);
        assert_eq!(store.count().unwrap(), 0);
    }

    #[test]
    fn append_and_read_back_in_order() {
        let mut store = EventStore::open_in_memory().unwrap();
        let batch: Vec<Event> = samples::all()
            .into_iter()
            .enumerate()
            .map(|(i, k)| event(i as u64 + 1, k))
            .collect();
        store.append(&batch).unwrap();
        assert_eq!(store.count().unwrap(), batch.len() as u64);
        assert_eq!(store.high_water().unwrap(), batch.len() as u64);
        let back = store.events(1, None).unwrap();
        assert_eq!(back, batch);
        let mid = store.events(3, Some(4)).unwrap();
        assert_eq!(mid.iter().map(|e| e.id).collect::<Vec<_>>(), vec![3, 4]);
        let report = store.verify().unwrap();
        assert!(report.is_ok(), "{report:?}");
        assert_eq!(report.events, batch.len() as u64);
    }

    #[test]
    fn rejects_non_contiguous_ids_atomically() {
        let mut store = EventStore::open_in_memory().unwrap();
        store.append(&[event(1, Kind::Exit { status: 0 })]).unwrap();
        let err = store
            .append(&[
                event(2, Kind::Exit { status: 0 }),
                event(4, Kind::Exit { status: 0 }),
            ])
            .unwrap_err();
        assert!(
            matches!(
                err,
                StoreError::IdOrder {
                    expected: 3,
                    got: 4
                }
            ),
            "{err}"
        );
        assert_eq!(store.count().unwrap(), 1, "the whole batch rolled back");
        assert_eq!(store.high_water().unwrap(), 1);
        let err = store
            .append(&[event(1, Kind::Exit { status: 0 })])
            .unwrap_err();
        assert!(matches!(
            err,
            StoreError::IdOrder {
                expected: 2,
                got: 1
            }
        ));
    }

    #[test]
    fn drop_events_land_in_drops_table() {
        let mut store = EventStore::open_in_memory().unwrap();
        store
            .append(&[event(
                1,
                Kind::Drop {
                    event_type: "exec".to_owned(),
                    expected_seq: 5,
                    got_seq: 9,
                    count: 4,
                    reason: DropReason::RingFull,
                },
            )])
            .unwrap();
        let (count, reason): (i64, String) = store
            .conn
            .query_row(
                "SELECT count, reason FROM drops WHERE event_id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((count, reason.as_str()), (4, "ring_full"));
    }

    #[test]
    fn high_water_survives_reopen_and_read_only_works() {
        let path = temp_db("reopen");
        let _ = std::fs::remove_file(&path);
        {
            let mut store = EventStore::open(&path).unwrap();
            store
                .append(&[
                    event(1, Kind::Exit { status: 0 }),
                    event(2, Kind::Exit { status: 1 }),
                ])
                .unwrap();
        }
        {
            let mut store = EventStore::open(&path).unwrap();
            assert_eq!(store.high_water().unwrap(), 2);
            store.append(&[event(3, Kind::Exit { status: 2 })]).unwrap();
        }
        let ro = EventStore::open_read_only(&path).unwrap();
        assert_eq!(ro.count().unwrap(), 3);
        assert!(ro.verify().unwrap().is_ok());
        let journal: String = ro
            .conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(journal, "wal");
    }

    #[test]
    fn refuses_a_newer_store() {
        let mut store = EventStore::open_in_memory().unwrap();
        let tx = store.conn.transaction().unwrap();
        EventStore::meta_set(&tx, META_SCHEMA_VERSION, "99").unwrap();
        tx.commit().unwrap();
        let err = store.migrate().unwrap_err();
        assert!(matches!(err, StoreError::Migration(_)));
    }

    #[test]
    fn verify_checks_wall_time_column() {
        let mut store = EventStore::open_in_memory().unwrap();
        store.append(&[event(1, Kind::Exit { status: 0 })]).unwrap();
        store
            .conn
            .execute("UPDATE events SET wall_time = 0 WHERE id = 1", [])
            .unwrap();
        let report = store.verify().unwrap();
        assert!(
            report.problems.iter().any(|p| p.contains("wall_time")),
            "{report:?}"
        );
    }

    #[test]
    fn io_errors_short_circuit_iteration() {
        let mut store = EventStore::open_in_memory().unwrap();
        let batch: Vec<Event> = (1..=5)
            .map(|i| event(i, Kind::Exit { status: 0 }))
            .collect();
        store.append(&batch).unwrap();
        let mut calls = 0;
        let err = store
            .for_each_event(1, None, |_| {
                calls += 1;
                Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe).into())
            })
            .unwrap_err();
        assert!(matches!(err, StoreError::Io(_)));
        assert_eq!(calls, 1, "iteration stops at the first callback error");
    }

    #[test]
    fn verify_reports_column_drift() {
        let mut store = EventStore::open_in_memory().unwrap();
        store.append(&[event(1, Kind::Exit { status: 0 })]).unwrap();
        store
            .conn
            .execute("UPDATE events SET kind = 'fork' WHERE id = 1", [])
            .unwrap();
        let report = store.verify().unwrap();
        assert!(!report.is_ok());
        assert!(
            report.problems[0].contains("kind column fork vs json exit"),
            "{report:?}"
        );
    }
}
