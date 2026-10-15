//! Platform-neutral app state, testable on Linux.

use std::collections::BTreeMap;
use std::path::Path;

use pl_core::live::{LiveProcesses, LiveStats};
use pl_core::pipeline::Pipeline;
use pl_core::schema::{Event, Kind};
use pl_core::store::EventStore;
use pl_raw::protocol::EsStatus;
use serde::Serialize;

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct AppStats {
    pub connected: bool,
    pub extension: Option<EsStatus>,
    pub events_ingested: u64,
    pub high_water: u64,
    pub live_processes: usize,
    pub live: LiveStats,
    /// Sum of `drop` counts by reason. `ring_full` is a subset of `sequence_gap`.
    pub drops: BTreeMap<String, u64>,
    pub batches: u64,
    pub ingest_errors: u64,
    pub last_error: Option<String>,
}

pub struct AppCore {
    pipeline: Pipeline,
    live: LiveProcesses,
    stats: AppStats,
}

impl AppCore {
    pub fn open(db_path: Option<&Path>) -> Result<Self, String> {
        let store = match db_path {
            Some(p) => EventStore::open(p),
            None => EventStore::open_in_memory(),
        }
        .map_err(|e| e.to_string())?;
        let pipeline = Pipeline::new(store).map_err(|e| e.to_string())?;
        let high_water = pipeline.next_id() - 1;
        Ok(Self {
            pipeline,
            live: LiveProcesses::new(),
            stats: AppStats {
                high_water,
                ..Default::default()
            },
        })
    }

    pub fn set_connected(&mut self, connected: bool) {
        self.stats.connected = connected;
    }

    pub fn set_extension_status(&mut self, status: EsStatus) {
        self.stats.extension = Some(status);
    }

    pub fn record_error(&mut self, error: String) {
        self.stats.last_error = Some(error);
    }

    /// Parses and ingests one `batch` payload.
    pub fn ingest_json(&mut self, json: &[u8]) -> Result<u64, String> {
        let mut batch: Vec<Event> = match serde_json::from_slice(json) {
            Ok(b) => b,
            Err(e) => {
                self.stats.ingest_errors += 1;
                let msg = format!("batch is not a JSON event array: {e}");
                self.stats.last_error = Some(msg.clone());
                return Err(msg);
            }
        };
        // Pre-assign the ids the pipeline will give, so live tracking can cite them.
        let first = self.pipeline.next_id();
        for (i, ev) in batch.iter_mut().enumerate() {
            ev.id = first + i as u64;
        }
        let applied = batch.clone();
        match self.pipeline.ingest(batch) {
            Ok(report) => {
                for ev in &applied {
                    self.live.apply(ev);
                    if let Kind::Drop { count, reason, .. } = &ev.kind {
                        let key = serde_json::to_value(reason)
                            .ok()
                            .and_then(|v| v.as_str().map(str::to_owned))
                            .unwrap_or_else(|| "unknown".to_owned());
                        *self.stats.drops.entry(key).or_insert(0) += count;
                    }
                }
                self.stats.events_ingested += report.ingested;
                self.stats.high_water = report.last_id.max(self.stats.high_water);
                self.stats.batches += 1;
                Ok(report.ingested)
            }
            Err(e) => {
                self.stats.ingest_errors += 1;
                let msg = format!("store append failed: {e}");
                self.stats.last_error = Some(msg.clone());
                Err(msg)
            }
        }
    }

    pub fn stats(&self) -> AppStats {
        let mut s = self.stats.clone();
        s.live_processes = self.live.len();
        s.live = self.live.stats().clone();
        s
    }
}
