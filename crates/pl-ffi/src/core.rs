//! Platform-neutral app state, testable on Linux.

use std::path::Path;

use pl_core::live::{LiveProcesses, LiveStats};
use pl_core::pipeline::Pipeline;
use pl_core::schema::{DropReason, Event, Kind, Source};
use pl_core::store::EventStore;
use pl_raw::protocol::EsStatus;
use serde::Serialize;

/// Losses by cause. `ring_full` is a subset of `sequence_gap` (docs/schema.md).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DropTotals {
    pub sequence_gap: u64,
    pub ring_full: u64,
    pub app_disconnected: u64,
    /// Events received from the extension that the store refused to append.
    pub store_failed: u64,
}

/// Every Endpoint Security message carries `global_seq_num`, contiguous per client. A hole
/// in what reached the store is a loss somewhere between the kernel and SQLite: the ring,
/// the extension's queue, or XPC delivery into a connection that was dying. This is the
/// single number that cannot under-count.
///
/// When M3 filters unmodified `close` in the handler, those messages create holes too and
/// this check must learn to expect them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct EndToEnd {
    pub delivered: u64,
    pub missing: u64,
    pub gaps: u64,
    /// The sequence went backwards: the extension restarted.
    pub restarts: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct AppStats {
    pub connected: bool,
    pub extension: Option<EsStatus>,
    pub events_ingested: u64,
    pub high_water: u64,
    pub retention_evicted: Option<u64>,
    pub live_processes: usize,
    pub live: LiveStats,
    pub drops: DropTotals,
    pub end_to_end: EndToEnd,
    pub batches: u64,
    pub ingest_errors: u64,
    pub last_error: Option<String>,
}

pub struct AppCore {
    pipeline: Pipeline,
    live: LiveProcesses,
    last_global: Option<u64>,
    stats: AppStats,
}

fn observe(
    stats: &mut AppStats,
    live: &mut LiveProcesses,
    last_global: &mut Option<u64>,
    ev: &Event,
) {
    live.apply(ev);
    match &ev.kind {
        Kind::Drop { count, reason, .. } => match reason {
            DropReason::SequenceGap => stats.drops.sequence_gap += count,
            DropReason::RingFull => stats.drops.ring_full += count,
            DropReason::AppDisconnected => stats.drops.app_disconnected += count,
        },
        _ if ev.source == Source::EndpointSecurity => {
            let e2e = &mut stats.end_to_end;
            e2e.delivered += 1;
            let g = ev.global_seq_num;
            match *last_global {
                Some(last) if g > last.saturating_add(1) => {
                    e2e.gaps += 1;
                    e2e.missing += g - last - 1;
                }
                Some(last) if g <= last => e2e.restarts += 1,
                _ => {}
            }
            *last_global = Some(g);
        }
        _ => {}
    }
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
            last_global: None,
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
        let batch: Vec<Event> = match serde_json::from_slice(json) {
            Ok(b) => b,
            Err(e) => {
                self.stats.ingest_errors += 1;
                let msg = format!("batch is not a JSON event array: {e}");
                self.stats.last_error = Some(msg.clone());
                return Err(msg);
            }
        };
        let n = batch.len() as u64;
        let (stats, live, last_global) = (&mut self.stats, &mut self.live, &mut self.last_global);
        match self
            .pipeline
            .ingest_inspect(batch, |ev| observe(stats, live, last_global, ev))
        {
            Ok(report) => {
                self.stats.events_ingested += report.ingested;
                self.stats.high_water = report.last_id.max(self.stats.high_water);
                self.stats.batches += 1;
                Ok(report.ingested)
            }
            Err(e) => {
                self.stats.ingest_errors += 1;
                self.stats.drops.store_failed += n;
                let msg = format!("store append failed, {n} events lost: {e}");
                self.stats.last_error = Some(msg.clone());
                Err(msg)
            }
        }
    }

    pub fn stats(&self) -> AppStats {
        let mut s = self.stats.clone();
        s.retention_evicted = self.pipeline.store().retention_floor().ok();
        s.live_processes = self.live.len();
        s.live = self.live.stats().clone();
        s
    }
}
