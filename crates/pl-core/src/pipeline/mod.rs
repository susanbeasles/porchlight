//! The pipeline (SPEC §5). In M1 it assigns ids and appends to the store. Graphs, the
//! inventory and the rule engine attach in M4 to M6; the scorer slot is reserved (§10).

use crate::reserved::AnomalyScorer;
use crate::schema::{Event, SCHEMA_VERSION};
use crate::store::{EventStore, Result};

/// What one `ingest` call did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct IngestReport {
    pub ingested: u64,
    /// First and last id assigned; both `0` when the batch was empty.
    pub first_id: u64,
    pub last_id: u64,
}

pub struct Pipeline {
    store: EventStore,
    next_id: u64,
    scorer: Option<Box<dyn AnomalyScorer + Send>>,
}

impl Pipeline {
    /// Wraps a store, continuing from its persisted high-water mark.
    pub fn new(store: EventStore) -> Result<Self> {
        let next_id = store.high_water()? + 1;
        Ok(Self {
            store,
            next_id,
            scorer: None,
        })
    }

    /// Installs an anomaly scorer. v0 never calls it; the slot exists so v1 can.
    pub fn with_scorer(mut self, scorer: Box<dyn AnomalyScorer + Send>) -> Self {
        self.scorer = Some(scorer);
        self
    }

    pub fn has_scorer(&self) -> bool {
        self.scorer.is_some()
    }

    /// Assigns monotonic ids, stamps the schema version and appends in one transaction.
    pub fn ingest(&mut self, batch: Vec<Event>) -> Result<IngestReport> {
        self.ingest_inspect(batch, |_| {})
    }

    /// As [`ingest`](Self::ingest), then calls `inspect` on each stored event, with its id,
    /// in order. `inspect` runs only if the append succeeded.
    pub fn ingest_inspect<F: FnMut(&Event)>(
        &mut self,
        mut batch: Vec<Event>,
        mut inspect: F,
    ) -> Result<IngestReport> {
        if batch.is_empty() {
            return Ok(IngestReport::default());
        }
        // Ids are committed to `next_id` only after the append succeeds, so a failed
        // append leaves the pipeline aligned with the store's high-water mark.
        let first_id = self.next_id;
        let mut id = first_id;
        for event in &mut batch {
            event.id = id;
            event.schema_version = SCHEMA_VERSION;
            id += 1;
        }
        self.store.append(&batch)?;
        self.next_id = id;
        batch.iter().for_each(&mut inspect);
        Ok(IngestReport {
            ingested: batch.len() as u64,
            first_id,
            last_id: id - 1,
        })
    }

    pub fn next_id(&self) -> u64 {
        self.next_id
    }

    pub fn store(&self) -> &EventStore {
        &self.store
    }

    pub fn into_store(self) -> EventStore {
        self.store
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::kind::samples;
    use crate::schema::{Kind, MachTime, Source, WallTime};

    fn unassigned(kind: Kind) -> Event {
        Event {
            schema_version: 0,
            capture: None,
            id: 0,
            mach_time: MachTime(1),
            wall_time: WallTime(1),
            seq_num: 1,
            global_seq_num: 1,
            source: Source::Replay,
            process: samples::process(2, "/x"),
            kind,
        }
    }

    #[test]
    fn assigns_contiguous_ids_across_batches() {
        let mut p = Pipeline::new(EventStore::open_in_memory().unwrap()).unwrap();
        assert!(!p.has_scorer());
        let r1 = p
            .ingest(vec![unassigned(Kind::Exit { status: 0 }); 3])
            .unwrap();
        assert_eq!((r1.first_id, r1.last_id, r1.ingested), (1, 3, 3));
        let r2 = p.ingest(vec![]).unwrap();
        assert_eq!(r2, IngestReport::default());
        let r3 = p
            .ingest(vec![unassigned(Kind::Exit { status: 1 })])
            .unwrap();
        assert_eq!((r3.first_id, r3.last_id), (4, 4));
        assert_eq!(p.next_id(), 5);
        let stored = p.store().events(1, None).unwrap();
        assert_eq!(
            stored.iter().map(|e| e.id).collect::<Vec<_>>(),
            vec![1, 2, 3, 4]
        );
        assert!(stored.iter().all(|e| e.schema_version == SCHEMA_VERSION));
    }

    #[test]
    fn inspect_sees_stored_events_with_ids_only_on_success() {
        let mut p = Pipeline::new(EventStore::open_in_memory().unwrap()).unwrap();
        let mut seen = Vec::new();
        p.ingest_inspect(vec![unassigned(Kind::Exit { status: 0 }); 2], |e| {
            seen.push(e.id)
        })
        .unwrap();
        assert_eq!(seen, vec![1, 2]);
        let mut bad = unassigned(Kind::Exit { status: 1 });
        bad.mach_time = MachTime(u64::MAX);
        let mut called = false;
        assert!(p.ingest_inspect(vec![bad], |_| called = true).is_err());
        assert!(!called);
    }

    #[test]
    fn failed_append_does_not_advance_ids() {
        let mut p = Pipeline::new(EventStore::open_in_memory().unwrap()).unwrap();
        p.ingest(vec![unassigned(Kind::Exit { status: 0 })])
            .unwrap();
        let mut bad = unassigned(Kind::Exit { status: 1 });
        bad.mach_time = MachTime(u64::MAX); // exceeds SQLite INTEGER: append fails
        assert!(
            p.ingest(vec![unassigned(Kind::Exit { status: 0 }), bad])
                .is_err()
        );
        assert_eq!(p.next_id(), 2, "ids not consumed by the failed batch");
        let r = p
            .ingest(vec![unassigned(Kind::Exit { status: 2 })])
            .unwrap();
        assert_eq!((r.first_id, r.last_id), (2, 2));
        assert_eq!(p.store().count().unwrap(), 2);
    }

    #[test]
    fn continues_from_high_water_of_existing_store() {
        let mut store = EventStore::open_in_memory().unwrap();
        let mut seeded = unassigned(Kind::Exit { status: 0 });
        seeded.id = 1;
        store.append(&[seeded]).unwrap();
        let mut p = Pipeline::new(store).unwrap();
        let r = p
            .ingest(vec![unassigned(Kind::Exit { status: 0 })])
            .unwrap();
        assert_eq!(r.first_id, 2);
    }
}
