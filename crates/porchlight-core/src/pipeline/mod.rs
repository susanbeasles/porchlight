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
    scorer: Option<Box<dyn AnomalyScorer>>,
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
    pub fn with_scorer(mut self, scorer: Box<dyn AnomalyScorer>) -> Self {
        self.scorer = Some(scorer);
        self
    }

    pub fn has_scorer(&self) -> bool {
        self.scorer.is_some()
    }

    /// Assigns monotonic ids, stamps the schema version and appends in one transaction.
    pub fn ingest(&mut self, mut batch: Vec<Event>) -> Result<IngestReport> {
        if batch.is_empty() {
            return Ok(IngestReport::default());
        }
        let first_id = self.next_id;
        for event in &mut batch {
            event.id = self.next_id;
            event.schema_version = SCHEMA_VERSION;
            self.next_id += 1;
        }
        self.store.append(&batch)?;
        Ok(IngestReport {
            ingested: batch.len() as u64,
            first_id,
            last_id: self.next_id - 1,
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
