//! Fixture ingest (SPEC §7, ADR-0002): NDJSON in either `eslogger` shape or Porchlight's own
//! dump shape, detected from the first non-empty line.

pub mod eslogger;
pub mod ndjson;

pub use ndjson::{Format, LineError, NdjsonReader, ReadStats, detect_format};
