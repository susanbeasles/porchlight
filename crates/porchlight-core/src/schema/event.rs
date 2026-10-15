//! The event envelope (SPEC §3.2).

use serde::{Deserialize, Serialize};

use super::identity::ProcessIdentity;
use super::kind::Kind;
use super::time::{MachTime, WallTime};

/// Where an event came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    EndpointSecurity,
    Replay,
    CrossView,
    Diagnostics,
    Synthetic,
}

impl Source {
    /// The string stored in the `events.source` column.
    pub fn as_str(self) -> &'static str {
        match self {
            Source::EndpointSecurity => "endpoint_security",
            Source::Replay => "replay",
            Source::CrossView => "cross_view",
            Source::Diagnostics => "diagnostics",
            Source::Synthetic => "synthetic",
        }
    }
}

/// One observed event. `id` is `0` until the pipeline assigns it on ingest.
/// Unknown fields are rejected: a newer shape must bump `SCHEMA_VERSION` (ADR-0004).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub schema_version: u32,
    pub id: u64,
    pub mach_time: MachTime,
    pub wall_time: WallTime,
    pub seq_num: u64,
    pub global_seq_num: u64,
    pub source: Source,
    /// The acting process.
    pub process: ProcessIdentity,
    pub kind: Kind,
}

impl Event {
    /// Canonical single-line JSON. Field order is declaration order; maps are sorted. This is
    /// the dump format and the XPC batch element format.
    pub fn to_json_line(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::SCHEMA_VERSION;
    use crate::schema::kind::samples;

    #[test]
    fn source_strings_match_serde() {
        for s in [
            Source::EndpointSecurity,
            Source::Replay,
            Source::CrossView,
            Source::Diagnostics,
            Source::Synthetic,
        ] {
            let json = serde_json::to_value(s).unwrap();
            assert_eq!(json.as_str(), Some(s.as_str()));
        }
    }

    #[test]
    fn envelope_round_trip_is_byte_stable() {
        for kind in samples::all() {
            let event = Event {
                schema_version: SCHEMA_VERSION,
                id: 42,
                mach_time: MachTime(1),
                wall_time: WallTime(2),
                seq_num: 3,
                global_seq_num: 4,
                source: Source::Replay,
                process: samples::process(9, "/usr/bin/x"),
                kind,
            };
            let line = event.to_json_line().unwrap();
            assert!(
                line.starts_with(r#"{"schema_version":1,"id":42,"mach_time":1,"wall_time":2,"#)
            );
            let back: Event = serde_json::from_str(&line).unwrap();
            assert_eq!(back, event);
            assert_eq!(back.to_json_line().unwrap(), line);
        }
    }
}
