//! The event schema (SPEC §3): versioned, serde-serializable, with a stable string
//! discriminator per event kind for SQL indexing.

pub mod es_events;
pub mod event;
pub mod finding;
pub mod identity;
pub mod kind;
pub mod time;

pub use event::{Event, Source};
pub use finding::{Action, Finding, FindingId, Severity, State};
pub use identity::{AuditToken, ProcessIdentity};
pub use kind::{CrossViewKind, DropReason, Kind, LaunchItem, ProfileInfo, TccUpdate};
pub use time::{MachTime, WallTime};

/// Current schema version. Bump on any change to serialized shape; add a store migration.
pub const SCHEMA_VERSION: u32 = 1;
