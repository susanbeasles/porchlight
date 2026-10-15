//! Porchlight core: the event schema, the local store, fixture ingest and the pipeline.
//!
//! This crate has no Apple framework dependency and builds and tests on Linux. It is the
//! single contract between the Endpoint Security extension, the container app and
//! `porchlightctl` (SPEC §3, ADR-0001).
//!
//! Determinism (SPEC C7): nothing in this crate iterates a hash map on the way to output.
//! `clippy.toml` forbids `HashMap` and `HashSet` here.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod ingest;
pub mod reserved;
pub mod schema;

#[cfg(feature = "store")]
pub mod store;

#[cfg(feature = "pipeline")]
pub mod pipeline;
