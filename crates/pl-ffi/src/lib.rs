//! C ABI for the Swift app (`include/pl.h`, ADR-0001).
//!
//! The app holds one `pl_app_t`. Batches from the extension arrive on an XPC queue, are
//! ingested into the store through the [`Pipeline`] and applied to [`LiveProcesses`]. Swift
//! polls `pl_app_stats_json` for the Status screen. No panic crosses the boundary: every
//! entry point runs inside `catch_unwind` and reports failure as an error code or NULL.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod abi;
#[cfg(target_os = "macos")]
mod client;
mod core;

pub use crate::core::{AppCore, AppStats};
