//! The raw side of the extension, minus anything that needs the macOS SDK.
//!
//! - [`PlRawEvent`] mirrors `include/rawevent.h` byte for byte (SPEC §4.5).
//! - [`Ring`] wraps the SPSC ring in `csrc/ring.c` (SPEC §4.6).
//! - [`decode`] turns a raw record into a schema [`pl_core::schema::Event`].
//! - [`bridge`] holds the consumer logic: sequence gaps, drop events, batching and the
//!   disconnected overflow queue (SPEC §4.6, §4.7).
//! - [`protocol`] is the XPC wire vocabulary shared by the extension and the app.
//!
//! Everything here builds and tests on Linux.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod bridge;
pub mod decode;
pub mod protocol;
mod raw;
mod ring;

pub use raw::{
    PL_CDHASH_LEN, PL_EV_EXEC, PL_EV_EXIT, PL_EV_FORK, PL_EV_SLOTS, PL_EXEC_BUF, PL_PATH_MAX,
    PL_RAW_VERSION, PlBody, PlExec, PlExit, PlFork, PlProcess, PlRawEvent, PlToken, flags,
    get_cstr, put_cstr,
};
pub use ring::Ring;

/// Ring capacity for M2. A build-time constant (SPEC §4.6). 8192 slots of 21,688 bytes is
/// about 178 MB of virtual memory, touched on demand. The final value is an M3 ADR
/// (SPEC §12: capacity versus memory on 8 GB machines).
pub const RING_CAPACITY: u32 = 8192;
