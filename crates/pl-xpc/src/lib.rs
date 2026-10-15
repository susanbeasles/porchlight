//! Safe-by-construction XPC for Porchlight (SPEC §4.7).
//!
//! - [`listen`] publishes a mach service and hands every peer that passes the code-signing
//!   requirement to the [`Handler`] as an owned [`Connection`].
//! - [`open_client`] opens a privileged mach-service client and returns an owned [`Connection`].
//!
//! A [`Connection`] holds its own XPC retain and releases it on drop, so sending on one that
//! the remote end has invalidated is harmless: XPC discards the message.
//!
//! Only meaningful on macOS. On other targets this crate is empty so the workspace builds.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

#[cfg(target_os = "macos")]
mod mac;

#[cfg(target_os = "macos")]
pub use mac::{ConnId, Connection, Handler, Msg, PeerEvent, listen, open_client};
