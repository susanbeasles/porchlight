//! `dev.susanb.porchlight.extension`: the Endpoint Security system extension (SPEC §4).
//!
//! The C shim owns the ES client and copies messages into the ring. This binary owns
//! everything after that: draining, decoding, sequence and drop accounting, batching, and
//! the XPC service the app connects to. It links no SQLite and no YAML (ADR-0001).

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

#[cfg(target_os = "macos")]
mod mac;
#[cfg(any(target_os = "macos", test))]
mod service;
#[cfg(all(test, not(target_os = "macos")))]
mod test_xpc;

#[cfg(target_os = "macos")]
fn main() {
    mac::run()
}

#[cfg(not(target_os = "macos"))]
fn main() -> std::process::ExitCode {
    eprintln!("pl-es is the macOS Endpoint Security extension; it does nothing on this platform");
    std::process::ExitCode::from(2)
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    #![allow(unsafe_code)]

    unsafe extern "C" {
        fn pl_es_selftest(msg: *mut std::ffi::c_char, cap: usize) -> std::ffi::c_int;
    }

    /// SPEC §8: the copy routine against hand-built es_message_t. Needs no entitlement.
    #[test]
    fn es_copy_selftest() {
        let mut buf = [0 as std::ffi::c_char; 512];
        // SAFETY: the C side writes at most `cap` bytes, NUL-terminated.
        let failures = unsafe { pl_es_selftest(buf.as_mut_ptr(), buf.len()) };
        // SAFETY: NUL-terminated by the C side (or still all zero).
        let msg = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }.to_string_lossy();
        assert_eq!(failures, 0, "{msg}");
    }
}
