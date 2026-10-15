//! The `extern "C"` surface. Thin: validate pointers, catch unwinds, delegate.

#![allow(unsafe_code)]

use std::ffi::{CStr, CString, c_char};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::core::AppCore;

pub const PL_OK: i32 = 0;
/// Returned by `pl_app_connect` off macOS.
#[cfg_attr(target_os = "macos", allow(dead_code))]
pub const PL_ERR_UNSUPPORTED: i32 = -1;
pub const PL_ERR_STATE: i32 = -2;
pub const PL_ERR_FAILED: i32 = -3;

/// The opaque `pl_app_t`.
pub struct PlApp {
    pub(crate) core: Arc<Mutex<AppCore>>,
    #[cfg(target_os = "macos")]
    pub(crate) client: Mutex<Option<crate::client::Client>>,
}

pub(crate) fn lock(core: &Mutex<AppCore>) -> std::sync::MutexGuard<'_, AppCore> {
    core.lock().unwrap_or_else(|p| p.into_inner())
}

fn guard<T>(fallback: T, f: impl FnOnce() -> T) -> T {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(fallback)
}

/// # Safety
/// `db_path` is NULL or a valid NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pl_app_open(db_path: *const c_char) -> *mut PlApp {
    guard(std::ptr::null_mut(), || {
        let path = if db_path.is_null() {
            None
        } else {
            // SAFETY: caller guarantees a valid C string.
            Some(PathBuf::from(
                unsafe { CStr::from_ptr(db_path) }
                    .to_string_lossy()
                    .into_owned(),
            ))
        };
        match AppCore::open(path.as_deref()) {
            Ok(core) => Box::into_raw(Box::new(PlApp {
                core: Arc::new(Mutex::new(core)),
                #[cfg(target_os = "macos")]
                client: Mutex::new(None),
            })),
            Err(_) => std::ptr::null_mut(),
        }
    })
}

/// # Safety
/// `app` is NULL or a live handle from `pl_app_open`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pl_app_connect(app: *mut PlApp) -> i32 {
    guard(PL_ERR_FAILED, || {
        // SAFETY: caller guarantees NULL or a live handle.
        let Some(app) = (unsafe { app.as_ref() }) else {
            return PL_ERR_STATE;
        };
        #[cfg(target_os = "macos")]
        {
            crate::client::start(app)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = app;
            PL_ERR_UNSUPPORTED
        }
    })
}

/// # Safety
/// `app` is NULL or live; `json` points to `len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pl_app_ingest_json(app: *mut PlApp, json: *const u8, len: usize) -> i32 {
    guard(PL_ERR_FAILED, || {
        // SAFETY: caller guarantees NULL or a live handle.
        let Some(app) = (unsafe { app.as_ref() }) else {
            return PL_ERR_STATE;
        };
        if json.is_null() {
            return PL_ERR_FAILED;
        }
        // SAFETY: caller guarantees `len` readable bytes at `json`.
        let bytes = unsafe { std::slice::from_raw_parts(json, len) };
        match lock(&app.core).ingest_json(bytes) {
            Ok(_) => PL_OK,
            Err(_) => PL_ERR_FAILED,
        }
    })
}

/// # Safety
/// `app` is NULL or live. The result is freed with `pl_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pl_app_stats_json(app: *mut PlApp) -> *mut c_char {
    guard(std::ptr::null_mut(), || {
        // SAFETY: caller guarantees NULL or a live handle.
        let Some(app) = (unsafe { app.as_ref() }) else {
            return std::ptr::null_mut();
        };
        let stats = lock(&app.core).stats();
        serde_json::to_string(&stats)
            .ok()
            .and_then(|s| CString::new(s).ok())
            .map_or(std::ptr::null_mut(), CString::into_raw)
    })
}

/// # Safety
/// `s` is NULL or a string returned by this library, freed once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pl_string_free(s: *mut c_char) {
    if !s.is_null() {
        // SAFETY: `s` came from `CString::into_raw` in this library.
        drop(unsafe { CString::from_raw(s) });
    }
}

/// # Safety
/// `app` is NULL or a live handle, not used afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pl_app_close(app: *mut PlApp) {
    if !app.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            // SAFETY: `app` came from `Box::into_raw` in `pl_app_open`.
            drop(unsafe { Box::from_raw(app) });
        }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pl_core::schema::{
        AuditToken, DropReason, Event, Kind, MachTime, ProcessIdentity, SCHEMA_VERSION, Source,
        WallTime,
    };

    fn proc_(pid: i32, pv: i32, path: &str) -> ProcessIdentity {
        ProcessIdentity {
            token: AuditToken {
                pid,
                pidversion: pv,
                ..Default::default()
            },
            parent_token: AuditToken {
                pid: 1,
                pidversion: 1,
                ..Default::default()
            },
            responsible_token: None,
            executable_path: path.to_owned(),
            signing_id: None,
            team_id: None,
            cdhash: String::new(),
            is_platform_binary: true,
            is_es_client: false,
            tty: None,
            session_id: 0,
            start_time: WallTime(0),
        }
    }

    fn ev(actor: ProcessIdentity, kind: Kind) -> Event {
        ev_g(actor, kind, 0)
    }

    fn ev_g(actor: ProcessIdentity, kind: Kind, global: u64) -> Event {
        Event {
            schema_version: SCHEMA_VERSION,
            id: 0,
            mach_time: MachTime(1),
            wall_time: WallTime(1),
            seq_num: 0,
            global_seq_num: global,
            source: Source::EndpointSecurity,
            process: actor,
            kind,
        }
    }

    fn stats(app: *mut PlApp) -> serde_json::Value {
        // SAFETY: live handle from pl_app_open.
        let p = unsafe { pl_app_stats_json(app) };
        assert!(!p.is_null());
        // SAFETY: NUL-terminated string from this library.
        let v = serde_json::from_str(&unsafe { CStr::from_ptr(p) }.to_string_lossy()).unwrap();
        // SAFETY: freed once.
        unsafe { pl_string_free(p) };
        v
    }

    #[test]
    fn ingest_batches_and_report_stats() {
        // SAFETY: NULL path means in-memory.
        let app = unsafe { pl_app_open(std::ptr::null()) };
        assert!(!app.is_null());
        let batch = vec![
            ev(
                proc_(100, 1, "/bin/zsh"),
                Kind::Fork {
                    child: AuditToken {
                        pid: 200,
                        pidversion: 1,
                        ..Default::default()
                    },
                },
            ),
            ev(
                proc_(200, 1, "/bin/zsh"),
                Kind::Exec {
                    target: Box::new(proc_(200, 2, "/usr/bin/curl")),
                    args: vec!["curl".to_owned()],
                    env: Default::default(),
                    cwd: None,
                    script_path: None,
                },
            ),
            ev(
                proc_(9, 1, "/ext"),
                Kind::Drop {
                    event_type: "exec".to_owned(),
                    expected_seq: 3,
                    got_seq: 5,
                    count: 2,
                    reason: DropReason::SequenceGap,
                },
            ),
        ];
        let json = serde_json::to_vec(&batch).unwrap();
        // SAFETY: live handle, valid buffer.
        let rc = unsafe { pl_app_ingest_json(app, json.as_ptr(), json.len()) };
        assert_eq!(rc, PL_OK);
        let s = stats(app);
        assert_eq!(s["events_ingested"], 3);
        assert_eq!(s["high_water"], 3);
        assert_eq!(s["live_processes"], 1);
        assert_eq!(s["live"]["exec_pidversion_changed"], 1);
        assert_eq!(s["drops"]["sequence_gap"], 2);
        assert_eq!(s["drops"]["store_failed"], 0);
        assert_eq!(s["connected"], false);

        let junk = b"not json";
        // SAFETY: live handle, valid buffer.
        let rc = unsafe { pl_app_ingest_json(app, junk.as_ptr(), junk.len()) };
        assert_eq!(rc, PL_ERR_FAILED);
        let s = stats(app);
        assert_eq!(s["ingest_errors"], 1);
        assert!(
            s["last_error"]
                .as_str()
                .unwrap()
                .contains("not a JSON event array")
        );
        // SAFETY: closing a live handle once.
        unsafe { pl_app_close(app) };
    }

    #[test]
    fn end_to_end_counts_holes_and_restarts_in_global_sequence() {
        // SAFETY: NULL path means in-memory.
        let app = unsafe { pl_app_open(std::ptr::null()) };
        let exit = |g| ev_g(proc_(5, 1, "/x"), Kind::Exit { status: 0 }, g);
        for batch in [vec![exit(1), exit(2)], vec![exit(5)], vec![exit(1)]] {
            let json = serde_json::to_vec(&batch).unwrap();
            // SAFETY: live handle, valid buffer.
            let rc = unsafe { pl_app_ingest_json(app, json.as_ptr(), json.len()) };
            assert_eq!(rc, PL_OK);
        }
        let s = stats(app);
        assert_eq!(s["end_to_end"]["delivered"], 4);
        assert_eq!(s["end_to_end"]["missing"], 2, "3 and 4 never arrived");
        assert_eq!(s["end_to_end"]["gaps"], 1);
        assert_eq!(s["end_to_end"]["restarts"], 1);
        // SAFETY: closing once.
        unsafe { pl_app_close(app) };
    }

    #[test]
    fn null_handles_fail_cleanly() {
        // SAFETY: every entry point accepts NULL.
        unsafe {
            assert_eq!(pl_app_connect(std::ptr::null_mut()), PL_ERR_STATE);
            assert_eq!(
                pl_app_ingest_json(std::ptr::null_mut(), std::ptr::null(), 0),
                PL_ERR_STATE
            );
            assert!(pl_app_stats_json(std::ptr::null_mut()).is_null());
            pl_string_free(std::ptr::null_mut());
            pl_app_close(std::ptr::null_mut());
        }
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn connect_is_unsupported_off_macos() {
        // SAFETY: NULL path means in-memory.
        let app = unsafe { pl_app_open(std::ptr::null()) };
        // SAFETY: live handle.
        assert_eq!(unsafe { pl_app_connect(app) }, PL_ERR_UNSUPPORTED);
        // SAFETY: closing once.
        unsafe { pl_app_close(app) };
    }

    #[test]
    fn persists_across_reopen() {
        let dir = std::env::temp_dir().join(format!("pl-ffi-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = CString::new(dir.join("events.db").to_string_lossy().into_owned()).unwrap();
        let json =
            serde_json::to_vec(&vec![ev(proc_(5, 1, "/x"), Kind::Exit { status: 0 })]).unwrap();
        for expected in [1, 2] {
            // SAFETY: valid C string.
            let app = unsafe { pl_app_open(path.as_ptr()) };
            assert!(!app.is_null());
            // SAFETY: live handle, valid buffer.
            let rc = unsafe { pl_app_ingest_json(app, json.as_ptr(), json.len()) };
            assert_eq!(rc, PL_OK);
            assert_eq!(stats(app)["high_water"], expected);
            // SAFETY: closing once.
            unsafe { pl_app_close(app) };
        }
    }
}
