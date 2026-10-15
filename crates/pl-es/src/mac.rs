#![allow(unsafe_code)]

use std::ffi::{CString, c_char, c_int, c_void};
use std::sync::Arc;
use std::time::{Duration, Instant};

use pl_core::schema::{ProcessIdentity, WallTime};
use pl_raw::bridge::{Bridge, MAX_BATCH};
use pl_raw::protocol::{EsState, MACH_SERVICE, app_requirement};
use pl_raw::{PlToken, RING_CAPACITY, Ring, decode};

use crate::service::Service;

unsafe extern "C" {
    fn pl_es_start(ring: *mut c_void) -> c_int;
    fn pl_es_self_token(out: *mut PlToken) -> c_int;
    fn pl_es_mute_failures() -> u32;
    fn pl_log_init();
    fn pl_log(level: c_int, msg: *const c_char);
    fn dispatch_main() -> !;
}

/// os_log through the shim. Never called from the ES handler (C5).
pub fn log(level: i32, msg: &str) {
    let clean: String = msg.chars().filter(|&c| c != '\0').collect();
    if let Ok(c) = CString::new(clean) {
        // SAFETY: valid C string for the duration of the call.
        unsafe { pl_log(level, c.as_ptr()) }
    }
}

fn self_identity() -> ProcessIdentity {
    let mut raw = PlToken::default();
    // SAFETY: writes one PlToken (same layout as audit_token_t, asserted in C).
    let ok = unsafe { pl_es_self_token(&mut raw) } == 0;
    if !ok {
        log(
            1,
            "could not read own audit token; drop events will carry a zero token",
        );
    }
    ProcessIdentity {
        token: decode::token(&raw),
        parent_token: Default::default(),
        responsible_token: None,
        executable_path: std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_default(),
        signing_id: Some(pl_raw::protocol::EXTENSION_BUNDLE_ID.to_owned()),
        team_id: Some(pl_raw::protocol::TEAM_ID.to_owned()),
        cdhash: String::new(),
        is_platform_binary: false,
        is_es_client: true,
        tty: None,
        session_id: 0,
        start_time: WallTime(0),
    }
}

/// Drains the ring forever. Sleeps briefly only when the ring was empty.
fn bridge_loop(ring: &'static Ring, service: Arc<Service>, identity: ProcessIdentity) {
    let mut bridge = Bridge::new(identity);
    let mut buf = Vec::with_capacity(MAX_BATCH);
    loop {
        let n = ring.pop(&mut buf, MAX_BATCH);
        let now = Instant::now();
        bridge.accept(&buf, &ring.drop_counts(), now);
        for batch in bridge.take_ready(now) {
            service.deliver(batch);
        }
        service.update_stats(bridge.stats(), ring.producer_overlaps());
        if n == 0 {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

pub fn run() -> ! {
    // SAFETY: one-time logger setup before any other thread exists.
    unsafe { pl_log_init() };
    log(0, "porchlight extension starting");

    let Some(ring) = Ring::new(RING_CAPACITY) else {
        log(2, "ring allocation failed");
        std::process::exit(1);
    };
    // The ES client writes into the ring for the life of the process.
    let ring: &'static Ring = Box::leak(Box::new(ring));
    let identity = self_identity();
    let service = Arc::new(Service::new(identity.clone(), ring.capacity()));

    if let Err(e) = pl_xpc::listen(MACH_SERVICE, &app_requirement(), service.clone()) {
        log(2, &e);
    }

    // SAFETY: `ring` is a live pl_ring_t for the life of the process.
    let code = unsafe { pl_es_start(ring.as_ptr()) };
    let state = EsState::from_shim(code);
    service.set_es_state(state);
    if state == EsState::Running {
        // SAFETY: plain getter.
        if unsafe { pl_es_mute_failures() } > 0 {
            log(
                1,
                "could not mute own process; Porchlight will observe itself",
            );
        }
        let svc = service.clone();
        if let Err(e) = std::thread::Builder::new()
            .name("pl-bridge".to_owned())
            .spawn(move || bridge_loop(ring, svc, identity))
        {
            log(2, &format!("bridge thread failed to start: {e}"));
        }
        log(0, "endpoint security client running");
    } else {
        // SPEC §4.1: report, stay alive so the app can tell the user what to do, no retry loop.
        log(
            2,
            &format!("endpoint security client not started: {state:?}"),
        );
    }

    // SAFETY: hands the main thread to libdispatch; never returns.
    unsafe { dispatch_main() }
}
