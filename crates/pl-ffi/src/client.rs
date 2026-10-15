//! The app's XPC client to the extension (SPEC §4.7). macOS only.

use std::sync::{Arc, Mutex};

use pl_raw::protocol::{EsStatus, MACH_SERVICE, Op, PROTOCOL_VERSION, extension_requirement, key};
use pl_xpc::{ConnId, Connection, Handler, Msg, PeerEvent};

use crate::abi::{PL_ERR_FAILED, PL_ERR_STATE, PL_OK, PlApp, lock};
use crate::core::AppCore;

/// Watch-list versioning arrives with M3; M2 always sends 0.
const WATCH_LIST_VERSION: i64 = 0;

pub struct Client {
    conn: Arc<Connection>,
    alive: Arc<Mutex<bool>>,
}

struct Receiver {
    core: Arc<Mutex<AppCore>>,
    alive: Arc<Mutex<bool>>,
    /// Set once `connect` has the connection, so an interruption can re-send setup.
    conn: Mutex<Option<Arc<Connection>>>,
}

fn send_setup(conn: &Connection) {
    conn.send(
        PROTOCOL_VERSION,
        Op::StartStreaming.as_str(),
        None,
        Some((key::WATCH_LIST_VERSION, WATCH_LIST_VERSION)),
    );
    conn.send(PROTOCOL_VERSION, Op::Status.as_str(), None, None);
}

impl Handler for Receiver {
    fn message(&self, _conn: ConnId, op: &str, version: i64, msg: &Msg<'_>) {
        if version != PROTOCOL_VERSION {
            lock(&self.core).record_error(format!("extension protocol version {version}"));
            return;
        }
        match Op::parse(op) {
            Some(Op::Batch) => {
                if let Some(json) = msg.data(key::EVENTS) {
                    let _ = lock(&self.core).ingest_json(json);
                }
            }
            Some(Op::StatusChanged) => {
                let parsed = msg
                    .data(key::STATUS)
                    .map(serde_json::from_slice::<EsStatus>);
                let mut core = lock(&self.core);
                match parsed {
                    Some(Ok(status)) => core.set_extension_status(status),
                    Some(Err(e)) => core.record_error(format!("bad status payload: {e}")),
                    None => core.record_error("status message without payload".to_owned()),
                }
            }
            _ => lock(&self.core).record_error(format!("unexpected op {op:?} from extension")),
        }
    }

    fn peer(&self, event: PeerEvent) {
        match event {
            PeerEvent::Interrupted(_) => {
                // The extension restarted: it forgot that we were streaming.
                if let Some(conn) = self.conn.lock().unwrap_or_else(|p| p.into_inner()).as_ref() {
                    send_setup(conn);
                }
            }
            PeerEvent::Invalid(_) => {
                *self.alive.lock().unwrap_or_else(|p| p.into_inner()) = false;
                lock(&self.core).set_connected(false);
            }
            PeerEvent::Connected(_) => {}
        }
    }
}

pub fn start(app: &PlApp) -> i32 {
    let mut slot = app.client.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(existing) = slot.as_ref()
        && *existing.alive.lock().unwrap_or_else(|p| p.into_inner())
    {
        return PL_ERR_STATE;
    }
    let alive = Arc::new(Mutex::new(true));
    let receiver = Arc::new(Receiver {
        core: app.core.clone(),
        alive: alive.clone(),
        conn: Mutex::new(None),
    });
    let Some(conn) = pl_xpc::open_client(MACH_SERVICE, &extension_requirement(), receiver.clone())
    else {
        lock(&app.core).record_error("could not create XPC connection".to_owned());
        return PL_ERR_FAILED;
    };
    let conn = Arc::new(conn);
    // Shared before the first send, so an early interruption can re-send setup.
    *receiver.conn.lock().unwrap_or_else(|p| p.into_inner()) = Some(conn.clone());
    send_setup(&conn);
    lock(&app.core).set_connected(true);
    // Replacing a dead client drops it, which cancels its connection.
    *slot = Some(Client { conn, alive });
    PL_OK
}

impl Drop for Client {
    fn drop(&mut self) {
        self.conn.cancel();
    }
}
