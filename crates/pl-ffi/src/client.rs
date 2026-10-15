//! The app's XPC client to the extension (SPEC §4.7). macOS only.
//!
//! One handler and one requirement are registered for the life of the app; each connection
//! attempt creates only a connection, which is released when it goes invalid. "Connected"
//! means the extension has answered, not that a connection object exists.

use std::sync::{Arc, Mutex, MutexGuard};

use pl_raw::protocol::{EsStatus, MACH_SERVICE, Op, PROTOCOL_VERSION, extension_requirement, key};
use pl_xpc::{ConnId, Connection, Handler, HandlerRef, Msg, PeerEvent, Requirement};

use crate::abi::{PL_ERR_FAILED, PL_ERR_STATE, PL_OK, PlApp, lock};
use crate::core::AppCore;

/// Watch-list versioning arrives with M3; M2 always sends 0.
const WATCH_LIST_VERSION: i64 = 0;

pub struct ClientState {
    handler: HandlerRef,
    requirement: Requirement,
    receiver: Arc<Receiver>,
}

struct Receiver {
    core: Arc<Mutex<AppCore>>,
    /// The live connection, if any. Cleared (and so released) when it goes invalid.
    current: Mutex<Option<Arc<Connection>>>,
}

impl Receiver {
    fn current(&self) -> MutexGuard<'_, Option<Arc<Connection>>> {
        self.current.lock().unwrap_or_else(|p| p.into_inner())
    }
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
                    let mut core = lock(&self.core);
                    core.set_connected(true);
                    let _ = core.ingest_json(json);
                }
            }
            Some(Op::StatusChanged) => {
                let parsed = msg
                    .data(key::STATUS)
                    .map(serde_json::from_slice::<EsStatus>);
                let mut core = lock(&self.core);
                core.set_connected(true);
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
        let mut current = self.current();
        match event {
            PeerEvent::Interrupted(id) => {
                // The extension restarted and forgot this client was streaming.
                if let Some(conn) = current.as_ref().filter(|c| c.id() == id) {
                    lock(&self.core).set_connected(false);
                    send_setup(conn);
                }
            }
            PeerEvent::Invalid(id) => {
                // Ignore invalidations of connections already replaced.
                if current.as_ref().is_some_and(|c| c.id() == id) {
                    *current = None;
                    lock(&self.core).set_connected(false);
                }
            }
            PeerEvent::Connected(_) => {}
        }
    }
}

/// Opens a connection unless one is live. Safe to call repeatedly.
pub fn start(app: &PlApp) -> i32 {
    let mut slot = app.client.lock().unwrap_or_else(|p| p.into_inner());
    if slot.is_none() {
        let Some(requirement) = Requirement::new(&extension_requirement()) else {
            return PL_ERR_FAILED;
        };
        let receiver = Arc::new(Receiver {
            core: app.core.clone(),
            current: Mutex::new(None),
        });
        let handler = pl_xpc::register(receiver.clone());
        *slot = Some(ClientState {
            handler,
            requirement,
            receiver,
        });
    }
    let Some(state) = slot.as_ref() else {
        return PL_ERR_FAILED;
    };
    // Held across creation: an INVALID delivered on the XPC queue waits until the new
    // connection is recorded, so it can never be missed.
    let mut current = state.receiver.current();
    if current.is_some() {
        return PL_ERR_STATE;
    }
    let Some(conn) = pl_xpc::open_client(MACH_SERVICE, state.requirement, state.handler) else {
        lock(&app.core).record_error("could not create XPC connection".to_owned());
        return PL_ERR_FAILED;
    };
    let conn = Arc::new(conn);
    send_setup(&conn);
    *current = Some(conn);
    PL_OK
}

impl Drop for ClientState {
    fn drop(&mut self) {
        if let Some(conn) = self.receiver.current().take() {
            conn.cancel();
        }
    }
}
