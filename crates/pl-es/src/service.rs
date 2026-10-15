//! The extension's XPC service: peers, streaming state, the outbox, and status.

use std::collections::BTreeMap;
use std::sync::Mutex;

use pl_core::schema::{Event, ProcessIdentity};
use pl_raw::bridge::{BridgeStats, Outbox};
use pl_raw::protocol::{EsState, EsStatus, Op, PROTOCOL_VERSION, key};
use pl_xpc::{ConnId, Connection, Handler, Msg, PeerEvent};

use crate::mac::log;

struct State {
    peers: BTreeMap<ConnId, Connection>,
    streaming: bool,
    outbox: Outbox,
    es_state: EsState,
    bridge: BridgeStats,
    ring_capacity: u32,
    producer_overlaps: u64,
}

pub struct Service {
    state: Mutex<State>,
}

impl Service {
    pub fn new(identity: ProcessIdentity, ring_capacity: u32) -> Self {
        Self {
            state: Mutex::new(State {
                peers: BTreeMap::new(),
                streaming: false,
                outbox: Outbox::new(identity),
                es_state: EsState::Starting,
                bridge: BridgeStats::default(),
                ring_capacity,
                producer_overlaps: 0,
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        // A poisoned lock means a panic mid-update; the state is still the best we have.
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn set_es_state(&self, es_state: EsState) {
        let mut st = self.lock();
        st.es_state = es_state;
        broadcast_status(&st);
    }

    pub fn update_stats(&self, bridge: &BridgeStats, producer_overlaps: u64) {
        let mut st = self.lock();
        st.bridge = bridge.clone();
        st.producer_overlaps = producer_overlaps;
    }

    /// Hands a batch from the bridge to connected streaming peers, or queues it.
    pub fn deliver(&self, batch: Vec<Event>) {
        let mut st = self.lock();
        if let Some(batch) = st.outbox.offer(batch) {
            send_batch(&st, &batch);
        }
    }

    fn sync_connected(st: &mut State) {
        let connected = st.streaming && !st.peers.is_empty();
        st.outbox.set_connected(connected);
        if connected {
            for batch in st.outbox.drain() {
                send_batch(st, &batch);
            }
        }
    }
}

fn status_json(st: &State) -> Vec<u8> {
    let status = EsStatus {
        protocol_version: PROTOCOL_VERSION,
        state: st.es_state,
        streaming: st.streaming,
        ring_capacity: st.ring_capacity,
        producer_overlaps: st.producer_overlaps,
        queued_while_disconnected: st.outbox.queued() as u64,
        bridge: st.bridge.clone(),
    };
    serde_json::to_vec(&status).unwrap_or_default()
}

fn send_status(st: &State, conn: &Connection) {
    let json = status_json(st);
    conn.send(
        PROTOCOL_VERSION,
        Op::StatusChanged.as_str(),
        Some((key::STATUS, &json)),
        None,
    );
}

fn broadcast_status(st: &State) {
    for conn in st.peers.values() {
        send_status(st, conn);
    }
}

fn send_batch(st: &State, batch: &[Event]) {
    let Ok(json) = serde_json::to_vec(batch) else {
        log(1, "batch serialization failed");
        return;
    };
    for conn in st.peers.values() {
        conn.send(
            PROTOCOL_VERSION,
            Op::Batch.as_str(),
            Some((key::EVENTS, &json)),
            None,
        );
    }
}

impl Handler for Service {
    fn message(&self, conn: ConnId, op: &str, version: i64, msg: &Msg<'_>) {
        if version != PROTOCOL_VERSION {
            log(
                1,
                &format!("rejected message with protocol version {version}"),
            );
            return;
        }
        let mut st = self.lock();
        match Op::parse(op) {
            Some(Op::Status) => {
                if let Some(c) = st.peers.get(&conn) {
                    send_status(&st, c);
                }
            }
            Some(Op::StartStreaming) => {
                let _watch_list_version = msg.int(key::WATCH_LIST_VERSION);
                st.streaming = true;
                Service::sync_connected(&mut st);
                broadcast_status(&st);
            }
            Some(Op::StopStreaming) => {
                st.streaming = false;
                Service::sync_connected(&mut st);
                broadcast_status(&st);
            }
            Some(Op::UpdateWatchList) => {
                // File events and path muting land in M3.
                let n = msg.strings(key::PATHS).len();
                log(
                    0,
                    &format!("update_watch_list with {n} paths ignored until M3"),
                );
            }
            _ => log(1, &format!("rejected unknown op {op:?}")),
        }
    }

    fn peer(&self, event: PeerEvent) {
        let mut st = self.lock();
        match event {
            PeerEvent::Connected(conn) => {
                st.peers.insert(conn.id(), conn);
            }
            PeerEvent::Interrupted(_) => {}
            PeerEvent::Invalid(id) => {
                st.peers.remove(&id);
                if st.peers.is_empty() {
                    st.streaming = false;
                }
            }
        }
        Service::sync_connected(&mut st);
    }
}
