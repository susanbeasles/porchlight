//! The extension's XPC service: peers, streaming state, the outbox, and status.

use std::collections::BTreeMap;
use std::sync::Mutex;

use pl_core::schema::{Event, ProcessIdentity};
use pl_raw::bridge::{BridgeStats, Outbox};
use pl_raw::protocol::{EsState, EsStatus, Op, PROTOCOL_VERSION, key};
#[cfg(target_os = "macos")]
use pl_xpc::{ConnId, Connection, Handler, Msg, PeerEvent, Principal};

#[cfg(target_os = "macos")]
use crate::mac::log;
#[cfg(all(test, not(target_os = "macos")))]
use crate::test_xpc::{ConnId, Connection, Handler, Msg, PeerEvent, Principal};
#[cfg(all(test, not(target_os = "macos")))]
fn log(_: i32, _: &str) {}

struct Peer {
    conn: Connection,
    streaming: bool,
}

struct State {
    peers: BTreeMap<ConnId, Peer>,
    outbox: Outbox,
    owner: Option<Principal>,
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
                outbox: Outbox::new(identity),
                owner: None,
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
        Self::reauthorize(&mut st);
        if st.owner.is_none() {
            let _ = st.outbox.offer(batch);
            st.outbox.discard_for_owner_change();
            return;
        }
        if let Some(batch) = st.outbox.offer(batch) {
            send_batch(&st, &batch);
        }
    }

    fn reauthorize(st: &mut State) {
        st.peers.retain(|_, peer| {
            let allowed = peer
                .conn
                .authorized_principal()
                .is_some_and(|p| Some(p) == st.owner);
            if !allowed {
                peer.conn.cancel();
            }
            allowed
        });
        if st.owner.is_some_and(|p| !p.is_current()) {
            st.owner = None;
            st.outbox.discard_for_owner_change();
        }
        st.outbox
            .set_connected(st.peers.values().any(|p| p.streaming));
    }

    fn sync_connected(st: &mut State) {
        Self::reauthorize(st);
        let connected = st.peers.values().any(|p| p.streaming);
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
        streaming: st.peers.values().any(|p| p.streaming),
        ring_capacity: st.ring_capacity,
        producer_overlaps: st.producer_overlaps,
        queued_while_disconnected: st.outbox.queued() as u64,
        bridge: BridgeStats {
            disconnected_drops: st.outbox.dropped_total(),
            ..st.bridge.clone()
        },
    };
    serde_json::to_vec(&status).unwrap_or_default()
}

fn send_status(st: &State, conn: &Connection) {
    if conn
        .authorized_principal()
        .is_none_or(|p| Some(p) != st.owner)
    {
        return;
    }
    let json = status_json(st);
    conn.send(
        PROTOCOL_VERSION,
        Op::StatusChanged.as_str(),
        Some((key::STATUS, &json)),
        None,
    );
}

fn broadcast_status(st: &State) {
    for peer in st.peers.values() {
        send_status(st, &peer.conn);
    }
}

fn send_batch(st: &State, batch: &[Event]) {
    let Ok(json) = serde_json::to_vec(batch) else {
        log(1, "batch serialization failed");
        return;
    };
    // Only peers that asked to stream receive events.
    for peer in st.peers.values().filter(|p| {
        p.streaming
            && p.conn
                .authorized_principal()
                .is_some_and(|owner| Some(owner) == st.owner)
    }) {
        peer.conn.send(
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
        Self::reauthorize(&mut st);
        if !st.peers.contains_key(&conn) {
            return;
        }
        match Op::parse(op) {
            Some(Op::Status) => {
                if let Some(p) = st.peers.get(&conn) {
                    send_status(&st, &p.conn);
                }
            }
            Some(Op::StartStreaming) => {
                let _watch_list_version = msg.int(key::WATCH_LIST_VERSION);
                if let Some(p) = st.peers.get_mut(&conn) {
                    p.streaming = true;
                }
                Service::sync_connected(&mut st);
                broadcast_status(&st);
            }
            Some(Op::StopStreaming) => {
                if let Some(p) = st.peers.get_mut(&conn) {
                    p.streaming = false;
                }
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
                Self::reauthorize(&mut st);
                let Some(principal) = conn.authorized_principal() else {
                    conn.cancel();
                    return;
                };
                // Single consumer, bound to an authorized principal. A second app instance
                // cannot consume another connection's backlog.
                if !st.peers.is_empty() {
                    conn.cancel();
                    return;
                }
                if st.owner != Some(principal) {
                    st.outbox.discard_for_owner_change();
                    st.owner = Some(principal);
                }
                st.peers.insert(
                    conn.id(),
                    Peer {
                        conn,
                        streaming: false,
                    },
                );
            }
            PeerEvent::Interrupted(_) => {}
            PeerEvent::Invalid(id) => {
                st.peers.remove(&id);
            }
        }
        Service::sync_connected(&mut st);
    }
}
