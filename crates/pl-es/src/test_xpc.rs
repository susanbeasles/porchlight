//! Portable transport double for exercising the real Service state machine.
//! Does not substitute for native audit-token, code-signature or user-switch validation.
#![allow(dead_code)]
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ConnId(usize);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Principal {
    pub uid: u32,
    pub asid: u32,
}
static CURRENT: Mutex<Option<Principal>> = Mutex::new(None);
impl Principal {
    pub fn is_current(self) -> bool {
        self.uid == 501 && *CURRENT.lock().unwrap() == Some(self)
    }
}
#[derive(Clone)]
pub struct Connection {
    id: ConnId,
    principal: Principal,
    messages: Arc<Mutex<Vec<Vec<u8>>>>,
    cancelled: Arc<Mutex<bool>>,
}
impl Connection {
    fn new(principal: Principal) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(1);
        Self {
            id: ConnId(NEXT.fetch_add(1, Ordering::Relaxed)),
            principal,
            messages: Default::default(),
            cancelled: Default::default(),
        }
    }
    pub fn id(&self) -> ConnId {
        self.id
    }
    pub fn authorized_principal(&self) -> Option<Principal> {
        (self.principal.is_current() && !*self.cancelled.lock().unwrap()).then_some(self.principal)
    }
    pub fn cancel(&self) {
        *self.cancelled.lock().unwrap() = true;
    }
    pub fn send(
        &self,
        _: i64,
        op: &str,
        data: Option<(&str, &[u8])>,
        _: Option<(&str, i64)>,
    ) -> bool {
        if op == "batch" {
            self.messages.lock().unwrap().push(data.unwrap().1.to_vec());
        }
        true
    }
}
pub enum PeerEvent {
    Connected(Connection),
    Interrupted(ConnId),
    Invalid(ConnId),
}
pub struct Msg<'a>(std::marker::PhantomData<&'a ()>);
impl Msg<'_> {
    pub fn int(&self, _: &str) -> i64 {
        0
    }
    pub fn strings(&self, _: &str) -> Vec<String> {
        Vec::new()
    }
}
pub trait Handler {
    fn message(&self, conn: ConnId, op: &str, version: i64, msg: &Msg<'_>);
    fn peer(&self, event: PeerEvent);
}
#[test]
fn service_binds_single_consumer_and_never_transfers_previous_session_backlog() {
    use pl_core::schema::{
        AuditToken, Event, Kind, MachTime, ProcessIdentity, SCHEMA_VERSION, Source, WallTime,
    };
    use pl_raw::protocol::PROTOCOL_VERSION;
    let identity = ProcessIdentity {
        token: AuditToken::default(),
        parent_token: AuditToken::default(),
        responsible_token: None,
        executable_path: "/fixture".into(),
        signing_id: None,
        team_id: None,
        cdhash: String::new(),
        is_platform_binary: false,
        is_es_client: false,
        tty: None,
        session_id: 0,
        start_time: WallTime(0),
    };
    let event = |seq| Event {
        schema_version: SCHEMA_VERSION,
        capture: None,
        id: 0,
        mach_time: MachTime(seq),
        wall_time: WallTime(seq as i64),
        seq_num: seq,
        global_seq_num: seq,
        source: Source::Synthetic,
        process: identity.clone(),
        kind: Kind::Exec {
            target: Box::new(identity.clone()),
            args: vec!["private".into()],
            env: BTreeMap::new(),
            cwd: None,
            script_path: None,
        },
    };
    let service = crate::service::Service::new(identity.clone(), 16);
    service.set_es_state(pl_raw::protocol::EsState::Running);
    service.update_stats(&pl_raw::bridge::BridgeStats::default(), 0);
    let a = Principal {
        uid: 501,
        asid: 100,
    };
    let other = Principal {
        uid: 502,
        asid: 200,
    };
    *CURRENT.lock().unwrap() = Some(a);
    let unauthorized = Connection::new(other);
    service.peer(PeerEvent::Connected(unauthorized.clone()));
    assert!(*unauthorized.cancelled.lock().unwrap());
    service.message(
        unauthorized.id(),
        "start_streaming",
        PROTOCOL_VERSION,
        &Msg(Default::default()),
    );
    service.deliver(vec![event(1)]); // Unowned payload cannot be claimed by the first peer.
    let first = Connection::new(a);
    service.peer(PeerEvent::Connected(first.clone()));
    service.message(
        first.id(),
        "start_streaming",
        PROTOCOL_VERSION,
        &Msg(Default::default()),
    );
    let unowned: Vec<Event> = serde_json::from_slice(&first.messages.lock().unwrap()[0]).unwrap();
    assert!(unowned.iter().all(|e| matches!(e.kind, Kind::Drop { .. })));
    service.deliver(vec![event(2)]);
    let second = Connection::new(a);
    service.peer(PeerEvent::Connected(second.clone()));
    assert!(*second.cancelled.lock().unwrap());
    service.peer(PeerEvent::Invalid(first.id()));
    service.deliver(vec![event(3)]); // Backlog belongs to A only.
    *CURRENT.lock().unwrap() = Some(other);
    let other_console_user = Connection::new(other);
    service.peer(PeerEvent::Connected(other_console_user.clone()));
    assert!(*other_console_user.cancelled.lock().unwrap());
    assert!(other_console_user.messages.lock().unwrap().is_empty());
    let returning_owner = Principal {
        uid: 501,
        asid: 101,
    };
    *CURRENT.lock().unwrap() = Some(returning_owner);
    let switched = Connection::new(returning_owner);
    service.peer(PeerEvent::Connected(switched.clone()));
    service.message(
        switched.id(),
        "start_streaming",
        PROTOCOL_VERSION,
        &Msg(Default::default()),
    );
    let lost: Vec<Event> = serde_json::from_slice(&switched.messages.lock().unwrap()[0]).unwrap();
    assert!(lost.iter().all(|e| matches!(e.kind, Kind::Drop { .. })));
    assert!(lost.iter().any(
        |e| matches!(&e.kind, Kind::Drop { event_type, .. } if event_type == "ownership_transition")
    ));
    let count = switched.messages.lock().unwrap().len();
    *CURRENT.lock().unwrap() = Some(Principal {
        uid: 502,
        asid: 201,
    });
    service.deliver(vec![event(4)]);
    assert!(*switched.cancelled.lock().unwrap());
    assert_eq!(switched.messages.lock().unwrap().len(), count);
    *CURRENT.lock().unwrap() = None;
}
