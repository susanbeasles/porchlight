#![allow(unsafe_code)]

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::marker::PhantomData;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr::NonNull;
use std::sync::Arc;

type MsgFn = extern "C" fn(*mut c_void, *mut c_void, *const c_char, i64, *mut c_void);
type PeerFn = extern "C" fn(*mut c_void, *mut c_void, c_int);

unsafe extern "C" {
    fn pl_xpc_listen(
        service: *const c_char,
        requirement: *const c_char,
        ctx: *mut c_void,
        on_msg: MsgFn,
        on_peer: PeerFn,
    ) -> c_int;
    fn pl_xpc_connect(
        service: *const c_char,
        requirement: *const c_char,
        ctx: *mut c_void,
        on_msg: MsgFn,
        on_peer: PeerFn,
    ) -> *mut c_void;
    fn pl_xpc_send(
        conn: *mut c_void,
        version: i64,
        op: *const c_char,
        data_key: *const c_char,
        data: *const u8,
        len: usize,
        int_key: *const c_char,
        int_val: i64,
    ) -> c_int;
    fn pl_xpc_msg_data(msg: *mut c_void, key: *const c_char, len: *mut usize) -> *const u8;
    fn pl_xpc_msg_int(msg: *mut c_void, key: *const c_char) -> i64;
    fn pl_xpc_msg_array_count(msg: *mut c_void, key: *const c_char) -> usize;
    fn pl_xpc_msg_array_string(msg: *mut c_void, key: *const c_char, index: usize)
    -> *const c_char;
    fn pl_xpc_cancel(conn: *mut c_void);
    fn pl_xpc_release(conn: *mut c_void);
}

/// Identity of a connection, stable for its lifetime. Usable as a map key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnId(usize);

/// An owned XPC connection (one retain).
#[derive(Debug)]
pub struct Connection {
    ptr: NonNull<c_void>,
}

// SAFETY: XPC connections are thread-safe; sending from any thread is supported.
unsafe impl Send for Connection {}
// SAFETY: as above; `send` takes `&self` and XPC serializes internally.
unsafe impl Sync for Connection {}

impl Connection {
    pub fn id(&self) -> ConnId {
        ConnId(self.ptr.as_ptr() as usize)
    }

    /// Sends `{v, op[, data_key: data][, int_key: int]}`.
    pub fn send(
        &self,
        version: i64,
        op: &str,
        data: Option<(&str, &[u8])>,
        int: Option<(&str, i64)>,
    ) -> bool {
        let Ok(op) = CString::new(op) else {
            return false;
        };
        let data_key = data.and_then(|(k, _)| CString::new(k).ok());
        let int_key = int.and_then(|(k, _)| CString::new(k).ok());
        let (dptr, dlen) = data.map_or((std::ptr::null(), 0), |(_, d)| (d.as_ptr(), d.len()));
        // SAFETY: `ptr` is retained by `self`; every pointer argument is either null or
        // points to memory that outlives the call; XPC copies the data.
        let rc = unsafe {
            pl_xpc_send(
                self.ptr.as_ptr(),
                version,
                op.as_ptr(),
                data_key.as_ref().map_or(std::ptr::null(), |k| k.as_ptr()),
                dptr,
                dlen,
                int_key.as_ref().map_or(std::ptr::null(), |k| k.as_ptr()),
                int.map_or(0, |(_, v)| v),
            )
        };
        rc == 0
    }

    pub fn cancel(&self) {
        // SAFETY: `ptr` is retained by `self`.
        unsafe { pl_xpc_cancel(self.ptr.as_ptr()) }
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        // SAFETY: releases exactly the one reference this value owns.
        unsafe { pl_xpc_release(self.ptr.as_ptr()) }
    }
}

/// A borrowed message, valid only inside [`Handler::message`].
pub struct Msg<'a> {
    ptr: *mut c_void,
    _borrow: PhantomData<&'a ()>,
}

impl<'a> Msg<'a> {
    pub fn data(&self, key: &str) -> Option<&'a [u8]> {
        let key = CString::new(key).ok()?;
        let mut len = 0usize;
        // SAFETY: `ptr` is a live dictionary for 'a; XPC returns a pointer into it or null.
        let p = unsafe { pl_xpc_msg_data(self.ptr, key.as_ptr(), &mut len) };
        if p.is_null() {
            return None;
        }
        // SAFETY: XPC guarantees `len` readable bytes at `p` while the message lives ('a).
        Some(unsafe { std::slice::from_raw_parts(p, len) })
    }

    pub fn int(&self, key: &str) -> i64 {
        let Ok(key) = CString::new(key) else { return 0 };
        // SAFETY: `ptr` is a live dictionary; missing keys yield 0.
        unsafe { pl_xpc_msg_int(self.ptr, key.as_ptr()) }
    }

    pub fn strings(&self, key: &str) -> Vec<String> {
        let Ok(k) = CString::new(key) else {
            return Vec::new();
        };
        // SAFETY: `ptr` is a live dictionary.
        let n = unsafe { pl_xpc_msg_array_count(self.ptr, k.as_ptr()) };
        (0..n)
            .filter_map(|i| {
                // SAFETY: `i < n`; the returned C string lives as long as the message.
                let s = unsafe { pl_xpc_msg_array_string(self.ptr, k.as_ptr(), i) };
                // SAFETY: non-null strings from XPC are NUL-terminated.
                (!s.is_null()).then(|| unsafe { CStr::from_ptr(s) }.to_string_lossy().into_owned())
            })
            .collect()
    }
}

pub enum PeerEvent {
    /// Listener: a new peer that passed the code-signing requirement.
    Connected(Connection),
    /// The remote process restarted. A client should re-send its setup messages.
    Interrupted(ConnId),
    /// Gone, or rejected by the requirement. Drop any `Connection` with this id.
    Invalid(ConnId),
}

pub trait Handler: Send + Sync + 'static {
    fn message(&self, conn: ConnId, op: &str, version: i64, msg: &Msg<'_>);
    fn peer(&self, event: PeerEvent);
}

type Ctx = Arc<dyn Handler>;

extern "C" fn on_msg(
    ctx: *mut c_void,
    conn: *mut c_void,
    op: *const c_char,
    version: i64,
    msg: *mut c_void,
) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: `ctx` is the leaked `Box<Ctx>` from `register`, alive for the process.
        let handler = unsafe { &*(ctx as *const Ctx) };
        // SAFETY: the shim passes a NUL-terminated op valid for this call.
        let op = unsafe { CStr::from_ptr(op) }.to_string_lossy();
        let msg = Msg {
            ptr: msg,
            _borrow: PhantomData,
        };
        handler.message(ConnId(conn as usize), &op, version, &msg);
    }));
}

extern "C" fn on_peer(ctx: *mut c_void, conn: *mut c_void, state: c_int) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: see `on_msg`.
        let handler = unsafe { &*(ctx as *const Ctx) };
        let event = match (state, NonNull::new(conn)) {
            // The shim retained this handle for us (+1).
            (1, Some(ptr)) => PeerEvent::Connected(Connection { ptr }),
            (0, _) => PeerEvent::Interrupted(ConnId(conn as usize)),
            _ => PeerEvent::Invalid(ConnId(conn as usize)),
        };
        handler.peer(event);
    }));
}

/// A handler registered once for the life of the process. Copy it into every connection, so
/// reconnecting allocates nothing that is never freed.
#[derive(Clone, Copy)]
pub struct HandlerRef(NonNull<c_void>);

// SAFETY: points at a leaked `Box<Arc<dyn Handler>>`, and `Handler: Send + Sync`.
unsafe impl Send for HandlerRef {}
// SAFETY: as above; the pointee is never mutated after registration.
unsafe impl Sync for HandlerRef {}

/// Registers `handler` for the life of the process.
pub fn register(handler: Arc<dyn Handler>) -> HandlerRef {
    let leaked: &'static mut Ctx = Box::leak(Box::new(handler));
    HandlerRef(NonNull::from(leaked).cast())
}

/// A code-signing requirement string, kept for the life of the process because the shim's
/// blocks and XPC may hold the pointer. Create one per distinct requirement, not per attempt.
#[derive(Clone, Copy)]
pub struct Requirement(&'static CStr);

impl Requirement {
    pub fn new(requirement: &str) -> Option<Self> {
        Some(Self(Box::leak(
            CString::new(requirement).ok()?.into_boxed_c_str(),
        )))
    }
}

/// Publishes `service`; peers must satisfy `requirement`.
pub fn listen(service: &str, requirement: Requirement, handler: HandlerRef) -> Result<(), String> {
    let service_c = CString::new(service).map_err(|e| e.to_string())?;
    // SAFETY: valid C strings; the requirement and the handler live for the process.
    let rc = unsafe {
        pl_xpc_listen(
            service_c.as_ptr(),
            requirement.0.as_ptr(),
            handler.0.as_ptr(),
            on_msg,
            on_peer,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(format!("xpc listen on {service} failed"))
    }
}

/// Connects to a privileged mach service whose process must satisfy `requirement`.
pub fn open_client(
    service: &str,
    requirement: Requirement,
    handler: HandlerRef,
) -> Option<Connection> {
    let service_c = CString::new(service).ok()?;
    // SAFETY: valid C strings; the requirement and the handler live for the process.
    let ptr = unsafe {
        pl_xpc_connect(
            service_c.as_ptr(),
            requirement.0.as_ptr(),
            handler.0.as_ptr(),
            on_msg,
            on_peer,
        )
    };
    NonNull::new(ptr).map(|ptr| Connection { ptr })
}
