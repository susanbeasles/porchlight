//! `#[repr(C)]` mirror of `include/rawevent.h`.

#![allow(unsafe_code)]

pub const PL_RAW_VERSION: u32 = 1;
pub const PL_PATH_MAX: usize = 1024;
pub const PL_SIGNING_ID_MAX: usize = 256;
pub const PL_TEAM_ID_MAX: usize = 32;
pub const PL_TTY_MAX: usize = 128;
pub const PL_CDHASH_LEN: usize = 20;
pub const PL_EXEC_BUF: usize = 16384;

pub const PL_EV_EXEC: u32 = 1;
pub const PL_EV_FORK: u32 = 2;
pub const PL_EV_EXIT: u32 = 3;
pub const PL_EV_SLOTS: usize = 64;

/// Bit flags, mirroring the `PL_PF_*` and `PL_XF_*` macros.
pub mod flags {
    pub const PLATFORM: u32 = 0x01;
    pub const ES_CLIENT: u32 = 0x02;
    pub const HAS_RESPONSIBLE: u32 = 0x04;
    pub const HAS_TTY: u32 = 0x08;
    pub const PATH_TRUNC: u32 = 0x10;
    pub const SIGNING_ID_TRUNC: u32 = 0x20;
    pub const TEAM_ID_TRUNC: u32 = 0x40;
    pub const TTY_TRUNC: u32 = 0x80;
    pub const PROCESS_TRUNC_MASK: u32 = PATH_TRUNC | SIGNING_ID_TRUNC | TEAM_ID_TRUNC | TTY_TRUNC;

    pub const ARGS_TRUNC: u32 = 0x01;
    pub const ENV_TRUNC: u32 = 0x02;
    pub const HAS_CWD: u32 = 0x04;
    pub const HAS_SCRIPT: u32 = 0x08;
    pub const CWD_TRUNC: u32 = 0x10;
    pub const SCRIPT_TRUNC: u32 = 0x20;
    pub const EXEC_TRUNC_MASK: u32 = ARGS_TRUNC | ENV_TRUNC | CWD_TRUNC | SCRIPT_TRUNC;
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PlToken {
    pub val: [u32; 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PlProcess {
    pub token: PlToken,
    pub parent_token: PlToken,
    pub responsible_token: PlToken,
    pub ppid: i32,
    pub session_id: i32,
    pub flags: u32,
    pub _pad0: u32,
    pub start_sec: i64,
    pub start_usec: i64,
    pub cdhash: [u8; PL_CDHASH_LEN],
    pub _pad1: [u8; 4],
    pub path: [u8; PL_PATH_MAX],
    pub signing_id: [u8; PL_SIGNING_ID_MAX],
    pub team_id: [u8; PL_TEAM_ID_MAX],
    pub tty: [u8; PL_TTY_MAX],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PlExec {
    pub target: PlProcess,
    pub argc: u32,
    pub envc: u32,
    pub args_len: u32,
    pub env_len: u32,
    pub flags: u32,
    pub _pad: u32,
    pub cwd: [u8; PL_PATH_MAX],
    pub script: [u8; PL_PATH_MAX],
    pub buf: [u8; PL_EXEC_BUF],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PlFork {
    pub child: PlToken,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PlExit {
    pub stat: i32,
    pub _pad: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union PlBody {
    pub exec: PlExec,
    pub fork: PlFork,
    pub exit: PlExit,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PlRawEvent {
    pub version: u32,
    pub event_type: u32,
    pub mach_time: u64,
    pub seq_num: u64,
    pub global_seq_num: u64,
    pub wall_sec: i64,
    pub wall_nsec: i64,
    pub process: PlProcess,
    pub u: PlBody,
}

const _: () = assert!(std::mem::size_of::<PlProcess>() == 1592);
const _: () = assert!(std::mem::size_of::<PlExec>() == 20048);
const _: () = assert!(std::mem::size_of::<PlRawEvent>() == 21688);
const _: () = assert!(std::mem::offset_of!(PlRawEvent, u) == 1640);

impl PlRawEvent {
    /// An all-zero record, boxed: the struct is 21 KB and should not live on the stack.
    pub fn zeroed_box() -> Box<Self> {
        // SAFETY: every field is an integer, an integer array, or a union of such types;
        // the all-zero bit pattern is a valid value for all of them.
        Box::new(unsafe { std::mem::zeroed() })
    }

    /// The exec body. Meaningful only when `event_type == PL_EV_EXEC`.
    pub fn exec(&self) -> &PlExec {
        // SAFETY: all union members are plain-old-data with no invalid bit patterns, so
        // reading any member is defined; the caller interprets it by `event_type`.
        unsafe { &self.u.exec }
    }

    pub fn exec_mut(&mut self) -> &mut PlExec {
        // SAFETY: as in `exec`; writes through a POD member are always valid.
        unsafe { &mut self.u.exec }
    }

    pub fn fork(&self) -> &PlFork {
        // SAFETY: see `exec`.
        unsafe { &self.u.fork }
    }

    pub fn fork_mut(&mut self) -> &mut PlFork {
        // SAFETY: see `exec_mut`.
        unsafe { &mut self.u.fork }
    }

    pub fn exit(&self) -> &PlExit {
        // SAFETY: see `exec`.
        unsafe { &self.u.exit }
    }

    pub fn exit_mut(&mut self) -> &mut PlExit {
        // SAFETY: see `exec_mut`.
        unsafe { &mut self.u.exit }
    }
}

/// Copies `s` into a NUL-terminated fixed buffer; returns true when it was truncated.
/// Used by tests and synthetic producers; the ES shim has its own C copy.
pub fn put_cstr(dst: &mut [u8], s: &str) -> bool {
    let cap = dst.len().saturating_sub(1);
    let n = s.len().min(cap);
    dst[..n].copy_from_slice(&s.as_bytes()[..n]);
    if let Some(b) = dst.get_mut(n) {
        *b = 0;
    }
    s.len() > cap
}

/// Reads a NUL-terminated string from a fixed buffer, lossily.
pub fn get_cstr(src: &[u8]) -> String {
    let end = src.iter().position(|&b| b == 0).unwrap_or(src.len());
    String::from_utf8_lossy(&src[..end]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::offset_of;

    unsafe extern "C" {
        fn pl_raw_layout(out: *mut usize, cap: usize) -> usize;
    }

    #[test]
    fn rust_and_c_layouts_agree() {
        let mut c = [0usize; 32];
        // SAFETY: the C function writes at most `cap` entries into `out`.
        let n = unsafe { pl_raw_layout(c.as_mut_ptr(), c.len()) };
        let rust = [
            std::mem::size_of::<PlRawEvent>(),
            std::mem::size_of::<PlProcess>(),
            std::mem::size_of::<PlExec>(),
            offset_of!(PlRawEvent, mach_time),
            offset_of!(PlRawEvent, wall_nsec),
            offset_of!(PlRawEvent, process),
            offset_of!(PlRawEvent, u),
            offset_of!(PlProcess, start_sec),
            offset_of!(PlProcess, cdhash),
            offset_of!(PlProcess, path),
            offset_of!(PlProcess, tty),
            offset_of!(PlExec, argc),
            offset_of!(PlExec, flags),
            offset_of!(PlExec, cwd),
            offset_of!(PlExec, buf),
        ];
        assert_eq!(n, rust.len());
        assert_eq!(&c[..n], &rust[..]);
    }

    #[test]
    fn cstr_round_trip_and_truncation() {
        let mut buf = [0xffu8; 8];
        assert!(!put_cstr(&mut buf, "abc"));
        assert_eq!(get_cstr(&buf), "abc");
        assert!(put_cstr(&mut buf, "abcdefghij"));
        assert_eq!(get_cstr(&buf), "abcdefg");
        let full = [b'x'; 4];
        assert_eq!(get_cstr(&full), "xxxx", "no NUL reads the whole buffer");
    }
}
