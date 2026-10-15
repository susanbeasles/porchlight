//! `PlRawEvent` to schema `Event` (SPEC §4.6: the bridge converts; ids are assigned later
//! by the app-side pipeline).

use std::collections::BTreeMap;
use std::fmt;

use pl_core::schema::{
    AuditToken, Event, Kind, MachTime, ProcessIdentity, SCHEMA_VERSION, Source, WallTime,
};

use crate::raw::{
    PL_EV_EXEC, PL_EV_EXIT, PL_EV_FORK, PL_RAW_VERSION, PlProcess, PlRawEvent, PlToken, flags,
    get_cstr,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    Version(u32),
    UnknownType(u32),
    ExecBuffer { args_len: u32, env_len: u32 },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::Version(v) => {
                write!(f, "raw event version {v}, expected {PL_RAW_VERSION}")
            }
            DecodeError::UnknownType(t) => write!(f, "unknown raw event type {t}"),
            DecodeError::ExecBuffer { args_len, env_len } => {
                write!(
                    f,
                    "exec buffer lengths out of range: args {args_len}, env {env_len}"
                )
            }
        }
    }
}

impl std::error::Error for DecodeError {}

/// The `eslogger`-style name of a raw event type, used in `drop` events.
pub fn event_type_name(event_type: u32) -> &'static str {
    match event_type {
        PL_EV_EXEC => "exec",
        PL_EV_FORK => "fork",
        PL_EV_EXIT => "exit",
        _ => "unknown",
    }
}

/// `audit_token_t` decomposition, libbsm order.
pub fn token(t: &PlToken) -> AuditToken {
    AuditToken {
        auid: t.val[0],
        euid: t.val[1],
        egid: t.val[2],
        ruid: t.val[3],
        rgid: t.val[4],
        pid: t.val[5] as i32,
        asid: t.val[6],
        pidversion: t.val[7] as i32,
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

fn non_empty(s: String) -> Option<String> {
    if s.is_empty() { None } else { Some(s) }
}

pub fn process(p: &PlProcess) -> ProcessIdentity {
    let responsible = (p.flags & flags::HAS_RESPONSIBLE != 0).then(|| token(&p.responsible_token));
    let tty = (p.flags & flags::HAS_TTY != 0)
        .then(|| get_cstr(&p.tty))
        .and_then(non_empty);
    ProcessIdentity {
        token: token(&p.token),
        parent_token: token(&p.parent_token),
        responsible_token: responsible,
        executable_path: get_cstr(&p.path),
        signing_id: non_empty(get_cstr(&p.signing_id)),
        team_id: non_empty(get_cstr(&p.team_id)),
        cdhash: hex(&p.cdhash),
        is_platform_binary: p.flags & flags::PLATFORM != 0,
        is_es_client: p.flags & flags::ES_CLIENT != 0,
        tty,
        session_id: p.session_id,
        start_time: WallTime(
            p.start_sec
                .saturating_mul(1_000_000_000)
                .saturating_add(p.start_usec.saturating_mul(1000)),
        ),
    }
}

fn split_nul(bytes: &[u8], limit: u32) -> Vec<String> {
    bytes
        .split(|&b| b == 0)
        .take(limit as usize)
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect()
}

/// True when any string or the exec buffer was cut short. The v1 schema has no truncation
/// field, so the bridge counts these instead (`BridgeStats::truncated`).
pub fn is_truncated(raw: &PlRawEvent) -> bool {
    let mut t = raw.process.flags & flags::PROCESS_TRUNC_MASK != 0;
    if raw.event_type == PL_EV_EXEC {
        let x = raw.exec();
        t |= x.flags & flags::EXEC_TRUNC_MASK != 0
            || x.target.flags & flags::PROCESS_TRUNC_MASK != 0;
    }
    t
}

pub fn decode(raw: &PlRawEvent) -> Result<Event, DecodeError> {
    if raw.version != PL_RAW_VERSION {
        return Err(DecodeError::Version(raw.version));
    }
    let kind = match raw.event_type {
        PL_EV_EXEC => {
            let x = raw.exec();
            let args_end = x.args_len as usize;
            let env_end = args_end + x.env_len as usize;
            if env_end > x.buf.len() {
                return Err(DecodeError::ExecBuffer {
                    args_len: x.args_len,
                    env_len: x.env_len,
                });
            }
            let args = if x.argc == 0 {
                Vec::new()
            } else {
                split_nul(&x.buf[..args_end], x.argc)
            };
            let env: BTreeMap<String, String> = if x.envc == 0 {
                BTreeMap::new()
            } else {
                split_nul(&x.buf[args_end..env_end], x.envc)
                    .into_iter()
                    .map(|kv| match kv.split_once('=') {
                        Some((k, v)) => (k.to_owned(), v.to_owned()),
                        None => (kv, String::new()),
                    })
                    .collect()
            };
            Kind::Exec {
                target: Box::new(process(&x.target)),
                args,
                env,
                cwd: (x.flags & flags::HAS_CWD != 0)
                    .then(|| get_cstr(&x.cwd))
                    .and_then(non_empty),
                script_path: (x.flags & flags::HAS_SCRIPT != 0)
                    .then(|| get_cstr(&x.script))
                    .and_then(non_empty),
            }
        }
        PL_EV_FORK => Kind::Fork {
            child: token(&raw.fork().child),
        },
        PL_EV_EXIT => Kind::Exit {
            status: raw.exit().stat,
        },
        other => return Err(DecodeError::UnknownType(other)),
    };
    Ok(Event {
        schema_version: SCHEMA_VERSION,
        id: 0,
        mach_time: MachTime(raw.mach_time),
        wall_time: WallTime(
            raw.wall_sec
                .saturating_mul(1_000_000_000)
                .saturating_add(raw.wall_nsec),
        ),
        seq_num: raw.seq_num,
        global_seq_num: raw.global_seq_num,
        source: Source::EndpointSecurity,
        process: process(&raw.process),
        kind,
    })
}

#[cfg(test)]
pub(crate) mod testing {
    //! Builders for synthetic raw events, shared by the decode and bridge tests.
    use super::*;
    use crate::raw::put_cstr;

    pub(crate) fn tok(pid: u32, pidversion: u32) -> PlToken {
        PlToken {
            val: [501, 501, 20, 501, 20, pid, 100_005, pidversion],
        }
    }

    pub(crate) fn fill_process(p: &mut PlProcess, pid: u32, pidversion: u32, path: &str) {
        p.token = tok(pid, pidversion);
        p.parent_token = tok(1, 1);
        p.flags = flags::PLATFORM;
        p.session_id = 100_005;
        p.start_sec = 1_760_000_000;
        p.start_usec = 250_000;
        p.cdhash = [0xab; 20];
        put_cstr(&mut p.path, path);
        put_cstr(&mut p.signing_id, "com.apple.zsh");
    }

    pub(crate) fn raw(ty: u32, seq: u64) -> Box<PlRawEvent> {
        let mut e = PlRawEvent::zeroed_box();
        e.version = PL_RAW_VERSION;
        e.event_type = ty;
        e.seq_num = seq;
        e.global_seq_num = seq;
        e.mach_time = 1000 + seq;
        e.wall_sec = 1_760_000_100;
        e.wall_nsec = 5;
        fill_process(&mut e.process, 400, 3, "/bin/zsh");
        e
    }

    pub(crate) fn exec(seq: u64, args: &[&str], env: &[&str]) -> Box<PlRawEvent> {
        let mut e = raw(PL_EV_EXEC, seq);
        let x = e.exec_mut();
        fill_process(&mut x.target, 400, 4, "/usr/bin/curl");
        let mut off = 0;
        for a in args {
            x.buf[off..off + a.len()].copy_from_slice(a.as_bytes());
            off += a.len() + 1;
        }
        x.args_len = off as u32;
        for kv in env {
            x.buf[off..off + kv.len()].copy_from_slice(kv.as_bytes());
            off += kv.len() + 1;
        }
        x.env_len = off as u32 - x.args_len;
        x.argc = args.len() as u32;
        x.envc = env.len() as u32;
        x.flags = flags::HAS_CWD;
        put_cstr(&mut x.cwd, "/Users/u");
        e
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;

    #[test]
    fn decodes_exec_with_args_env_and_identity() {
        let raw = exec(
            9,
            &["curl", "-fsSL", ""],
            &["PATH=/bin", "NOEQ", "HOME=/Users/u"],
        );
        let ev = decode(&raw).unwrap();
        assert_eq!(ev.source, Source::EndpointSecurity);
        assert_eq!(ev.seq_num, 9);
        assert_eq!(ev.wall_time, WallTime(1_760_000_100_000_000_005));
        assert_eq!(ev.process.token.key(), "400:3");
        assert_eq!(ev.process.token.auid, 501);
        assert_eq!(ev.process.token.egid, 20);
        assert_eq!(ev.process.cdhash, "ab".repeat(20));
        assert_eq!(ev.process.start_time, WallTime(1_760_000_000_250_000_000));
        assert_eq!(ev.process.team_id, None);
        assert_eq!(ev.process.responsible_token, None);
        match ev.kind {
            Kind::Exec {
                target,
                args,
                env,
                cwd,
                script_path,
            } => {
                assert_eq!(target.token.key(), "400:4");
                assert_eq!(target.executable_path, "/usr/bin/curl");
                assert_eq!(args, vec!["curl", "-fsSL", ""], "empty argument preserved");
                assert_eq!(env.get("PATH").map(String::as_str), Some("/bin"));
                assert_eq!(env.get("NOEQ").map(String::as_str), Some(""));
                assert_eq!(env.len(), 3);
                assert_eq!(cwd.as_deref(), Some("/Users/u"));
                assert_eq!(script_path, None);
            }
            other => panic!("{other:?}"),
        }
        assert!(!is_truncated(&raw));
    }

    #[test]
    fn decodes_fork_exit_and_flags() {
        let mut f = raw(PL_EV_FORK, 1);
        f.fork_mut().child = tok(401, 1);
        f.process.flags |= flags::HAS_TTY | flags::HAS_RESPONSIBLE | flags::PATH_TRUNC;
        f.process.responsible_token = tok(300, 2);
        crate::raw::put_cstr(&mut f.process.tty, "/dev/ttys001");
        let ev = decode(&f).unwrap();
        assert_eq!(
            ev.kind,
            Kind::Fork {
                child: AuditToken {
                    pid: 401,
                    pidversion: 1,
                    ..Default::default()
                }
            }
        );
        assert_eq!(ev.process.tty.as_deref(), Some("/dev/ttys001"));
        assert_eq!(
            ev.process.responsible_token.map(|t| t.key()),
            Some("300:2".to_owned())
        );
        assert!(is_truncated(&f));
        let mut x = raw(PL_EV_EXIT, 2);
        x.exit_mut().stat = 256;
        assert_eq!(decode(&x).unwrap().kind, Kind::Exit { status: 256 });
    }

    #[test]
    fn rejects_bad_version_type_and_buffer() {
        let mut e = raw(PL_EV_EXIT, 1);
        e.version = 2;
        assert_eq!(decode(&e).unwrap_err(), DecodeError::Version(2));
        let e = raw(77, 1);
        assert_eq!(decode(&e).unwrap_err(), DecodeError::UnknownType(77));
        let mut e = exec(1, &["a"], &[]);
        e.exec_mut().env_len = u32::MAX / 2;
        assert!(matches!(
            decode(&e).unwrap_err(),
            DecodeError::ExecBuffer { .. }
        ));
    }
}
