//! Adapter from Apple `eslogger` NDJSON to [`Event`] (ADR-0002).
//!
//! `eslogger` prints one JSON object per message using the `es_message_t` field names:
//! top-level `mach_time`, `seq_num`, `global_seq_num`, `time` (RFC 3339), `process`, and an
//! `event` object whose single key is the event name. This adapter is tolerant: a missing
//! optional field becomes empty or zero, an event name it does not know becomes
//! [`Kind::Unsupported`], and only a structurally broken line (no process audit token, no
//! event object) is an error. Coverage shows up in [`super::ReadStats`].
//!
//! The field names below follow the Endpoint Security headers. Validate against a real
//! recording on the first replay; the unsupported and malformed counters will say where
//! this adapter is wrong.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use crate::schema::{
    AuditToken, Event, Kind, LaunchItem, MachTime, ProcessIdentity, ProfileInfo, SCHEMA_VERSION,
    Source, TccUpdate, WallTime,
};

/// `eslogger` `schema_version` values this adapter accepts. Absent means accept.
pub const SUPPORTED_SCHEMA_VERSIONS: &[u64] = &[1];

type Obj = Map<String, Value>;

fn obj<'a>(v: &'a Value, key: &str) -> Option<&'a Obj> {
    v.get(key)?.as_object()
}

fn str_field<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key)?.as_str()
}

fn string(v: &Value, key: &str) -> String {
    str_field(v, key).unwrap_or_default().to_owned()
}

fn opt_string(v: &Value, key: &str) -> Option<String> {
    str_field(v, key)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

/// String, number or bool rendered as text; anything else is empty.
fn vstr(v: &Value, key: &str) -> String {
    match v.get(key) {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        _ => String::new(),
    }
}

fn u64_field(v: &Value, key: &str) -> Option<u64> {
    v.get(key)?.as_u64()
}

fn i64_field(v: &Value, key: &str) -> Option<i64> {
    v.get(key)?.as_i64()
}

fn u32_field(v: &Value, key: &str) -> u32 {
    u64_field(v, key)
        .and_then(|n| u32::try_from(n).ok())
        .unwrap_or(0)
}

fn i32_field(v: &Value, key: &str) -> i32 {
    i64_field(v, key)
        .and_then(|n| i32::try_from(n).ok())
        .unwrap_or(0)
}

fn bool_field(v: &Value, key: &str) -> bool {
    v.get(key).and_then(Value::as_bool).unwrap_or(false)
}

/// `es_file_t` is `{"path": ..., "path_truncated": ..., "stat": ...}`.
fn path(v: &Value) -> String {
    string(v, "path")
}

fn path_field(v: &Value, key: &str) -> String {
    v.get(key).map(path).unwrap_or_default()
}

fn join(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_owned()
    } else if dir.ends_with('/') {
        format!("{dir}{name}")
    } else {
        format!("{dir}/{name}")
    }
}

/// `es_destination_t`: `{"existing_file": es_file_t}` or
/// `{"new_path": {"dir": es_file_t, "filename": ..., "mode": ...}}`.
fn destination(v: Option<&Value>) -> (String, u32) {
    let Some(v) = v else {
        return (String::new(), 0);
    };
    if let Some(existing) = v.get("existing_file") {
        return (path(existing), 0);
    }
    if let Some(new_path) = v.get("new_path") {
        let dir = path_field(new_path, "dir");
        let name = string(new_path, "filename");
        return (join(&dir, &name), u32_field(new_path, "mode"));
    }
    (String::new(), 0)
}

fn token(v: &Value) -> Option<AuditToken> {
    let pid = i64_field(v, "pid").and_then(|n| i32::try_from(n).ok())?;
    let pidversion = i64_field(v, "pidversion").and_then(|n| i32::try_from(n).ok())?;
    Some(AuditToken {
        pid,
        pidversion,
        auid: u32_field(v, "auid"),
        euid: u32_field(v, "euid"),
        ruid: u32_field(v, "ruid"),
        egid: u32_field(v, "egid"),
        rgid: u32_field(v, "rgid"),
        asid: u32_field(v, "asid"),
    })
}

fn token_field(v: &Value, key: &str) -> Option<AuditToken> {
    token(v.get(key)?)
}

/// Audit token of an `es_process_t` nested under `key`, or the zero token.
fn target_token(e: &Value, key: &str) -> AuditToken {
    e.get(key)
        .and_then(|p| token_field(p, "audit_token"))
        .unwrap_or_default()
}

/// Maps an `es_process_t` object.
fn process(v: &Value) -> Result<ProcessIdentity, String> {
    let token = token_field(v, "audit_token").ok_or("process.audit_token missing")?;
    let parent_token = token_field(v, "parent_audit_token").unwrap_or(AuditToken {
        pid: i32_field(v, "ppid"),
        pidversion: 0,
        ..Default::default()
    });
    let tty = v
        .get("tty")
        .filter(|t| !t.is_null())
        .map(path)
        .filter(|s| !s.is_empty());
    Ok(ProcessIdentity {
        token,
        parent_token,
        responsible_token: token_field(v, "responsible_audit_token"),
        executable_path: path_field(v, "executable"),
        signing_id: opt_string(v, "signing_id"),
        team_id: opt_string(v, "team_id"),
        cdhash: string(v, "cdhash"),
        is_platform_binary: bool_field(v, "is_platform_binary"),
        is_es_client: bool_field(v, "is_es_client"),
        tty,
        session_id: i32_field(v, "session_id"),
        start_time: str_field(v, "start_time")
            .and_then(WallTime::from_rfc3339)
            .unwrap_or_default(),
    })
}

fn string_array(v: &Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn env_map(v: &Value, key: &str) -> BTreeMap<String, String> {
    string_array(v, key)
        .into_iter()
        .map(|kv| match kv.split_once('=') {
            Some((k, val)) => (k.to_owned(), val.to_owned()),
            None => (kv, String::new()),
        })
        .collect()
}

fn launch_item(v: Option<&Value>) -> LaunchItem {
    let v = v.unwrap_or(&Value::Null);
    LaunchItem {
        item_type: vstr(v, "item_type"),
        legacy: bool_field(v, "legacy"),
        managed: bool_field(v, "managed"),
        uid: u32_field(v, "uid"),
        item_url: string(v, "item_url"),
        app_url: opt_string(v, "app_url"),
    }
}

fn profile(v: Option<&Value>) -> ProfileInfo {
    let v = v.unwrap_or(&Value::Null);
    ProfileInfo {
        identifier: string(v, "identifier"),
        uuid: string(v, "uuid"),
        display_name: opt_string(v, "display_name"),
        organization: opt_string(v, "organization"),
        install_source: vstr(v, "install_source"),
        scope: vstr(v, "scope"),
    }
}

/// Maps one `event` entry. `Ok(None)` filters the line (unmodified `close`, SPEC §4.2).
fn map_kind(name: &str, e: &Value) -> Result<Option<Kind>, String> {
    let kind = match name {
        "exec" => {
            let target = e.get("target").ok_or("exec.target missing")?;
            Kind::Exec {
                target: Box::new(process(target)?),
                args: string_array(e, "args"),
                env: env_map(e, "env"),
                cwd: e.get("cwd").map(path).filter(|s| !s.is_empty()),
                script_path: e
                    .get("script")
                    .filter(|s| !s.is_null())
                    .map(path)
                    .filter(|s| !s.is_empty()),
            }
        }
        "fork" => Kind::Fork {
            child: target_token(e, "child"),
        },
        "exit" => Kind::Exit {
            status: i32_field(e, "stat"),
        },
        "create" => {
            let (p, mode) = destination(e.get("destination"));
            Kind::FileCreate { path: p, mode }
        }
        "write" => Kind::FileWrite {
            path: path_field(e, "target"),
        },
        "close" => {
            if !bool_field(e, "modified") {
                return Ok(None);
            }
            Kind::FileCloseModified {
                path: path_field(e, "target"),
            }
        }
        "rename" => Kind::FileRename {
            from: path_field(e, "source"),
            to: destination(e.get("destination")).0,
        },
        "unlink" => Kind::FileUnlink {
            path: path_field(e, "target"),
        },
        "setflags" => Kind::FileSetFlags {
            path: path_field(e, "target"),
            flags: u32_field(e, "flags"),
        },
        "setmode" => Kind::FileSetMode {
            path: path_field(e, "target"),
            mode: u32_field(e, "mode"),
        },
        "setowner" => Kind::FileSetOwner {
            path: path_field(e, "target"),
            uid: u32_field(e, "uid"),
            gid: u32_field(e, "gid"),
        },
        "setextattr" => Kind::FileSetXattr {
            path: path_field(e, "target"),
            name: string(e, "extattr"),
        },
        "clone" => Kind::FileClone {
            from: path_field(e, "source"),
            to: join(&path_field(e, "target_dir"), &string(e, "target_name")),
        },
        "link" => Kind::FileLink {
            from: path_field(e, "source"),
            to: join(&path_field(e, "target_dir"), &string(e, "target_filename")),
        },
        "truncate" => Kind::FileTruncate {
            path: path_field(e, "target"),
        },
        "btm_launch_item_add" => Kind::LaunchItemAdd {
            item: launch_item(e.get("item")),
        },
        "btm_launch_item_remove" => Kind::LaunchItemRemove {
            item: launch_item(e.get("item")),
        },
        "profile_add" => Kind::ProfileAdd {
            profile: profile(e.get("profile")),
        },
        "profile_remove" => Kind::ProfileRemove {
            profile: profile(e.get("profile")),
        },
        "tcc_modify" => Kind::TccModify {
            service: string(e, "service"),
            identity: string(e, "identity"),
            update: TccUpdate {
                update_type: vstr(e, "update_type"),
                identity_type: vstr(e, "identity_type"),
                right: vstr(e, "right"),
                reason: vstr(e, "reason"),
            },
        },
        "gatekeeper_user_override" => {
            let mut p = path_field(e, "file");
            if p.is_empty() {
                p = string(e, "file_path");
            }
            Kind::GatekeeperOverride {
                path: p,
                verdict: "user_override".to_owned(),
            }
        }
        "xp_malware_detected" => Kind::XpMalwareDetected {
            signature: string(e, "malware_identifier"),
            path: string(e, "detected_path"),
        },
        "xp_malware_remediated" => Kind::XpMalwareRemediated {
            signature: string(e, "malware_identifier"),
            path: string(e, "remediated_path"),
        },
        "kextload" => Kind::KextLoad {
            identifier: string(e, "identifier"),
        },
        "mount" => {
            let s = e.get("statfs").unwrap_or(&Value::Null);
            Kind::Mount {
                path: string(s, "f_mntonname"),
                fs_type: string(s, "f_fstypename"),
                device: string(s, "f_mntfromname"),
            }
        }
        "unmount" => {
            let s = e.get("statfs").unwrap_or(&Value::Null);
            Kind::Unmount {
                path: string(s, "f_mntonname"),
            }
        }
        "xpc_connect" => Kind::XpcConnect {
            service_name: string(e, "service_name"),
            domain_type: vstr(e, "service_domain_type"),
        },
        "uipc_bind" => Kind::UipcBind {
            path: join(&path_field(e, "dir"), &string(e, "filename")),
        },
        "uipc_connect" => Kind::UipcConnect {
            path: path_field(e, "file"),
        },
        "get_task" => Kind::GetTask {
            target: target_token(e, "target"),
            flavor: vstr(e, "type"),
        },
        "get_task_read" => Kind::GetTask {
            target: target_token(e, "target"),
            flavor: "read".to_owned(),
        },
        "remote_thread_create" => Kind::RemoteThreadCreate {
            target: target_token(e, "target"),
        },
        "proc_suspend_resume" => Kind::ProcSuspendResume {
            target: target_token(e, "target"),
            action: vstr(e, "type"),
        },
        "signal" => Kind::Signal {
            target: target_token(e, "target"),
            signum: i32_field(e, "sig"),
        },
        "su" => Kind::Su {
            from: u32_field(e, "from_uid"),
            to: u32_field(e, "to_uid"),
            success: bool_field(e, "success"),
            shell: opt_string(e, "shell"),
        },
        "sudo" => Kind::Sudo {
            success: bool_field(e, "success"),
            command: opt_string(e, "command"),
            from: u32_field(e, "from_uid"),
            to: u32_field(e, "to_uid"),
        },
        "authentication" => Kind::Authentication {
            auth_type: vstr(e, "type"),
            success: bool_field(e, "success"),
        },
        "openssh_login" => Kind::SshLogin {
            success: bool_field(e, "success"),
            user: string(e, "username"),
            source: string(e, "source_address"),
        },
        "openssh_logout" => Kind::SshLogout {
            user: string(e, "username"),
            source: string(e, "source_address"),
        },
        "login_login" => Kind::LoginLogin {
            success: bool_field(e, "success"),
            user: string(e, "username"),
        },
        "login_logout" => Kind::LoginLogout {
            user: string(e, "username"),
        },
        "screensharing_attach" => Kind::ScreenSharingAttach {
            success: bool_field(e, "success"),
            source: string(e, "source_address"),
            user: string(e, "session_username"),
        },
        "screensharing_detach" => Kind::ScreenSharingDetach {
            source: string(e, "source_address"),
            user: string(e, "viewer_appleid"),
        },
        n if n.starts_with("lw_session_") => Kind::LwSession {
            action: n.trim_start_matches("lw_session_").to_owned(),
            user: string(e, "username"),
        },
        n if n.starts_with("od_") => {
            let user = ["user_name", "account_name", "group_name"]
                .iter()
                .map(|k| string(e, k))
                .find(|s| !s.is_empty())
                .unwrap_or_default();
            Kind::OdEvent {
                action: n.trim_start_matches("od_").to_owned(),
                user,
                node: string(e, "node_name"),
            }
        }
        other => Kind::Unsupported {
            name: other.to_owned(),
        },
    };
    Ok(Some(kind))
}

/// Parses one `eslogger` line. `Ok(None)` means the line was filtered on purpose.
pub fn parse_line(line: &str) -> Result<Option<Event>, String> {
    let value: Value = serde_json::from_str(line).map_err(|e| format!("not JSON: {e}"))?;
    parse_value(&value)
}

/// Parses one already-decoded `eslogger` message.
pub fn parse_value(v: &Value) -> Result<Option<Event>, String> {
    if !v.is_object() {
        return Err("not a JSON object".to_owned());
    }
    if let Some(sv) = u64_field(v, "schema_version")
        && !SUPPORTED_SCHEMA_VERSIONS.contains(&sv)
    {
        return Err(format!("unsupported eslogger schema_version {sv}"));
    }
    let process = process(v.get("process").ok_or("process missing")?)?;
    let event = obj(v, "event").ok_or("event missing or not an object")?;
    let (name, body) = event.iter().next().ok_or("event object is empty")?;
    let Some(kind) = map_kind(name, body)? else {
        return Ok(None);
    };
    Ok(Some(Event {
        schema_version: SCHEMA_VERSION,
        id: 0,
        mach_time: MachTime(u64_field(v, "mach_time").unwrap_or(0)),
        wall_time: str_field(v, "time")
            .and_then(WallTime::from_rfc3339)
            .unwrap_or_default(),
        seq_num: u64_field(v, "seq_num").unwrap_or(0),
        global_seq_num: u64_field(v, "global_seq_num").unwrap_or(0),
        source: Source::Replay,
        process,
        kind,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROC: &str = r#"{"audit_token":{"pid":512,"pidversion":9,"auid":501,"euid":501,"ruid":501,"egid":20,"rgid":20,"asid":100005},"ppid":1,"parent_audit_token":{"pid":1,"pidversion":1,"auid":4294967295,"euid":0,"ruid":0,"egid":0,"rgid":0,"asid":100000},"responsible_audit_token":{"pid":400,"pidversion":2,"auid":501,"euid":501,"ruid":501,"egid":20,"rgid":20,"asid":100005},"executable":{"path":"/bin/zsh","path_truncated":false},"signing_id":"com.apple.zsh","team_id":"","cdhash":"ab12","is_platform_binary":true,"is_es_client":false,"tty":{"path":"/dev/ttys001"},"session_id":100005,"start_time":"2026-10-15T02:00:00.000000Z"}"#;

    fn line(event: &str) -> String {
        format!(
            r#"{{"schema_version":1,"mach_time":123456,"seq_num":7,"global_seq_num":99,"time":"2026-10-15T02:33:44.5Z","event_type":9,"process":{PROC},"event":{event}}}"#
        )
    }

    fn parse(event: &str) -> Option<Event> {
        parse_line(&line(event)).unwrap()
    }

    #[test]
    fn envelope_and_process() {
        let ev = parse(r#"{"exit":{"stat":3}}"#).unwrap();
        assert_eq!(ev.id, 0);
        assert_eq!(ev.mach_time, MachTime(123_456));
        assert_eq!(ev.seq_num, 7);
        assert_eq!(ev.global_seq_num, 99);
        assert_eq!(ev.wall_time.to_rfc3339(), "2026-10-15T02:33:44.500000000Z");
        assert_eq!(ev.source, Source::Replay);
        assert_eq!(ev.process.token.key(), "512:9");
        assert_eq!(ev.process.parent_token.key(), "1:1");
        assert_eq!(
            ev.process.responsible_token.map(|t| t.key()),
            Some("400:2".to_owned())
        );
        assert_eq!(ev.process.executable_path, "/bin/zsh");
        assert_eq!(ev.process.signing_id.as_deref(), Some("com.apple.zsh"));
        assert_eq!(ev.process.team_id, None, "empty team_id becomes None");
        assert_eq!(ev.process.tty.as_deref(), Some("/dev/ttys001"));
        assert!(ev.process.is_platform_binary);
        assert_eq!(
            ev.process.start_time.to_rfc3339(),
            "2026-10-15T02:00:00.000000000Z"
        );
        assert_eq!(ev.kind, Kind::Exit { status: 3 });
    }

    #[test]
    fn exec_maps_target_args_env() {
        let ev = parse(&format!(
            r#"{{"exec":{{"target":{PROC},"args":["zsh","-c","id"],"env":["PATH=/bin","NOEQ"],"cwd":{{"path":"/tmp"}},"script":null}}}}"#
        ))
        .unwrap();
        match ev.kind {
            Kind::Exec {
                target,
                args,
                env,
                cwd,
                script_path,
            } => {
                assert_eq!(target.token.key(), "512:9");
                assert_eq!(args, vec!["zsh", "-c", "id"]);
                assert_eq!(env.get("PATH").map(String::as_str), Some("/bin"));
                assert_eq!(env.get("NOEQ").map(String::as_str), Some(""));
                assert_eq!(cwd.as_deref(), Some("/tmp"));
                assert_eq!(script_path, None);
            }
            other => panic!("wrong kind {other:?}"),
        }
    }

    #[test]
    fn exec_without_target_is_malformed() {
        assert!(parse_line(&line(r#"{"exec":{"args":[]}}"#)).is_err());
    }

    #[test]
    fn close_is_filtered_unless_modified() {
        assert!(parse(r#"{"close":{"modified":false,"target":{"path":"/a"}}}"#).is_none());
        let ev = parse(r#"{"close":{"modified":true,"target":{"path":"/a"}}}"#).unwrap();
        assert_eq!(
            ev.kind,
            Kind::FileCloseModified {
                path: "/a".to_owned()
            }
        );
    }

    #[test]
    fn create_and_rename_destinations() {
        let ev = parse(r#"{"create":{"destination_type":1,"destination":{"new_path":{"dir":{"path":"/Users/u/Library/LaunchAgents"},"filename":"x.plist","mode":420}}}}"#).unwrap();
        assert_eq!(
            ev.kind,
            Kind::FileCreate {
                path: "/Users/u/Library/LaunchAgents/x.plist".to_owned(),
                mode: 420
            }
        );
        let ev = parse(r#"{"rename":{"source":{"path":"/a"},"destination_type":0,"destination":{"existing_file":{"path":"/b"}}}}"#).unwrap();
        assert_eq!(
            ev.kind,
            Kind::FileRename {
                from: "/a".to_owned(),
                to: "/b".to_owned()
            }
        );
    }

    #[test]
    fn fork_and_signal_take_nested_tokens() {
        let ev = parse(&format!(r#"{{"fork":{{"child":{PROC}}}}}"#)).unwrap();
        assert_eq!(
            ev.kind,
            Kind::Fork {
                child: AuditToken {
                    pid: 512,
                    pidversion: 9,
                    ..Default::default()
                }
            }
        );
        let ev = parse(&format!(r#"{{"signal":{{"sig":9,"target":{PROC}}}}}"#)).unwrap();
        match ev.kind {
            Kind::Signal { target, signum } => {
                assert_eq!(target.key(), "512:9");
                assert_eq!(signum, 9);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn btm_profile_tcc_and_od() {
        let ev = parse(r#"{"btm_launch_item_add":{"item":{"item_type":2,"legacy":false,"managed":false,"uid":501,"item_url":"file:///x.plist","app_url":""}}}"#).unwrap();
        match ev.kind {
            Kind::LaunchItemAdd { item } => {
                assert_eq!(item.item_type, "2");
                assert_eq!(item.item_url, "file:///x.plist");
                assert_eq!(item.app_url, None);
            }
            other => panic!("{other:?}"),
        }
        let ev = parse(r#"{"profile_add":{"profile":{"identifier":"com.x","uuid":"U","display_name":"X","organization":null,"install_source":1,"scope":2}}}"#).unwrap();
        match ev.kind {
            Kind::ProfileAdd { profile } => {
                assert_eq!(profile.identifier, "com.x");
                assert_eq!(profile.install_source, "1");
                assert_eq!(profile.organization, None);
            }
            other => panic!("{other:?}"),
        }
        let ev = parse(r#"{"tcc_modify":{"service":"kTCCServiceCamera","identity":"com.x","identity_type":0,"update_type":1,"right":2,"reason":3}}"#).unwrap();
        match ev.kind {
            Kind::TccModify {
                service, update, ..
            } => {
                assert_eq!(service, "kTCCServiceCamera");
                assert_eq!(update.right, "2");
            }
            other => panic!("{other:?}"),
        }
        let ev = parse(r#"{"od_create_user":{"user_name":"bob","node_name":"/Local/Default"}}"#)
            .unwrap();
        assert_eq!(
            ev.kind,
            Kind::OdEvent {
                action: "create_user".to_owned(),
                user: "bob".to_owned(),
                node: "/Local/Default".to_owned()
            }
        );
        let ev =
            parse(r#"{"lw_session_lock":{"username":"u","graphical_session_id":257}}"#).unwrap();
        assert_eq!(
            ev.kind,
            Kind::LwSession {
                action: "lock".to_owned(),
                user: "u".to_owned()
            }
        );
    }

    #[test]
    fn unknown_event_is_unsupported_not_an_error() {
        let ev = parse(r#"{"open":{"file":{"path":"/a"}}}"#).unwrap();
        assert_eq!(
            ev.kind,
            Kind::Unsupported {
                name: "open".to_owned()
            }
        );
    }

    #[test]
    fn structural_failures_are_errors() {
        assert!(parse_line("{}").is_err());
        assert!(
            parse_line(r#"{"process":{},"event":{"exit":{}}}"#).is_err(),
            "no audit token"
        );
        assert!(
            parse_line(&format!(r#"{{"process":{PROC},"event":{{}}}}"#)).is_err(),
            "empty event"
        );
        assert!(
            parse_line(&format!(
                r#"{{"schema_version":2,"process":{PROC},"event":{{"exit":{{}}}}}}"#
            ))
            .is_err()
        );
    }
}
