//! Event kinds (SPEC §3.3). Internally tagged on `type` with a stable `snake_case`
//! discriminator. The list is exhaustive for v0 plus `unsupported`, which the fixture
//! adapters emit for event names they do not map yet so coverage gaps are visible
//! (ADR-0002).
//!
//! Two field names differ from the SPEC sketch because `type` is the enum tag:
//! `authentication.type` is `auth_type` and `diagnostic_report.type` is `report_type`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::identity::{AuditToken, ProcessIdentity};

/// Background Task Management launch item (`BTM_LAUNCH_ITEM_*`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchItem {
    pub item_type: String,
    pub legacy: bool,
    pub managed: bool,
    pub uid: u32,
    pub item_url: String,
    pub app_url: Option<String>,
}

/// Configuration profile (`PROFILE_*`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileInfo {
    pub identifier: String,
    pub uuid: String,
    pub display_name: Option<String>,
    pub organization: Option<String>,
    pub install_source: String,
    pub scope: String,
}

/// The change carried by a `TCC_MODIFY` event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TccUpdate {
    pub update_type: String,
    pub identity_type: String,
    pub right: String,
    pub reason: String,
}

/// What the cross-view checker found missing from user-space enumeration (SPEC §5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossViewKind {
    HiddenProcess,
    HiddenLaunchItem,
    HiddenFile,
    HiddenLoginItem,
}

/// Why events were lost (SPEC C6, §4.6, §4.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DropReason {
    /// A per-type `seq_num` gap observed by the bridge.
    SequenceGap,
    /// The handler found the ring full and counted the message instead of enqueueing it.
    RingFull,
    /// The extension's overflow queue filled while the app was not connected.
    AppDisconnected,
}

/// The exhaustive v0 event kinds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Kind {
    Exec {
        target: Box<ProcessIdentity>,
        args: Vec<String>,
        env: BTreeMap<String, String>,
        cwd: Option<String>,
        script_path: Option<String>,
    },
    Fork {
        child: AuditToken,
    },
    Exit {
        status: i32,
    },

    FileCreate {
        path: String,
        mode: u32,
    },
    FileWrite {
        path: String,
    },
    FileCloseModified {
        path: String,
    },
    FileRename {
        from: String,
        to: String,
    },
    FileUnlink {
        path: String,
    },
    FileSetFlags {
        path: String,
        flags: u32,
    },
    FileSetMode {
        path: String,
        mode: u32,
    },
    FileSetOwner {
        path: String,
        uid: u32,
        gid: u32,
    },
    FileSetXattr {
        path: String,
        name: String,
    },
    FileClone {
        from: String,
        to: String,
    },
    FileLink {
        from: String,
        to: String,
    },
    FileTruncate {
        path: String,
    },

    LaunchItemAdd {
        item: LaunchItem,
    },
    LaunchItemRemove {
        item: LaunchItem,
    },
    ProfileAdd {
        profile: ProfileInfo,
    },
    ProfileRemove {
        profile: ProfileInfo,
    },
    TccModify {
        service: String,
        identity: String,
        update: TccUpdate,
    },
    GatekeeperOverride {
        path: String,
        verdict: String,
    },
    XpMalwareDetected {
        signature: String,
        path: String,
    },
    XpMalwareRemediated {
        signature: String,
        path: String,
    },
    KextLoad {
        identifier: String,
    },
    Mount {
        path: String,
        fs_type: String,
        device: String,
    },
    Unmount {
        path: String,
    },

    XpcConnect {
        service_name: String,
        domain_type: String,
    },
    UipcBind {
        path: String,
    },
    UipcConnect {
        path: String,
    },

    GetTask {
        target: AuditToken,
        flavor: String,
    },
    RemoteThreadCreate {
        target: AuditToken,
    },
    ProcSuspendResume {
        target: AuditToken,
        action: String,
    },
    Signal {
        target: AuditToken,
        signum: i32,
    },
    Su {
        from: u32,
        to: u32,
        success: bool,
        shell: Option<String>,
    },
    Sudo {
        success: bool,
        command: Option<String>,
        from: u32,
        to: u32,
    },
    Authentication {
        auth_type: String,
        success: bool,
    },
    SshLogin {
        success: bool,
        user: String,
        source: String,
    },
    SshLogout {
        user: String,
        source: String,
    },
    LoginLogin {
        success: bool,
        user: String,
    },
    LoginLogout {
        user: String,
    },
    ScreenSharingAttach {
        success: bool,
        source: String,
        user: String,
    },
    ScreenSharingDetach {
        source: String,
        user: String,
    },
    LwSession {
        action: String,
        user: String,
    },
    OdEvent {
        action: String,
        user: String,
        node: String,
    },

    SelfProtectionDenied {
        path: String,
        operation: String,
    },
    Drop {
        event_type: String,
        expected_seq: u64,
        got_seq: u64,
        count: u64,
        reason: DropReason,
    },
    CrossViewMismatch {
        kind: CrossViewKind,
        subject: String,
        detail: String,
    },
    DiagnosticReport {
        report_type: String,
        process: String,
        module: Option<String>,
        path: String,
    },
    /// Reserved for the network extension. Never emitted in v0.
    Flow {
        reserved: bool,
    },
    /// An input event the adapter does not map. `name` is the source's raw event name.
    Unsupported {
        name: String,
    },
}

impl Kind {
    /// Every discriminator, in declaration order. Must match `discriminator()` and the serde
    /// tag; the tests enforce all three agree.
    pub const DISCRIMINATORS: &'static [&'static str] = &[
        "exec",
        "fork",
        "exit",
        "file_create",
        "file_write",
        "file_close_modified",
        "file_rename",
        "file_unlink",
        "file_set_flags",
        "file_set_mode",
        "file_set_owner",
        "file_set_xattr",
        "file_clone",
        "file_link",
        "file_truncate",
        "launch_item_add",
        "launch_item_remove",
        "profile_add",
        "profile_remove",
        "tcc_modify",
        "gatekeeper_override",
        "xp_malware_detected",
        "xp_malware_remediated",
        "kext_load",
        "mount",
        "unmount",
        "xpc_connect",
        "uipc_bind",
        "uipc_connect",
        "get_task",
        "remote_thread_create",
        "proc_suspend_resume",
        "signal",
        "su",
        "sudo",
        "authentication",
        "ssh_login",
        "ssh_logout",
        "login_login",
        "login_logout",
        "screen_sharing_attach",
        "screen_sharing_detach",
        "lw_session",
        "od_event",
        "self_protection_denied",
        "drop",
        "cross_view_mismatch",
        "diagnostic_report",
        "flow",
        "unsupported",
    ];

    /// The stable string stored in the `events.kind` column.
    pub fn discriminator(&self) -> &'static str {
        match self {
            Kind::Exec { .. } => "exec",
            Kind::Fork { .. } => "fork",
            Kind::Exit { .. } => "exit",
            Kind::FileCreate { .. } => "file_create",
            Kind::FileWrite { .. } => "file_write",
            Kind::FileCloseModified { .. } => "file_close_modified",
            Kind::FileRename { .. } => "file_rename",
            Kind::FileUnlink { .. } => "file_unlink",
            Kind::FileSetFlags { .. } => "file_set_flags",
            Kind::FileSetMode { .. } => "file_set_mode",
            Kind::FileSetOwner { .. } => "file_set_owner",
            Kind::FileSetXattr { .. } => "file_set_xattr",
            Kind::FileClone { .. } => "file_clone",
            Kind::FileLink { .. } => "file_link",
            Kind::FileTruncate { .. } => "file_truncate",
            Kind::LaunchItemAdd { .. } => "launch_item_add",
            Kind::LaunchItemRemove { .. } => "launch_item_remove",
            Kind::ProfileAdd { .. } => "profile_add",
            Kind::ProfileRemove { .. } => "profile_remove",
            Kind::TccModify { .. } => "tcc_modify",
            Kind::GatekeeperOverride { .. } => "gatekeeper_override",
            Kind::XpMalwareDetected { .. } => "xp_malware_detected",
            Kind::XpMalwareRemediated { .. } => "xp_malware_remediated",
            Kind::KextLoad { .. } => "kext_load",
            Kind::Mount { .. } => "mount",
            Kind::Unmount { .. } => "unmount",
            Kind::XpcConnect { .. } => "xpc_connect",
            Kind::UipcBind { .. } => "uipc_bind",
            Kind::UipcConnect { .. } => "uipc_connect",
            Kind::GetTask { .. } => "get_task",
            Kind::RemoteThreadCreate { .. } => "remote_thread_create",
            Kind::ProcSuspendResume { .. } => "proc_suspend_resume",
            Kind::Signal { .. } => "signal",
            Kind::Su { .. } => "su",
            Kind::Sudo { .. } => "sudo",
            Kind::Authentication { .. } => "authentication",
            Kind::SshLogin { .. } => "ssh_login",
            Kind::SshLogout { .. } => "ssh_logout",
            Kind::LoginLogin { .. } => "login_login",
            Kind::LoginLogout { .. } => "login_logout",
            Kind::ScreenSharingAttach { .. } => "screen_sharing_attach",
            Kind::ScreenSharingDetach { .. } => "screen_sharing_detach",
            Kind::LwSession { .. } => "lw_session",
            Kind::OdEvent { .. } => "od_event",
            Kind::SelfProtectionDenied { .. } => "self_protection_denied",
            Kind::Drop { .. } => "drop",
            Kind::CrossViewMismatch { .. } => "cross_view_mismatch",
            Kind::DiagnosticReport { .. } => "diagnostic_report",
            Kind::Flow { .. } => "flow",
            Kind::Unsupported { .. } => "unsupported",
        }
    }
}

#[cfg(test)]
pub(crate) mod samples {
    //! One sample value per variant, for round-trip and discriminator tests.
    use super::*;
    use crate::schema::time::WallTime;

    pub(crate) fn token(pid: i32) -> AuditToken {
        AuditToken {
            pid,
            pidversion: 1,
            auid: 501,
            euid: 501,
            ruid: 501,
            egid: 20,
            rgid: 20,
            asid: 100_005,
        }
    }

    pub(crate) fn process(pid: i32, path: &str) -> ProcessIdentity {
        ProcessIdentity {
            token: token(pid),
            parent_token: token(1),
            responsible_token: Some(token(1)),
            executable_path: path.to_owned(),
            signing_id: Some("com.apple.test".to_owned()),
            team_id: None,
            cdhash: "00".repeat(20),
            is_platform_binary: true,
            is_es_client: false,
            tty: None,
            session_id: 100_005,
            start_time: WallTime(1_700_000_000_000_000_000),
        }
    }

    pub(crate) fn launch_item() -> LaunchItem {
        LaunchItem {
            item_type: "agent".to_owned(),
            legacy: false,
            managed: false,
            uid: 501,
            item_url: "file:///Users/u/Library/LaunchAgents/x.plist".to_owned(),
            app_url: None,
        }
    }

    pub(crate) fn profile() -> ProfileInfo {
        ProfileInfo {
            identifier: "com.example.p".to_owned(),
            uuid: "0000-1111".to_owned(),
            display_name: Some("P".to_owned()),
            organization: None,
            install_source: "manual".to_owned(),
            scope: "system".to_owned(),
        }
    }

    pub(crate) fn all() -> Vec<Kind> {
        let p = "/p".to_owned();
        vec![
            Kind::Exec {
                target: Box::new(process(2, "/bin/sh")),
                args: vec!["sh".to_owned(), "-c".to_owned()],
                env: [("A".to_owned(), "B".to_owned())].into_iter().collect(),
                cwd: Some("/".to_owned()),
                script_path: None,
            },
            Kind::Fork { child: token(3) },
            Kind::Exit { status: 0 },
            Kind::FileCreate {
                path: p.clone(),
                mode: 0o644,
            },
            Kind::FileWrite { path: p.clone() },
            Kind::FileCloseModified { path: p.clone() },
            Kind::FileRename {
                from: p.clone(),
                to: "/q".to_owned(),
            },
            Kind::FileUnlink { path: p.clone() },
            Kind::FileSetFlags {
                path: p.clone(),
                flags: 2,
            },
            Kind::FileSetMode {
                path: p.clone(),
                mode: 0o755,
            },
            Kind::FileSetOwner {
                path: p.clone(),
                uid: 0,
                gid: 0,
            },
            Kind::FileSetXattr {
                path: p.clone(),
                name: "com.apple.quarantine".to_owned(),
            },
            Kind::FileClone {
                from: p.clone(),
                to: "/q".to_owned(),
            },
            Kind::FileLink {
                from: p.clone(),
                to: "/q".to_owned(),
            },
            Kind::FileTruncate { path: p.clone() },
            Kind::LaunchItemAdd {
                item: launch_item(),
            },
            Kind::LaunchItemRemove {
                item: launch_item(),
            },
            Kind::ProfileAdd { profile: profile() },
            Kind::ProfileRemove { profile: profile() },
            Kind::TccModify {
                service: "kTCCServiceMicrophone".to_owned(),
                identity: "com.example".to_owned(),
                update: TccUpdate {
                    update_type: "allow".to_owned(),
                    identity_type: "bundle_id".to_owned(),
                    right: "allowed".to_owned(),
                    reason: "user_consent".to_owned(),
                },
            },
            Kind::GatekeeperOverride {
                path: p.clone(),
                verdict: "user_override".to_owned(),
            },
            Kind::XpMalwareDetected {
                signature: "OSX.X".to_owned(),
                path: p.clone(),
            },
            Kind::XpMalwareRemediated {
                signature: "OSX.X".to_owned(),
                path: p.clone(),
            },
            Kind::KextLoad {
                identifier: "com.example.kext".to_owned(),
            },
            Kind::Mount {
                path: "/Volumes/X".to_owned(),
                fs_type: "apfs".to_owned(),
                device: "/dev/disk3".to_owned(),
            },
            Kind::Unmount {
                path: "/Volumes/X".to_owned(),
            },
            Kind::XpcConnect {
                service_name: "com.apple.x".to_owned(),
                domain_type: "system".to_owned(),
            },
            Kind::UipcBind {
                path: "/var/run/s".to_owned(),
            },
            Kind::UipcConnect {
                path: "/var/run/s".to_owned(),
            },
            Kind::GetTask {
                target: token(4),
                flavor: "control".to_owned(),
            },
            Kind::RemoteThreadCreate { target: token(4) },
            Kind::ProcSuspendResume {
                target: token(4),
                action: "suspend".to_owned(),
            },
            Kind::Signal {
                target: token(4),
                signum: 9,
            },
            Kind::Su {
                from: 501,
                to: 0,
                success: true,
                shell: Some("/bin/zsh".to_owned()),
            },
            Kind::Sudo {
                success: false,
                command: Some("ls".to_owned()),
                from: 501,
                to: 0,
            },
            Kind::Authentication {
                auth_type: "touchid".to_owned(),
                success: true,
            },
            Kind::SshLogin {
                success: true,
                user: "u".to_owned(),
                source: "10.0.0.2".to_owned(),
            },
            Kind::SshLogout {
                user: "u".to_owned(),
                source: "10.0.0.2".to_owned(),
            },
            Kind::LoginLogin {
                success: true,
                user: "u".to_owned(),
            },
            Kind::LoginLogout {
                user: "u".to_owned(),
            },
            Kind::ScreenSharingAttach {
                success: true,
                source: "10.0.0.2".to_owned(),
                user: "u".to_owned(),
            },
            Kind::ScreenSharingDetach {
                source: "10.0.0.2".to_owned(),
                user: "u".to_owned(),
            },
            Kind::LwSession {
                action: "lock".to_owned(),
                user: "u".to_owned(),
            },
            Kind::OdEvent {
                action: "create_user".to_owned(),
                user: "u".to_owned(),
                node: "/Local/Default".to_owned(),
            },
            Kind::SelfProtectionDenied {
                path: p.clone(),
                operation: "unlink".to_owned(),
            },
            Kind::Drop {
                event_type: "exec".to_owned(),
                expected_seq: 10,
                got_seq: 12,
                count: 2,
                reason: DropReason::SequenceGap,
            },
            Kind::CrossViewMismatch {
                kind: CrossViewKind::HiddenProcess,
                subject: "7:1".to_owned(),
                detail: "absent".to_owned(),
            },
            Kind::DiagnosticReport {
                report_type: "panic".to_owned(),
                process: "kernel".to_owned(),
                module: None,
                path: p,
            },
            Kind::Flow { reserved: true },
            Kind::Unsupported {
                name: "od_group_set".to_owned(),
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_variant_has_one_sample_and_a_matching_discriminator() {
        let all = samples::all();
        assert_eq!(
            all.len(),
            Kind::DISCRIMINATORS.len(),
            "one sample per discriminator"
        );
        for (kind, expected) in all.iter().zip(Kind::DISCRIMINATORS) {
            assert_eq!(kind.discriminator(), *expected);
            let value = serde_json::to_value(kind).unwrap();
            assert_eq!(
                value["type"].as_str(),
                Some(*expected),
                "serde tag for {expected}"
            );
            let back: Kind = serde_json::from_value(value).unwrap();
            assert_eq!(&back, kind, "round trip for {expected}");
        }
    }

    #[test]
    fn discriminators_are_unique_snake_case() {
        let mut seen = std::collections::BTreeSet::new();
        for d in Kind::DISCRIMINATORS {
            assert!(seen.insert(*d), "duplicate discriminator {d}");
            assert!(
                d.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
                "{d}"
            );
        }
    }

    #[test]
    fn exec_env_serializes_sorted() {
        let kind = Kind::Exec {
            target: Box::new(samples::process(2, "/bin/sh")),
            args: vec![],
            env: [
                ("Z".to_owned(), "1".to_owned()),
                ("A".to_owned(), "2".to_owned()),
            ]
            .into_iter()
            .collect(),
            cwd: None,
            script_path: None,
        };
        let json = serde_json::to_string(&kind).unwrap();
        assert!(json.contains(r#""env":{"A":"2","Z":"1"}"#), "{json}");
    }
}
