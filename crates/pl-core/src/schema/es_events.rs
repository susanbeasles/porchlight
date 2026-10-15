//! The exact Endpoint Security notify subscription set (SPEC §4.2), spelled the way
//! `eslogger` names events. One list, consumed by `plctl record` and checked against
//! `scripts/record-fixture.sh` by a test. The four AUTH events are not here: they are
//! self-protection only and `eslogger` cannot record them.

/// `eslogger` event names for every `ES_EVENT_TYPE_NOTIFY_*` Porchlight subscribes to.
pub const ES_NOTIFY_EVENT_NAMES: &[&str] = &[
    "exec",
    "fork",
    "exit",
    "create",
    "write",
    "close",
    "rename",
    "unlink",
    "setflags",
    "setmode",
    "setowner",
    "setextattr",
    "clone",
    "link",
    "truncate",
    "btm_launch_item_add",
    "btm_launch_item_remove",
    "profile_add",
    "profile_remove",
    "tcc_modify",
    "gatekeeper_user_override",
    "xp_malware_detected",
    "xp_malware_remediated",
    "kextload",
    "mount",
    "unmount",
    "xpc_connect",
    "uipc_bind",
    "uipc_connect",
    "get_task",
    "get_task_read",
    "remote_thread_create",
    "proc_suspend_resume",
    "signal",
    "su",
    "sudo",
    "authentication",
    "openssh_login",
    "openssh_logout",
    "login_login",
    "login_logout",
    "screensharing_attach",
    "screensharing_detach",
    "lw_session_login",
    "lw_session_logout",
    "lw_session_lock",
    "lw_session_unlock",
    "od_group_add",
    "od_group_remove",
    "od_group_set",
    "od_modify_password",
    "od_disable_user",
    "od_enable_user",
    "od_attribute_value_add",
    "od_attribute_value_remove",
    "od_attribute_set",
    "od_create_user",
    "od_create_group",
    "od_delete_user",
    "od_delete_group",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_unique_and_lowercase() {
        let mut seen = std::collections::BTreeSet::new();
        for n in ES_NOTIFY_EVENT_NAMES {
            assert!(seen.insert(*n), "duplicate {n}");
            assert!(
                n.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
                "{n}"
            );
        }
        assert!(
            !ES_NOTIFY_EVENT_NAMES.contains(&"open"),
            "NOTIFY_OPEN is excluded by SPEC §4.2"
        );
    }
}
