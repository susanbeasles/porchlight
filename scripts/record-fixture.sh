#!/usr/bin/env bash
# Record an eslogger fixture with Porchlight's exact notify event set (SPEC §4.2, §7).
# macOS only. The terminal running this needs Full Disk Access, or eslogger prints nothing.
# Usage: scripts/record-fixture.sh <out.ndjson> [duration-seconds]
# The event list below must match pl-core's ES_NOTIFY_EVENT_NAMES; a test checks it.
set -euo pipefail
out="${1:?usage: record-fixture.sh <out.ndjson> [duration-seconds]}"
duration="${2:-}"
events=(
  exec fork exit
  create write close rename unlink setflags setmode setowner setextattr clone link truncate
  btm_launch_item_add btm_launch_item_remove profile_add profile_remove tcc_modify
  gatekeeper_user_override xp_malware_detected xp_malware_remediated kextload mount unmount
  xpc_connect uipc_bind uipc_connect
  get_task get_task_read remote_thread_create proc_suspend_resume signal su sudo authentication
  openssh_login openssh_logout login_login login_logout screensharing_attach screensharing_detach
  lw_session_login lw_session_logout lw_session_lock lw_session_unlock
  od_group_add od_group_remove od_group_set od_modify_password od_disable_user od_enable_user
  od_attribute_value_add od_attribute_value_remove od_attribute_set od_create_user od_create_group
  od_delete_user od_delete_group
)
if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "record-fixture: eslogger exists only on macOS. Command that would run:" >&2
  echo "  eslogger ${events[*]} > $out" >&2
  exit 2
fi
if [[ -n "$duration" ]]; then
  eslogger "${events[@]}" > "$out" &
  pid=$!
  sleep "$duration"
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
else
  eslogger "${events[@]}" > "$out"
fi
echo "record-fixture: $(wc -l < "$out") lines in $out" >&2
