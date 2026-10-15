# Event schema, version 1

Normative source: `crates/pl-core/src/schema/`. This page is the human summary; a
test fails if a kind discriminator is missing from it.

## Envelope

One event is one JSON object. Field order is fixed; maps are sorted; timestamps are integers.

```json
{"schema_version":1,"id":42,"mach_time":1234567890,"wall_time":1760495624500000000,
 "seq_num":7,"global_seq_num":99,"source":"replay","process":{...},"kind":{"type":"exec",...}}
```

| Field | Type | Meaning |
|---|---|---|
| `schema_version` | u32 | `1` |
| `id` | u64 | Monotonic, assigned by the pipeline on ingest. `0` before ingest |
| `mach_time` | u64 | Nanoseconds, `mach_continuous_time` domain. The ordering key |
| `wall_time` | i64 | Nanoseconds since the Unix epoch, UTC. Display only |
| `seq_num`, `global_seq_num` | u64 | From `es_message_t` |
| `source` | string | `endpoint_security`, `replay`, `cross_view`, `diagnostics`, `synthetic` |
| `process` | object | The acting process (below) |
| `kind` | object | Tagged on `type` (below) |

## Process identity

```json
{"token":{"pid":512,"pidversion":9,"auid":501,"euid":501,"ruid":501,"egid":20,"rgid":20,"asid":100005},
 "parent_token":{...},"responsible_token":{...}|null,"executable_path":"/bin/zsh",
 "signing_id":"com.apple.zsh"|null,"team_id":null,"cdhash":"<hex>","is_platform_binary":true,
 "is_es_client":false,"tty":"/dev/ttys001"|null,"session_id":100005,"start_time":<i64 ns>}
```

Audit tokens are equal, ordered and hashed on `(pid, pidversion)` only (C4).

## Kinds

Each `kind` object carries `"type"` plus the fields listed. Field names follow SPEC §3.3 in
`snake_case`. Two differ because `type` is the tag: `authentication` uses `auth_type` and
`diagnostic_report` uses `report_type`.

| `type` | Fields |
|---|---|
| `exec` | `target` (process identity), `args` [string], `env` {string: string}, `cwd`, `script_path` |
| `fork` | `child` (token) |
| `exit` | `status` |
| `file_create` | `path`, `mode` |
| `file_write` | `path` |
| `file_close_modified` | `path` |
| `file_rename` | `from`, `to` |
| `file_unlink` | `path` |
| `file_set_flags` | `path`, `flags` |
| `file_set_mode` | `path`, `mode` |
| `file_set_owner` | `path`, `uid`, `gid` |
| `file_set_xattr` | `path`, `name` |
| `file_clone` | `from`, `to` |
| `file_link` | `from`, `to` |
| `file_truncate` | `path` |
| `launch_item_add` | `item` {item_type, legacy, managed, uid, item_url, app_url} |
| `launch_item_remove` | `item` |
| `profile_add` | `profile` {identifier, uuid, display_name, organization, install_source, scope} |
| `profile_remove` | `profile` |
| `tcc_modify` | `service`, `identity`, `update` {update_type, identity_type, right, reason} |
| `gatekeeper_override` | `path`, `verdict` |
| `xp_malware_detected` | `signature`, `path` |
| `xp_malware_remediated` | `signature`, `path` |
| `kext_load` | `identifier` |
| `mount` | `path`, `fs_type`, `device` |
| `unmount` | `path` |
| `xpc_connect` | `service_name`, `domain_type` |
| `uipc_bind` | `path` |
| `uipc_connect` | `path` |
| `get_task` | `target` (token), `flavor` |
| `remote_thread_create` | `target` |
| `proc_suspend_resume` | `target`, `action` |
| `signal` | `target`, `signum` |
| `su` | `from`, `to`, `success`, `shell` |
| `sudo` | `success`, `command`, `from`, `to` |
| `authentication` | `auth_type`, `success` |
| `ssh_login` | `success`, `user`, `source` |
| `ssh_logout` | `user`, `source` |
| `login_login` | `success`, `user` |
| `login_logout` | `user` |
| `screen_sharing_attach` | `success`, `source`, `user` |
| `screen_sharing_detach` | `source`, `user` |
| `lw_session` | `action` (login, logout, lock, unlock), `user` |
| `od_event` | `action`, `user`, `node` |
| `self_protection_denied` | `path`, `operation` |
| `drop` | `event_type`, `expected_seq`, `got_seq`, `count`, `reason` (sequence_gap, ring_full, app_disconnected) |
| `cross_view_mismatch` | `kind` (hidden_process, hidden_launch_item, hidden_file, hidden_login_item), `subject`, `detail` |
| `diagnostic_report` | `report_type`, `process`, `module`, `path` |
| `flow` | `reserved`. Never emitted in v0 |
| `unsupported` | `name`: the source event name the adapter did not map |

## Drop accounting

A message the ring refused still consumed an Endpoint Security sequence number, so it is
reported twice: once as `ring_full` (exact, from the ring's own counters) and once inside a
`sequence_gap` for that event type. `sequence_gap` is the total loss for a type; `ring_full`
says how much of it happened inside Porchlight. Never sum across reasons. `app_disconnected`
counts events the extension discarded from its 10,000-event queue while no app was
streaming; those never had a chance to reach the store.

`drop` events are attributed to the extension's own process identity.

The app adds one more check that does not depend on any of these counters: Endpoint
Security's `global_seq_num` is contiguous per client, so a hole among the events that
reached the store is a loss somewhere between the kernel and SQLite, including XPC
delivery into a connection that was dying. The Status screen leads with that number
(`end_to_end.missing`, plus `drops.store_failed` for batches the store refused).

## Store columns

`events(id, mach_time, wall_time, seq_num, global_seq_num, source, kind, process_token,
parent_token, json)`. `kind` is the `type` string above; `process_token` and `parent_token`
are `pid:pidversion`. The full event is in `json`. Indexes: `(kind, mach_time)`,
`(process_token)`, `(wall_time)`.

## Fixture dialects

`plctl replay` reads this format and `eslogger` output. Detection: a line with
`kind`, `source` and `process` is Porchlight; a line with `event` and `process` is eslogger.
