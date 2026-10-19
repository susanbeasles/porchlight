# Event schema, version 1

Normative source: `crates/pl-core/src/schema/`. This page is the human summary; a
test fails if a kind discriminator is missing from it.

## Envelope

One event is one JSON object. Field order is fixed; maps are sorted; timestamps are integers.

```json
{"schema_version":2,"id":42,"mach_time":1234567890,"wall_time":1760495624500000000,
 "seq_num":7,"global_seq_num":99,"source":"replay","process":{...},"kind":{"type":"exec",...}}
```

| Field | Type | Meaning |
|---|---|---|
| `schema_version` | u32 | `2` (legacy v1 replay remains readable) |
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
counts events the extension discarded while no app was streaming; those never had
a chance to reach the store. The queue retains at most 10,000 events and 16 MiB of
accounted decoded storage, evicting oldest events when either limit is reached.
Accounting includes String and Vec capacities, process identities, and a conservative
allowance for environment-map nodes, rather than serialized bytes alone. Queue backing
storage and allocator overhead are additional bounded costs; this is not an RSS cap.
A single event exceeding the byte budget is dropped without evicting retained events.

Native exec records with more than 1,024 combined argv/environment entries are rejected
before allocating owned entries. They increment `BridgeStats::decode_errors`; they are
not silently truncated. This also bounds per-record allocation before queue admission.

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

Native events carry `capture` metadata with the raw format version, process/target/exec
flags, retained argv/env counts, and a per-event `truncated` bit. This survives IPC,
SQLite and JSON export. `capture: null` means unknown completeness, including migrated
v1 records and replay sources; it must never be treated as complete negative evidence.
The XPC protocol is version 2, requiring matched app/extension updates. The Status
screen counts incomplete and unknown observations separately. The current
scorer slot is inactive; future detectors must not infer absence from incomplete fields. Incomplete observations
remain stored, but do not replace known identities in the live-process view.

The store retains at most 100,000 events and 64 MiB of JSON, expires observations
after seven days by arrival time, caps SQLite pages at 128 MiB, and admits at most
4 MiB and 1,024 events per append. It pauses writes below 512 MiB plus a batch reserve and when a
reader prevents WAL truncation. Capacity failures use the existing unsaved-event
counter; retention reports an explicit evicted prefix without recycling event IDs.
Existing stores larger than the page budget fail closed and need offline recovery.

XPC policy requires a fixed installer-enrolled UID from the root-owned, non-writable
`/Library/Preferences/dev.susanb.porchlight.owner-uid` file (a decimal UID, optional
trailing newline). The source change does not create or commission that file; missing
or unsafe enrollment disables the listener. The enrolled owner must also be the
current local graphical-console UID/audit session, in
addition to the existing signing requirement. Remote/non-console sessions are denied.
Only one consumer connection is admitted; ownership is rechecked on commands and
delivery. Initial unowned events and events queued across ownership changes are
discarded with an `ownership_transition` loss marker, never transferred as backlog.
Native multi-user and fast-user-switch qualification remains required on macOS.

The inactive npm release switch additionally requires independently reviewed artifact
filename/SHA-256, source package Git tree, and package-lock SHA-256 in
`artifact_identity`. These must come from independent verification, not copied from
the potentially compromised builder. The signer rechecks them from its clean source
checkout; no approved identity is populated by this change.

Guard hooks reject shell expansions, links and multiply-linked targets. This is
preflight defense only: race-free enforcement also requires the execution platform
to keep policy files read-only and credentials inaccessible. This patch does not
change live filesystem permissions or claim hooks replace that boundary.
