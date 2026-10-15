# Porchlight — Technical Specification (v0: Collector)

Status: draft for implementation. Audience: an engineering agent building v0 from scratch.
Read the README first for mission and threat model. This document is the contract.

---

## 0. Scope of this document

This spec covers **v0 only**: the Endpoint Security collector, the event schema, the
process/IPC graph, the persistence inventory, the cross-view diff, the rule engine,
local storage, and a minimal timeline UI. It defines the interfaces that v1 (on-device
models) and v2 (community baseline) will consume, but does not implement them.

Anything not listed under "In scope" is out of scope for v0. Do not build it.

### In scope (v0)

1. macOS app bundle containing an Endpoint Security system extension.
2. Normalized event schema and append-only local event store.
3. Process graph, IPC graph, persistence inventory, maintained incrementally.
4. Cross-view consistency checker.
5. Rule engine executing a Sigma-derived rule format over the schema, with ATT&CK tags.
6. Findings model and a minimal timeline UI.
7. Self-protection (AUTH deny on own paths) and tamper logging.
8. Replay harness: run the full pipeline from recorded `eslogger` NDJSON without a live ES client.
9. Developer documentation sufficient for a second contributor to build and run it.

### Out of scope (v0)

- Any ML. No MLX dependency in v0. Reserve the interface only.
- Network extension. Reserve the bundle ID and the `flow` event kind in the schema only.
- Community contribution, differential privacy, any network call.
- Remediation actions beyond "reveal in Finder" and "open System Settings".
- Intel Macs. Apple Silicon only.
- Localization.

---

## 1. Non-negotiable constraints

These apply to every line of code. A PR that violates one is rejected regardless of merit.

| ID | Constraint |
|---|---|
| C1 | **No network.** v0 makes zero outbound connections. No analytics, no update checks, no crash reporting. `NSAppTransportSecurity` is irrelevant because there are no requests. Add a CI check that greps for `URLSession`, `NWConnection`, `CFSocket`, `curl` and fails the build if found outside `Tests/`. |
| C2 | **No file contents.** The extension never reads the contents of any file it observes. Paths, metadata, flags, and process attribution only. |
| C3 | **Notify-only detection.** The only AUTH subscriptions are on Porchlight's own install directory and data directory. Every AUTH handler must respond within the message deadline and must never deny anything outside those paths. |
| C4 | **Audit tokens, not PIDs.** Process identity is `audit_token_t` (pid + pidversion) everywhere. PIDs may be displayed but never used as keys. |
| C5 | **Handler never blocks.** The ES message handler copies, enqueues, returns. No allocation-heavy work, no locks that can contend, no I/O, no logging in the hot path. |
| C6 | **Drops are visible.** Sequence-number gaps are detected per event type and recorded as `drop` events in the store. The UI shows a drop indicator. A silent gap is a bug. |
| C7 | **Deterministic replay.** Given the same NDJSON input, the pipeline produces byte-identical graph, inventory, and findings output. Every component is testable without a live ES client. |
| C8 | **Everything is public.** No private dependencies, no vendored binaries, no obfuscation. Third-party packages must be MIT/Apache/BSD and pinned by commit. |
| C9 | **Enhanced Security on.** All targets adopt the Enhanced Security capability (hardened heap, dyld-ro, platform restrictions, pointer authentication, typed allocator build settings for C) from the first commit. If something crashes under it, fix the code, don't disable the protection. Rust code receives the entitlement-level protections; the C shim receives the compiler-level ones. See ADR-0001 and the arm64e question in §12. |
| C10 | **Minimum macOS 26.0.** Required for the Enhanced Security capability (C9); also provides `NOTIFY_TCC_MODIFY`, `NOTIFY_GATEKEEPER_USER_OVERRIDE`, and the current `es_message_t` version without version checks. Do not add fallbacks for older versions. See ADR-0003. |

---

## 2. Repository layout

Rust is the application language. Swift exists only in the container app. C exists only
where an Apple API hands us a block or a struct. See ADR-0001.

```
porchlight/
├── Cargo.toml                          # Workspace; exact-version pins; shared profiles
├── Cargo.lock                          # Committed; checksums are the pin (C8)
├── rust-toolchain.toml                 # Pinned toolchain
├── crates/                             # Crate names use the short prefix `pl-` (ADR-0005)
│   ├── pl-core/                        # Pure Rust, std only. Builds and tests on Linux.
│   │   └── src/
│   │       ├── schema/                 # Event, ProcessIdentity, Finding; serde; versioned
│   │       ├── live.rs                 # M2 live-process set; replaced by graph/ in M4
│   │       ├── graph/                  # ProcessGraph, IPCGraph
│   │       ├── inventory/              # PersistenceInventory
│   │       ├── crossview/              # CrossViewChecker over enumerator traits
│   │       ├── rules/                  # RuleEngine, rule format, ATT&CK mapping
│   │       ├── store/                  # EventStore (rusqlite on system SQLite), migrations
│   │       └── pipeline/               # ingest → normalize → graph/inventory/rules → findings
│   │                                   # features: schema (default), store, rules, pipeline
│   ├── pl-raw/                         # rawevent.h + #[repr(C)] mirror, ring.c, decode,
│   │                                   # bridge logic, XPC protocol. Builds and tests on Linux
│   ├── pl-xpc/                         # xpc_shim.c (block-taking libxpc calls) + owned
│   │                                   # connections in Rust. macOS only
│   ├── pl-es/                          # Extension executable. macOS only.
│   │   ├── csrc/es_copy.c              # es_message_t → PLRawEvent, the handler's copy
│   │   ├── csrc/es_shim.c              # es_new_client, muting, subscriptions, handler, os_log
│   │   ├── csrc/es_selftest.c          # Copy tests against hand-built es_message_t
│   │   └── src/                        # main (ring, bridge thread), service (XPC peers)
│   ├── pl-sys-macos/                   # libproc/csops seeding; launchctl, sfltool, profiles
│   │                                   # parsers; TCC.db metadata. Implements core traits
│   ├── pl-ffi/                         # staticlib + include/pl.h for the app; XPC client
│   └── plctl/                          # CLI: record, replay, dump, verify-db, processes, rules
├── apple/
│   ├── project.yml                     # XcodeGen spec; Porchlight.xcodeproj is generated
│   ├── PorchlightApp/                  # SwiftUI container app (the only Swift target)
│   │   ├── ExtensionManager.swift      # OSSystemExtensionRequest activation, status
│   │   ├── CoreBridge.swift            # Calls pl-ffi; JSON in, JSON out
│   │   ├── Timeline/                   # Minimal UI
│   │   └── Settings/
│   ├── PorchlightExtension/            # Info.plist, entitlements; no sources: the bundle's
│   │                                   # executable is the cargo-built pl-es, copied before signing
│   └── PorchlightNE/                   # Reserved. Info.plist only.
├── Rules/                              # Rule corpus (YAML), ATT&CK mapping JSON
├── Fixtures/                           # Human-recorded eslogger NDJSON + golden outputs
├── docs/
│   ├── development.md
│   ├── schema.md                       # Generated from schema doc comments
│   └── adr/                            # Architecture decision records
└── scripts/
    ├── check                           # fmt, clippy, test, no-network: the one entrypoint
    ├── build-apple                     # cargo, then XcodeGen, then xcodebuild (macOS)
    ├── accept-m2                       # M2 acceptance via eslogger, SIP on (macOS)
    ├── spike-arm64e                    # Enhanced Security evidence for ADR-0006 (macOS)
    ├── record-fixture.sh               # Wraps eslogger with Porchlight's event set
    └── check-no-network.sh             # C1: source grep + cargo tree deny-list
```

Tests live beside each crate (`crates/*/tests/` and `#[cfg(test)]` modules). Golden replay
tests live in `crates/plctl/tests/`. Extension copy tests against hand-built
`es_message_t` structs live in `crates/pl-es` and run only on macOS.

Bundle identifiers (already registered, Team ID `2VB7966G7R`):

- App: `dev.susanb.porchlight`
- ES extension: `dev.susanb.porchlight.extension`
- Network extension (reserved): `dev.susanb.porchlight.networkextension`

---

## 3. Event schema

`pl-core::schema` is the single contract between every component. It is versioned
(`schema_version: u32`), implements serde `Serialize` and `Deserialize`, and serializes to
JSON (fixtures, debugging, XPC) and the SQLite store. All timestamps are `u64` nanoseconds
since boot (`mach_continuous_time` domain) **and** wall-clock time as `i64` nanoseconds since
the Unix epoch; the former is the ordering key, the latter is for display. Wall-clock time is
never serialized as a float or a formatted string.

The type sketches in §3.1 to §3.4 keep the original Swift-style notation. They are semantic
contracts, not source. The normative definitions are the Rust types in
`pl-core::schema`. Mapping: `UInt64` is `u64`, `Int32` is `i32`, `Date` is wall-clock
`i64` nanoseconds, `Codable` is serde, `Hashable` is `Hash + Eq`, and field names are
`snake_case` in Rust and in JSON. Any map that reaches serialization or an ordered output is a
`BTreeMap` or is explicitly sorted; hash-map iteration order never reaches output (C7).

### 3.1 Identity types

```swift
struct AuditToken: Hashable, Codable {
    let pid: Int32
    let pidVersion: Int32
    let auid: uid_t
    let euid: uid_t
    let ruid: uid_t
    let egid: gid_t
    let rgid: gid_t
    let asid: au_asid_t
}
// Hashable on (pid, pidVersion) only. Equality on the same.
```

```swift
struct ProcessIdentity: Codable {
    let token: AuditToken
    let parentToken: AuditToken
    let responsibleToken: AuditToken?
    let executablePath: String
    let signingID: String?
    let teamID: String?
    let cdhash: String             // hex
    let isPlatformBinary: Bool
    let isESClient: Bool
    let tty: String?
    let sessionID: Int32
    let startTime: Date
}
```

### 3.2 Event envelope

```swift
struct Event: Codable {
    let schemaVersion: Int           // = 1
    let id: UInt64                   // monotonic, assigned by Pipeline on ingest
    let machTime: UInt64
    let wallTime: Date
    let seqNum: UInt64               // es_message_t.seq_num
    let globalSeqNum: UInt64         // es_message_t.global_seq_num
    let source: Source               // .endpointSecurity, .replay, .crossView, .diagnostics, .synthetic
    let process: ProcessIdentity     // the acting process
    let kind: Kind
}
```

### 3.3 Event kinds

`Kind` is an enum with associated values. Exhaustive list for v0:

```
exec(target: ProcessIdentity, args: [String], env: [String: String], cwd: String?, scriptPath: String?)
fork(child: AuditToken)
exit(status: Int32)

fileCreate(path: String, mode: mode_t)
fileWrite(path: String)
fileCloseModified(path: String)
fileRename(from: String, to: String)
fileUnlink(path: String)
fileSetFlags(path: String, flags: UInt32)
fileSetMode(path: String, mode: mode_t)
fileSetOwner(path: String, uid: uid_t, gid: gid_t)
fileSetXattr(path: String, name: String)
fileClone(from: String, to: String)
fileLink(from: String, to: String)
fileTruncate(path: String)

launchItemAdd(item: LaunchItem)          // BTM
launchItemRemove(item: LaunchItem)
profileAdd(profile: ProfileInfo)
profileRemove(profile: ProfileInfo)
tccModify(service: String, identity: String, update: TCCUpdate)
gatekeeperOverride(path: String, verdict: String)
xpMalwareDetected(signature: String, path: String)
xpMalwareRemediated(signature: String, path: String)
kextLoad(identifier: String)
mount(path: String, fsType: String, device: String)
unmount(path: String)

xpcConnect(serviceName: String, domainType: String)
uipcBind(path: String)
uipcConnect(path: String)

getTask(target: AuditToken, flavor: String)
remoteThreadCreate(target: AuditToken)
procSuspendResume(target: AuditToken, action: String)
signal(target: AuditToken, signum: Int32)
su(from: uid_t, to: uid_t, success: Bool, shell: String?)
sudo(success: Bool, command: String?, from: uid_t, to: uid_t)
authentication(type: String, success: Bool)
sshLogin(success: Bool, user: String, source: String)
sshLogout(user: String, source: String)
loginLogin(success: Bool, user: String)
loginLogout(user: String)
screenSharingAttach(success: Bool, source: String, user: String)
screenSharingDetach(source: String, user: String)
lwSession(action: String, user: String)   // login/logout/lock/unlock
odEvent(action: String, user: String, node: String)

selfProtectionDenied(path: String, operation: String)   // emitted by AUTH handlers
drop(eventType: String, expectedSeq: UInt64, gotSeq: UInt64, count: UInt64)
crossViewMismatch(kind: CrossViewKind, subject: String, detail: String)
diagnosticReport(type: String, process: String, module: String?, path: String)
flow(reserved: Bool)   // placeholder for network extension; never emitted in v0
```

Supporting types `LaunchItem`, `ProfileInfo`, `TCCUpdate`, `CrossViewKind` are defined in
`Schema/`. Every `kind` must have a stable `String` discriminator for SQL indexing.

### 3.4 Finding

```swift
struct Finding: Codable, Identifiable {
    let id: UUID
    let createdAt: Date
    let firstEvidenceAt: Date
    let severity: Severity           // .info, .low, .medium, .high
    let confidence: Double           // 0...1
    let title: String                // plain language, ≤ 80 chars
    let consequence: String          // plain language, one sentence: what this means for the user
    let technicalSummary: String     // for the "details" disclosure
    let attackTechniques: [String]   // e.g. ["T1543.001"]
    let evidence: [UInt64]           // Event ids
    let subjects: [AuditToken]       // processes involved
    let ruleIDs: [String]            // which rules contributed (v0: always ≥1)
    let suggestedActions: [Action]   // v0: revealInFinder, openSystemSettings(pane)
    var state: State                 // .open, .acknowledged, .dismissed
}
```

The `consequence` field is mandatory and is the thing the grandmother reads. Rules must
supply it. "Suspicious LaunchAgent" is a title; "Something set itself up to start every
time you log in" is a consequence.

---

## 4. Endpoint Security extension

### 4.1 Client lifecycle

- `es_new_client` once, at extension start. On `ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED`
  or `ERR_NOT_PERMITTED`, log via `os_log` at fault level, report status to the app over
  XPC, and keep the process alive so the app can show the user what to do. Do not retry
  in a loop.
- Subscribe with a single `es_subscribe` call containing the full event list (§4.2).
- Apply muting (§4.3) **before** subscribing.
- `es_clear_cache` after any change to AUTH scope.
- On `es_delete_client` (extension shutdown) flush the ring buffer first.

### 4.2 Subscriptions

Exactly these, no others:

```
ES_EVENT_TYPE_NOTIFY_EXEC
ES_EVENT_TYPE_NOTIFY_FORK
ES_EVENT_TYPE_NOTIFY_EXIT
ES_EVENT_TYPE_NOTIFY_CREATE
ES_EVENT_TYPE_NOTIFY_WRITE
ES_EVENT_TYPE_NOTIFY_CLOSE
ES_EVENT_TYPE_NOTIFY_RENAME
ES_EVENT_TYPE_NOTIFY_UNLINK
ES_EVENT_TYPE_NOTIFY_SETFLAGS
ES_EVENT_TYPE_NOTIFY_SETMODE
ES_EVENT_TYPE_NOTIFY_SETOWNER
ES_EVENT_TYPE_NOTIFY_SETEXTATTR
ES_EVENT_TYPE_NOTIFY_CLONE
ES_EVENT_TYPE_NOTIFY_LINK
ES_EVENT_TYPE_NOTIFY_TRUNCATE
ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD
ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE
ES_EVENT_TYPE_NOTIFY_PROFILE_ADD
ES_EVENT_TYPE_NOTIFY_PROFILE_REMOVE
ES_EVENT_TYPE_NOTIFY_TCC_MODIFY
ES_EVENT_TYPE_NOTIFY_GATEKEEPER_USER_OVERRIDE
ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED
ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED
ES_EVENT_TYPE_NOTIFY_KEXTLOAD
ES_EVENT_TYPE_NOTIFY_MOUNT
ES_EVENT_TYPE_NOTIFY_UNMOUNT
ES_EVENT_TYPE_NOTIFY_XPC_CONNECT
ES_EVENT_TYPE_NOTIFY_UIPC_BIND
ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT
ES_EVENT_TYPE_NOTIFY_GET_TASK
ES_EVENT_TYPE_NOTIFY_GET_TASK_READ
ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE
ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME
ES_EVENT_TYPE_NOTIFY_SIGNAL
ES_EVENT_TYPE_NOTIFY_SU
ES_EVENT_TYPE_NOTIFY_SUDO
ES_EVENT_TYPE_NOTIFY_AUTHENTICATION
ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN
ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT
ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN
ES_EVENT_TYPE_NOTIFY_LOGIN_LOGOUT
ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH
ES_EVENT_TYPE_NOTIFY_SCREENSHARING_DETACH
ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN
ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT
ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK
ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK
ES_EVENT_TYPE_NOTIFY_OD_*            (all OD_ notify events)
ES_EVENT_TYPE_AUTH_UNLINK            (self-protection only)
ES_EVENT_TYPE_AUTH_RENAME            (self-protection only)
ES_EVENT_TYPE_AUTH_SETFLAGS          (self-protection only)
ES_EVENT_TYPE_AUTH_SETMODE           (self-protection only)
```

`NOTIFY_OPEN` is explicitly excluded. `CLOSE` events are dropped in the handler unless
`event.close.modified == true`.

### 4.3 Muting

Two layers:

1. **Process muting.** `es_mute_process` for Porchlight's own extension and app audit
   tokens so the collector does not observe itself. Record the fact of muting in the store
   at startup so replay knows.
2. **Path muting for file events.** Use `es_mute_path_events` to **invert** the default:
   mute all file event types for path prefix `/`, then `es_unmute_path_events` for the
   watch list. The watch list is a config file in the app's container, defaulting to:

   ```
   /Library/LaunchDaemons
   /Library/LaunchAgents
   /Library/Preferences/SystemConfiguration
   /Library/Application Support/com.apple.TCC
   /etc
   /private/etc
   /usr/local/bin
   /usr/local/lib
   /usr/local/libexec
   ~/Library/LaunchAgents
   ~/Library/Application Support/com.apple.TCC
   ~/Library/Preferences
   ~/.ssh
   ~/.config
   ~/.zshrc  ~/.zprofile  ~/.zshenv  ~/.bashrc  ~/.bash_profile  ~/.profile
   ~/.gitconfig
   ~/Library/Application Scripts
   ~/Library/Containers/*/Data/Library/Preferences   (reduced: CREATE/UNLINK/RENAME only)
   ```

   `~` expands per logged-in user at startup; re-evaluate on `LW_SESSION_LOGIN`.
   Process and persistence and IPC events are **not** path-muted; they are system-wide.

3. **AUTH scope.** The four AUTH events are muted for every path except the extension's
   own bundle path and the app's data container. Implemented as mute-all then unmute the
   two prefixes.

### 4.4 Handler contract

The `es_handler_block_t`:

1. Reads `msg->event_type`. If `CLOSE` and `!modified`, return.
2. Copies into a `PLRawEvent` (fixed-size C struct, §4.5) using only data already in the
   message. String fields are copied into fixed-size inline buffers with truncation flags;
   exec args/env are copied up to a fixed byte budget (16 KiB) with a truncation flag.
3. For AUTH events: evaluates path against the self-protection prefix list and calls
   `es_respond_auth_result(client, msg, ES_AUTH_RESULT_DENY|ALLOW, false)` before
   enqueueing. `cache` is always `false`.
4. Pushes `PLRawEvent` onto the ring buffer. If the ring is full, increments a per-type
   drop counter (atomic) and returns. **Never blocks.**
5. Returns. Does not retain the message.

`es_retain_message` is not used in v0. If a future event needs it, that's an ADR.

`es_shim.c` is the only translation unit that includes `EndpointSecurity/EndpointSecurity.h`.
Rust never sees an `es_message_t`.

### 4.5 `PLRawEvent`

Fixed layout, ~20 KiB, no pointers to message memory. Fields: event type, mach time,
seq/global seq, both audit tokens (+responsible), exec path, signing ID, team ID, cdhash,
flags (platform binary, ES client, truncation bits), tty path, and a type-specific union
sized for the largest member (exec with args/env). Document the layout in
`docs/schema.md`; it is the second fixture format, recorded by `plctl` as NDJSON of
the decoded struct from M3 onward (ADR-0002). The struct is defined once in C (`rawevent.h`)
and mirrored as a `#[repr(C)]` Rust struct; both sides carry static size and offset
assertions so layout drift fails the build.

### 4.6 Ring buffer and bridge

- SPSC ring, capacity a build-time constant (`pl_raw::RING_CAPACITY`), allocated once at
  start (slots × 21,688 bytes virtual; physical pages touched on demand). M2 uses 8,192
  slots (~178 MB virtual) as an interim value; the final value and its trade-off are an
  M3 ADR (§12).
- Consumer thread (`bridge.rs`) drains in batches, converts to `Event`, assigns nothing
  (ids are assigned by the app-side Pipeline), serializes as JSON (`serde_json`, the same
  encoding as fixtures), and sends over XPC to the app in batches of ≤ 512 events or every
  250 ms, whichever first.
- Consumer reads the drop counters every batch and emits `drop` events when they change.
- Sequence tracking: per event type, expected next `seq_num`; a gap emits `drop` with
  `count = got − expected`.

### 4.7 XPC

XPC listener in the extension, Mach service name `2VB7966G7R.dev.susanb.porchlight.extension.xpc`
(system extensions must prefix the name with the Team ID; ADR-0005),
declared in the extension's `Info.plist` and created with
`xpc_connection_create_mach_service` (libxpc, not NSXPC). Each peer connection is accepted
only after `xpc_connection_set_peer_code_signing_requirement` succeeds with a requirement on
Team ID `2VB7966G7R` and the app's bundle identifier; the app applies the mirror requirement
for the extension's identifier when it connects. Messages are `xpc_dictionary` objects with a
`v` key (protocol version, `1`) and an `op` key:

| Direction | `op` | Payload keys |
|---|---|---|
| app → extension | `status` | none; the extension answers with `status_changed` to that peer |
| app → extension | `start_streaming` | `watch_list_version: int64` |
| app → extension | `stop_streaming` | none |
| app → extension | `update_watch_list` | `paths: array<string>`, `version: int64` |
| extension → app | `batch` | `events: data` (JSON `[Event]`) |
| extension → app | `status_changed` | `status: data` (JSON `ESStatus`) |

Unknown `v` or `op` is rejected and logged. No Objective-C runtime, `NSXPCConnection`, or
`NSSecureCoding` anywhere in the extension. See ADR-0001.

If the app is not connected, the extension buffers up to 10 000 events in a secondary
heap queue then begins dropping (and counting) oldest-first. Replay cannot reconstruct
these; they are reported as `drop` with a distinct reason.

### 4.8 Self-protection

AUTH handlers deny `UNLINK`, `RENAME`, `SETFLAGS`, `SETMODE` on:

- the extension bundle path (resolved at start from `Bundle.main`),
- the app's container data directory (resolved at start),
- the rule corpus directory inside the container.

On deny, emit `selfProtectionDenied`. Deny is unconditional; there is no allow-list of
"legitimate" updaters in v0. The app's own updater (future) will stop the extension before
replacing it.

---

## 5. Pipeline (app side)

`Pipeline` is a pure, single-threaded type in `pl-core`, embedded in the app through
the `pl-ffi` C ABI. Input: `Vec<Event>` from XPC or from a fixture. Output: writes
to `EventStore`, updates to `ProcessGraph`, `IPCGraph`, `PersistenceInventory`, and emits
`Finding`s via `RuleEngine`.

```
ingest(batch)
  → assign ids (monotonic, persisted high-water mark)
  → EventStore.append
  → for each event:
      ProcessGraph.apply
      IPCGraph.apply
      PersistenceInventory.apply
      RuleEngine.evaluate(event, context) → [Finding]
  → FindingStore.upsert
```

### 5.1 ProcessGraph

- Node: `ProcessIdentity` keyed by `AuditToken`. Edges: parent→child (from `exec`/`fork`),
  responsible→process.
- `exec` replaces the node's identity for that token (same pid/pidversion, new image).
- `exit` marks the node terminated at `machTime`; nodes are retained for the session and
  persisted.
- At startup, the app seeds the graph from `proc_listpids` + `proc_pidinfo` + `csops` for
  every running process so lineage is not blind to pre-start processes. Seeded nodes are
  flagged `seeded: true`. Enumeration is a trait in `pl-core` implemented by
  `pl-sys-macos`, so seeding logic is tested with recorded enumeration fixtures.
- Query API: ancestors, descendants, siblings by `signingID`, "has this `signingID` ever
  had a parent with `signingID` X" (needed by rules).

### 5.2 IPCGraph

- Directed multigraph: edges from `xpcConnect`, `uipcConnect`, `uipcBind`. Node key:
  `AuditToken` for processes; string key for XPC service names and socket paths.
- Query API: out-degree, in-degree, neighbors by name, first-seen timestamp per edge.

### 5.3 PersistenceInventory

Maintains current state and full change history for:

| Category | Sources |
|---|---|
| launchd jobs | `launchItemAdd/Remove`, file events under `*/LaunchAgents`, `*/LaunchDaemons`, plus a startup scan |
| login items | `launchItemAdd/Remove` with BTM type, plus `sfltool dumpbtm` parse at startup |
| configuration profiles | `profileAdd/Remove`, plus `profiles list` parse at startup |
| TCC grants | `tccModify`, plus startup read of TCC.db **metadata only** (service, client, auth value; never the prompt text) |
| shell init | file events on rc files |
| cron / at | file events under `/usr/lib/cron/tabs`, `/var/at` |
| SSH | file events under `~/.ssh`; `authorized_keys` tracked by **hash of contents** computed by the *app* (not the extension) on change, so key additions are detectable without storing keys |
| Git | file events on `~/.gitconfig` and `.git/hooks/*`, `.git/config` under configured dev roots |

Each inventory entry has `firstSeen`, `lastChanged`, `changedBy: AuditToken`, `history`.

### 5.4 CrossViewChecker

Runs every 60 s and on demand. Compares:

1. Processes ES has seen `exec` without `exit` vs `proc_listpids`. Missing from enumeration
   → `crossViewMismatch(.hiddenProcess)`.
2. launchd jobs the inventory believes exist (from BTM/file events) vs `launchctl print`
   for the relevant domains and a directory listing. Missing → `.hiddenLaunchItem`.
3. Files the inventory believes exist under watch paths vs `stat`. ES said created and not
   unlinked, but `stat` fails → `.hiddenFile`.
4. Login items from BTM vs `sfltool dumpbtm` → `.hiddenLoginItem`.

False-positive guards: suppress if the process exited within the last 2 s (race), if the
file was in a temp directory, or if the mismatch resolves on the next check. Persist
mismatches that survive two consecutive checks as events; those are rule inputs.

Enumeration (process list, `launchctl print`, directory listings, `sfltool dumpbtm`) is
behind traits implemented in `pl-sys-macos`. The comparison logic lives in
`pl-core` and is tested on Linux with recorded enumeration output.

### 5.5 RuleEngine

- Rule format: a YAML subset of Sigma, extended with Porchlight fields. One file per rule
  under `Rules/`. Required keys: `id`, `title`, `consequence`, `severity`, `attack: [T…]`,
  `detection` (Sigma-style selection/condition over `Schema.Event` fields and graph
  queries), `references`.
- Rules compile at app start into closures over `(Event, Context)`. `Context` exposes the
  three graphs and the inventory via read-only query APIs. Compilation errors are fatal
  for that rule and logged; the rest load.
- Correlation rules (sequence within window) are supported via a sliding-window
  `correlate:` block with `timeframe` and `by: [field]`. Keep it minimal: count-within-window
  and ordered-sequence only.
- Every finding records `ruleIDs` and the event ids that satisfied the selection.
- Initial corpus for v0: port **20–40** macOS rules from Sigma and Elastic's open rules
  covering persistence (T1543.001, T1543.004, T1547.015, T1546.004, T1053.003),
  execution (T1059.002, T1059.004, T1204.002), defense evasion (T1070, T1562.001, T1553.001),
  credential access (T1555.001), discovery and C2 patterns expressible without flow data.
  Each ported rule gets a `consequence` written for a non-technical reader.
- A rule hit is a `Finding` in v0. In v1 it becomes a feature. The engine API must expose
  `evaluateAsFeatures(event) -> [RuleHit]` alongside `evaluate` so v1 can consume hits
  without findings. Implement both now; the latter is a thin wrapper.

### 5.6 EventStore

- SQLite via the system library (`rusqlite` linking `libsqlite3`, no bundled copy), WAL
  mode, in the app's container. No ORM; a thin typed layer. Schema versioned with
  forward-only migrations.
- Tables: `events` (id, mach_time, wall_time, kind, process_token, parent_token, json),
  `processes`, `ipc_edges`, `inventory`, `inventory_history`, `findings`, `drops`, `meta`.
  Indexes on `(kind, mach_time)`, `(process_token)`, `(wall_time)`.
- Retention: default 30 days of raw events, findings and inventory history indefinitely.
  Retention is user-configurable; purge runs daily.
- The database file is protected by self-protection paths and `chflags uchg` is **not**
  used (SQLite needs to write).
- Export: `plctl dump --from --to --format ndjson` for support and for building
  training corpora later. Export is explicit and user-initiated only.

---

## 6. App

Minimal SwiftUI. Three screens:

1. **Status.** Extension state (not installed / needs approval / needs FDA / running /
   error with instruction), event rate, drop indicator, last cross-view check.
2. **Timeline.** Findings, newest first, each a card: title, consequence, severity,
   "started" time, expand for technical summary, evidence list (events rendered
   human-readably), ATT&CK tags, actions. Filter by severity and state.
3. **Settings.** Watch list editor, dev roots for Git monitoring, retention, "export
   events", "about" with the signing identity and build hash shown prominently.

Activation flow uses `OSSystemExtensionRequest.activationRequest`; the app explains each
system prompt before it appears (extension approval, then Full Disk Access) with a
screenshot-free, plain-language page and a "open System Settings to the right pane" button.

The app is the only Swift target. It links `libpl_ffi.a` and exchanges JSON with
it. It contains no detection logic.

No menu-bar agent in v0. No notifications in v0.

---

## 7. `plctl`

CLI in the same repo, for developers:

- `record --out fixture.ndjson [--duration 60s]` — runs `eslogger` with Porchlight's exact
  event set and writes NDJSON. Requires FDA on the terminal; document that.
- `replay fixture.ndjson [--rules Rules/] [--out findings.json]` — runs the full Pipeline
  headlessly against the fixture, prints findings and graph stats. **This is the primary
  development loop.** The ES extension is not needed to iterate on anything in
  `pl-core`. Accepts `eslogger` NDJSON (from M1) and Porchlight raw-event NDJSON
  (from M3), detected from the first line (ADR-0002).
- `dump`, `verify-db`, `rules lint`, `rules test` (runs each rule's embedded positive and
  negative fixture snippets).

`plctl` builds and runs on Linux as well as macOS. `record` is macOS-only.

---

## 8. Testing

- Unit tests for every type in `Schema` (round-trip Codable, discriminator stability).
- The copy routine in `es_shim.c` tested against hand-built `es_message_t` structs for
  every subscribed type, including truncation paths. These run on a macOS CI runner without
  an ES client.
- Core, raw-event layout, ring and CLI tests run on Linux (`cargo test --workspace`).
  `cargo check --target aarch64-apple-darwin` runs on Linux for the pure-Rust macOS crates.
- `RingBuffer` tested for SPSC correctness under contention and for full-buffer drop
  accounting.
- Golden-file replay tests: each fixture in `Fixtures/` has an expected `findings.json`;
  CI fails on diff. Fixtures include at least: a clean 10-minute session, a session with a
  LaunchAgent install via `osascript`, a session with `curl | sh`, a session with an SSH
  key added, a session with simulated hidden-process mismatch, a session with sequence gaps.
- Rule tests: every rule file carries `tests: {positive: [...], negative: [...]}` with
  minimal event snippets; `plctl rules test` runs them.
- A CI job runs `scripts/check-no-network.sh` (C1), which greps sources and checks
  `cargo tree` against a deny-list of network crates.
- A CI job builds with Enhanced Security on and runs the replay suite under it (C9).

---

## 9. Milestones and acceptance

Build in this order. Each milestone is a PR with tests, and must pass CI.

**M0 — Contract amendment.** This revision of the spec, ADR-0001 through ADR-0003, and the
guard policy updates a Rust workspace needs. Docs only. Acceptance: merged.

**M1 — Schema and store.** Cargo workspace, `schema`, `EventStore`, `plctl replay`
reading `eslogger` NDJSON into the store with no graphs or rules, `scripts/check`,
`check-no-network.sh`, Linux CI. Acceptance: round-trip a 10k-event fixture, byte-identical
dump.

**M2 — ES extension skeleton.** Xcode project, extension bundle wrapping the cargo-built
executable, `es_shim.c` with `EXEC/FORK/EXIT` only, ring, bridge, XPC both ways, app shows
live event count. Resolves the arm64e / pointer-authentication build question for Rust with
an ADR. Acceptance: `ps` output and the process graph agree on running processes after 60 s.
Until Apple grants the Endpoint Security entitlement, the pipeline is accepted with SIP on
through `eslogger` (`scripts/accept-m2`), and the live extension path is accepted once the
entitlement arrives. No acceptance step requires disabling SIP (ADR-0007). The same applies
to the M3 storm test and the M7 tamper test.

**M3 — Full subscriptions, muting, ring, drops.** All events in §4.2, path muting, drop
accounting, `CLOSE` filtering. Acceptance: under a synthetic file-write storm, drops are
counted and surfaced; no handler stalls (measure with `es_message_t` deadline headroom
logging in debug builds).

**M4 — Graphs and inventory.** `ProcessGraph`, `IPCGraph`, `PersistenceInventory` with
startup seeding. Acceptance: replay of the clean fixture produces an inventory matching a
hand-verified snapshot.

**M5 — Cross-view.** `CrossViewChecker` with the four comparisons and the FP guards.
Acceptance: the hidden-process fixture produces exactly one mismatch; the clean fixture
produces zero over 1 hour.

**M6 — Rules and findings.** `RuleEngine`, 20+ ported rules with consequences, `Finding`
model, `rules test` passing. Acceptance: the four malicious fixtures each produce the
expected finding and the clean fixture produces none.

**M7 — Self-protection.** AUTH handlers, `selfProtectionDenied` events, tested by
attempting `rm`/`mv`/`chflags` against the extension bundle from a terminal.

**M8 — App UI.** Status, timeline, settings, activation flow. Acceptance: a person who
has never seen the project can install, approve, and read a finding without being told
what to click.

**M9 — Docs and release candidate.** `docs/development.md`, `docs/schema.md`, ADRs for
every non-obvious decision (ring capacity, path-mute inversion, no `OPEN`, no network),
notarized build, `v0.1.0` tag.

---

## 10. Interfaces reserved for v1 and v2

Do not implement; define the protocol and leave a stub.

```rust
pub trait AnomalyScorer {
    fn score(&self, window: &[Event], context: &ScoringContext) -> Vec<WindowScore>;
}
pub trait FeatureExtractor {
    fn features(&self, event: &Event, context: &Context) -> FeatureVector;
}
pub trait BaselineProvider {
    fn personal(&self) -> Option<&Baseline>;
    fn community(&self) -> Option<&Baseline>;
}
```

`Pipeline` has a single `scorer: Option<Box<dyn AnomalyScorer + Send>>` that is `None` in v0.
`RuleHit` is already the feature form of a rule result (§5.5).

---

## 11. Decisions already made (do not relitigate)

- Rust for the application. A C shim in the extension only where an Apple API hands us a
  block or a struct. Swift only in the container app. No Objective-C anywhere (ADR-0001).
- SQLite over anything else. No Core Data, no Realm, no GRDB.
- Cargo workspace for core and tools; Xcode project only for bundling and signing the two
  bundles; cargo is never invoked from inside Xcode (ADR-0001).
- Raw libxpc dictionaries with peer code-signing requirements, not NSXPC (ADR-0001).
- `eslogger` NDJSON is the first fixture format (ADR-0002).
- No `NOTIFY_OPEN`.
- Path-mute inversion rather than filtering in the handler.
- Audit tokens as the universal process key.
- Notify-only; AUTH only for self-protection.
- Minimum macOS 26, Apple Silicon only (ADR-0003).
- Apache-2.0, everything public, pinned deps only.

## 12. Open questions (answer with an ADR, not a Slack message)

- Ring buffer capacity vs memory footprint on 8 GB machines.
- Whether `~/Library/Containers/*` monitoring is worth the volume in v0 or deferred.
- Which 20–40 rules to port first; propose the list in the M6 PR description.
- Whether `crossViewMismatch` events should be rule inputs or findings directly in v0.
- Whether `pidversion` changes on `exec`. If it does, §5.1's "same pid/pidversion" is wrong
  and the graph must link the pre-exec token to the post-exec token as one lineage line.
  Verify in M2 and amend §5.1.
- Whether the Enhanced Security pointer-authentication component requires an `arm64e`
  slice. If it does, decide between a pinned nightly with `-Zbuild-std` for the Rust
  extension and shipping without that one component. Decide in M2 with a measured build.
- Whether the ES handler for a single client can be invoked concurrently. If yes, the ring
  producer side must be multi-producer safe; if no, record the serial guarantee and keep
  SPSC. Verify against the header in M2.
- Whether §4.3's path-muting inversion should be implemented with `es_invert_muting` rather
  than mute-then-unmute, which is not how mute sets compose. Verify in M3.
