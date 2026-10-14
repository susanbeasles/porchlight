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
| C9 | **Enhanced Security on.** All targets adopt the Enhanced Security capability (hardened heap, dyld-ro, platform restrictions, typed allocator build settings) from the first commit. If something crashes under it, fix the code, don't disable the protection. |
| C10 | **Minimum macOS 15.0.** Required for `NOTIFY_TCC_MODIFY`, `NOTIFY_GATEKEEPER_USER_OVERRIDE`, and the current `es_message_t` version. Do not add fallbacks for older versions. |

---

## 2. Repository layout

```
porchlight/
├── Porchlight.xcodeproj
├── Package.swift                       # SwiftPM for all non-UI logic; Xcode project wraps it
├── Sources/
│   ├── PorchlightCore/                 # Pure Swift, no Apple framework deps beyond Foundation
│   │   ├── Schema/                     # Event, Process, Finding types; Codable; versioned
│   │   ├── Graph/                      # ProcessGraph, IPCGraph
│   │   ├── Inventory/                  # PersistenceInventory
│   │   ├── CrossView/                  # CrossViewChecker
│   │   ├── Rules/                      # RuleEngine, rule format, ATT&CK mapping
│   │   ├── Store/                      # EventStore (SQLite), schema migrations
│   │   └── Pipeline/                   # Pipeline: ingest → normalize → graph/inventory/rules → findings
│   ├── PorchlightES/                   # The system extension target (C + Swift)
│   │   ├── ESClient.c                  # es_new_client, subscriptions, muting, handler
│   │   ├── ESMessageCopy.c             # es_message_t → PLRawEvent (fixed layout, no heap in handler)
│   │   ├── RingBuffer.c                # SPSC lock-free ring, fixed capacity
│   │   ├── Bridge.swift                # Drains ring, converts PLRawEvent → Schema.Event, forwards via XPC
│   │   ├── SelfProtection.swift        # AUTH handlers for own paths
│   │   └── main.swift
│   ├── PorchlightApp/                  # SwiftUI container app
│   │   ├── ExtensionManager.swift      # OSSystemExtensionRequest activation, status
│   │   ├── XPCListener.swift           # Receives events from extension, feeds Pipeline
│   │   ├── Timeline/                   # Minimal UI
│   │   └── Settings/
│   ├── PorchlightNE/                   # Reserved. Empty target with Info.plist only.
│   └── porchlightctl/                  # CLI: replay, dump, verify
├── Rules/                              # Rule corpus (YAML), ATT&CK mapping JSON
├── Fixtures/                           # Recorded eslogger NDJSON for tests and replay
├── Tests/
│   ├── PorchlightCoreTests/
│   ├── PorchlightESTests/              # Tests ESMessageCopy against synthetic es_message_t
│   └── ReplayTests/                    # Golden-file tests: fixture → expected findings
├── docs/
│   ├── development.md
│   ├── schema.md                       # Generated from Schema/ doc comments
│   └── adr/                            # Architecture decision records
└── scripts/
    ├── record-fixture.sh               # Wraps eslogger with Porchlight's event set
    └── check-no-network.sh             # C1 enforcement
```

Bundle identifiers (already registered, Team ID `2VB7966G7R`):

- App: `dev.susanb.porchlight`
- ES extension: `dev.susanb.porchlight.extension`
- Network extension (reserved): `dev.susanb.porchlight.networkextension`

---

## 3. Event schema

`PorchlightCore/Schema` is the single contract between every component. It is versioned
(`schemaVersion: Int`), `Codable`, and serializes to both JSON (fixtures, debugging) and
the SQLite store. All timestamps are `UInt64` nanoseconds since boot (`mach_continuous_time`
domain) **and** wall-clock `Date`; the former is the ordering key, the latter is for display.

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

### 4.5 `PLRawEvent`

Fixed layout, ~20 KiB, no pointers to message memory. Fields: event type, mach time,
seq/global seq, both audit tokens (+responsible), exec path, signing ID, team ID, cdhash,
flags (platform binary, ES client, truncation bits), tty path, and a type-specific union
sized for the largest member (exec with args/env). Document the layout in
`docs/schema.md`; it is the fixture format when recorded by `porchlightctl` (as NDJSON of
the decoded struct).

### 4.6 Ring buffer and bridge

- SPSC ring, capacity 65 536 slots, allocated once at start (~1.3 GB virtual; physical
  pages touched on demand; document the trade-off and make capacity a build-time constant).
- Consumer thread (`Bridge.swift`) drains in batches, converts to `Schema.Event`, assigns
  nothing (ids are assigned by the app-side Pipeline), serializes with a compact binary
  `Codable` encoder, and sends over XPC to the app in batches of ≤ 512 events or every
  250 ms, whichever first.
- Consumer reads the drop counters every batch and emits `drop` events when they change.
- Sequence tracking: per event type, expected next `seq_num`; a gap emits `drop` with
  `count = got − expected`.

### 4.7 XPC

Anonymous XPC listener in the extension, Mach service name
`dev.susanb.porchlight.extension.xpc`, restricted by code-signing requirement to the app's
team ID and bundle ID. Protocol:

```swift
@objc protocol PorchlightESProtocol {
    func status(reply: @escaping (ESStatus) -> Void)
    func startStreaming(watchListVersion: Int)
    func stopStreaming()
    func updateWatchList(_ paths: [String], version: Int)
}
@objc protocol PorchlightAppProtocol {
    func receive(batch: Data)            // encoded [Schema.Event]
    func extensionStatusChanged(_ status: ESStatus)
}
```

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

`Pipeline` is a pure, single-threaded actor in `PorchlightCore`. Input: `[Schema.Event]`
from XPC or from a fixture. Output: writes to `EventStore`, updates to `ProcessGraph`,
`IPCGraph`, `PersistenceInventory`, and emits `Finding`s via `RuleEngine`.

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
  flagged `seeded: true`.
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

- SQLite via the system library, WAL mode, in the app's container. No ORM; a thin typed
  layer. Schema versioned with forward-only migrations.
- Tables: `events` (id, mach_time, wall_time, kind, process_token, parent_token, json),
  `processes`, `ipc_edges`, `inventory`, `inventory_history`, `findings`, `drops`, `meta`.
  Indexes on `(kind, mach_time)`, `(process_token)`, `(wall_time)`.
- Retention: default 30 days of raw events, findings and inventory history indefinitely.
  Retention is user-configurable; purge runs daily.
- The database file is protected by self-protection paths and `chflags uchg` is **not**
  used (SQLite needs to write).
- Export: `porchlightctl dump --from --to --format ndjson` for support and for building
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

No menu-bar agent in v0. No notifications in v0.

---

## 7. `porchlightctl`

CLI in the same repo, for developers:

- `record --out fixture.ndjson [--duration 60s]` — runs `eslogger` with Porchlight's exact
  event set and writes NDJSON. Requires FDA on the terminal; document that.
- `replay fixture.ndjson [--rules Rules/] [--out findings.json]` — runs the full Pipeline
  headlessly against the fixture, prints findings and graph stats. **This is the primary
  development loop.** The ES extension is not needed to iterate on anything in
  `PorchlightCore`.
- `dump`, `verify-db`, `rules lint`, `rules test` (runs each rule's embedded positive and
  negative fixture snippets).

---

## 8. Testing

- Unit tests for every type in `Schema` (round-trip Codable, discriminator stability).
- `ESMessageCopy` tested against hand-built `es_message_t` structs for every subscribed
  type, including truncation paths. These run on CI without an ES client.
- `RingBuffer` tested for SPSC correctness under contention and for full-buffer drop
  accounting.
- Golden-file replay tests: each fixture in `Fixtures/` has an expected `findings.json`;
  CI fails on diff. Fixtures include at least: a clean 10-minute session, a session with a
  LaunchAgent install via `osascript`, a session with `curl | sh`, a session with an SSH
  key added, a session with simulated hidden-process mismatch, a session with sequence gaps.
- Rule tests: every rule file carries `tests: {positive: [...], negative: [...]}` with
  minimal event snippets; `porchlightctl rules test` runs them.
- A CI job runs `scripts/check-no-network.sh` (C1).
- A CI job builds with Enhanced Security on and runs the replay suite under it (C9).

---

## 9. Milestones and acceptance

Build in this order. Each milestone is a PR with tests, and must pass CI.

**M1 — Schema and store.** `Schema`, `EventStore`, `porchlightctl replay` reading NDJSON
into the store with no graphs or rules. Acceptance: round-trip a 10k-event fixture,
byte-identical dump.

**M2 — ES extension skeleton.** Extension activates, subscribes to `EXEC/FORK/EXIT` only,
streams to the app over XPC, app shows live event count. Acceptance: `ps` output and the
process graph agree on running processes after 60 s.

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

```swift
protocol AnomalyScorer {
    func score(window: [Event], context: ScoringContext) -> [WindowScore]
}
protocol FeatureExtractor {
    func features(for event: Event, context: Context) -> FeatureVector
}
protocol BaselineProvider {
    var personal: Baseline? { get }
    var community: Baseline? { get }
}
```

`Pipeline` has a single optional `scorer: AnomalyScorer?` that is `nil` in v0. `RuleHit`
is already the feature form of a rule result (§5.5).

---

## 11. Decisions already made (do not relitigate)

- Swift + C for the extension; no Objective-C beyond `@objc` XPC protocols.
- SQLite over anything else. No Core Data, no Realm, no GRDB.
- SwiftPM package for Core; Xcode project only for the bundle targets.
- No `NOTIFY_OPEN`.
- Path-mute inversion rather than filtering in the handler.
- Audit tokens as the universal process key.
- Notify-only; AUTH only for self-protection.
- Minimum macOS 15, Apple Silicon only.
- Apache-2.0, everything public, pinned deps only.

## 12. Open questions (answer with an ADR, not a Slack message)

- Ring buffer capacity vs memory footprint on 8 GB machines.
- Whether `~/Library/Containers/*` monitoring is worth the volume in v0 or deferred.
- Which 20–40 rules to port first; propose the list in the M6 PR description.
- Whether `crossViewMismatch` events should be rule inputs or findings directly in v0.
