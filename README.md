# Porchlight

**Free, open-source, on-device behavioral endpoint security for Apple Silicon Macs.**

Porchlight does no signature matching. It learns what a Mac looks like when it is
healthy, notices when it stops looking like that, and tells the person who lives
there in words they understand. Every line of code, every model weight, and every
byte of data that could ever leave the machine is public and auditable.

> Status: pre-alpha. Endpoint Security entitlement requested from Apple on
> 2026-10-14. No releases yet. See [Roadmap](#roadmap).

---

## Why

Consumer endpoint security on macOS is built around a question from 2005:
*is this file's hash in a database of bad hashes?* That question has a known,
exploited answer: don't drop a file. Use what is already there.

Modern compromise on a Mac is mostly living-off-the-land. `launchd`, `cupsd`,
`mDNSResponder`, `networkserviceproxy`, `bluetoothd`, `osascript`, `curl`,
`ssh`, `python` — every binary involved is Apple-signed, every hash is clean,
and the only thing malicious is the *shape of the behavior*: who spawned what,
what talked to what, what persisted, what started fanning out across the LAN,
and when. Hash scanners cannot see shape. Enterprise EDR can, but it is
cloud-scored, closed, and not something an individual can buy.

Porchlight is for the people the current market has decided are not worth
protecting:

- the retiree whose bank credentials have been skimmed for two years by
  something that never tripped a scanner,
- the parent whose laptop is a node in a botnet DDoSing the services they
  depend on,
- the kid who ran "free V-Bucks" and now has a machine that is not his.

All three have one thing in common: by the time they install anything, the
compromise is already there. Porchlight is designed for that case first.

## What it is

A macOS app containing an **Endpoint Security system extension** and an
on-device **behavioral model** that runs on the Neural Engine and GPU through
[MLX](https://github.com/ml-explore/mlx).

1. The extension observes process, file, persistence, IPC, and authentication
   events through Apple's Endpoint Security framework.
2. Events are normalized into a single schema and assembled into a process /
   IPC graph, a persistence inventory, and per-process behavioral vectors.
3. Models score live activity against two baselines: a **personal baseline**
   learned on-device from this Mac's own history, and an opt-in,
   differentially-private **community baseline** that answers "is this normal
   for a Mac at all."
4. Findings are rendered as plain-language explanations with a confidence, the
   evidence that drove the score, the time it started, and a safe action.

Nothing is scored in the cloud. Nothing leaves the machine unless the user
opts in, and what leaves then is aggregated feature statistics, never events,
paths, or process names.

## Threat model

**In scope**

- Living-off-the-land tradecraft composed entirely of platform binaries.
- User-space persistence: LaunchAgents and LaunchDaemons, login items,
  configuration profiles, cron, shell rc files, TCC grants, SSH keys and config.
- Lateral movement and beaconing patterns visible in process and IPC structure
  and (via the companion network extension) in flow shape.
- Attempts to hide from user-space enumeration.
- Post-exploitation chains where an actively-exploited vulnerability in the
  installed build is followed by anomalous behavior in the affected component.

**Out of scope, stated plainly**

- Kernel-resident rootkits on Apple Silicon with SIP and the Signed System
  Volume intact. Endpoint Security is a user-space API and cannot observe the
  kernel; Apple's boot chain addresses that layer upstream of this tool.
- Firmware and baseband.
- Anything on Intel Macs. MLX is Apple Silicon only, and that is where the
  users are.

Porchlight does not claim to catch everything. It claims to catch the class
that hash scanners structurally cannot, and to be honest about the rest.

## How Endpoint Security is used

Porchlight ships as a `SystemExtensions`-managed ES extension inside a
container app. The extension is the only component that holds an
`es_client_t`. Detection is **notify-only**. The single AUTH subscription is
on the extension's own bundle and data directory so it can refuse tampering
with itself; that is the only place it ever returns a deny.

### Subscriptions

| Purpose | Events |
|---|---|
| Process lineage and arguments | `NOTIFY_EXEC`, `NOTIFY_FORK`, `NOTIFY_EXIT` |
| File behavior on scoped paths | `NOTIFY_CREATE`, `NOTIFY_WRITE`, `NOTIFY_CLOSE` (modified), `NOTIFY_RENAME`, `NOTIFY_UNLINK`, `NOTIFY_SETFLAGS`, `NOTIFY_SETMODE`, `NOTIFY_SETOWNER`, `NOTIFY_SETEXTATTR`, `NOTIFY_CLONE`, `NOTIFY_LINK`, `NOTIFY_TRUNCATE` |
| Persistence and configuration | `NOTIFY_BTM_LAUNCH_ITEM_ADD/REMOVE`, `NOTIFY_PROFILE_ADD/REMOVE`, `NOTIFY_TCC_MODIFY`, `NOTIFY_GATEKEEPER_USER_OVERRIDE`, `NOTIFY_XP_MALWARE_DETECTED/REMEDIATED`, `NOTIFY_KEXTLOAD`, `NOTIFY_MOUNT/UNMOUNT` |
| IPC topology | `NOTIFY_XPC_CONNECT`, `NOTIFY_UIPC_BIND`, `NOTIFY_UIPC_CONNECT` |
| Process manipulation and credentials | `NOTIFY_GET_TASK`, `NOTIFY_GET_TASK_READ`, `NOTIFY_REMOTE_THREAD_CREATE`, `NOTIFY_PROC_SUSPEND_RESUME`, `NOTIFY_SIGNAL`, `NOTIFY_SU`, `NOTIFY_SUDO`, `NOTIFY_AUTHENTICATION`, `NOTIFY_OPENSSH_LOGIN/LOGOUT`, `NOTIFY_LOGIN_LOGIN/LOGOUT`, `NOTIFY_SCREENSHARING_ATTACH/DETACH`, `NOTIFY_LW_SESSION_*`, `NOTIFY_OD_*` |
| Self-protection only | `AUTH_UNLINK`, `AUTH_RENAME`, `AUTH_SETFLAGS`, `AUTH_SETMODE`, muted to everything except Porchlight's own paths |

`NOTIFY_OPEN` is deliberately not subscribed system-wide: it is the
highest-volume event in the system and adds little beyond `CLOSE` with
`modified`.

### Why these and not something else

- Exec messages carry a full `es_process_t` for target and parent: `audit_token`,
  `parent_audit_token`, `responsible_audit_token`, `signing_id`, `team_id`,
  `cdhash`, `is_platform_binary`, `tty`. Arguments and environment come from
  `es_exec_arg` / `es_exec_env`. This is where LOTL shows itself: `osascript -e`,
  `curl | sh`, `launchctl bootstrap` from an unexpected parent,
  `DYLD_INSERT_LIBRARIES` or `GIT_CONFIG_GLOBAL` in the environment.
- Lineage is keyed on audit tokens, not PIDs, so PID reuse cannot corrupt
  the graph.
- File subscriptions are constrained with `es_mute_path_events` /
  `es_unmute_path_events` so the client receives file events only for the
  directories the model cares about: `~/Library/LaunchAgents`,
  `/Library/LaunchDaemons`, `~/.ssh`, `~/.config`, shell rc files, `/etc/cups`,
  `/etc/hosts`, `/Library/Preferences/SystemConfiguration`, the TCC databases,
  and the user's home at reduced resolution.
- Persistence events (`BTM_*`, `PROFILE_*`, `TCC_MODIFY`) are low-volume and
  high-value. Every one is a feature.
- `XPC_CONNECT` and `UIPC_*` build the IPC graph: who talks to whom. Proxy
  policy abuse, inter-process routing tricks, and daemons with neighbors they
  have never had before all live here.

### Message handling

The ES handler copies what it needs out of the `es_message_t` into a
fixed-layout record (audit tokens, event type, timestamps, `seq_num`,
`global_seq_num`, resolved paths, exec args) and returns.
`es_retain_message` / `es_release_message` are used only when the copy cannot
complete inline. Feature extraction runs on a separate queue fed by a
lock-free ring buffer; the handler never blocks on inference.

Per-event-type `seq_num` gaps are tracked and surfaced as drops. A model
scoring an incomplete stream must know it is incomplete.

### What ES does not provide

ES has no socket or flow events beyond Unix-domain IPC. Network behavior comes
from a companion `NEFilterDataProvider` content-filter system extension, which
contributes per-process flow features (destinations, port fan-out, byte-rate
shape, DNS query patterns) keyed on the same audit tokens so they join the
ES-derived process graph. `cupsd` opening connections to three hundred LAN
hosts is a network-extension observation attached to an ES process node.

## Detection

### Everything is data

There is no "rule layer" and "ML layer" and "threat-intel layer" as separate
systems. There is one event schema. Every source is normalized into it, and
the model sees all of it:

- ES and network-extension events are the primary stream.
- Open behavioral rule corpora (Sigma macOS rules, Elastic's open detection
  rules, Objective-See heuristics) are compiled against the schema; a rule hit
  is a feature, not a verdict.
- [MITRE ATT&CK](https://attack.mitre.org/matrices/enterprise/macos/) is the
  taxonomy. Every finding carries technique IDs (`T1543.001` Launch Agent,
  `T1059.002` AppleScript, `T1053.003` cron, `T1546.004` shell rc, `T1070`
  indicator removal) so findings are explainable and coverage is measurable.
- CISA KEV and Apple's "may have been actively exploited" release notes are
  crossed against the installed OS build and app versions. An unpatched machine
  with an actively-exploited bug in a component that just started behaving
  oddly gets a lower anomaly threshold and higher severity. This is a prior,
  not a detector; most of the CVE corpus never maps to anything observable and
  is not ingested.
- Crash and panic reports from `/Library/Logs/DiagnosticReports` are events.
  A panic in a driver followed within minutes by new persistence and new
  network behavior is a sequence worth learning.

### Structural features

From the stream Porchlight maintains:

- a **process graph**: lineage, responsible process, signing identity, TTY,
  session;
- an **IPC graph**: XPC and Unix-socket edges;
- a **persistence inventory** with change history: launchd jobs, login items,
  profiles, TCC grants, rc files, cron;
- a **per-process behavioral vector**: exec-argument embeddings, file-touch
  distribution over scoped paths, IPC degree, network fan-out and
  periodicity, privilege transitions, time-of-day shape.

### Models

All on-device, all in MLX, all quantized:

- A small transformer trained as a masked sequence model over event windows.
  Per-window anomaly score is reconstruction loss against the baseline
  distribution.
- A graph model over the process / IPC graph scoring structural novelty: a
  platform binary with a parent, neighbor, or fan-out it has not had before.
- A density model over per-process vectors for outliers.

Steady-state budget: under 2% of one performance core and a few hundred
megabytes of unified memory. Windows are scored in batches; the ES handler is
never on the inference path.

### Two baselines, blended

- The **community baseline** is the pretrained weights plus aggregated
  per-feature statistics contributed by opted-in users as
  differentially-private histograms. It answers "is this normal for a Mac."
- The **personal baseline** is fine-tuned on-device from this Mac's first weeks
  and continuously updated. It answers "is this normal for *this* Mac."

A finding must be anomalous against the personal baseline to surface at all.
Its severity is weighted by how anomalous it also is against the community
baseline. A developer's unusual-but-stable setup does not generate noise; a
stable-looking machine that is wildly off community norms does.

The already-compromised user has no clean personal baseline. For them the
community baseline does all the work, which is why it must be good enough on
its own and why the VM-generated known-good corpus (below) is the trusted
anchor it is built around.

### Cross-view consistency

For user-space hiding, Porchlight continuously diffs what ES has observed
(processes exec'd and not yet exited, files created and not unlinked, launchd
jobs registered through BTM) against what user-space enumeration reports
(`proc_listpids`, directory listings, `launchctl print`, `sfltool`). A process
ES saw start that enumeration does not show, or a LaunchAgent BTM reported
that the directory lacks, is a direct indicator of interposition or filtering,
independent of any model.

### A worked example

A compromised machine where every process is Apple-signed: `mDNSResponder`
with a custom resolver configuration, `networkserviceproxy` with policy
routing inter-process traffic through an unexpected path, `bluetoothd`
advertising services it never has, `cupsd` fanning out to hundreds of LAN
hosts. No single event is malicious.

- The IPC graph shows `networkserviceproxy` with XPC edges it has in no
  community baseline and did not have in the personal baseline before week N.
- The persistence inventory shows a profile or a
  `/Library/Preferences/SystemConfiguration` write preceding the change,
  attributed via `NOTIFY_PROFILE_ADD` or a scoped `NOTIFY_CLOSE`.
- The network extension shows `cupsd` with LAN fan-out two orders of magnitude
  above both baselines and a periodicity that looks like scanning.
- The sequence model scores the window as high-loss because that ordering of
  events has essentially no support in either baseline.

The user gets **one finding**: a cluster of system components whose combined
behavior started at a specific time, the change that preceded it, the network
behavior that followed, a confidence derived from distance from both
baselines, and a plain-language consequence ("this is probably using your
computer to attack other computers") with a safe action. That is the thing a
hash database cannot produce.

## Training data

### Known-bad

VirusTotal's behavioral corpus, pulled offline through the API: sandbox
reports for macOS samples (process trees, files touched, persistence used,
network contacted), crowdsourced Sigma matches, and the relationship graph.
Normalized into the Porchlight schema and used as labeled positives and rule
seeds. VirusTotal is upstream of every release and never called at runtime.

### Known-good

The part everyone skips. A model learns "anomalous" only relative to "normal,"
so the benign corpus matters more than the malicious one. It is generated in
**attestable, ephemeral macOS virtual machines**:

- built from an IPSW fetched and verified directly from Apple, with the IPSW
  hash, build number, and resulting image hash recorded as provenance;
- no inbound network of any kind: no SSH, no VNC, no Remote Login, firewall in
  stealth mode. Telemetry leaves over a virtio-fs shared folder or serial
  console, never a socket;
- driven by scripted personas (retiree, student, developer, …) with jitter,
  because an idle Mac is not "normal";
- clone, run, collect, destroy. Nothing persists between runs.

These VM baselines are the trusted anchor. Contributor data later widens the
distribution around it but never replaces it, and is aggregated with robust
statistics (trimmed means, median-of-means) and filtered against the
known-bad corpus, because some contributors will be compromised.

### Training compute

Training runs on Apple Silicon with MLX. Compute location and data provenance
are separate concerns: a matmul does not care where it runs, and training on
a personal machine is fine as long as every byte of training data is from an
attestable source.

## Privacy

- Detection is entirely local.
- The extension records event type, paths on the scoped watch list, flag
  values, process executable and signing identity, audit-token fields, parent
  and responsible process, and TTY. It does not read file contents,
  keystrokes, clipboard, or browser data.
- Community contribution is **off by default**, requires explicit consent,
  and transmits only differentially-private feature histograms with no paths,
  names, identifiers, or timestamps finer than one hour. Users can inspect
  exactly what would be sent before enabling it.
- There is no account, no telemetry, and no network call Porchlight makes on
  its own behalf.
- Source, model weights, and the aggregation code are all public.

## Roadmap

**v0 — collector.** ES extension, event schema, process / IPC graph,
persistence inventory, cross-view diff, open rule corpora compiled against the
schema with ATT&CK tags. No ML. Already useful: a timeline of what changed on
the machine, with attribution, and detection of user-space hiding and known
LOTL patterns.

**v1 — personal baseline.** Sequence, graph, and density models on-device.
Learn for two weeks, then score. Where the false-positive landscape gets
mapped.

**v2 — community baseline.** Differentially-private contribution, shared
weights, the blend. The part that serves the already-compromised user, and the
part that only works once v1 has earned contributors.

**v0.5, in parallel —** the finding UI. Designed for the grandmother first; if
she can act on it, the developer can too. The reverse is not true.

## Building

Requires macOS 26, Xcode 26 and the pinned Rust toolchain (`rust-toolchain.toml`) on
Apple Silicon. The core, the CLI and most tests also build on Linux. During development the
ES extension runs without the approved entitlement using the DTS-documented workaround; see
`docs/development.md` once it exists.

```sh
git clone https://github.com/susanbeasles/porchlight
cd porchlight
# build instructions land with v0
```

## Contributing

Not yet. Once v0 has a schema and a collector that streams `NOTIFY_EXEC`,
contributions will be welcome, and the first thing needed will be scripted
personas for the known-good corpus.

## License

Apache-2.0. The code, the model weights, the training pipeline, and the
community aggregation are all under the same license. There is no proprietary
component and there will not be one.

---

*Endpoint security should not be a thing you can only buy if you are a
company. Leave the light on.*
