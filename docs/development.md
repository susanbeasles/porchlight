# Developing Porchlight

State as of M2: schema, store, fixture ingest and the `plctl` replay loop (M1); the
Endpoint Security extension streaming `exec`, `fork` and `exit` to the app over XPC (M2).

## Prerequisites

- Rust, pinned by `rust-toolchain.toml` (rustup installs it on first use).
- A system SQLite with headers. macOS ships it. Debian and Ubuntu: `libsqlite3-dev`.
- For M2 onward: macOS 26, Xcode 26, Apple Silicon.

The core, the CLI and every test in this milestone build and run on Linux. `cargo check
--target aarch64-apple-darwin` also runs on Linux once the target's standard library is
installed, which `rust-toolchain.toml` requests.

## The check

```sh
scripts/check
```

That runs `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test`, the C1 no-network
check, and, when the Apple target is installed, `cargo check --target aarch64-apple-darwin`.
CI runs the same script. Do not push without it passing.

## The development loop

The pipeline is exercised headlessly against NDJSON fixtures (SPEC §7, ADR-0002). No ES
client is needed to work on anything in `pl-core`.

Record a fixture on a Mac whose terminal has Full Disk Access:

```sh
scripts/record-fixture.sh Fixtures/clean-10min.ndjson 600
```

Replay it, persist to a store, and write the canonical dump:

```sh
cargo run -p plctl -- replay Fixtures/clean-10min.ndjson --db /tmp/pl.db --dump /tmp/pl.ndjson --strict
```

The summary on stderr lists events by kind and, separately, every source event name the
adapter does not map yet. Those are adapter coverage gaps, not errors; the first real
recording is how the `eslogger` field mapping gets validated.

Byte-identical round trip (M1 acceptance):

```sh
cargo run -p plctl -- replay /tmp/pl.ndjson --dump /tmp/pl2.ndjson
cmp /tmp/pl.ndjson /tmp/pl2.ndjson && echo identical
cargo run -p plctl -- verify-db --db /tmp/pl.db
```

`replay` reads either dialect and detects which from the first line.

## Layout

See SPEC.md §2. Crates:

- `crates/pl-core`: schema, ingest, store, pipeline, live-process tracking, reserved v1
  interfaces. Default feature is `schema` only; `plctl` and `pl-ffi` enable `pipeline`.
- `crates/pl-raw`: the raw event layout shared with C, the ring, decoding, and the
  extension's bridge logic. Builds and tests on Linux.
- `crates/pl-xpc`: libxpc shim and owned connections. macOS only.
- `crates/pl-es`: the extension executable. macOS only.
- `crates/pl-ffi`: the C ABI the Swift app links (`include/pl.h`).
- `crates/plctl`: the CLI.

`cargo check --target aarch64-apple-darwin` type-checks the macOS crates from Linux; their C
is compiled only on a Mac.

## Running on a Mac (M2)

Requirements: macOS 26 or later on Apple Silicon, full Xcode (not only the Command Line
Tools; `xcode-select -p` must point into `Xcode.app`), the pinned Rust toolchain, and
XcodeGen (MIT; `brew install xcodegen` or its GitHub releases).

**Nothing in this project asks you to disable SIP** (ADR-0007). Until Apple grants the
Endpoint Security entitlement, the extension cannot run live; everything else is validated
with SIP on:

```sh
cargo test -p pl-es                  # C copy routine against hand-built es_message_t
scripts/build-apple --no-sign        # C, Swift and link against the real SDK, unsigned
```

Once the entitlement is granted, `scripts/build-apple` (signed) produces an installable app.
Install it in `/Applications`, press **Install extension**, approve it in System Settings →
General → Login Items & Extensions, and grant the extension Full Disk Access.

Logs: `log stream --predicate 'subsystem == "dev.susanb.porchlight.extension"'`.

### M2 acceptance

SPEC §9: after 60 seconds, `ps` and the process graph agree on running processes.

**Now, with SIP on, through `eslogger`.** Apple's `eslogger` produces the same exec, fork and
exit stream the extension does. macOS attributes its ES client to the app that launched
the shell, so that app needs Full Disk Access, or `eslogger` fails with
`ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED`:

1. System Settings → Privacy & Security → Full Disk Access → enable your terminal app.
2. Quit the app completely and reopen it. TCC applies at launch, so a new tab or window is
   not enough. In tmux, start a new tmux server from the reopened app.
3. Turn the grant off when acceptance is done. Full Disk Access is broad. If you prefer, grant
   it only to a terminal you use just for this, such as Terminal.app, and keep your everyday
   terminal without it.

```sh
scripts/accept-m2          # 60 seconds; pass a number for longer
```

It builds `plctl` first so nothing compiles during the measurement, asks for sudo up
front, records (failing at once, with the app to grant, if `eslogger` stops early), snapshots `ps` the instant recording stops, drops a partial last line,
replays into a throwaway store, and prints the comparison. The trace contains every
command line on the machine for that window, so it is kept in a private 0700 directory and
deleted on exit. Only the JSON report is printed.

This exercises the adapter, the store, live-process tracking and the comparison. The
extension's own path (ring, bridge, XPC) is accepted once the entitlement is granted, by
running `plctl processes --db ~/Library/Application\ Support/dev.susanb.porchlight/events.db`
after the extension has streamed for a minute.

`processes` replays the store into the live-process set, runs `ps -axo pid=,etime=`, and
compares the processes started since collection began (with a 3-second slack at both
edges). Exit 0 and `"agrees": true` is a pass. A process in `missing_from_ps` means an `exit`
was missed; one in `untracked_in_window` means a `fork` or `exec` was. Processes older than
the collection window are out of scope until M4 seeds the graph at startup.

Only the latest collection session is compared: a backwards step in the global sequence
marks a restart, and `sessions_in_store` says how many the store holds.

The report also answers SPEC §12's pidversion question: `live.exec_pidversion_changed`
against `live.exec_pidversion_same`.

### Enhanced Security (C9)

Not yet configured; see ADR-0006. Enable the capability on both targets once in Xcode, then
run `scripts/spike-arm64e` and record the output in that ADR.

## Determinism rules (C7)

- No `HashMap` or `HashSet` in `pl-core`; clippy refuses them. Use ordered maps.
- Timestamps serialize as integers. Never a float, never a formatted string.
- Finding ids are derived from rule id and evidence, never random.

## Agent guard notes

The repository's agent guard quarantines `**/*.ndjson`, so coding agents cannot read or
write files under `Fixtures/`. That is intentional: fixtures are recorded by a person. Tests
synthesize their own fixtures in a temporary directory.

## CI

| Workflow | Runs | Does |
|---|---|---|
| `.github/workflows/rust.yml` | every PR, push to `main` | `scripts/check` on Linux: fmt, clippy, tests, no-network, the release-chain tests |
| `.github/workflows/agent-guard.yml` | every PR, push to `main` | guard validation, hidden-Unicode scan, secret scan |
| `.github/workflows/release.yml` | push to `main` | npm release chain; stops at a read-only gate until `release/npm.json` is enabled (ADR-0008) |
| `.github/workflows/deploy.yml` | dispatched by `release.yml` | publishes a sealed release to npm (ADR-0008) |

`.github/workflows/` is a protected path. Agents still maintain it. An agent writes there
only when the owner has directed that change in the session, and the write goes through an
approval prompt. CI on the PR then proves the change.

## Who does what

Agents do the work end to end:

- code, tests, docs and ADRs;
- branches, commits, pushes and PRs;
- CI fixes and review responses;
- release activation;
- reading acceptance output and judging it against SPEC §9.

The owner gives direction and approves. A step is the owner's only when no agent can hold the
authority it needs:

| Step | Why no agent can do it | What the agent does around it |
|---|---|---|
| Merge a milestone PR | Repository rule: the human merges M(n) before M(n+1) starts | Drives the PR to green and mergeable, then says it is ready |
| Grant the terminal Full Disk Access for `scripts/accept-m2` | macOS TCC grants are made by a person in System Settings; nothing can grant them programmatically | The script fails fast and names the app. The agent reads the output and judges acceptance |
| Type the sudo password for `eslogger` | Repository policy denies agents `sudo` | Builds everything beforehand, so the password is the only prompt |
| Configure the npm trusted publisher | Bound to the owner's npm account and 2FA | States the exact values, then verifies them on the first deploy |
| Apple entitlement and provisioning | Bound to the Apple Developer account | Keeps the build passing with `--no-sign` until they arrive |
| Repository admin settings (the `npm` environment, release immutability) | Need admin permission, which the agent's GitHub App may not have | Attempts them through the API first; on refusal, reports the exact error and setting |

Anything not in this table is an agent's job. A doc that tells the owner to copy, apply or
run something outside this table is a bug.
