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

Requirements: macOS 26 on Apple Silicon, Xcode 26, the pinned Rust toolchain, and XcodeGen
(MIT; from its GitHub releases or Homebrew).

```sh
scripts/build-apple            # cargo, then XcodeGen, then xcodebuild; Debug by default
open build/Debug/Porchlight.app
```

Until Apple grants the Endpoint Security entitlement, the extension can only run with
system-extension developer mode on a machine with SIP disabled. Do that in a macOS virtual
machine, not on the Mac you use every day:

1. Boot the VM to Recovery, run `csrutil disable`, restart.
2. `systemextensionsctl developer on`
3. Run the app from `/Applications` (copy it there) and press **Install extension**.
4. Approve it in System Settings → General → Login Items & Extensions.
5. Grant the extension Full Disk Access in System Settings → Privacy & Security.

The Status screen shows the extension state, events recorded, running programs seen, and
missed events. Logs: `log stream --predicate 'subsystem == "dev.susanb.porchlight.extension"'`.

The copy self-test runs without any entitlement: `cargo test -p pl-es` on a Mac.

### M2 acceptance

SPEC §9: after 60 seconds, `ps` and the process graph agree on running processes. With the
extension streaming for at least a minute:

```sh
cargo run -p plctl -- processes --db ~/Library/Application\ Support/dev.susanb.porchlight/events.db
```

It replays the store into the live-process set, runs `ps -axo pid=,etime=`, and compares
the processes started since collection began (with a 3-second slack at both edges). Exit 0
and `"agrees": true` is a pass. A process in `missing_from_ps` means an `exit` was missed;
one in `untracked_in_window` means a `fork` or `exec` was. Processes older than the
collection window are out of scope until M4 seeds the graph at startup.

Only the latest collection session is compared: a backwards step in the global sequence
marks an extension restart, and `sessions_in_store` says how many the store holds.

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

`docs/ci/rust.yml` is the GitHub Actions workflow for this milestone. Workflow files are a
human-owned path in this repository; copy it to `.github/workflows/rust.yml` when merging M1.
