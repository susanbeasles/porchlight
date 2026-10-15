# Developing Porchlight

This is the M1 state of the project: schema, store, fixture ingest and the `porchlightctl`
replay loop. There is no extension or app yet; those start in M2.

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
client is needed to work on anything in `porchlight-core`.

Record a fixture on a Mac whose terminal has Full Disk Access:

```sh
scripts/record-fixture.sh Fixtures/clean-10min.ndjson 600
```

Replay it, persist to a store, and write the canonical dump:

```sh
cargo run -p porchlightctl -- replay Fixtures/clean-10min.ndjson --db /tmp/pl.db --dump /tmp/pl.ndjson --strict
```

The summary on stderr lists events by kind and, separately, every source event name the
adapter does not map yet. Those are adapter coverage gaps, not errors; the first real
recording is how the `eslogger` field mapping gets validated.

Byte-identical round trip (M1 acceptance):

```sh
cargo run -p porchlightctl -- replay /tmp/pl.ndjson --dump /tmp/pl2.ndjson
cmp /tmp/pl.ndjson /tmp/pl2.ndjson && echo identical
cargo run -p porchlightctl -- verify-db --db /tmp/pl.db
```

`replay` reads either dialect and detects which from the first line.

## Layout

See SPEC.md §2. In M1 the workspace holds two crates:

- `crates/porchlight-core`: schema, ingest, store, pipeline, reserved v1 interfaces.
- `crates/porchlightctl`: the CLI.

Features on `porchlight-core`: `store` and `pipeline` (default). The extension will link with
`default-features = false` so the privileged process carries no SQLite.

## Determinism rules (C7)

- No `HashMap` or `HashSet` in `porchlight-core`; clippy refuses them. Use ordered maps.
- Timestamps serialize as integers. Never a float, never a formatted string.
- Finding ids are derived from rule id and evidence, never random.

## Agent guard notes

The repository's agent guard quarantines `**/*.ndjson`, so coding agents cannot read or
write files under `Fixtures/`. That is intentional: fixtures are recorded by a person. Tests
synthesize their own fixtures in a temporary directory.

## CI

`docs/ci/rust.yml` is the GitHub Actions workflow for this milestone. Workflow files are a
human-owned path in this repository; copy it to `.github/workflows/rust.yml` when merging M1.
