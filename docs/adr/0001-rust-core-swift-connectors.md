# ADR-0001: Rust core, C shim for Endpoint Security, Swift container app

Status: proposed
Date: 2026-10-15
Amends: SPEC.md §2, §3, §4.4 to §4.7, §5, §6 to §11

## Context

The original SPEC.md draft specified Swift for all non-C logic and a SwiftPM package for
the core. The project owner has directed that the application be written in Rust, with Swift
used only where a macOS integration requires it.

Facts that shape the decision:

- The Endpoint Security handler is an Objective-C block (`es_handler_block_t`). Receiving it
  requires C, Objective-C, Swift, or Rust with generated SDK bindings. The draft already
  placed the handler in C.
- System extension management (`OSSystemExtensionRequest`), SwiftUI, and `NSWorkspace`
  actions are reachable only from Swift or Objective-C.
- Everything between those two edges is platform-neutral logic: schema, store, graphs,
  inventory, cross-view comparison, rule engine, pipeline, replay. C7 requires all of it to be
  testable without a live ES client.
- The privileged process should link as little as possible. A root ES client that parses
  YAML and writes SQLite has more surface than one that copies, batches and forwards.

## Decision

1. **Core in Rust.** `pl-core` holds schema, store, graphs, inventory, cross-view
   logic, rules and pipeline. It has no Apple framework dependency and builds and tests on
   Linux. Cargo features (`schema`, `store`, `rules`, `pipeline`) let the extension link only
   the schema.
2. **Extension is a Rust binary with a C shim.** `es_shim.c` is the only translation unit
   that includes the ES header. It owns `es_new_client`, subscriptions, muting, the handler,
   the AUTH prefix check and response, and pushes fixed-layout `PLRawEvent` records into
   `ring.c`. Rust (`bridge.rs`) drains the ring, converts to `Event`, tracks sequence gaps,
   emits `drop` events, batches and sends over XPC. `PLRawEvent` and the ring live in
   `pl-raw`, which has no ES dependency and is tested on Linux. The struct is
   mirrored as a `#[repr(C)]` Rust type with static size and offset assertions on both sides.
3. **XPC is raw libxpc with a versioned dictionary protocol.** Plain libxpc functions are
   declared `extern "C"` from Rust. The two block-taking calls (listener and peer event
   handlers) go through `xpc_shim.c`. Both peers set a code-signing requirement on the Team
   ID and the counterpart bundle identifier. The payload is JSON `[Event]`, the same encoding
   as fixtures. No NSXPC, no `NSSecureCoding`, no Objective-C runtime in the extension.
4. **Swift is the container app only.** SwiftUI screens, extension activation and status,
   System Settings and Finder actions. The app embeds `pl-ffi`, a Rust staticlib with
   a hand-written C header and roughly ten functions exchanging JSON. Every FFI entry point
   catches unwinds and returns an error code; Rust panics never cross the boundary. The
   extension builds with `panic = "abort"`: a root process in an unknown state exits and is
   relaunched rather than continuing.
5. **Cargo workspace replaces SwiftPM; cargo is never run from inside Xcode.** `scripts/check`
   builds the Rust targets first. The Xcode project owns bundling, `Info.plist` processing,
   entitlements, provisioning and signing for both bundles. The extension target compiles a
   placeholder `main.c`, and a script phase with declared inputs and outputs copies the
   prebuilt Rust executable over it before signing. This keeps Xcode's user-script sandbox
   and `SDKROOT` environment away from cargo entirely.
6. **Determinism rule for C7.** No hash-map iteration order reaches serialization or any
   ordered output. Ordered maps or explicit sorts only. Enforced with a clippy
   `disallowed_types` entry for `HashMap` and `HashSet` in `pl-core`.
7. **Dependencies.** Exact-version pins, committed `Cargo.lock`, pinned toolchain in
   `rust-toolchain.toml`. Initial set: `serde`, `serde_json`, `rusqlite` against the system
   SQLite. Additions are named in the PR that adds them. CI checks `cargo tree` against a
   deny-list of network crates (C1).

## Consequences

Positive:

- Milestones M1, M4 (logic), M5 (logic), M6 and the docs half of M9 build and test on Linux,
  so most of CI runs on ubuntu runners. `cargo check --target aarch64-apple-darwin` also runs
  on Linux for the pure-Rust macOS crates, so type errors in extension and seeding code are
  caught before a Mac is involved; only the C shims and linking need the SDK.
- Deterministic replay (C7) has no Foundation `Date` or dictionary-order surprises.
- The privileged process links libc, libEndpointSecurity, libxpc and the Rust standard
  library. No Swift or Objective-C runtime, no SQLite, no YAML.
- Untrusted text (eslogger JSON, rule files, `launchctl` and `sfltool` output, TCC.db
  metadata) is parsed in a memory-safe language.

Negative and accepted:

- Two toolchains. Mitigated by never mixing them in one build step (decision 5).
- C does not disappear from the extension. The hot path is C by necessity.
- C9: typed allocation is a clang feature and does not cover Rust allocations. Rust's
  compile-time memory safety addresses the same bug class differently. Entitlement-level
  protections (hardened heap, dyld-ro, platform restrictions) apply to every signed binary
  regardless of language. If the pointer-authentication component requires an `arm64e`
  slice, the Rust target `arm64e-apple-darwin` is tier 3 and needs a pinned nightly toolchain
  with `-Zbuild-std`. **M2 resolves this first and records the answer in an ADR.** The
  intended outcome is full C9 adoption; a nightly pinned by date, used only for
  `-Zbuild-std` and never for unstable language features, is an acceptable cost.
- Rust build scripts and proc-macros execute at build time with no opt-out. Mitigated by the
  small pinned set and lockfile checksums.

## Alternatives considered

- **Swift throughout, as drafted.** Rejected by the owner. Would also keep all tests on macOS
  runners and put the Swift runtime, Foundation and SQLite into the privileged process.
- **A community Rust ES bindings crate instead of a C shim.** Rejected for v0: a third-party
  dependency in the root process versus a shim of a few hundred lines this repository owns
  and tests.
- **UniFFI or swift-bridge for the app boundary.** Deferred. The surface is about ten
  functions; codegen and proc-macro dependencies are not justified yet. Revisit by ADR if the
  surface grows past roughly twenty functions or needs rich types.
- **Running cargo from an Xcode Run Script phase.** Rejected: Xcode's user-script sandbox
  blocks writes to `target/`, and Xcode exports `SDKROOT` and deployment-target variables that
  leak into host builds of proc-macro crates.
- **Running the pipeline in the extension.** Rejected: puts parsers and a database in the
  root process.

## Verification

- `cargo test --workspace` on Linux covers core, raw-event layout, ring and CLI.
- `cargo check --workspace --target aarch64-apple-darwin` on Linux covers the pure-Rust
  macOS crates.
- `cargo build --target aarch64-apple-darwin` plus `xcodebuild` on a macOS runner covers the
  extension and app.
- `scripts/check-no-network.sh` includes a `cargo tree` deny-list.
