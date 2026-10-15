# ADR-0003: Minimum macOS 26

Status: proposed
Date: 2026-10-15
Amends: SPEC.md C10, §11

## Context

The SPEC.md draft set the minimum at macOS 15.0 for `NOTIFY_TCC_MODIFY`,
`NOTIFY_GATEKEEPER_USER_OVERRIDE` and the current `es_message_t` version, while C9 requires
the Enhanced Security capability, which is a macOS 26 and Xcode 26 feature. On 15.x the
hardened-process entitlements are inert, so C9 and C10 could not both be true at once.
`NOTIFY_TCC_MODIFY` may also have a later minimum than 15.0.

## Decision

Minimum macOS is 26.0. No fallbacks, no version checks, no support for earlier releases.
Deployment target is set in one place per toolchain: `MACOSX_DEPLOYMENT_TARGET=26.0` for the
Xcode project and for `cc`, and the same value passed to rustc through the workspace
configuration so the Rust binaries carry a matching `LC_BUILD_VERSION`.

## Consequences

- C9 applies in full on every supported machine. Every event in §4.2 is available without a
  version gate.
- Xcode 26 and a macOS 26 build host are required. GitHub-hosted macOS runners must offer a
  26 image; until then macOS CI runs on a self-hosted or owner-operated machine.
- The user base is Apple Silicon Macs that can run macOS 26. The project accepts that.
- The owner's position for the record: no backports, ever. If a later OS adds a capability
  the project wants, the minimum moves forward.
