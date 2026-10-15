# ADR-0006: Enhanced Security (C9) and arm64e for Rust binaries

Status: open, pending measurement on macOS 26 (owner runs `scripts/spike-arm64e`)
Date: 2026-10-15
Answers: SPEC.md §12 (arm64e question); C9

## Context

C9 requires the Enhanced Security capability on every target from the first commit. The
capability is added in Xcode's Signing & Capabilities tab and contributes entitlements and
build settings. Two things are unknown from Linux and are not guessed here:

1. The exact entitlement keys and build settings the capability adds in Xcode 26.
2. Whether its pointer-authentication component requires an `arm64e` slice. The Rust target
   `arm64e-apple-darwin` is tier 3: nightly only, with `-Zbuild-std`.

The M2 entitlements files therefore contain only what is known: the system-extension
install entitlement for the app and the Endpoint Security client entitlement for the
extension. Writing guessed keys into an entitlements file would either fail signing or,
worse, silently do nothing while claiming C9.

## Procedure

1. In Xcode, add the Enhanced Security capability to both targets in the generated project.
2. Run `scripts/build-apple`, then `scripts/spike-arm64e`.
3. Record here: the entitlement keys and settings added; whether `ARCHS` became `arm64e`;
   whether the arm64 Rust extension launches with those entitlements.
4. Copy the keys into `apple/*/…entitlements` and the settings into `apple/project.yml`.

## Decision rule

- If the capability works with an `arm64` Rust binary: keep stable Rust. C9 is met by the
  entitlements for every binary and by compiler flags for the C shims.
- If it requires `arm64e`: build `pl-es` and `pl-ffi` with a nightly pinned by date, used
  only for `-Zbuild-std --target arm64e-apple-darwin`, never for unstable language features.
  Pin it in a second toolchain file used only by `scripts/build-apple`.
- Shipping without pointer authentication is not an option this ADR can choose; that would
  need the owner to amend C9.
