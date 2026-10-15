# ADR-0007: No SIP-disabled development path

Status: accepted (owner's decision)
Date: 2026-10-15
Amends: README "Building"; docs/development.md; SPEC.md §9; ADR-0005, ADR-0006

## Context

Before Apple grants the Endpoint Security entitlement, the only way to run an unapproved ES
system extension is system-extension developer mode on a machine with System Integrity
Protection disabled. That is what the README's "DTS-documented workaround" refers to. M2's
first docs recommended it inside a virtual machine.

## Decision

Porchlight's development process never asks anyone to disable SIP, in a VM or otherwise.
A security product whose build instructions weaken the host's security sets the wrong
example and normalizes the step for contributors.

Until the entitlement is granted, everything is validated with SIP on:

- The C shims and copy routine: `cargo test -p pl-es` (no entitlement needed).
- The Mac build: `scripts/build-apple --no-sign` (C, Swift and link against the real SDK).
- The Rust pipeline and the M2 acceptance check: `scripts/accept-m2` records with Apple's
  `eslogger` (Full Disk Access for the terminal only), replays, and compares with `ps`.

What waits for the entitlement: the extension running live, its XPC link to the app, and
self-protection (M7). With the granted entitlement and its provisioning profile, the
extension runs on a normal, fully protected Mac.

## Consequences

- M2's live acceptance (extension streaming to the app for 60 seconds) is deferred until the
  entitlement arrives. Its logic is accepted now through the `eslogger` path.
- M3's storm test and M7's tamper test likewise run only once the entitlement is granted.
