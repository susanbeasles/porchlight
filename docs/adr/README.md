# Architecture decision records

One file per decision, numbered, never edited after acceptance except to change `Status`
(for example to `superseded by ADR-00NN`). SPEC.md is the contract; an ADR records why the
contract says what it says, or answers one of its open questions.

| ADR | Title | Status |
|---|---|---|
| [0001](0001-rust-core-swift-connectors.md) | Rust core, C shim for Endpoint Security, Swift container app | proposed |
| [0002](0002-fixture-ingress-eslogger.md) | Fixture ingress format is eslogger NDJSON first | proposed |
| [0003](0003-minimum-macos-26.md) | Minimum macOS 26 | proposed |
| [0004](0004-m1-schema-and-ingest-decisions.md) | M1 schema and ingest decisions | proposed |
| [0005](0005-m2-extension-build-and-ipc.md) | M2 extension build, IPC and naming | proposed |
| [0006](0006-enhanced-security-and-arm64e.md) | Enhanced Security (C9) and arm64e for Rust binaries | open |
| [0007](0007-no-sip-workarounds.md) | No SIP-disabled development path | accepted |
| [0008](0008-supply-chain-actions.md) | Sealed releases, then npm deploy from the sealed artifacts | proposed |
| [0009](0009-m2-acceptance-stop-race.md) | M2 acceptance resolves the collector-stop race with a pre-stop snapshot | proposed |
