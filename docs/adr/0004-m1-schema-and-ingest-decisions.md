# ADR-0004: M1 schema and ingest decisions

Status: proposed
Date: 2026-10-15
Clarifies: SPEC.md §2, §3.3, §3.4, §7; ADR-0001; ADR-0002

## Context

M1 implemented the schema, store and replay loop. Several choices diverge from the SPEC
sketch or extend an earlier ADR. They are recorded here rather than left in code comments.

## Decisions

1. **Porchlight dump is a replay dialect from M1.** `porchlightctl dump` writes canonical
   `Event` JSON, and `replay` reads it back. This is what makes the M1 acceptance test
   (byte-identical round trip) possible without a Mac. It is distinct from the `PLRawEvent`
   NDJSON that ADR-0002 schedules for M3; `replay` will then detect three dialects.
2. **The dump dialect is strict.** `Event`, `ProcessIdentity` and `AuditToken` reject
   unknown fields, and a line whose `schema_version` differs from the build's is malformed.
   A newer shape must bump `SCHEMA_VERSION`; silently dropping fields would break both the
   round trip and the versioning contract. The `eslogger` adapter stays tolerant because
   Apple owns that format.
3. **`FindingId` is a string, not a UUID.** SPEC §3.4 says `UUID`. A random UUID breaks C7
   (byte-identical findings on replay). The id will be derived from the rule id and the
   first evidence event id when the rule engine lands in M6.
4. **Two field renames.** `authentication.type` is `auth_type` and `diagnostic_report.type`
   is `report_type`, because `type` is the serde tag of the `Kind` enum. The JSON is
   otherwise SPEC §3.3 in `snake_case`.
5. **`drop` carries a `reason`.** `sequence_gap`, `ring_full` or `app_disconnected`. SPEC §4.7
   requires app-disconnected drops to be reported with a distinct reason.
6. **`Kind::Unsupported { name }`.** Per ADR-0002, unmapped source events are kept and
   counted, never silently skipped.
7. **`porchlight-core` defaults to schema only.** The `store` and `pipeline` features are
   opt-in. The privileged extension (M2) therefore cannot link SQLite by forgetting
   `default-features = false`. `porchlightctl` and the app FFI enable `pipeline`.
8. **Appends take the write lock first.** `EventStore::append` opens an `IMMEDIATE`
   transaction so a second writer waits on SQLite's busy handler instead of failing with
   `SQLITE_BUSY_SNAPSHOT` after reading a stale high-water mark.

## Consequences

- Dumps from a future schema version are refused by older builds, loudly.
- Readers of SPEC §3 should read `docs/schema.md` for the exact wire names.
- M2 must enable no core features beyond `schema` in the extension crate.
