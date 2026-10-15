# ADR-0009: M2 acceptance resolves the collector-stop race with a pre-stop snapshot

Status: proposed
Date: 2026-10-15
Amends: SPEC.md §9 (M2 acceptance method); `scripts/accept-m2`; `plctl processes`

## Context

The owner's first complete `scripts/accept-m2` run recorded 988 events: 339 exec, 330 exit
and 319 fork events. None were malformed. It reported `agrees: false` for one reason: a
single tracked-live pid was missing from `ps`. Nothing was untracked.

The check compared the collector's live set with one `ps` snapshot taken just after
`eslogger` stopped. That design has two races at the stop:

1. A process that exits between the stop and the snapshot is gone from `ps`, but its `exit`
   was never recorded.
2. The stopper itself, `sudo kill`, forks and execs while recording is still running. Its
   `exit` happens after the stop, and it is gone before any snapshot taken afterwards.

Either race produces a "missing" pid that is not a collector error. The `ps` side already
ignored processes within `slack_secs` of the window's edges. The live side had no
equivalent.

## Decision

Take a second `ps` snapshot immediately before stopping, and record when it was taken.

A tracked-live pid passes if either snapshot shows it. If neither shows it:
- **`unverifiable`:** the pid became live after the pre-stop snapshot (minus `slack_secs`).
  No snapshot could have seen it, so it is reported but does not fail the check.
- **`missing_from_ps`:** the pid became live before that. This is a real missed `exit`, and
  it still fails the check.

To support this, `LiveProcesses` records when each token became live (`since_wall_ns`). The
time is carried through `exec` from the original `fork`. `compare_with_ps` takes the pre-stop
snapshot as an option. Without it the old strict rule applies.

The `untracked_in_window` check is unchanged.

## Consequences

- Real missed exits are still caught: any process older than the last few seconds of the
  window that is absent from both snapshots fails the check.
- The excused set is bounded. It covers only processes that started within `slack_secs` of
  the stop, and the report lists them by pid.
- The decision rests on reasoning about the timeline. The run that motivated it deleted its
  trace, by design, so pid 42957 was not identified directly. If `unverifiable` grows beyond
  one or two pids per run, revisit this.

## Evidence: M2 acceptance

On the owner's Mac, with SIP on and Full Disk Access granted to the terminal, a run of
`scripts/accept-m2` at this branch (60 s window, slack 3 s) produced:

| Measure | Result |
|---|---|
| Events | 996 (335 exec, 345 exit, 316 fork), 0 malformed, 0 filtered |
| Tracked live at stop | 3 |
| `missing_from_ps` | none |
| `untracked_in_window` | none |
| `unverifiable` | one pid, the predicted stopper |
| Result | `agrees: true` |
| `exec_pidversion_changed` | 335 of 335 |

The last row answers SPEC §12: on this system, `exec` always changes `pidversion`.

This accepts M2's pipeline criterion under ADR-0007. The live extension path waits for the
Endpoint Security entitlement.
