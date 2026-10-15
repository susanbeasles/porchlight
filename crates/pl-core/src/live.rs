//! Live-process tracking from `exec`, `fork` and `exit` (SPEC §9 M2 acceptance).
//!
//! This is the M2 slice of the process graph: which audit tokens are alive. M4 replaces it
//! with the full `ProcessGraph`. It also measures SPEC §12's open question, whether
//! `pidversion` changes on `exec`, by counting both outcomes.
//!
//! `compare_with_ps` implements the acceptance check: after a collection window, every
//! process the collector believes alive is in `ps`, and every process `ps` shows as started
//! during the window is tracked. Processes started before collection are out of scope until
//! M4's startup seeding, so they are filtered by age.
//!
//! Stopping the collector races with `ps`: a process can exit between the stop and the
//! snapshot, and the stopper itself (`sudo kill`) starts and exits around that instant. With a
//! second snapshot taken just before the stop, a live process counts as present if either
//! snapshot shows it, and one that started after the first snapshot is `unverifiable`: no
//! snapshot could have seen it, so it is reported but does not fail the check (ADR-0009).

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::schema::{AuditToken, Event, Kind};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LiveProcess {
    pub pid: i32,
    pub executable_path: String,
    /// Event id that first made this token live.
    pub since_event: u64,
    /// Wall time (ns) of the `fork` or `exec` that first made this token live.
    pub since_wall_ns: i64,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct LiveStats {
    pub forks: u64,
    pub execs: u64,
    /// `exec` where the post-exec token differs from the acting token (SPEC §12).
    pub exec_pidversion_changed: u64,
    pub exec_pidversion_same: u64,
    pub exits: u64,
    /// `exit` for a token never seen starting: it predates collection, or its start was dropped.
    pub exits_untracked: u64,
}

#[derive(Debug, Default, Clone)]
pub struct LiveProcesses {
    live: BTreeMap<AuditToken, LiveProcess>,
    stats: LiveStats,
}

impl LiveProcesses {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn apply(&mut self, event: &Event) {
        match &event.kind {
            Kind::Fork { child } => {
                self.stats.forks += 1;
                self.live.insert(
                    *child,
                    LiveProcess {
                        pid: child.pid,
                        executable_path: event.process.executable_path.clone(),
                        since_event: event.id,
                        since_wall_ns: event.wall_time.0,
                    },
                );
            }
            Kind::Exec { target, .. } => {
                self.stats.execs += 1;
                let fresh = (event.id, event.wall_time.0);
                let (since, since_wall_ns) = if target.token.pidversion
                    != event.process.token.pidversion
                    || target.token.pid != event.process.token.pid
                {
                    self.stats.exec_pidversion_changed += 1;
                    self.live
                        .remove(&event.process.token)
                        .map_or(fresh, |p| (p.since_event, p.since_wall_ns))
                } else {
                    self.stats.exec_pidversion_same += 1;
                    self.live
                        .get(&target.token)
                        .map_or(fresh, |p| (p.since_event, p.since_wall_ns))
                };
                self.live.insert(
                    target.token,
                    LiveProcess {
                        pid: target.token.pid,
                        executable_path: target.executable_path.clone(),
                        since_event: since,
                        since_wall_ns,
                    },
                );
            }
            Kind::Exit { .. } => {
                self.stats.exits += 1;
                if self.live.remove(&event.process.token).is_none() {
                    self.stats.exits_untracked += 1;
                }
            }
            _ => {}
        }
    }

    pub fn stats(&self) -> &LiveStats {
        &self.stats
    }

    pub fn len(&self) -> usize {
        self.live.len()
    }

    pub fn is_empty(&self) -> bool {
        self.live.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&AuditToken, &LiveProcess)> {
        self.live.iter()
    }

    pub fn pids(&self) -> BTreeSet<i32> {
        self.live.keys().map(|t| t.pid).collect()
    }

    /// Live pids with the wall time (ns) each became live. For a pid held by several tokens
    /// (pid reuse inside the window), the latest start wins.
    pub fn started(&self) -> BTreeMap<i32, i64> {
        let mut out = BTreeMap::new();
        for p in self.live.values() {
            let e = out.entry(p.pid).or_insert(p.since_wall_ns);
            *e = (*e).max(p.since_wall_ns);
        }
        out
    }
}

/// A `ps` snapshot taken just before the collector stopped, and when it was taken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeforeStop {
    pub pids: BTreeSet<i32>,
    pub wall_ns: i64,
}

/// One `ps -axo pid=,etime=` row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PsRow {
    pub pid: i32,
    pub age_secs: u64,
}

/// Parses `etime`: `[[dd-]hh:]mm:ss`.
pub fn parse_etime(s: &str) -> Option<u64> {
    let (days, rest) = match s.split_once('-') {
        Some((d, r)) => (d.parse::<u64>().ok()?, r),
        None => (0, s),
    };
    let parts: Vec<&str> = rest.split(':').collect();
    let nums: Vec<u64> = parts
        .iter()
        .map(|p| p.parse::<u64>().ok())
        .collect::<Option<_>>()?;
    let (h, m, sec) = match nums.as_slice() {
        [m, s] => (0, *m, *s),
        [h, m, s] => (*h, *m, *s),
        _ => return None,
    };
    if m >= 60 || sec >= 60 || (days > 0 && parts.len() != 3) {
        return None;
    }
    Some(((days * 24 + h) * 60 + m) * 60 + sec)
}

/// Parses `ps -axo pid=,etime=` output. Unparseable lines are returned as errors by index.
pub fn parse_ps(text: &str) -> (Vec<PsRow>, Vec<usize>) {
    let mut rows = Vec::new();
    let mut bad = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let mut it = line.split_whitespace();
        let (Some(pid), Some(etime), None) = (it.next(), it.next(), it.next()) else {
            if !line.trim().is_empty() {
                bad.push(i + 1);
            }
            continue;
        };
        match (pid.parse::<i32>(), parse_etime(etime)) {
            (Ok(pid), Some(age_secs)) => rows.push(PsRow { pid, age_secs }),
            _ => bad.push(i + 1),
        }
    }
    (rows, bad)
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct Comparison {
    pub tracked_live: usize,
    pub ps_total: usize,
    pub ps_in_window: usize,
    /// Alive per the collector, absent from `ps`: a missed or dropped `exit`.
    pub missing_from_ps: Vec<i32>,
    /// Alive per the collector, absent from both snapshots, but started after the pre-stop
    /// snapshot (within slack), so no snapshot could have seen it. Reported, not a failure.
    pub unverifiable: Vec<i32>,
    /// In `ps`, started inside the window, never seen starting: a missed `fork`/`exec`.
    pub untracked_in_window: Vec<i32>,
}

impl Comparison {
    pub fn agrees(&self) -> bool {
        self.missing_from_ps.is_empty() && self.untracked_in_window.is_empty()
    }
}

/// `live` maps each live pid to when it became live (`LiveProcesses::started`). `ps` is the
/// snapshot taken just after the collector stopped; `before` the optional one taken just
/// before. `window_secs` is how long collection had been running when `ps` ran. `slack_secs`
/// ignores processes too close to either edge of the window: ones that started as collection
/// began, and ones (like `ps` itself) whose events were still in flight.
pub fn compare_with_ps(
    live: &BTreeMap<i32, i64>,
    ps: &[PsRow],
    before: Option<&BeforeStop>,
    window_secs: u64,
    slack_secs: u64,
) -> Comparison {
    let ps_pids: BTreeSet<i32> = ps.iter().map(|r| r.pid).collect();
    let slack_ns = i64::try_from(slack_secs.saturating_mul(1_000_000_000)).unwrap_or(i64::MAX);
    let mut missing_from_ps = Vec::new();
    let mut unverifiable = Vec::new();
    for (&pid, &since_wall_ns) in live {
        if ps_pids.contains(&pid) {
            continue;
        }
        match before {
            Some(b) if b.pids.contains(&pid) => {}
            Some(b) if since_wall_ns > b.wall_ns.saturating_sub(slack_ns) => unverifiable.push(pid),
            _ => missing_from_ps.push(pid),
        }
    }
    let in_window: Vec<&PsRow> = ps
        .iter()
        .filter(|r| r.age_secs >= slack_secs && r.age_secs.saturating_add(slack_secs) < window_secs)
        .collect();
    Comparison {
        tracked_live: live.len(),
        ps_total: ps.len(),
        ps_in_window: in_window.len(),
        missing_from_ps,
        unverifiable,
        untracked_in_window: in_window
            .iter()
            .filter(|r| !live.contains_key(&r.pid))
            .map(|r| r.pid)
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::kind::samples;
    use crate::schema::{MachTime, SCHEMA_VERSION, Source, WallTime};

    fn tok(pid: i32, pv: i32) -> AuditToken {
        AuditToken {
            pid,
            pidversion: pv,
            ..Default::default()
        }
    }

    fn ev(id: u64, actor: AuditToken, kind: Kind) -> Event {
        let mut process = samples::process(actor.pid, "/bin/zsh");
        process.token = actor;
        Event {
            schema_version: SCHEMA_VERSION,
            id,
            mach_time: MachTime(id),
            wall_time: WallTime(0),
            seq_num: id,
            global_seq_num: id,
            source: Source::EndpointSecurity,
            process,
            kind,
        }
    }

    fn exec_into(id: u64, actor: AuditToken, target: AuditToken, path: &str) -> Event {
        let mut t = samples::process(target.pid, path);
        t.token = target;
        ev(
            id,
            actor,
            Kind::Exec {
                target: Box::new(t),
                args: vec![],
                env: Default::default(),
                cwd: None,
                script_path: None,
            },
        )
    }

    #[test]
    fn fork_exec_exit_lifecycle_with_pidversion_change() {
        let mut l = LiveProcesses::new();
        l.apply(&ev(1, tok(100, 1), Kind::Fork { child: tok(200, 1) }));
        l.apply(&exec_into(2, tok(200, 1), tok(200, 2), "/usr/bin/curl"));
        assert_eq!(l.len(), 1);
        let (t, p) = l.iter().next().unwrap();
        assert_eq!(
            (t.key(), p.executable_path.as_str(), p.since_event),
            ("200:2".to_owned(), "/usr/bin/curl", 1)
        );
        l.apply(&ev(3, tok(200, 2), Kind::Exit { status: 0 }));
        assert!(l.is_empty());
        let s = l.stats();
        assert_eq!(
            (
                s.forks,
                s.execs,
                s.exec_pidversion_changed,
                s.exec_pidversion_same,
                s.exits,
                s.exits_untracked
            ),
            (1, 1, 1, 0, 1, 0)
        );
    }

    #[test]
    fn exec_without_pidversion_change_and_untracked_exit() {
        let mut l = LiveProcesses::new();
        l.apply(&ev(1, tok(100, 1), Kind::Fork { child: tok(200, 1) }));
        l.apply(&exec_into(2, tok(200, 1), tok(200, 1), "/bin/ls"));
        assert_eq!(l.pids(), BTreeSet::from([200]));
        assert_eq!(l.iter().next().unwrap().1.executable_path, "/bin/ls");
        l.apply(&ev(3, tok(50, 1), Kind::Exit { status: 0 }));
        assert_eq!(l.stats().exec_pidversion_same, 1);
        assert_eq!(l.stats().exits_untracked, 1);
        assert_eq!(l.len(), 1);
    }

    #[test]
    fn etime_formats() {
        assert_eq!(parse_etime("00:05"), Some(5));
        assert_eq!(parse_etime("12:34"), Some(754));
        assert_eq!(parse_etime("01:00:00"), Some(3600));
        assert_eq!(
            parse_etime("2-03:04:05"),
            Some(2 * 86400 + 3 * 3600 + 4 * 60 + 5)
        );
        for bad in ["", "5", "1:60", "x:00", "2-04:05", "1:2:3:4"] {
            assert_eq!(parse_etime(bad), None, "{bad}");
        }
    }

    #[test]
    fn parse_ps_rows_and_bad_lines() {
        let (rows, bad) = parse_ps("    1 3-01:02:03\n  412   00:42\n\nnot a row\n  9 zz\n");
        assert_eq!(
            rows,
            vec![
                PsRow {
                    pid: 1,
                    age_secs: 262_923
                },
                PsRow {
                    pid: 412,
                    age_secs: 42
                }
            ]
        );
        assert_eq!(bad, vec![4, 5]);
    }

    #[test]
    fn compare_filters_by_window_with_slack() {
        let live = BTreeMap::from([(10, 0), (11, 0), (99, 0)]);
        let ps = [
            PsRow {
                pid: 1,
                age_secs: 100_000,
            }, // predates collection: ignored
            PsRow {
                pid: 10,
                age_secs: 30,
            },
            PsRow {
                pid: 11,
                age_secs: 2,
            }, // too new: inside slack, still fine because tracked
            PsRow {
                pid: 12,
                age_secs: 40,
            }, // in window, untracked: a miss
            PsRow {
                pid: 13,
                age_secs: 1,
            }, // in slack: ignored
            PsRow {
                pid: 14,
                age_secs: 58,
            }, // within slack of window start: ignored
        ];
        let c = compare_with_ps(&live, &ps, None, 60, 3);
        assert_eq!(c.missing_from_ps, vec![99]);
        assert_eq!(c.untracked_in_window, vec![12]);
        assert_eq!((c.tracked_live, c.ps_total, c.ps_in_window), (3, 6, 2));
        assert!(!c.agrees());
        let ok = compare_with_ps(&BTreeMap::from([(10, 0)]), &ps[..2], None, 60, 3);
        assert!(ok.agrees());
    }

    #[test]
    fn stop_race_uses_the_pre_stop_snapshot() {
        const S: i64 = 1_000_000_000;
        // ps (after the stop) shows only pid 10.
        let after = [PsRow {
            pid: 10,
            age_secs: 30,
        }];
        let before = BeforeStop {
            pids: BTreeSet::from([10, 20]),
            wall_ns: 100 * S,
        };
        let live = BTreeMap::from([
            (10, 50 * S),      // in both snapshots
            (20, 40 * S),      // exited between the stop and ps: seen before the stop
            (30, 100 * S + 1), // the stopper: started after the pre-stop snapshot
            (40, 98 * S),      // started within slack before that snapshot
            (50, 10 * S),      // long-lived, in neither snapshot: a missed exit
        ]);
        let c = compare_with_ps(&live, &after, Some(&before), 60, 3);
        assert_eq!(c.missing_from_ps, vec![50]);
        assert_eq!(c.unverifiable, vec![30, 40]);
        assert!(!c.agrees());

        let without_miss: BTreeMap<i32, i64> = live.into_iter().filter(|(p, _)| *p != 50).collect();
        let ok = compare_with_ps(&without_miss, &after, Some(&before), 60, 3);
        assert!(ok.agrees(), "{ok:?}");
        // Without a pre-stop snapshot the old, strict rule applies.
        let strict = compare_with_ps(&without_miss, &after, None, 60, 3);
        assert_eq!(strict.missing_from_ps, vec![20, 30, 40]);
    }

    #[test]
    fn started_tracks_wall_time_through_exec() {
        let mut l = LiveProcesses::new();
        let (parent, child, after) = (tok(1, 1), tok(2, 1), tok(2, 2));
        let mut fork = ev(1, parent, Kind::Fork { child });
        fork.wall_time = crate::schema::WallTime(7);
        l.apply(&fork);
        let mut exec = exec_into(2, child, after, "/bin/ls");
        exec.wall_time = crate::schema::WallTime(9);
        l.apply(&exec);
        assert_eq!(l.started(), BTreeMap::from([(2, 7)]));
    }
}
