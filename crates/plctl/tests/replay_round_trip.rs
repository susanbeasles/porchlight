//! M1 acceptance (SPEC §9): round-trip a 10k-event fixture with a byte-identical dump.
//!
//! The fixture is synthesized here in `eslogger` shape because `Fixtures/` holds only
//! human-recorded data (ADR-0002). Replaying the dump of a replay must reproduce the dump
//! exactly, and `verify-db` must pass on the persisted store.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const EVENTS: usize = 10_000;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_plctl"))
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("plctl-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn process_json(pid: i32, pidversion: i32, path: &str) -> String {
    format!(
        r#"{{"audit_token":{{"pid":{pid},"pidversion":{pidversion},"auid":501,"euid":501,"ruid":501,"egid":20,"rgid":20,"asid":100005}},"ppid":1,"parent_audit_token":{{"pid":1,"pidversion":1,"auid":4294967295,"euid":0,"ruid":0,"egid":0,"rgid":0,"asid":100000}},"executable":{{"path":"{path}","path_truncated":false}},"signing_id":"com.apple.{pid}","team_id":"","cdhash":"{:040x}","is_platform_binary":true,"is_es_client":false,"tty":null,"session_id":100005,"start_time":"2026-10-15T02:00:00.000000Z"}}"#,
        pid as u128 * 7919
    )
}

/// Ten thousand lines cycling through the event shapes the adapter maps, plus one it does
/// not, plus unmodified closes that must be filtered.
fn synth_fixture() -> (String, usize) {
    let mut out = String::new();
    let mut expected_events = 0;
    for i in 0..EVENTS {
        let pid = 100 + (i % 50) as i32;
        let proc_ = process_json(pid, 1, "/bin/zsh");
        let event = match i % 8 {
            0 => format!(
                r#"{{"exec":{{"target":{},"args":["zsh","-c","echo {i}"],"env":["PATH=/usr/bin:/bin","HOME=/Users/u"],"cwd":{{"path":"/Users/u"}},"script":null}}}}"#,
                process_json(pid, 2, "/bin/zsh")
            ),
            1 => format!(
                r#"{{"fork":{{"child":{}}}}}"#,
                process_json(pid + 1000, 1, "/bin/zsh")
            ),
            2 => r#"{"exit":{"stat":0}}"#.to_owned(),
            3 => r#"{"close":{"modified":true,"target":{"path":"/Users/u/.zshrc"}}}"#.to_owned(),
            4 => format!(r#"{{"close":{{"modified":false,"target":{{"path":"/tmp/{i}"}}}}}}"#),
            5 => format!(
                r#"{{"create":{{"destination_type":1,"destination":{{"new_path":{{"dir":{{"path":"/Users/u/Library/LaunchAgents"}},"filename":"com.example.{i}.plist","mode":420}}}}}}}}"#
            ),
            6 => format!(
                r#"{{"btm_launch_item_add":{{"item":{{"item_type":2,"legacy":false,"managed":false,"uid":501,"item_url":"file:///Users/u/Library/LaunchAgents/com.example.{i}.plist","app_url":""}}}}}}"#
            ),
            _ => r#"{"open":{"file":{"path":"/etc/hosts"}}}"#.to_owned(),
        };
        if i % 8 != 4 {
            expected_events += 1;
        }
        let mach = 1_000_000_000_u64 + i as u64 * 1000;
        let secs = 44 + (i / 1_000_000);
        out.push_str(&format!(
            r#"{{"schema_version":1,"mach_time":{mach},"seq_num":{},"global_seq_num":{},"time":"2026-10-15T02:33:{secs:02}.{:06}Z","event_type":9,"process":{proc_},"event":{event}}}"#,
            i / 8 + 1,
            i + 1,
            i % 1_000_000,
        ));
        out.push('\n');
    }
    (out, expected_events)
}

fn run_replay(fixture: &Path, db: &Path, dump: &Path) -> String {
    let output = bin()
        .args([
            "replay",
            fixture.to_str().unwrap(),
            "--db",
            db.to_str().unwrap(),
            "--dump",
            dump.to_str().unwrap(),
            "--strict",
        ])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(output.status.success(), "replay failed: {stderr}");
    stderr
}

#[test]
fn ten_thousand_events_round_trip_byte_identical() {
    let dir = temp_dir("roundtrip");
    let fixture = dir.join("synthetic.ndjson");
    let (text, expected_events) = synth_fixture();
    fs::write(&fixture, text).unwrap();

    let db1 = dir.join("one.db");
    let dump1 = dir.join("one.ndjson");
    let stderr1 = run_replay(&fixture, &db1, &dump1);
    assert!(stderr1.contains("format=eslogger"), "{stderr1}");
    assert!(
        stderr1.contains(&format!("ingested={expected_events}")),
        "{stderr1}"
    );
    assert!(stderr1.contains("filtered=1250"), "{stderr1}");
    assert!(
        stderr1.contains("open: 1250"),
        "unsupported coverage must be visible: {stderr1}"
    );

    let db2 = dir.join("two.db");
    let dump2 = dir.join("two.ndjson");
    let stderr2 = run_replay(&dump1, &db2, &dump2);
    assert!(stderr2.contains("format=porchlight"), "{stderr2}");

    let bytes1 = fs::read(&dump1).unwrap();
    let bytes2 = fs::read(&dump2).unwrap();
    assert_eq!(bytes1.len(), bytes2.len());
    assert!(
        bytes1 == bytes2,
        "dump of a replayed dump must be byte-identical"
    );
    assert_eq!(
        bytes1.iter().filter(|b| **b == b'\n').count(),
        expected_events
    );

    let verify = bin()
        .args(["verify-db", "--db", db2.to_str().unwrap()])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&verify.stdout);
    assert!(verify.status.success(), "{stdout}");
    assert!(
        stdout.contains(&format!("events={expected_events}")),
        "{stdout}"
    );
    assert!(stdout.trim_end().ends_with("ok"), "{stdout}");

    let dumped = bin()
        .args([
            "dump",
            "--db",
            db1.to_str().unwrap(),
            "--from",
            "3",
            "--to",
            "4",
        ])
        .output()
        .unwrap();
    assert!(dumped.status.success());
    let lines: Vec<&str> = std::str::from_utf8(&dumped.stdout)
        .unwrap()
        .lines()
        .collect();
    assert_eq!(lines.len(), 2);
    assert!(lines[0].starts_with(r#"{"schema_version":2,"id":3,"#));
}

#[test]
fn strict_fails_on_malformed_and_reports_line() {
    let dir = temp_dir("strict");
    let fixture = dir.join("bad.ndjson");
    let (text, _) = synth_fixture();
    let first_two: String = text.lines().take(2).map(|l| format!("{l}\n")).collect();
    fs::write(&fixture, format!("{first_two}this is not json\n")).unwrap();
    let output = bin()
        .args(["replay", fixture.to_str().unwrap(), "--strict"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("line 3"), "{stderr}");
    assert!(stderr.contains("malformed=1"), "{stderr}");
    let lenient = bin()
        .args(["replay", fixture.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(lenient.status.success());
}

#[test]
fn batch_out_of_range_is_a_usage_error_not_a_panic() {
    let dir = temp_dir("batch");
    let fixture = dir.join("f.ndjson");
    let (text, _) = synth_fixture();
    fs::write(
        &fixture,
        text.lines().take(3).collect::<Vec<_>>().join("\n"),
    )
    .unwrap();
    for bad in ["0", "18446744073709551615"] {
        let out = bin()
            .args(["replay", fixture.to_str().unwrap(), "--batch", bad])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(1), "--batch {bad}");
        assert!(String::from_utf8_lossy(&out.stderr).contains("outside 1..=65536"));
    }
}

#[test]
fn dump_contains_only_this_runs_events() {
    let dir = temp_dir("dumprun");
    let fixture = dir.join("f.ndjson");
    let (text, _) = synth_fixture();
    let first: String = text.lines().take(5).map(|l| format!("{l}\n")).collect();
    fs::write(&fixture, first).unwrap();
    let db = dir.join("s.db");
    let d1 = dir.join("d1.ndjson");
    let d2 = dir.join("d2.ndjson");
    run_replay(&fixture, &db, &d1);
    run_replay(&fixture, &db, &d2);
    let l1: Vec<String> = fs::read_to_string(&d1)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    let l2: Vec<String> = fs::read_to_string(&d2)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    assert_eq!(
        l1.len(),
        4,
        "5 lines, the unmodified close (line 5) filtered"
    );
    assert_eq!(l2.len(), 4, "second dump excludes the first run's events");
    assert!(
        l2[0].starts_with(r#"{"schema_version":2,"id":5,"#),
        "{}",
        l2[0]
    );
}

fn es_line(seq: u64, actor: &str, event: &str) -> String {
    format!(
        r#"{{"schema_version":1,"mach_time":{},"seq_num":{seq},"global_seq_num":{seq},"time":"2026-10-15T02:33:44.000000Z","event_type":0,"process":{actor},"event":{event}}}"#,
        1000 + seq
    )
}

fn processes_db(dir: &Path) -> PathBuf {
    let lines = [
        // An earlier session: its process must not count as live in the latest one.
        es_line(
            900,
            &process_json(100, 1, "/bin/zsh"),
            &format!(
                r#"{{"fork":{{"child":{}}}}}"#,
                process_json(777, 1, "/bin/zsh")
            ),
        ),
        es_line(
            1,
            &process_json(100, 1, "/bin/zsh"),
            &format!(
                r#"{{"fork":{{"child":{}}}}}"#,
                process_json(200, 1, "/bin/zsh")
            ),
        ),
        es_line(
            2,
            &process_json(200, 1, "/bin/zsh"),
            &format!(
                r#"{{"exec":{{"target":{},"args":["curl"],"env":[],"cwd":{{"path":"/"}},"script":null}}}}"#,
                process_json(200, 2, "/usr/bin/curl")
            ),
        ),
        es_line(
            3,
            &process_json(100, 1, "/bin/zsh"),
            &format!(
                r#"{{"fork":{{"child":{}}}}}"#,
                process_json(300, 1, "/bin/zsh")
            ),
        ),
        es_line(
            4,
            &process_json(300, 1, "/bin/zsh"),
            r#"{"exit":{"stat":0}}"#,
        ),
    ];
    let fixture = dir.join("proc.ndjson");
    fs::write(&fixture, lines.join("\n")).unwrap();
    let db = dir.join("proc.db");
    let out = bin()
        .args([
            "replay",
            fixture.to_str().unwrap(),
            "--db",
            db.to_str().unwrap(),
            "--strict",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    db
}

#[test]
fn processes_agrees_with_matching_ps() {
    let dir = temp_dir("procs-ok");
    let db = processes_db(&dir);
    let ps = dir.join("ps.txt");
    fs::write(&ps, "    1 5-00:00:00\n  200   00:10\n").unwrap();
    let out = bin()
        .args([
            "processes",
            "--db",
            db.to_str().unwrap(),
            "--ps-file",
            ps.to_str().unwrap(),
            "--window-secs",
            "60",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["agrees"], true);
    assert_eq!(v["comparison"]["tracked_live"], 1);
    assert_eq!(v["live"]["exec_pidversion_changed"], 1);
    assert_eq!(v["live"]["exits"], 1);
    assert_eq!(v["sessions_in_store"], 2);
}

#[test]
fn processes_reports_misses_both_ways() {
    let dir = temp_dir("procs-bad");
    let db = processes_db(&dir);
    let ps = dir.join("ps.txt");
    fs::write(&ps, "    1 5-00:00:00\n  250   00:10\n").unwrap();
    let out = bin()
        .args([
            "processes",
            "--db",
            db.to_str().unwrap(),
            "--ps-file",
            ps.to_str().unwrap(),
            "--window-secs",
            "60",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["comparison"]["missing_from_ps"], serde_json::json!([200]));
    assert_eq!(
        v["comparison"]["untracked_in_window"],
        serde_json::json!([250])
    );
    let no_window = bin()
        .args([
            "processes",
            "--db",
            db.to_str().unwrap(),
            "--ps-file",
            ps.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(no_window.status.code(), Some(1));
}

#[test]
fn usage_and_unknown_command() {
    let none = bin().output().unwrap();
    assert_eq!(none.status.code(), Some(2));
    let bad = bin().arg("frobnicate").output().unwrap();
    assert_eq!(bad.status.code(), Some(1));
    let events = bin().arg("events").output().unwrap();
    assert!(events.status.success());
    assert!(
        String::from_utf8_lossy(&events.stdout)
            .lines()
            .any(|l| l == "tcc_modify")
    );
}

#[test]
fn processes_resolves_the_stop_race_with_a_pre_stop_snapshot() {
    // The fixture's live process (pid 200) started at 2026-10-15T02:33:44Z = 1792031624.
    let dir = temp_dir("procs-before");
    let db = processes_db(&dir);
    let after = dir.join("after.txt");
    fs::write(&after, "    1 5-00:00:00\n").unwrap(); // pid 200 exited after the stop
    let run = |before: &str, at: &str| {
        let file = dir.join("before.txt");
        fs::write(&file, before).unwrap();
        let out = bin()
            .args([
                "processes",
                "--db",
                db.to_str().unwrap(),
                "--ps-file",
                after.to_str().unwrap(),
                "--window-secs",
                "60",
                "--ps-before",
                file.to_str().unwrap(),
                "--ps-before-at",
                at,
            ])
            .output()
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_default();
        (out.status.code(), v)
    };
    // Seen just before the stop: present.
    let (code, v) = run("    1 5-00:00:00\n  200   00:20\n", "1792031700");
    assert_eq!(
        (code, &v["agrees"]),
        (Some(0), &serde_json::json!(true)),
        "{v}"
    );
    // Started after the pre-stop snapshot (like the stopper): unverifiable, not a failure.
    let (code, v) = run("    1 5-00:00:00\n", "1792031620");
    assert_eq!(code, Some(0), "{v}");
    assert_eq!(v["comparison"]["unverifiable"], serde_json::json!([200]));
    // Started well before the pre-stop snapshot and in neither: a real miss.
    let (code, v) = run("    1 5-00:00:00\n", "1792031700");
    assert_eq!(code, Some(2), "{v}");
    assert_eq!(v["comparison"]["missing_from_ps"], serde_json::json!([200]));
    // The two options go together.
    let half = bin()
        .args([
            "processes",
            "--db",
            db.to_str().unwrap(),
            "--ps-file",
            after.to_str().unwrap(),
            "--window-secs",
            "60",
            "--ps-before-at",
            "1",
        ])
        .output()
        .unwrap();
    assert_eq!(half.status.code(), Some(1));
}
