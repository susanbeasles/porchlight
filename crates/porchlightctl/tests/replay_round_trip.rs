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
    Command::new(env!("CARGO_BIN_EXE_porchlightctl"))
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("porchlightctl-{}-{name}", std::process::id()));
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
    assert!(lines[0].starts_with(r#"{"schema_version":1,"id":3,"#));
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
