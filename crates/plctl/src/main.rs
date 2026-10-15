//! `plctl` (SPEC §7): the developer loop. Builds and runs on Linux and macOS;
//! `record` needs macOS because it wraps `eslogger`.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use pl_core::ingest::{NdjsonReader, ReadStats};
use pl_core::pipeline::Pipeline;
use pl_core::schema::es_events::ES_NOTIFY_EVENT_NAMES;
use pl_core::store::EventStore;

const USAGE: &str = "\
plctl <command> [options]

Commands:
  replay <fixture.ndjson> [--db <path>] [--dump <out.ndjson>] [--batch <n>] [--strict]
      Run the pipeline headlessly over an eslogger or porchlight NDJSON fixture.
      Without --db the store is in memory. --dump writes the events this run ingested as
      canonical NDJSON. --batch is 1..=65536. --strict exits 2 when any line was malformed.
  dump --db <path> [--from <id>] [--to <id>] [--out <file>]
      Write events as canonical NDJSON, one per line, in id order.
  verify-db --db <path>
      Integrity check plus a full scan of the events table.
  record --out <fixture.ndjson> [--duration <seconds>]
      Run eslogger with Porchlight's exact notify event set (macOS only; needs Full Disk
      Access on the terminal).
  processes --db <path> [--ps-file <file> --window-secs <n>] [--slack-secs <n>]
      M2 acceptance: replay the store's exec/fork/exit into a live-process set and compare
      it with `ps -axo pid=,etime=` (run on macOS, or read from --ps-file). Exits 2 when a
      tracked process is missing from ps, or ps shows a process started during collection
      that was never seen starting.
  rules <lint|test> ...
      Not available before M6.
  events
      Print the eslogger event names Porchlight subscribes to, one per line.
";

/// Batch size for replay ingest. Matches the extension's XPC batch ceiling (SPEC §4.6).
const DEFAULT_BATCH: usize = 512;
/// Upper bound for `--batch`; one SQLite transaction per batch.
const MAX_BATCH: u64 = 65_536;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("plctl: {e}");
            ExitCode::from(1)
        }
    }
}

type CliResult = Result<ExitCode, Box<dyn std::error::Error>>;

fn run(args: &[String]) -> CliResult {
    let Some(command) = args.first() else {
        eprint!("{USAGE}");
        return Ok(ExitCode::from(2));
    };
    let rest = &args[1..];
    match command.as_str() {
        "replay" => replay(rest),
        "dump" => dump(rest),
        "verify-db" => verify_db(rest),
        "processes" => processes(rest),
        "record" => record(rest),
        "events" => {
            let mut out = io::stdout().lock();
            for name in ES_NOTIFY_EVENT_NAMES {
                writeln!(out, "{name}")?;
            }
            Ok(ExitCode::SUCCESS)
        }
        "rules" => {
            eprintln!("plctl rules: the rule engine lands in M6");
            Ok(ExitCode::from(2))
        }
        "-h" | "--help" | "help" => {
            print!("{USAGE}");
            Ok(ExitCode::SUCCESS)
        }
        other => Err(format!("unknown command {other:?}\n{USAGE}").into()),
    }
}

/// Minimal option parsing: `--key value` pairs, `--flag` booleans, bare positionals.
struct Opts {
    positional: Vec<String>,
    values: Vec<(String, String)>,
    flags: Vec<String>,
}

impl Opts {
    fn parse(args: &[String], value_keys: &[&str], flag_keys: &[&str]) -> Result<Self, String> {
        let mut opts = Opts {
            positional: vec![],
            values: vec![],
            flags: vec![],
        };
        let mut i = 0;
        while i < args.len() {
            let a = &args[i];
            if let Some(key) = a.strip_prefix("--") {
                if flag_keys.contains(&key) {
                    opts.flags.push(key.to_owned());
                    i += 1;
                } else if value_keys.contains(&key) {
                    let value = args
                        .get(i + 1)
                        .ok_or_else(|| format!("--{key} needs a value"))?;
                    opts.values.push((key.to_owned(), value.clone()));
                    i += 2;
                } else {
                    return Err(format!("unknown option --{key}"));
                }
            } else {
                opts.positional.push(a.clone());
                i += 1;
            }
        }
        Ok(opts)
    }

    fn value(&self, key: &str) -> Option<&str> {
        self.values
            .iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    fn flag(&self, key: &str) -> bool {
        self.flags.iter().any(|k| k == key)
    }

    fn u64_value(&self, key: &str) -> Result<Option<u64>, String> {
        self.value(key)
            .map(|v| v.parse::<u64>().map_err(|e| format!("--{key}: {e}")))
            .transpose()
    }
}

fn open_store(opts: &Opts) -> Result<EventStore, Box<dyn std::error::Error>> {
    Ok(match opts.value("db") {
        Some(path) => EventStore::open(Path::new(path))?,
        None => EventStore::open_in_memory()?,
    })
}

fn write_dump(
    store: &EventStore,
    from: u64,
    to: Option<u64>,
    out: &mut dyn Write,
) -> Result<u64, Box<dyn std::error::Error>> {
    let mut written = 0_u64;
    store.for_each_event(from, to, |event| {
        let line = event.to_json_line()?;
        out.write_all(line.as_bytes())?;
        out.write_all(b"\n")?;
        written += 1;
        Ok(())
    })?;
    out.flush()?;
    Ok(written)
}

fn print_stats(stats: &ReadStats, ingested: u64) {
    eprintln!(
        "replay: format={} lines={} events={} ingested={} filtered={} malformed={}",
        stats.format.map_or("unknown", |f| f.as_str()),
        stats.lines,
        stats.events,
        ingested,
        stats.filtered,
        stats.malformed
    );
    for (kind, n) in &stats.by_kind {
        eprintln!("  {kind}: {n}");
    }
    if !stats.unsupported.is_empty() {
        eprintln!("unsupported source events (adapter coverage gaps):");
        for (name, n) in &stats.unsupported {
            eprintln!("  {name}: {n}");
        }
    }
}

fn replay(args: &[String]) -> CliResult {
    let opts = Opts::parse(args, &["db", "dump", "batch"], &["strict"])?;
    let fixture = opts
        .positional
        .first()
        .ok_or("replay: missing fixture path")?;
    let batch_size = match opts.u64_value("batch")? {
        None => DEFAULT_BATCH,
        Some(n) if (1..=MAX_BATCH).contains(&n) => n as usize,
        Some(n) => return Err(format!("replay: --batch {n} is outside 1..={MAX_BATCH}").into()),
    };
    let store = open_store(&opts)?;
    let mut pipeline = Pipeline::new(store)?;
    let first_id_of_run = pipeline.next_id();
    let file = File::open(fixture).map_err(|e| format!("replay: open {fixture}: {e}"))?;
    let mut reader = NdjsonReader::new(BufReader::new(file));
    let mut batch = Vec::with_capacity(batch_size);
    let mut ingested = 0_u64;
    let mut errors = 0_u64;
    for item in reader.by_ref() {
        match item {
            Ok(event) => {
                batch.push(event);
                if batch.len() >= batch_size {
                    ingested += pipeline.ingest(std::mem::take(&mut batch))?.ingested;
                }
            }
            Err(e) => {
                errors += 1;
                if errors <= 20 {
                    eprintln!("replay: {e}");
                } else if errors == 21 {
                    eprintln!("replay: further malformed lines not shown");
                }
            }
        }
    }
    ingested += pipeline.ingest(batch)?.ingested;
    let stats = reader.stats().clone();
    print_stats(&stats, ingested);
    let store = pipeline.into_store();
    if let Some(path) = opts.value("dump") {
        let mut out = BufWriter::new(File::create(path)?);
        let n = write_dump(&store, first_id_of_run, None, &mut out)?;
        eprintln!("replay: wrote {n} events to {path}");
    }
    if opts.flag("strict") && stats.malformed > 0 {
        eprintln!("replay: --strict and {} malformed lines", stats.malformed);
        return Ok(ExitCode::from(2));
    }
    Ok(ExitCode::SUCCESS)
}

fn dump(args: &[String]) -> CliResult {
    let opts = Opts::parse(args, &["db", "from", "to", "out"], &[])?;
    let db = opts.value("db").ok_or("dump: --db is required")?;
    let store = EventStore::open_read_only(Path::new(db))?;
    let from = opts.u64_value("from")?.unwrap_or(1);
    let to = opts.u64_value("to")?;
    let n = match opts.value("out") {
        Some(path) => write_dump(&store, from, to, &mut BufWriter::new(File::create(path)?))?,
        None => write_dump(&store, from, to, &mut BufWriter::new(io::stdout().lock()))?,
    };
    eprintln!("dump: {n} events");
    Ok(ExitCode::SUCCESS)
}

fn verify_db(args: &[String]) -> CliResult {
    let opts = Opts::parse(args, &["db"], &[])?;
    let db = opts.value("db").ok_or("verify-db: --db is required")?;
    let store = EventStore::open_read_only(Path::new(db))?;
    let report = store.verify()?;
    println!(
        "schema_version={} events={} high_water={} integrity={}",
        report.schema_version, report.events, report.high_water, report.integrity
    );
    for p in &report.problems {
        println!("problem: {p}");
    }
    if report.is_ok() {
        println!("ok");
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(2))
    }
}

fn processes(args: &[String]) -> CliResult {
    use pl_core::live::{LiveProcesses, compare_with_ps, parse_ps};
    let opts = Opts::parse(args, &["db", "ps-file", "window-secs", "slack-secs"], &[])?;
    let db = opts.value("db").ok_or("processes: --db is required")?;
    let slack = opts.u64_value("slack-secs")?.unwrap_or(3);
    let store = EventStore::open_read_only(Path::new(db))?;
    // Only the latest collection session counts: Endpoint Security's global sequence restarts
    // with each client, so a backwards step marks a new session and resets the live set.
    let mut live = LiveProcesses::new();
    let mut first_wall: Option<i64> = None;
    let mut last_global: Option<u64> = None;
    let mut sessions = 1u64;
    store.for_each_event(1, None, |event| {
        let is_es_message = event.source == pl_core::schema::Source::EndpointSecurity
            && !matches!(event.kind, pl_core::schema::Kind::Drop { .. });
        let is_replayed = event.source == pl_core::schema::Source::Replay;
        if is_es_message || is_replayed {
            if last_global.is_some_and(|last| event.global_seq_num < last) {
                live = LiveProcesses::new();
                first_wall = None;
                sessions += 1;
            }
            last_global = Some(event.global_seq_num);
        }
        if event.wall_time.0 > 0 {
            first_wall.get_or_insert(event.wall_time.0);
        }
        live.apply(&event);
        Ok(())
    })?;
    let (ps_text, window) = match (opts.value("ps-file"), opts.u64_value("window-secs")?) {
        (Some(file), Some(window)) => (std::fs::read_to_string(file)?, window),
        (Some(_), None) => return Err("processes: --ps-file needs --window-secs".into()),
        (None, _) if cfg!(target_os = "macos") => {
            let out = std::process::Command::new("ps")
                .args(["-axo", "pid=,etime="])
                .output()?;
            if !out.status.success() {
                return Err("processes: ps failed".into());
            }
            let now_ns = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as i64)
                .unwrap_or(0);
            let window = first_wall.map_or(0, |w| {
                (now_ns.saturating_sub(w) / 1_000_000_000).max(0) as u64
            });
            (String::from_utf8_lossy(&out.stdout).into_owned(), window)
        }
        (None, _) => return Err("processes: off macOS, pass --ps-file and --window-secs".into()),
    };
    let (rows, bad) = parse_ps(&ps_text);
    if !bad.is_empty() {
        eprintln!("processes: ignored {} unparseable ps lines", bad.len());
    }
    let cmp = compare_with_ps(&live.pids(), &rows, window, slack);
    let report = serde_json::json!({
                "sessions_in_store": sessions,
        "window_secs": window,
        "slack_secs": slack,
        "live": live.stats(),
        "comparison": cmp,
        "agrees": cmp.agrees(),
    });
    println!("{report:#}");
    Ok(if cmp.agrees() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    })
}

/// The exact `eslogger` invocation `record` and `scripts/record-fixture.sh` use.
pub fn eslogger_command() -> Vec<String> {
    let mut cmd = vec!["eslogger".to_owned()];
    cmd.extend(ES_NOTIFY_EVENT_NAMES.iter().map(|s| (*s).to_owned()));
    cmd
}

fn record(args: &[String]) -> CliResult {
    let opts = Opts::parse(args, &["out", "duration"], &[])?;
    let out = PathBuf::from(opts.value("out").ok_or("record: --out is required")?);
    let duration = opts.u64_value("duration")?;
    let cmd = eslogger_command();
    if !cfg!(target_os = "macos") {
        eprintln!(
            "record: eslogger exists only on macOS. On a Mac with Full Disk Access granted to the terminal, run:"
        );
        eprintln!("  {} > {}", cmd.join(" "), out.display());
        return Ok(ExitCode::from(2));
    }
    record_macos(&cmd, &out, duration)
}

fn record_macos(cmd: &[String], out: &Path, duration: Option<u64>) -> CliResult {
    use std::process::{Command, Stdio};
    let file = File::create(out)?;
    let mut child = Command::new(&cmd[0])
        .args(&cmd[1..])
        .stdout(Stdio::from(file))
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("record: launch eslogger: {e}"))?;
    if let Some(secs) = duration {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
        loop {
            if let Some(status) = child.try_wait()? {
                eprintln!("record: eslogger exited early: {status}");
                return Ok(ExitCode::from(1));
            }
            if std::time::Instant::now() >= deadline {
                child.kill()?;
                let _ = child.wait()?;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    } else {
        let status = child.wait()?;
        if !status.success() {
            return Ok(ExitCode::from(1));
        }
    }
    let lines = BufReader::new(File::open(out)?).lines().count();
    eprintln!("record: {lines} lines in {}", out.display());
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opts_parse_values_flags_positionals() {
        let args: Vec<String> = ["f.ndjson", "--db", "x.db", "--strict", "--batch", "7"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        let o = Opts::parse(&args, &["db", "batch"], &["strict"]).unwrap();
        assert_eq!(o.positional, vec!["f.ndjson"]);
        assert_eq!(o.value("db"), Some("x.db"));
        assert!(o.flag("strict"));
        assert_eq!(o.u64_value("batch").unwrap(), Some(7));
        assert!(Opts::parse(&["--nope".to_owned()], &[], &[]).is_err());
        assert!(Opts::parse(&["--db".to_owned()], &["db"], &[]).is_err());
    }

    #[test]
    fn eslogger_command_is_the_full_notify_set() {
        let cmd = eslogger_command();
        assert_eq!(cmd[0], "eslogger");
        assert_eq!(cmd.len(), ES_NOTIFY_EVENT_NAMES.len() + 1);
        assert!(cmd.contains(&"exec".to_owned()));
        assert!(!cmd.contains(&"open".to_owned()));
    }
}
