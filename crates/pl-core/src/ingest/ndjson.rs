//! Line reader over NDJSON fixtures with format detection and coverage statistics.

use std::collections::BTreeMap;
use std::fmt;
use std::io::BufRead;

use serde_json::Value;

use super::eslogger;
use crate::schema::{Event, Kind, SCHEMA_VERSION};

/// Which NDJSON dialect a fixture is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Output of Apple's `eslogger`.
    Eslogger,
    /// Porchlight's own `Event` JSON, as written by `plctl dump`.
    Porchlight,
}

impl Format {
    pub fn as_str(self) -> &'static str {
        match self {
            Format::Eslogger => "eslogger",
            Format::Porchlight => "porchlight",
        }
    }
}

/// A line that could not be turned into an event. Never silently skipped (C6 in spirit).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineError {
    pub line: u64,
    pub reason: String,
}

impl fmt::Display for LineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.reason)
    }
}

impl std::error::Error for LineError {}

/// Coverage statistics for one read. All maps are ordered (C7).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ReadStats {
    pub format: Option<Format>,
    /// Non-empty lines seen.
    pub lines: u64,
    /// Events produced.
    pub events: u64,
    /// Lines the adapter deliberately dropped, such as unmodified `close`.
    pub filtered: u64,
    /// Lines that failed to parse.
    pub malformed: u64,
    pub by_kind: BTreeMap<String, u64>,
    /// Raw source event names that mapped to `Kind::Unsupported`.
    pub unsupported: BTreeMap<String, u64>,
}

/// Decides the dialect from one line. Errors describe why neither shape matched.
pub fn detect_format(line: &str) -> Result<Format, String> {
    let value: Value = serde_json::from_str(line).map_err(|e| format!("not JSON: {e}"))?;
    let obj = value
        .as_object()
        .ok_or_else(|| "not a JSON object".to_owned())?;
    if obj.contains_key("kind") && obj.contains_key("source") && obj.contains_key("process") {
        Ok(Format::Porchlight)
    } else if obj.contains_key("event") && obj.contains_key("process") {
        Ok(Format::Eslogger)
    } else {
        Err(
            "unrecognized line: expected eslogger keys (event, process) or porchlight keys \
             (kind, source, process)"
                .to_owned(),
        )
    }
}

/// Parses one line in the given dialect. `Ok(None)` means the line was filtered on purpose.
pub fn parse_line(format: Format, line: &str) -> Result<Option<Event>, String> {
    match format {
        Format::Porchlight => {
            let event = serde_json::from_str::<Event>(line)
                .map_err(|e| format!("porchlight event: {e}"))?;
            if event.schema_version != SCHEMA_VERSION {
                return Err(format!(
                    "porchlight event schema_version {} (this build reads {SCHEMA_VERSION})",
                    event.schema_version
                ));
            }
            Ok(Some(event))
        }
        Format::Eslogger => eslogger::parse_line(line),
    }
}

/// Iterator of events over a buffered reader. Blank lines are ignored. The first non-empty
/// line fixes the format unless one was given.
pub struct NdjsonReader<R> {
    inner: R,
    line_no: u64,
    format: Option<Format>,
    stats: ReadStats,
    buf: String,
    /// Set after an I/O error. A failing reader is not retried; iteration ends.
    done: bool,
}

impl<R: BufRead> NdjsonReader<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            line_no: 0,
            format: None,
            stats: ReadStats::default(),
            buf: String::new(),
            done: false,
        }
    }

    pub fn with_format(inner: R, format: Format) -> Self {
        let mut reader = Self::new(inner);
        reader.format = Some(format);
        reader.stats.format = Some(format);
        reader
    }

    pub fn stats(&self) -> &ReadStats {
        &self.stats
    }

    pub fn format(&self) -> Option<Format> {
        self.format
    }

    fn record(&mut self, event: &Event) {
        self.stats.events += 1;
        *self
            .stats
            .by_kind
            .entry(event.kind.discriminator().to_owned())
            .or_insert(0) += 1;
        if let Kind::Unsupported { name } = &event.kind {
            *self.stats.unsupported.entry(name.clone()).or_insert(0) += 1;
        }
    }
}

impl<R: BufRead> Iterator for NdjsonReader<R> {
    type Item = Result<Event, LineError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        loop {
            self.buf.clear();
            match self.inner.read_line(&mut self.buf) {
                Ok(0) => return None,
                Ok(_) => {}
                Err(e) => {
                    self.done = true;
                    self.line_no += 1;
                    self.stats.malformed += 1;
                    return Some(Err(LineError {
                        line: self.line_no,
                        reason: format!("read error: {e}"),
                    }));
                }
            }
            self.line_no += 1;
            let line = self.buf.trim();
            if line.is_empty() {
                continue;
            }
            self.stats.lines += 1;
            let format = match self.format {
                Some(f) => f,
                None => match detect_format(line) {
                    Ok(f) => {
                        self.format = Some(f);
                        self.stats.format = Some(f);
                        f
                    }
                    Err(reason) => {
                        self.stats.malformed += 1;
                        return Some(Err(LineError {
                            line: self.line_no,
                            reason,
                        }));
                    }
                },
            };
            match parse_line(format, line) {
                Ok(Some(event)) => {
                    self.record(&event);
                    return Some(Ok(event));
                }
                Ok(None) => {
                    self.stats.filtered += 1;
                }
                Err(reason) => {
                    self.stats.malformed += 1;
                    return Some(Err(LineError {
                        line: self.line_no,
                        reason,
                    }));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::kind::samples;
    use crate::schema::{MachTime, SCHEMA_VERSION, Source, WallTime};
    use std::io::Cursor;

    fn porchlight_line(id: u64, kind: Kind) -> String {
        Event {
            schema_version: SCHEMA_VERSION,
            id,
            mach_time: MachTime(id),
            wall_time: WallTime(0),
            seq_num: id,
            global_seq_num: id,
            source: Source::Synthetic,
            process: samples::process(1, "/x"),
            kind,
        }
        .to_json_line()
        .unwrap()
    }

    #[test]
    fn detects_porchlight_and_eslogger() {
        let pl = porchlight_line(1, Kind::Exit { status: 0 });
        assert_eq!(detect_format(&pl).unwrap(), Format::Porchlight);
        let es = r#"{"event":{"exit":{"stat":0}},"process":{}}"#;
        assert_eq!(detect_format(es).unwrap(), Format::Eslogger);
        assert!(detect_format(r#"{"a":1}"#).is_err());
        assert!(detect_format("[]").is_err());
        assert!(detect_format("nope").is_err());
    }

    #[test]
    fn reads_porchlight_lines_and_counts() {
        let input = format!(
            "{}\n\n{}\nnot json\n{}\n",
            porchlight_line(1, Kind::Exit { status: 0 }),
            porchlight_line(
                2,
                Kind::Fork {
                    child: samples::token(3)
                }
            ),
            porchlight_line(
                3,
                Kind::Unsupported {
                    name: "x".to_owned()
                }
            ),
        );
        let mut reader = NdjsonReader::new(Cursor::new(input));
        let mut ok = 0;
        let mut errs = vec![];
        for item in reader.by_ref() {
            match item {
                Ok(_) => ok += 1,
                Err(e) => errs.push(e),
            }
        }
        assert_eq!(ok, 3);
        assert_eq!(errs.len(), 1);
        assert_eq!(errs[0].line, 4);
        let stats = reader.stats();
        assert_eq!(stats.format, Some(Format::Porchlight));
        assert_eq!(stats.lines, 4);
        assert_eq!(stats.events, 3);
        assert_eq!(stats.malformed, 1);
        assert_eq!(stats.by_kind.get("exit"), Some(&1));
        assert_eq!(stats.unsupported.get("x"), Some(&1));
    }

    #[test]
    fn rejects_other_schema_versions() {
        let line = porchlight_line(1, Kind::Exit { status: 0 }).replacen(
            r#""schema_version":1"#,
            r#""schema_version":99"#,
            1,
        );
        let err = parse_line(Format::Porchlight, &line).unwrap_err();
        assert!(err.contains("schema_version 99"), "{err}");
    }

    #[test]
    fn rejects_unknown_fields() {
        let line = porchlight_line(1, Kind::Exit { status: 0 }).replacen(
            r#""id":1,"#,
            r#""id":1,"surprise":true,"#,
            1,
        );
        assert!(parse_line(Format::Porchlight, &line).is_err());
    }

    #[test]
    fn read_error_ends_iteration() {
        struct Failing;
        impl std::io::Read for Failing {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("EIO"))
            }
        }
        let mut reader = NdjsonReader::new(std::io::BufReader::new(Failing));
        assert!(reader.next().unwrap().is_err());
        assert!(
            reader.next().is_none(),
            "a failing reader must not be retried forever"
        );
    }

    #[test]
    fn first_line_fixes_the_format() {
        let input = format!(
            "{}\n{}\n",
            porchlight_line(1, Kind::Exit { status: 0 }),
            r#"{"event":{"exit":{"stat":0}},"process":{}}"#,
        );
        let mut reader = NdjsonReader::new(Cursor::new(input));
        assert!(reader.next().unwrap().is_ok());
        let second = reader.next().unwrap();
        assert!(
            second.is_err(),
            "an eslogger line inside a porchlight file is malformed"
        );
    }
}
