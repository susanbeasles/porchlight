//! Timestamps. `MachTime` orders events; `WallTime` is for display (SPEC §3).
//!
//! Both serialize as plain integers. Wall-clock time is never a float or a formatted string
//! on the wire (C7). RFC 3339 parsing exists only for the `eslogger` adapter.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Nanoseconds in the `mach_continuous_time` domain. The ordering key.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct MachTime(pub u64);

/// Nanoseconds since the Unix epoch, UTC. Display only.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct WallTime(pub i64);

const NANOS_PER_SEC: i64 = 1_000_000_000;
const SECS_PER_DAY: i64 = 86_400;

impl WallTime {
    /// Parses an RFC 3339 timestamp such as `2026-10-15T02:33:44.123456789Z` or
    /// `2026-10-15T02:33:44+01:00`. Fractional seconds beyond nine digits are truncated.
    /// Returns `None` on any syntax or range error.
    pub fn from_rfc3339(s: &str) -> Option<Self> {
        let b = s.as_bytes();
        if b.len() < 20 {
            return None;
        }
        let num = |range: std::ops::Range<usize>| -> Option<i64> {
            let slice = b.get(range)?;
            if slice.is_empty() || !slice.iter().all(u8::is_ascii_digit) {
                return None;
            }
            std::str::from_utf8(slice).ok()?.parse::<i64>().ok()
        };
        let year = num(0..4)?;
        let month = num(5..7)?;
        let day = num(8..10)?;
        let hour = num(11..13)?;
        let minute = num(14..16)?;
        let second = num(17..19)?;
        if b[4] != b'-' || b[7] != b'-' || !matches!(b[10], b'T' | b't' | b' ') {
            return None;
        }
        if b[13] != b':' || b[16] != b':' {
            return None;
        }
        if !(1..=12).contains(&month)
            || !(1..=31).contains(&day)
            || !(0..=23).contains(&hour)
            || !(0..=59).contains(&minute)
            || !(0..=60).contains(&second)
        {
            return None;
        }
        let mut pos = 19;
        let mut nanos: i64 = 0;
        if b.get(pos) == Some(&b'.') {
            pos += 1;
            let start = pos;
            while pos < b.len() && b[pos].is_ascii_digit() {
                pos += 1;
            }
            if pos == start {
                return None;
            }
            let mut scale = 100_000_000;
            for &c in &b[start..pos] {
                if scale == 0 {
                    break;
                }
                nanos += i64::from(c - b'0') * scale;
                scale /= 10;
            }
        }
        let offset_secs: i64 = match b.get(pos) {
            Some(b'Z' | b'z') if pos + 1 == b.len() => 0,
            Some(sign @ (b'+' | b'-')) if pos + 6 == b.len() && b[pos + 3] == b':' => {
                let oh = num(pos + 1..pos + 3)?;
                let om = num(pos + 4..pos + 6)?;
                if oh > 23 || om > 59 {
                    return None;
                }
                let secs = oh * 3600 + om * 60;
                if *sign == b'+' { secs } else { -secs }
            }
            _ => return None,
        };
        let days = days_from_civil(year, month, day);
        let secs = days * SECS_PER_DAY + hour * 3600 + minute * 60 + second - offset_secs;
        Some(Self(secs.checked_mul(NANOS_PER_SEC)?.checked_add(nanos)?))
    }

    /// Formats as RFC 3339 in UTC with nine fractional digits.
    pub fn to_rfc3339(self) -> String {
        let secs = self.0.div_euclid(NANOS_PER_SEC);
        let nanos = self.0.rem_euclid(NANOS_PER_SEC);
        let days = secs.div_euclid(SECS_PER_DAY);
        let sod = secs.rem_euclid(SECS_PER_DAY);
        let (y, m, d) = civil_from_days(days);
        format!(
            "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{nanos:09}Z",
            sod / 3600,
            (sod % 3600) / 60,
            sod % 60
        )
    }
}

impl fmt::Display for WallTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_rfc3339())
    }
}

/// Days since 1970-01-01 for a proleptic Gregorian civil date.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Inverse of [`days_from_civil`].
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_round_trip() {
        let t = WallTime::from_rfc3339("1970-01-01T00:00:00Z").unwrap();
        assert_eq!(t.0, 0);
        assert_eq!(t.to_rfc3339(), "1970-01-01T00:00:00.000000000Z");
    }

    #[test]
    fn fraction_and_offset() {
        let t = WallTime::from_rfc3339("2026-10-15T02:33:44.123456789Z").unwrap();
        assert_eq!(t.to_rfc3339(), "2026-10-15T02:33:44.123456789Z");
        let plus = WallTime::from_rfc3339("2026-10-15T03:33:44.5+01:00").unwrap();
        assert_eq!(plus.to_rfc3339(), "2026-10-15T02:33:44.500000000Z");
        let minus = WallTime::from_rfc3339("2026-10-14T22:33:44-04:00").unwrap();
        assert_eq!(minus.to_rfc3339(), "2026-10-15T02:33:44.000000000Z");
    }

    #[test]
    fn truncates_beyond_nanos() {
        let t = WallTime::from_rfc3339("2000-02-29T12:00:00.1234567891234Z").unwrap();
        assert_eq!(t.to_rfc3339(), "2000-02-29T12:00:00.123456789Z");
    }

    #[test]
    fn rejects_garbage() {
        for s in [
            "",
            "2026-10-15",
            "2026-13-01T00:00:00Z",
            "2026-10-15T24:00:00Z",
            "2026-10-15T02:33:44",
            "2026-10-15T02:33:44+1:00",
            "x026-10-15T02:33:44Z",
        ] {
            assert!(WallTime::from_rfc3339(s).is_none(), "{s}");
        }
    }

    #[test]
    fn negative_times_format() {
        let t = WallTime(-1);
        assert_eq!(t.to_rfc3339(), "1969-12-31T23:59:59.999999999Z");
    }

    #[test]
    fn civil_round_trip_over_range() {
        for days in (-800_000..800_000).step_by(997) {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days);
        }
    }

    #[test]
    fn serializes_as_integer() {
        let json = serde_json::to_string(&WallTime(42)).unwrap();
        assert_eq!(json, "42");
        let json = serde_json::to_string(&MachTime(7)).unwrap();
        assert_eq!(json, "7");
    }
}
