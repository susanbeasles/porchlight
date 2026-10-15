//! Consumer-side logic of the extension (SPEC §4.6, §4.7), free of I/O and of the clock so
//! it is deterministic under test. The extension's bridge thread drives it:
//!
//! ```text
//! loop { ring.pop -> Bridge::accept(raws, ring.drop_counts, now)
//!        for batch in Bridge::take_ready(now) { Outbox::offer(batch) -> send or queue } }
//! ```
//!
//! Drop accounting: an event the ring refused still consumed an ES sequence number, so it
//! shows up twice: once as a `ring_full` drop (exact, from the ring counters) and once inside
//! a `sequence_gap` drop for that type. Consumers must not sum across reasons; the gap count
//! is the total loss for a type, `ring_full` says how much of it was ours. See docs/schema.md.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use pl_core::schema::{
    DropReason, Event, Kind, MachTime, ProcessIdentity, SCHEMA_VERSION, Source, WallTime,
};
use serde::{Deserialize, Serialize};

use crate::decode::{decode, event_type_name, is_truncated};
use crate::raw::{PL_EV_SLOTS, PlRawEvent};

/// Largest XPC batch (SPEC §4.6).
pub const MAX_BATCH: usize = 512;
/// Longest a partial batch waits (SPEC §4.6).
pub const BATCH_INTERVAL: Duration = Duration::from_millis(250);
/// Events held while the app is not connected (SPEC §4.7).
pub const OVERFLOW_CAP: usize = 10_000;

/// Per-type expected next `seq_num`.
#[derive(Debug, Clone)]
pub struct SeqTracker {
    expected: [Option<u64>; PL_EV_SLOTS],
}

impl Default for SeqTracker {
    fn default() -> Self {
        Self {
            expected: [None; PL_EV_SLOTS],
        }
    }
}

impl SeqTracker {
    /// Records `seq` for `event_type`. Returns `(expected, got)` when messages were skipped.
    /// A sequence that goes backwards (client restart) resets the expectation silently.
    pub fn observe(&mut self, event_type: u32, seq: u64) -> Option<(u64, u64)> {
        let slot = self.expected.get_mut(event_type as usize)?;
        let gap = match *slot {
            Some(expected) if seq > expected => Some((expected, seq)),
            _ => None,
        };
        *slot = Some(seq.saturating_add(1));
        gap
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeStats {
    pub raw_events: u64,
    pub events: u64,
    pub decode_errors: u64,
    pub truncated: u64,
    pub sequence_gaps: u64,
    pub sequence_gap_messages: u64,
    pub ring_drops: u64,
    pub disconnected_drops: u64,
    pub batches: u64,
}

/// Builds a `drop` event attributed to the extension itself.
pub fn drop_event(
    identity: &ProcessIdentity,
    event_type: &str,
    expected_seq: u64,
    got_seq: u64,
    count: u64,
    reason: DropReason,
    at: (MachTime, WallTime),
) -> Event {
    Event {
        schema_version: SCHEMA_VERSION,
        id: 0,
        mach_time: at.0,
        wall_time: at.1,
        seq_num: 0,
        global_seq_num: 0,
        source: Source::EndpointSecurity,
        process: identity.clone(),
        kind: Kind::Drop {
            event_type: event_type.to_owned(),
            expected_seq,
            got_seq,
            count,
            reason,
        },
    }
}

pub struct Bridge {
    identity: ProcessIdentity,
    seq: SeqTracker,
    last_ring_drops: [u64; PL_EV_SLOTS],
    last_at: (MachTime, WallTime),
    pending: Vec<Event>,
    pending_since: Option<Instant>,
    stats: BridgeStats,
}

impl Bridge {
    /// `identity` is the extension's own process identity, used on `drop` events.
    pub fn new(identity: ProcessIdentity) -> Self {
        Self {
            identity,
            seq: SeqTracker::default(),
            last_ring_drops: [0; PL_EV_SLOTS],
            last_at: (MachTime(0), WallTime(0)),
            pending: Vec::new(),
            pending_since: None,
            stats: BridgeStats::default(),
        }
    }

    pub fn stats(&self) -> &BridgeStats {
        &self.stats
    }

    pub fn identity(&self) -> &ProcessIdentity {
        &self.identity
    }

    fn push(&mut self, event: Event, now: Instant) {
        self.pending.push(event);
        self.pending_since.get_or_insert(now);
    }

    /// Converts a drained slice of raw events and folds in the ring's drop counters.
    pub fn accept(&mut self, raws: &[PlRawEvent], ring_drops: &[u64; PL_EV_SLOTS], now: Instant) {
        for raw in raws {
            self.stats.raw_events += 1;
            // Every timestamp on a drop event comes from a real message, never a default.
            self.last_at = (
                MachTime(raw.mach_time),
                WallTime(
                    raw.wall_sec
                        .saturating_mul(1_000_000_000)
                        .saturating_add(raw.wall_nsec),
                ),
            );
            if let Some((expected, got)) = self.seq.observe(raw.event_type, raw.seq_num) {
                self.stats.sequence_gaps += 1;
                self.stats.sequence_gap_messages += got - expected;
                let at = self.last_at;
                let ev = drop_event(
                    &self.identity,
                    event_type_name(raw.event_type),
                    expected,
                    got,
                    got - expected,
                    DropReason::SequenceGap,
                    at,
                );
                self.push(ev, now);
            }
            if is_truncated(raw) {
                self.stats.truncated += 1;
            }
            match decode(raw) {
                Ok(ev) => {
                    self.stats.events += 1;
                    self.push(ev, now);
                }
                Err(_) => self.stats.decode_errors += 1,
            }
        }
        // Until a first message has been seen there is no honest timestamp; the counters are
        // monotonic, so deferring loses nothing.
        let have_time = self.last_at.1 != WallTime(0);
        for (ty, &now_count) in ring_drops.iter().enumerate() {
            let last = self.last_ring_drops[ty];
            if have_time && now_count > last {
                let delta = now_count - last;
                self.last_ring_drops[ty] = now_count;
                self.stats.ring_drops += delta;
                let name = event_type_name(ty as u32);
                let ev = drop_event(
                    &self.identity,
                    name,
                    0,
                    0,
                    delta,
                    DropReason::RingFull,
                    self.last_at,
                );
                self.push(ev, now);
            }
        }
    }

    /// Full batches, plus the partial batch once it has waited `BATCH_INTERVAL`.
    pub fn take_ready(&mut self, now: Instant) -> Vec<Vec<Event>> {
        let due = self
            .pending_since
            .is_some_and(|since| now.saturating_duration_since(since) >= BATCH_INTERVAL);
        let mut out = Vec::new();
        while self.pending.len() >= MAX_BATCH {
            let rest = self.pending.split_off(MAX_BATCH);
            out.push(std::mem::replace(&mut self.pending, rest));
        }
        if due && !self.pending.is_empty() {
            out.push(std::mem::take(&mut self.pending));
        }
        if self.pending.is_empty() {
            self.pending_since = None;
        } else if !out.is_empty() && due {
            self.pending_since = Some(now);
        }
        self.stats.batches += out.len() as u64;
        out
    }

    /// Everything pending, in batches, regardless of age (shutdown flush, SPEC §4.1).
    pub fn take_all(&mut self) -> Vec<Vec<Event>> {
        let mut out = Vec::new();
        let mut all = std::mem::take(&mut self.pending);
        while !all.is_empty() {
            let rest = all.split_off(all.len().min(MAX_BATCH));
            out.push(std::mem::replace(&mut all, rest));
        }
        self.pending_since = None;
        self.stats.batches += out.len() as u64;
        out
    }
}

/// Holds batches while no app is connected; drops oldest past `OVERFLOW_CAP` (SPEC §4.7).
pub struct Outbox {
    identity: ProcessIdentity,
    connected: bool,
    queue: VecDeque<Event>,
    dropped: u64,
    dropped_total: u64,
    last_at: (MachTime, WallTime),
}

impl Outbox {
    pub fn new(identity: ProcessIdentity) -> Self {
        Self {
            identity,
            connected: false,
            queue: VecDeque::new(),
            dropped: 0,
            dropped_total: 0,
            last_at: (MachTime(0), WallTime(0)),
        }
    }

    pub fn is_connected(&self) -> bool {
        self.connected
    }

    pub fn queued(&self) -> usize {
        self.queue.len()
    }

    pub fn dropped_total(&self) -> u64 {
        self.dropped_total
    }

    /// Returns the batch to send now, or queues it when disconnected.
    pub fn offer(&mut self, batch: Vec<Event>) -> Option<Vec<Event>> {
        if let Some(last) = batch.last() {
            self.last_at = (last.mach_time, last.wall_time);
        }
        if self.connected && self.queue.is_empty() && self.dropped == 0 {
            return Some(batch);
        }
        for ev in batch {
            if self.queue.len() >= OVERFLOW_CAP {
                self.queue.pop_front();
                self.dropped += 1;
                self.dropped_total += 1;
            }
            self.queue.push_back(ev);
        }
        None
    }

    pub fn set_connected(&mut self, connected: bool) {
        self.connected = connected;
    }

    /// When connected: the `app_disconnected` drop event if any were lost, then the queue,
    /// in batches of at most `MAX_BATCH`.
    pub fn drain(&mut self) -> Vec<Vec<Event>> {
        if !self.connected {
            return Vec::new();
        }
        let mut events: Vec<Event> = Vec::with_capacity(self.queue.len() + 1);
        if self.dropped > 0 {
            events.push(drop_event(
                &self.identity,
                "all",
                0,
                0,
                self.dropped,
                DropReason::AppDisconnected,
                self.last_at,
            ));
            self.dropped = 0;
        }
        events.extend(self.queue.drain(..));
        let mut out = Vec::new();
        while !events.is_empty() {
            let rest = events.split_off(events.len().min(MAX_BATCH));
            out.push(std::mem::replace(&mut events, rest));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::testing::{exec, raw};
    use crate::raw::{PL_EV_EXIT, PL_EV_FORK};
    use pl_core::schema::AuditToken;

    fn me() -> ProcessIdentity {
        ProcessIdentity {
            token: AuditToken {
                pid: 99,
                pidversion: 1,
                ..Default::default()
            },
            parent_token: AuditToken::default(),
            responsible_token: None,
            executable_path: "/Library/SystemExtensions/x/dev.susanb.porchlight.extension"
                .to_owned(),
            signing_id: Some("dev.susanb.porchlight.extension".to_owned()),
            team_id: Some("2VB7966G7R".to_owned()),
            cdhash: String::new(),
            is_platform_binary: false,
            is_es_client: true,
            tty: None,
            session_id: 0,
            start_time: WallTime(0),
        }
    }

    fn kinds(batch: &[Event]) -> Vec<&'static str> {
        batch.iter().map(|e| e.kind.discriminator()).collect()
    }

    #[test]
    fn seq_tracker_reports_gaps_per_type_and_resets_backwards() {
        let mut s = SeqTracker::default();
        assert_eq!(s.observe(PL_EV_EXIT, 0), None);
        assert_eq!(s.observe(PL_EV_EXIT, 1), None);
        assert_eq!(
            s.observe(PL_EV_FORK, 7),
            None,
            "first sighting of a type is not a gap"
        );
        assert_eq!(s.observe(PL_EV_EXIT, 4), Some((2, 4)));
        assert_eq!(s.observe(PL_EV_EXIT, 0), None, "restart resets");
        assert_eq!(s.observe(PL_EV_EXIT, 1), None);
        assert_eq!(s.observe(999, 5), None, "out-of-range types are ignored");
    }

    #[test]
    fn gaps_and_ring_drops_become_drop_events_in_order() {
        let t0 = Instant::now();
        let mut b = Bridge::new(me());
        let raws = [
            *raw(PL_EV_EXIT, 0),
            *raw(PL_EV_EXIT, 3),
            *raw(PL_EV_FORK, 0),
        ];
        let mut ring = [0u64; PL_EV_SLOTS];
        ring[PL_EV_EXIT as usize] = 2;
        b.accept(&raws, &ring, t0);
        let batches = b.take_ready(t0 + BATCH_INTERVAL);
        assert_eq!(batches.len(), 1);
        assert_eq!(
            kinds(&batches[0]),
            vec!["exit", "drop", "exit", "fork", "drop"]
        );
        match &batches[0][1].kind {
            Kind::Drop {
                event_type,
                expected_seq,
                got_seq,
                count,
                reason,
            } => {
                assert_eq!(
                    (event_type.as_str(), *expected_seq, *got_seq, *count),
                    ("exit", 1, 3, 2)
                );
                assert_eq!(*reason, DropReason::SequenceGap);
            }
            other => panic!("{other:?}"),
        }
        match &batches[0][4].kind {
            Kind::Drop {
                event_type,
                count,
                reason,
                ..
            } => {
                assert_eq!(
                    (event_type.as_str(), *count, *reason),
                    ("exit", 2, DropReason::RingFull)
                );
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            batches[0][1].process.token.key(),
            "99:1",
            "drops are attributed to the extension"
        );
        // The same counter value again is not a new drop.
        b.accept(&[], &ring, t0);
        assert!(b.take_ready(t0 + BATCH_INTERVAL * 2).is_empty());
        let s = b.stats();
        assert_eq!(
            (
                s.raw_events,
                s.events,
                s.sequence_gaps,
                s.sequence_gap_messages,
                s.ring_drops
            ),
            (3, 3, 1, 2, 2)
        );
    }

    #[test]
    fn ring_drops_wait_for_a_real_timestamp() {
        let t0 = Instant::now();
        let mut b = Bridge::new(me());
        let mut ring = [0u64; PL_EV_SLOTS];
        ring[PL_EV_EXIT as usize] = 3;
        b.accept(&[], &ring, t0);
        assert!(
            b.take_all().is_empty(),
            "no message yet: no timestamp to give the drop"
        );
        b.accept(&[*raw(PL_EV_EXIT, 0)], &ring, t0);
        let all: Vec<Event> = b.take_all().into_iter().flatten().collect();
        assert_eq!(kinds(&all), vec!["exit", "drop"]);
        assert_eq!(all[1].wall_time, WallTime(1_760_000_100_000_000_005));
        assert_eq!(all[1].mach_time, MachTime(1000));
    }

    #[test]
    fn gap_drop_takes_its_times_from_the_message_even_if_decode_fails() {
        let t0 = Instant::now();
        let mut b = Bridge::new(me());
        let mut first = raw(PL_EV_EXIT, 0);
        first.version = 99; // undecodable
        let mut second = raw(PL_EV_EXIT, 5);
        second.version = 99;
        b.accept(&[*first, *second], &[0; PL_EV_SLOTS], t0);
        let all: Vec<Event> = b.take_all().into_iter().flatten().collect();
        assert_eq!(kinds(&all), vec!["drop"]);
        assert_eq!(all[0].mach_time, MachTime(1005));
        assert_ne!(all[0].wall_time, WallTime(0));
    }

    #[test]
    fn batches_by_size_then_by_age() {
        let t0 = Instant::now();
        let mut b = Bridge::new(me());
        let raws: Vec<PlRawEvent> = (0..(MAX_BATCH as u64 + 10))
            .map(|i| *raw(PL_EV_EXIT, i))
            .collect();
        b.accept(&raws, &[0; PL_EV_SLOTS], t0);
        let first = b.take_ready(t0);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].len(), MAX_BATCH);
        assert!(
            b.take_ready(t0 + BATCH_INTERVAL / 2).is_empty(),
            "partial batch waits"
        );
        let second = b.take_ready(t0 + BATCH_INTERVAL);
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].len(), 10);
        assert!(b.take_ready(t0 + BATCH_INTERVAL * 10).is_empty());
    }

    #[test]
    fn decode_errors_are_counted_not_forwarded() {
        let t0 = Instant::now();
        let mut b = Bridge::new(me());
        let mut bad = raw(PL_EV_EXIT, 0);
        bad.version = 9;
        let good = exec(1, &["ls"], &[]);
        b.accept(&[*bad, *good], &[0; PL_EV_SLOTS], t0);
        let all = b.take_all();
        assert_eq!(kinds(&all[0]), vec!["exec"]);
        assert_eq!(b.stats().decode_errors, 1);
    }

    fn batch_of(n: u64) -> Vec<Event> {
        let t0 = Instant::now();
        let mut b = Bridge::new(me());
        let raws: Vec<PlRawEvent> = (0..n).map(|i| *raw(PL_EV_EXIT, i)).collect();
        b.accept(&raws, &[0; PL_EV_SLOTS], t0);
        b.take_all().into_iter().flatten().collect()
    }

    #[test]
    fn outbox_passes_through_when_connected() {
        let mut o = Outbox::new(me());
        o.set_connected(true);
        assert_eq!(o.offer(batch_of(3)).map(|b| b.len()), Some(3));
        assert_eq!(o.queued(), 0);
    }

    #[test]
    fn outbox_queues_drops_oldest_and_reports_on_reconnect() {
        let mut o = Outbox::new(me());
        for _ in 0..21 {
            assert!(o.offer(batch_of(500)).is_none());
        }
        assert_eq!(o.queued(), OVERFLOW_CAP);
        assert_eq!(o.dropped_total(), 500);
        assert!(o.drain().is_empty(), "nothing drains while disconnected");
        o.set_connected(true);
        let batches = o.drain();
        let flat: Vec<&Event> = batches.iter().flatten().collect();
        assert!(batches.iter().all(|b| b.len() <= MAX_BATCH));
        assert_eq!(flat.len(), OVERFLOW_CAP + 1);
        match &flat[0].kind {
            Kind::Drop { count, reason, .. } => {
                assert_eq!((*count, *reason), (500, DropReason::AppDisconnected))
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(o.queued(), 0);
        assert_eq!(
            o.offer(batch_of(1)).map(|b| b.len()),
            Some(1),
            "back to pass-through"
        );
    }
}
