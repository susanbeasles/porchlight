//! Safe wrapper over the C SPSC ring.

#![allow(unsafe_code)]

use std::ffi::c_void;
use std::ptr::NonNull;

use crate::raw::{PL_EV_SLOTS, PlRawEvent};

unsafe extern "C" {
    fn pl_ring_create(capacity: u32) -> *mut c_void;
    fn pl_ring_destroy(ring: *mut c_void);
    fn pl_ring_capacity(ring: *const c_void) -> u32;
    fn pl_ring_push(ring: *mut c_void, ev: *const PlRawEvent) -> bool;
    fn pl_ring_pop(ring: *mut c_void, out: *mut PlRawEvent, max: u32) -> u32;
    fn pl_ring_drop_counts(ring: *const c_void, out: *mut u64);
    fn pl_ring_producer_overlaps(ring: *const c_void) -> u64;
}

/// Owner of a C ring. The SPSC contract: exactly one thread produces (the ES handler, or
/// `push` in tests) and exactly one thread calls `pop`. The C side detects and refuses
/// overlapping producers.
pub struct Ring {
    ptr: NonNull<c_void>,
}

// SAFETY: the ring's shared state is C11 atomics; the slot memory is handed between one
// producer and one consumer through acquire/release on head and tail.
unsafe impl Send for Ring {}
// SAFETY: as above; concurrent `push` and `pop` from two threads is the designed use.
unsafe impl Sync for Ring {}

impl Ring {
    /// `capacity` must be a power of two of at least 2.
    pub fn new(capacity: u32) -> Option<Self> {
        // SAFETY: plain constructor; returns NULL on bad capacity or allocation failure.
        NonNull::new(unsafe { pl_ring_create(capacity) }).map(|ptr| Self { ptr })
    }

    /// The raw pointer handed to the ES shim, which produces into it.
    pub fn as_ptr(&self) -> *mut c_void {
        self.ptr.as_ptr()
    }

    pub fn capacity(&self) -> u32 {
        // SAFETY: `ptr` is a live ring for the lifetime of `self`.
        unsafe { pl_ring_capacity(self.ptr.as_ptr()) }
    }

    /// Copies one event in. Returns false, and counts a drop, when the ring is full.
    pub fn push(&self, ev: &PlRawEvent) -> bool {
        // SAFETY: `ptr` is live; `ev` is a valid record for the duration of the call.
        unsafe { pl_ring_push(self.ptr.as_ptr(), ev) }
    }

    /// Replaces `out`'s contents with up to `max` events. Returns how many.
    pub fn pop(&self, out: &mut Vec<PlRawEvent>, max: usize) -> usize {
        out.clear();
        out.reserve(max);
        let max32 = u32::try_from(max).unwrap_or(u32::MAX);
        // SAFETY: `out` has capacity for `max` records and the C side writes at most `max`.
        let n = unsafe { pl_ring_pop(self.ptr.as_ptr(), out.as_mut_ptr(), max32) } as usize;
        // SAFETY: the first `n` slots were initialized by memcpy of complete records, and
        // `PlRawEvent` is plain-old-data.
        unsafe { out.set_len(n) };
        n
    }

    pub fn drop_counts(&self) -> [u64; PL_EV_SLOTS] {
        let mut out = [0u64; PL_EV_SLOTS];
        // SAFETY: `out` holds exactly PL_EV_SLOTS entries, as the C side requires.
        unsafe { pl_ring_drop_counts(self.ptr.as_ptr(), out.as_mut_ptr()) };
        out
    }

    pub fn producer_overlaps(&self) -> u64 {
        // SAFETY: `ptr` is live.
        unsafe { pl_ring_producer_overlaps(self.ptr.as_ptr()) }
    }
}

impl Drop for Ring {
    fn drop(&mut self) {
        // SAFETY: `ptr` came from pl_ring_create and is destroyed exactly once.
        unsafe { pl_ring_destroy(self.ptr.as_ptr()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raw::{PL_EV_EXIT, PL_EV_FORK};
    use std::sync::Arc;

    fn ev(ty: u32, seq: u64) -> Box<PlRawEvent> {
        let mut e = PlRawEvent::zeroed_box();
        e.event_type = ty;
        e.seq_num = seq;
        e
    }

    #[test]
    fn rejects_bad_capacity() {
        assert!(Ring::new(0).is_none());
        assert!(Ring::new(3).is_none());
        assert_eq!(Ring::new(4).unwrap().capacity(), 4);
    }

    #[test]
    fn full_ring_counts_drops_per_type_and_recovers() {
        let ring = Ring::new(4).unwrap();
        for i in 0..4 {
            assert!(ring.push(&ev(PL_EV_EXIT, i)));
        }
        assert!(!ring.push(&ev(PL_EV_EXIT, 4)));
        assert!(!ring.push(&ev(PL_EV_FORK, 5)));
        assert!(!ring.push(&ev(99, 6)), "out-of-range types count in slot 0");
        let drops = ring.drop_counts();
        assert_eq!(
            (
                drops[0],
                drops[PL_EV_FORK as usize],
                drops[PL_EV_EXIT as usize]
            ),
            (1, 1, 1)
        );
        let mut out = Vec::new();
        assert_eq!(ring.pop(&mut out, 2), 2);
        assert_eq!(
            out.iter().map(|e| e.seq_num).collect::<Vec<_>>(),
            vec![0, 1]
        );
        assert!(ring.push(&ev(PL_EV_EXIT, 7)));
        assert_eq!(ring.pop(&mut out, 16), 3);
        assert_eq!(
            out.iter().map(|e| e.seq_num).collect::<Vec<_>>(),
            vec![2, 3, 7]
        );
        assert_eq!(ring.pop(&mut out, 16), 0);
        assert_eq!(ring.producer_overlaps(), 0);
    }

    #[test]
    fn spsc_under_contention_loses_nothing_it_does_not_count() {
        const N: u64 = 200_000;
        let ring = Arc::new(Ring::new(64).unwrap());
        let producer = {
            let ring = Arc::clone(&ring);
            std::thread::spawn(move || {
                let mut e = PlRawEvent::zeroed_box();
                e.event_type = PL_EV_EXIT;
                let mut accepted = 0u64;
                for seq in 0..N {
                    e.seq_num = seq;
                    if ring.push(&e) {
                        accepted += 1;
                    }
                }
                accepted
            })
        };
        let mut seen = Vec::with_capacity(N as usize);
        let mut out = Vec::new();
        loop {
            ring.pop(&mut out, 32);
            seen.extend(out.iter().map(|e| e.seq_num));
            if producer.is_finished() {
                while ring.pop(&mut out, 32) > 0 {
                    seen.extend(out.iter().map(|e| e.seq_num));
                }
                break;
            }
        }
        let accepted = producer.join().unwrap();
        let drops = ring.drop_counts()[PL_EV_EXIT as usize];
        assert_eq!(
            seen.len() as u64,
            accepted,
            "every accepted event is delivered once"
        );
        assert_eq!(
            accepted + drops,
            N,
            "every event is either delivered or counted"
        );
        assert!(seen.windows(2).all(|w| w[0] < w[1]), "order preserved");
    }
}
