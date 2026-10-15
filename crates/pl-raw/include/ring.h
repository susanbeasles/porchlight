/*
 * Single-producer single-consumer ring of pl_raw_event_t (SPEC §4.6).
 *
 * Producer: the ES handler. reserve() returns a slot to fill in place, or NULL when the
 * ring is full, in which case a per-type drop counter is incremented. The handler never
 * blocks and never allocates. commit() publishes the slot.
 *
 * Consumer: the bridge thread. pop() copies up to `max` events out. A concurrent second
 * consumer is refused (returns 0) and counted, so misuse cannot race on the head index.
 *
 * SPEC §12 asks whether the ES handler can run concurrently for one client. If it ever
 * does, reserve() detects the overlap, refuses the second producer, and counts it in
 * pl_ring_producer_overlaps() and the drop counters, so the answer is measured, not assumed.
 */
#ifndef PORCHLIGHT_RING_H
#define PORCHLIGHT_RING_H

#include <stdbool.h>
#include <stdint.h>

#include "rawevent.h"

typedef struct pl_ring pl_ring_t;

/* capacity must be a power of two >= 2. Slots are mmap'd once; pages are touched on use. */
pl_ring_t *pl_ring_create(uint32_t capacity);
void pl_ring_destroy(pl_ring_t *ring);
uint32_t pl_ring_capacity(const pl_ring_t *ring);

pl_raw_event_t *pl_ring_reserve(pl_ring_t *ring, uint32_t event_type);
void pl_ring_commit(pl_ring_t *ring);
/* reserve + memcpy + commit. Returns false (and counts a drop) when full. */
bool pl_ring_push(pl_ring_t *ring, const pl_raw_event_t *ev);

uint32_t pl_ring_pop(pl_ring_t *ring, pl_raw_event_t *out, uint32_t max);

/* Monotonic per-type drop counters; out must hold PL_EV_SLOTS entries. */
void pl_ring_drop_counts(const pl_ring_t *ring, uint64_t *out);
uint64_t pl_ring_producer_overlaps(const pl_ring_t *ring);
uint64_t pl_ring_consumer_overlaps(const pl_ring_t *ring);

#endif
