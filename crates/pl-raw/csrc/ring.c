#include "ring.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#define PL_CACHE_LINE 128

struct pl_ring {
    _Alignas(PL_CACHE_LINE) _Atomic uint64_t tail; /* written by producer */
    _Alignas(PL_CACHE_LINE) _Atomic uint64_t head; /* written by consumer */
    _Alignas(PL_CACHE_LINE) atomic_bool producing;
    atomic_bool consuming;
    _Atomic uint64_t overlaps;
    _Atomic uint64_t consumer_overlaps;
    _Atomic uint64_t drops[PL_EV_SLOTS];
    uint32_t capacity;
    uint32_t mask;
    size_t bytes;
    pl_raw_event_t *slots;
};

pl_ring_t *pl_ring_create(uint32_t capacity) {
    if (capacity < 2 || (capacity & (capacity - 1)) != 0) {
        return NULL;
    }
    pl_ring_t *ring = calloc(1, sizeof(*ring));
    if (ring == NULL) {
        return NULL;
    }
    ring->bytes = (size_t)capacity * sizeof(pl_raw_event_t);
    void *mem = mmap(NULL, ring->bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (mem == MAP_FAILED) {
        free(ring);
        return NULL;
    }
    ring->slots = mem;
    ring->capacity = capacity;
    ring->mask = capacity - 1;
    atomic_init(&ring->tail, 0);
    atomic_init(&ring->head, 0);
    atomic_init(&ring->producing, false);
    atomic_init(&ring->consuming, false);
    atomic_init(&ring->overlaps, 0);
    atomic_init(&ring->consumer_overlaps, 0);
    for (size_t i = 0; i < PL_EV_SLOTS; i++) {
        atomic_init(&ring->drops[i], 0);
    }
    return ring;
}

void pl_ring_destroy(pl_ring_t *ring) {
    if (ring == NULL) {
        return;
    }
    munmap(ring->slots, ring->bytes);
    free(ring);
}

uint32_t pl_ring_capacity(const pl_ring_t *ring) {
    return ring->capacity;
}

static void count_drop(pl_ring_t *ring, uint32_t event_type) {
    uint32_t slot = event_type < PL_EV_SLOTS ? event_type : 0;
    atomic_fetch_add_explicit(&ring->drops[slot], 1, memory_order_relaxed);
}

pl_raw_event_t *pl_ring_reserve(pl_ring_t *ring, uint32_t event_type) {
    if (atomic_exchange_explicit(&ring->producing, true, memory_order_acquire)) {
        /* Another producer holds the reservation: SPSC contract violated. Refuse. */
        atomic_fetch_add_explicit(&ring->overlaps, 1, memory_order_relaxed);
        count_drop(ring, event_type);
        return NULL;
    }
    uint64_t tail = atomic_load_explicit(&ring->tail, memory_order_relaxed);
    uint64_t head = atomic_load_explicit(&ring->head, memory_order_acquire);
    if (tail - head >= ring->capacity) {
        atomic_store_explicit(&ring->producing, false, memory_order_release);
        count_drop(ring, event_type);
        return NULL;
    }
    return &ring->slots[tail & ring->mask];
}

void pl_ring_commit(pl_ring_t *ring) {
    uint64_t tail = atomic_load_explicit(&ring->tail, memory_order_relaxed);
    atomic_store_explicit(&ring->tail, tail + 1, memory_order_release);
    atomic_store_explicit(&ring->producing, false, memory_order_release);
}

bool pl_ring_push(pl_ring_t *ring, const pl_raw_event_t *ev) {
    pl_raw_event_t *slot = pl_ring_reserve(ring, ev->event_type);
    if (slot == NULL) {
        return false;
    }
    memcpy(slot, ev, sizeof(*slot));
    pl_ring_commit(ring);
    return true;
}

uint32_t pl_ring_pop(pl_ring_t *ring, pl_raw_event_t *out, uint32_t max) {
    if (atomic_exchange_explicit(&ring->consuming, true, memory_order_acquire)) {
        /* A second consumer: refuse rather than race on head. */
        atomic_fetch_add_explicit(&ring->consumer_overlaps, 1, memory_order_relaxed);
        return 0;
    }
    uint64_t head = atomic_load_explicit(&ring->head, memory_order_relaxed);
    uint64_t tail = atomic_load_explicit(&ring->tail, memory_order_acquire);
    uint64_t avail = tail - head;
    uint32_t n = avail < max ? (uint32_t)avail : max;
    for (uint32_t i = 0; i < n; i++) {
        memcpy(&out[i], &ring->slots[(head + i) & ring->mask], sizeof(pl_raw_event_t));
    }
    atomic_store_explicit(&ring->head, head + n, memory_order_release);
    atomic_store_explicit(&ring->consuming, false, memory_order_release);
    return n;
}

void pl_ring_drop_counts(const pl_ring_t *ring, uint64_t *out) {
    for (size_t i = 0; i < PL_EV_SLOTS; i++) {
        out[i] = atomic_load_explicit(&ring->drops[i], memory_order_relaxed);
    }
}

uint64_t pl_ring_producer_overlaps(const pl_ring_t *ring) {
    return atomic_load_explicit(&ring->overlaps, memory_order_relaxed);
}

uint64_t pl_ring_consumer_overlaps(const pl_ring_t *ring) {
    return atomic_load_explicit(&ring->consumer_overlaps, memory_order_relaxed);
}
