#include "rawevent.h"

size_t pl_raw_layout(size_t *out, size_t cap) {
    const size_t v[] = {
        sizeof(pl_raw_event_t),
        sizeof(pl_process_t),
        sizeof(pl_exec_t),
        offsetof(pl_raw_event_t, mach_time),
        offsetof(pl_raw_event_t, wall_nsec),
        offsetof(pl_raw_event_t, process),
        offsetof(pl_raw_event_t, u),
        offsetof(pl_process_t, start_sec),
        offsetof(pl_process_t, cdhash),
        offsetof(pl_process_t, path),
        offsetof(pl_process_t, tty),
        offsetof(pl_exec_t, argc),
        offsetof(pl_exec_t, flags),
        offsetof(pl_exec_t, cwd),
        offsetof(pl_exec_t, buf),
    };
    size_t n = sizeof(v) / sizeof(v[0]);
    for (size_t i = 0; i < n && i < cap; i++) {
        out[i] = v[i];
    }
    return n;
}
