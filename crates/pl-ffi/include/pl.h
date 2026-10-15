/*
 * pl.h: the C ABI between the Swift container app and the Rust core (ADR-0001).
 * JSON in, JSON out. Every function is safe to call with a NULL handle (it fails).
 * Strings returned by the library are freed with pl_string_free.
 */
#ifndef PL_H
#define PL_H

#include <stddef.h>
#include <stdint.h>

typedef struct pl_app pl_app_t;

enum {
    PL_OK = 0,
    PL_ERR_UNSUPPORTED = -1, /* not available on this platform */
    PL_ERR_STATE = -2,       /* already connected, or no handle */
    PL_ERR_FAILED = -3,      /* see "last_error" in pl_app_stats_json */
};

/* Opens (or creates) the event store at db_path; NULL db_path means in memory. */
pl_app_t *pl_app_open(const char *db_path);

/* Connects to the extension's XPC service and starts streaming. Safe to call again
 * after the connection went away. */
int32_t pl_app_connect(pl_app_t *app);

/* Ingests a JSON array of events, exactly as a `batch` message carries them. */
int32_t pl_app_ingest_json(pl_app_t *app, const uint8_t *json, size_t len);

/* Current state as JSON: connection, extension status, counts, live processes, drops. */
char *pl_app_stats_json(pl_app_t *app);

void pl_string_free(char *s);
void pl_app_close(pl_app_t *app);

#endif
