/*
 * The only translation unit family that includes EndpointSecurity.h (SPEC §4.4).
 * Rust never sees an es_message_t.
 */
#ifndef PL_ES_SHIM_H
#define PL_ES_SHIM_H

#include <stddef.h>
#include <stdint.h>

#include "rawevent.h"

/* pl_es_start results; mirrored by pl_raw::protocol::EsState::from_shim. */
enum {
    PL_ES_OK = 0,
    PL_ES_NOT_ENTITLED = 1,
    PL_ES_NOT_PERMITTED = 2,
    PL_ES_NOT_PRIVILEGED = 3,
    PL_ES_TOO_MANY_CLIENTS = 4,
    PL_ES_INVALID_ARGUMENT = 5,
    PL_ES_INTERNAL = 6,
};

/* Creates the client, mutes this process, subscribes. `ring` is a pl_ring_t*. */
int pl_es_start(void *ring);
void pl_es_stop(void);
int pl_es_self_token(pl_token_t *out);
/* Messages es_mute_process refused (0 when self-muting worked). */
uint32_t pl_es_mute_failures(void);

/* Runs the copy self-test against hand-built messages. Returns failures; writes the first
 * failure's description into msg. macOS only; needs no entitlement. */
int pl_es_selftest(char *msg, size_t cap);

void pl_log_init(void);
/* level: 0 default, 1 error, 2 fault. Never called from the ES handler (C5). */
void pl_log(int level, const char *msg);

#endif
