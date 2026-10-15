/*
 * Minimal libxpc shim (SPEC §4.7, ADR-0001). Only the calls that take blocks live in C;
 * everything else is plain dictionary plumbing so Rust never touches an xpc_object_t.
 *
 * Ownership: a connection handed to Rust as "connected" (listener peers) or returned by
 * pl_xpc_connect carries one retain owned by Rust, released with pl_xpc_release. Handles
 * passed to callbacks with any other state are borrowed and valid only for the callback.
 * Messages are borrowed and valid only for the callback.
 */
#ifndef PL_XPC_SHIM_H
#define PL_XPC_SHIM_H

#include <stddef.h>
#include <stdint.h>

enum {
    PL_XPC_PEER_CONNECTED = 1,   /* listener: new peer passed the requirement (owned +1) */
    PL_XPC_PEER_INTERRUPTED = 0, /* remote end restarted; connection still usable */
    PL_XPC_PEER_INVALID = -1,    /* gone for good, or failed the code-signing requirement */
};

typedef void (*pl_xpc_msg_fn)(void *ctx, void *conn, const char *op, int64_t version, void *msg);
typedef void (*pl_xpc_peer_fn)(void *ctx, void *conn, int state);

/* Returns 0, or -1 when the listener could not be created. */
int pl_xpc_listen(const char *service, const char *peer_requirement, void *ctx,
                  pl_xpc_msg_fn on_msg, pl_xpc_peer_fn on_peer);

/* Privileged mach-service client. Returns an owned (+1) connection or NULL. */
void *pl_xpc_connect(const char *service, const char *peer_requirement, void *ctx,
                     pl_xpc_msg_fn on_msg, pl_xpc_peer_fn on_peer);

/* Sends {v, op[, data_key: data][, int_key: int_val]}. Keys may be NULL. Returns 0. */
int pl_xpc_send(void *conn, int64_t version, const char *op, const char *data_key,
                const uint8_t *data, size_t len, const char *int_key, int64_t int_val);

const uint8_t *pl_xpc_msg_data(void *msg, const char *key, size_t *len);
int64_t pl_xpc_msg_int(void *msg, const char *key);
size_t pl_xpc_msg_array_count(void *msg, const char *key);
const char *pl_xpc_msg_array_string(void *msg, const char *key, size_t index);

void pl_xpc_cancel(void *conn);
void pl_xpc_release(void *conn);

#endif
