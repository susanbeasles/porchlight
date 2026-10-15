#include "xpc_shim.h"

#include <xpc/xpc.h>

static void deliver(xpc_connection_t conn, xpc_object_t obj, void *ctx, pl_xpc_msg_fn on_msg,
                    pl_xpc_peer_fn on_peer, int owns_internal_ref) {
    xpc_type_t type = xpc_get_type(obj);
    if (type == XPC_TYPE_DICTIONARY) {
        const char *op = xpc_dictionary_get_string(obj, "op");
        if (op != NULL) {
            on_msg(ctx, (void *)conn, op, xpc_dictionary_get_int64(obj, "v"), (void *)obj);
        }
        return;
    }
    if (type == XPC_TYPE_ERROR) {
        if (obj == XPC_ERROR_CONNECTION_INTERRUPTED) {
            on_peer(ctx, (void *)conn, PL_XPC_PEER_INTERRUPTED);
        } else {
            /* XPC_ERROR_CONNECTION_INVALID, XPC_ERROR_PEER_CODE_SIGNING_REQUIREMENT, ... */
            on_peer(ctx, (void *)conn, PL_XPC_PEER_INVALID);
            if (owns_internal_ref) {
                xpc_release(conn);
            }
        }
    }
}

int pl_xpc_listen(const char *service, const char *peer_requirement, void *ctx,
                  pl_xpc_msg_fn on_msg, pl_xpc_peer_fn on_peer) {
    xpc_connection_t listener =
        xpc_connection_create_mach_service(service, NULL, XPC_CONNECTION_MACH_SERVICE_LISTENER);
    if (listener == NULL) {
        return -1;
    }
    xpc_connection_set_event_handler(listener, ^(xpc_object_t peer) {
      if (xpc_get_type(peer) != XPC_TYPE_CONNECTION) {
          return;
      }
      xpc_connection_t conn = (xpc_connection_t)peer;
      if (xpc_connection_set_peer_code_signing_requirement(conn, peer_requirement) != 0) {
          /* libxpc requires a handler and activation before cancel. */
          xpc_connection_set_event_handler(conn, ^(xpc_object_t ignored) {
            (void)ignored;
          });
          xpc_connection_activate(conn);
          xpc_connection_cancel(conn);
          return;
      }
      xpc_retain(conn); /* internal reference, dropped when the peer becomes invalid */
      xpc_connection_set_event_handler(conn, ^(xpc_object_t obj) {
        deliver(conn, obj, ctx, on_msg, on_peer, 1);
      });
      /* Register with Rust before activating: no message or INVALID can arrive for a
       * connection Rust has not seen yet. */
      xpc_retain(conn); /* reference owned by Rust */
      on_peer(ctx, (void *)conn, PL_XPC_PEER_CONNECTED);
      xpc_connection_activate(conn);
    });
    xpc_connection_activate(listener);
    return 0; /* the listener lives for the life of the process */
}

void *pl_xpc_connect(const char *service, const char *peer_requirement, void *ctx,
                     pl_xpc_msg_fn on_msg, pl_xpc_peer_fn on_peer) {
    xpc_connection_t conn =
        xpc_connection_create_mach_service(service, NULL, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);
    if (conn == NULL) {
        return NULL;
    }
    if (xpc_connection_set_peer_code_signing_requirement(conn, peer_requirement) != 0) {
        /* Releasing the last reference to an inactive connection is misuse: activate first. */
        xpc_connection_set_event_handler(conn, ^(xpc_object_t ignored) {
          (void)ignored;
        });
        xpc_connection_activate(conn);
        xpc_connection_cancel(conn);
        xpc_release(conn);
        return NULL;
    }
    xpc_connection_set_event_handler(conn, ^(xpc_object_t obj) {
      deliver(conn, obj, ctx, on_msg, on_peer, 0);
    });
    xpc_connection_activate(conn);
    return (void *)conn; /* the create reference is owned by Rust */
}

int pl_xpc_send(void *conn, int64_t version, const char *op, const char *data_key,
                const uint8_t *data, size_t len, const char *int_key, int64_t int_val) {
    xpc_object_t msg = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_int64(msg, "v", version);
    xpc_dictionary_set_string(msg, "op", op);
    if (data_key != NULL && data != NULL) {
        xpc_dictionary_set_data(msg, data_key, data, len);
    }
    if (int_key != NULL) {
        xpc_dictionary_set_int64(msg, int_key, int_val);
    }
    xpc_connection_send_message((xpc_connection_t)conn, msg);
    xpc_release(msg);
    return 0;
}

const uint8_t *pl_xpc_msg_data(void *msg, const char *key, size_t *len) {
    return xpc_dictionary_get_data((xpc_object_t)msg, key, len);
}

int64_t pl_xpc_msg_int(void *msg, const char *key) {
    return xpc_dictionary_get_int64((xpc_object_t)msg, key);
}

size_t pl_xpc_msg_array_count(void *msg, const char *key) {
    xpc_object_t arr = xpc_dictionary_get_value((xpc_object_t)msg, key);
    if (arr == NULL || xpc_get_type(arr) != XPC_TYPE_ARRAY) {
        return 0;
    }
    return xpc_array_get_count(arr);
}

const char *pl_xpc_msg_array_string(void *msg, const char *key, size_t index) {
    xpc_object_t arr = xpc_dictionary_get_value((xpc_object_t)msg, key);
    if (arr == NULL || xpc_get_type(arr) != XPC_TYPE_ARRAY) {
        return NULL;
    }
    return xpc_array_get_string(arr, index);
}

void pl_xpc_cancel(void *conn) {
    xpc_connection_cancel((xpc_connection_t)conn);
}

void pl_xpc_release(void *conn) {
    xpc_release((xpc_object_t)conn);
}
