#include "xpc_shim.h"

#include <xpc/xpc.h>
#include <SystemConfiguration/SystemConfiguration.h>
#include <Security/AuthSession.h>
#include <bsm/audit.h>
#include <unistd.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

/* Public owner enrollment is provisioned independently by the installer/operator.
 * This library never creates it; missing/unsafe enrollment disables listening. */
static uid_t telemetry_owner = (uid_t)-1;

static int load_telemetry_owner(void) {
    telemetry_owner = (uid_t)-1;
    struct stat st;
    const char *parents[] = {"/Library", "/Library/Preferences"};
    for (size_t i = 0; i < sizeof(parents) / sizeof(parents[0]); i++) {
        if (lstat(parents[i], &st) != 0 || !S_ISDIR(st.st_mode) ||
            st.st_uid != 0 || (st.st_mode & 0022) != 0) {
            return -1;
        }
    }
    int fd = open("/Library/Preferences/dev.susanb.porchlight.owner-uid",
                  O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != 0 ||
        (st.st_mode & 0022) != 0 || st.st_nlink != 1 || st.st_size < 1 || st.st_size > 16) {
        close(fd);
        return -1;
    }
    char text[18] = {0};
    ssize_t n = read(fd, text, sizeof(text) - 1);
    close(fd);
    if (n != st.st_size || strlen(text) != (size_t)n || text[0] < '0' || text[0] > '9') {
        return -1;
    }
    char *end;
    errno = 0;
    unsigned long owner = strtoul(text, &end, 10);
    if (errno != 0 || owner == 0 || owner >= (unsigned long)(uid_t)-1 ||
        !(*end == '\0' || (*end == '\n' && end[1] == '\0'))) {
        return -1;
    }
    telemetry_owner = (uid_t)owner;
    return 0;
}


static int enrolled_owner_matches(uint32_t uid) {
    return telemetry_owner != (uid_t)-1 && uid == telemetry_owner;
}

/* System policy: only the current local graphical console principal may consume.
 * UID and audit session come from libxpc/kernel state, never the message dictionary.
 * Rechecked on every command and delivery; errors revoke access. */
int pl_xpc_principal_is_current(uint32_t uid, uint32_t asid) {
    uid_t console_uid = (uid_t)-1;
    gid_t console_gid = (gid_t)-1;
    CFStringRef user = SCDynamicStoreCopyConsoleUser(NULL, &console_uid, &console_gid);
    if (user == NULL) return 0;
    CFRelease(user);
    if (!enrolled_owner_matches(uid) || uid == 0 || uid == (uint32_t)-1 || console_uid != uid || asid == 0 || asid == (uint32_t)-1) return 0;
    auditinfo_addr_t info = {0};
    info.ai_asid = (au_asid_t)asid;
    if (auditon(A_GETSINFO_ADDR, &info, sizeof(info)) != 0 || info.ai_auid != uid) return 0;
    SecuritySessionId session = 0;
    SessionAttributeBits attributes = 0;
    if (SessionGetInfo((SecuritySessionId)asid, &session, &attributes) != errSessionSuccess) return 0;
    return session == asid && (attributes & sessionHasGraphicAccess) != 0 && (attributes & sessionIsRemote) == 0;
}

int pl_xpc_authorized_principal(void *peer, uint32_t *uid, uint32_t *asid) {
    xpc_connection_t conn = (xpc_connection_t)peer;
    *uid = (uint32_t)xpc_connection_get_euid(conn);
    *asid = (uint32_t)xpc_connection_get_asid(conn);
    return pl_xpc_principal_is_current(*uid, *asid);
}


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
    if (load_telemetry_owner() != 0) return -1;
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
