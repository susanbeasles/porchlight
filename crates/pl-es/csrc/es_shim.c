#include "es_shim.h"

#include <EndpointSecurity/EndpointSecurity.h>
#include <mach/mach.h>
#include <os/log.h>
#include <stdatomic.h>
#include <string.h>

#include "es_copy.h"
#include "ring.h"

static es_client_t *g_client;
static pl_ring_t *g_ring;
static _Atomic uint32_t g_mute_failures;

/* The ES handler (SPEC §4.4): classify, reserve a ring slot, copy in place, commit.
 * No allocation, no locks that can contend, no I/O, no logging. A full ring is counted
 * by the ring itself. NOTIFY only in M2: nothing to respond to. */
static void handle(const es_message_t *msg) {
    uint32_t type = pl_es_classify(msg->event_type);
    if (type == PL_EV_NONE) {
        return;
    }
    pl_raw_event_t *slot = pl_ring_reserve(g_ring, type);
    if (slot == NULL) {
        return;
    }
    pl_es_copy(msg, type, slot);
    pl_ring_commit(g_ring);
}

static int self_audit_token(audit_token_t *out) {
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    kern_return_t kr = task_info(mach_task_self(), TASK_AUDIT_TOKEN, (task_info_t)out, &count);
    return kr == KERN_SUCCESS ? 0 : -1;
}

int pl_es_self_token(pl_token_t *out) {
    audit_token_t t;
    if (self_audit_token(&t) != 0) {
        return -1;
    }
    memcpy(out->val, t.val, sizeof(out->val));
    return 0;
}

uint32_t pl_es_mute_failures(void) {
    return atomic_load(&g_mute_failures);
}

int pl_es_start(void *ring) {
    if (g_client != NULL || ring == NULL) {
        return PL_ES_INTERNAL;
    }
    g_ring = (pl_ring_t *)ring;
    es_client_t *client = NULL;
    es_new_client_result_t r = es_new_client(&client, ^(es_client_t *c, const es_message_t *msg) {
      (void)c;
      handle(msg);
    });
    switch (r) {
    case ES_NEW_CLIENT_RESULT_SUCCESS:
        break;
    case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
        return PL_ES_NOT_ENTITLED;
    case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
        return PL_ES_NOT_PERMITTED;
    case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
        return PL_ES_NOT_PRIVILEGED;
    case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS:
        return PL_ES_TOO_MANY_CLIENTS;
    case ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT:
        return PL_ES_INVALID_ARGUMENT;
    default:
        return PL_ES_INTERNAL;
    }
    /* Muting before subscribing (SPEC §4.1, §4.3): the collector does not observe itself.
     * The app's token is muted when M3 adds it to the protocol. */
    audit_token_t self;
    if (self_audit_token(&self) != 0 || es_mute_process(client, &self) != ES_RETURN_SUCCESS) {
        atomic_fetch_add(&g_mute_failures, 1);
    }
    /* M2 subscription set: process lineage only (SPEC §9). */
    const es_event_type_t events[] = {
        ES_EVENT_TYPE_NOTIFY_EXEC,
        ES_EVENT_TYPE_NOTIFY_FORK,
        ES_EVENT_TYPE_NOTIFY_EXIT,
    };
    if (es_subscribe(client, events, sizeof(events) / sizeof(events[0])) != ES_RETURN_SUCCESS) {
        es_delete_client(client);
        return PL_ES_INTERNAL;
    }
    g_client = client;
    return PL_ES_OK;
}

void pl_es_stop(void) {
    if (g_client == NULL) {
        return;
    }
    es_unsubscribe_all(g_client);
    es_delete_client(g_client);
    g_client = NULL;
}

static os_log_t g_log;

void pl_log_init(void) {
    if (g_log == NULL) {
        g_log = os_log_create("dev.susanb.porchlight.extension", "es");
    }
}

void pl_log(int level, const char *msg) {
    os_log_t log = g_log != NULL ? g_log : OS_LOG_DEFAULT;
    os_log_type_t type = level >= 2 ? OS_LOG_TYPE_FAULT
                         : level == 1 ? OS_LOG_TYPE_ERROR
                                      : OS_LOG_TYPE_DEFAULT;
    os_log_with_type(log, type, "%{public}s", msg);
}
