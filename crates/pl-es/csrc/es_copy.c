#include "es_copy.h"

#include <string.h>

_Static_assert(sizeof(audit_token_t) == sizeof(pl_token_t), "audit_token_t size changed");

uint32_t pl_es_classify(es_event_type_t type) {
    switch (type) {
    case ES_EVENT_TYPE_NOTIFY_EXEC:
        return PL_EV_EXEC;
    case ES_EVENT_TYPE_NOTIFY_FORK:
        return PL_EV_FORK;
    case ES_EVENT_TYPE_NOTIFY_EXIT:
        return PL_EV_EXIT;
    default:
        return PL_EV_NONE;
    }
}

static void copy_token(pl_token_t *dst, const audit_token_t *src) {
    memcpy(dst->val, src->val, sizeof(dst->val));
}

/* Returns 1 when the source did not fit. Always NUL-terminates. */
static int copy_str(char *dst, size_t cap, es_string_token_t s) {
    size_t n = s.length < cap - 1 ? s.length : cap - 1;
    if (n > 0 && s.data != NULL) {
        memcpy(dst, s.data, n);
    } else {
        n = 0;
    }
    dst[n] = '\0';
    return s.length > cap - 1;
}

static int copy_file(char *dst, size_t cap, const es_file_t *f) {
    if (f == NULL) {
        dst[0] = '\0';
        return 0;
    }
    int truncated = copy_str(dst, cap, f->path);
    return truncated || f->path_truncated;
}

static void copy_process(pl_process_t *p, const es_process_t *src) {
    uint32_t flags = PL_PF_HAS_RESPONSIBLE;
    copy_token(&p->token, &src->audit_token);
    copy_token(&p->parent_token, &src->parent_audit_token);
    copy_token(&p->responsible_token, &src->responsible_audit_token);
    p->ppid = src->ppid;
    p->session_id = src->session_id;
    p->start_sec = src->start_time.tv_sec;
    p->start_usec = src->start_time.tv_usec;
    memcpy(p->cdhash, src->cdhash, PL_CDHASH_LEN);
    if (src->is_platform_binary) {
        flags |= PL_PF_PLATFORM;
    }
    if (src->is_es_client) {
        flags |= PL_PF_ES_CLIENT;
    }
    if (copy_file(p->path, sizeof(p->path), src->executable)) {
        flags |= PL_PF_PATH_TRUNC;
    }
    if (copy_str(p->signing_id, sizeof(p->signing_id), src->signing_id)) {
        flags |= PL_PF_SIGNING_ID_TRUNC;
    }
    if (copy_str(p->team_id, sizeof(p->team_id), src->team_id)) {
        flags |= PL_PF_TEAM_ID_TRUNC;
    }
    if (src->tty != NULL) {
        flags |= PL_PF_HAS_TTY;
        if (copy_file(p->tty, sizeof(p->tty), src->tty)) {
            flags |= PL_PF_TTY_TRUNC;
        }
    } else {
        p->tty[0] = '\0';
    }
    p->flags = flags;
    p->_pad0 = 0;
}

/* Appends NUL-terminated strings to buf; stops (and reports) at the first that won't fit. */
static uint32_t append_strings(pl_exec_t *x, uint32_t *off, uint32_t count,
                               es_string_token_t (*get)(const es_event_exec_t *, uint32_t),
                               const es_event_exec_t *e, int *truncated) {
    uint32_t copied = 0;
    for (uint32_t i = 0; i < count; i++) {
        es_string_token_t s = get(e, i);
        if ((size_t)*off + s.length + 1 > PL_EXEC_BUF) {
            *truncated = 1;
            break;
        }
        if (s.length > 0 && s.data != NULL) {
            memcpy(x->buf + *off, s.data, s.length);
        }
        *off += (uint32_t)s.length;
        x->buf[(*off)++] = '\0';
        copied++;
    }
    return copied;
}

static void copy_exec(pl_exec_t *x, const es_event_exec_t *e) {
    uint32_t flags = 0;
    uint32_t off = 0;
    int args_trunc = 0;
    int env_trunc = 0;
    copy_process(&x->target, e->target);
    x->argc = append_strings(x, &off, es_exec_arg_count(e), es_exec_arg, e, &args_trunc);
    x->args_len = off;
    x->envc = append_strings(x, &off, es_exec_env_count(e), es_exec_env, e, &env_trunc);
    x->env_len = off - x->args_len;
    if (args_trunc) {
        flags |= PL_XF_ARGS_TRUNC;
    }
    if (env_trunc) {
        flags |= PL_XF_ENV_TRUNC;
    }
    if (e->cwd != NULL) {
        flags |= PL_XF_HAS_CWD;
        if (copy_file(x->cwd, sizeof(x->cwd), e->cwd)) {
            flags |= PL_XF_CWD_TRUNC;
        }
    } else {
        x->cwd[0] = '\0';
    }
    if (e->script != NULL) {
        flags |= PL_XF_HAS_SCRIPT;
        if (copy_file(x->script, sizeof(x->script), e->script)) {
            flags |= PL_XF_SCRIPT_TRUNC;
        }
    } else {
        x->script[0] = '\0';
    }
    x->flags = flags;
    x->_pad = 0;
}

void pl_es_copy(const es_message_t *msg, uint32_t pl_type, pl_raw_event_t *out) {
    out->version = PL_RAW_VERSION;
    out->event_type = pl_type;
    out->mach_time = msg->mach_time;
    out->seq_num = msg->seq_num;
    out->global_seq_num = msg->global_seq_num;
    out->wall_sec = msg->time.tv_sec;
    out->wall_nsec = msg->time.tv_nsec;
    copy_process(&out->process, msg->process);
    switch (pl_type) {
    case PL_EV_EXEC:
        copy_exec(&out->u.exec, &msg->event.exec);
        break;
    case PL_EV_FORK:
        copy_token(&out->u.fork.child, &msg->event.fork.child->audit_token);
        break;
    case PL_EV_EXIT:
        out->u.exit.stat = msg->event.exit.stat;
        out->u.exit._pad = 0;
        break;
    default:
        break;
    }
}
