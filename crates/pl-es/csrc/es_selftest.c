/*
 * Copy self-test against hand-built es_message_t (SPEC §8). Covers the envelope, process
 * identity, string truncation, fork and exit. Exec arguments are read through
 * es_exec_arg(), which walks private message memory and cannot be hand-built; exec is
 * validated on a live system by the M2 acceptance run.
 */
#include <stdio.h>
#include <string.h>

#include "es_copy.h"
#include "es_shim.h"

#define CHECK(cond)                                                                   \
    do {                                                                              \
        if (!(cond)) {                                                                \
            if (failures++ == 0) {                                                    \
                snprintf(msg, cap, "%s:%d: %s", __FILE__, __LINE__, #cond);           \
            }                                                                         \
        }                                                                             \
    } while (0)

static audit_token_t token(uint32_t pid, uint32_t pidversion) {
    audit_token_t t;
    memset(&t, 0, sizeof(t));
    t.val[0] = 501;
    t.val[5] = pid;
    t.val[7] = pidversion;
    return t;
}

static es_string_token_t str(const char *s) {
    es_string_token_t t = {strlen(s), s};
    return t;
}

int pl_es_selftest(char *msg, size_t cap) {
    int failures = 0;
    static char long_path[2000];
    memset(long_path, 'a', sizeof(long_path) - 1);
    long_path[0] = '/';
    long_path[sizeof(long_path) - 1] = '\0';

    es_file_t exe;
    memset(&exe, 0, sizeof(exe));
    exe.path = str("/bin/zsh");
    es_file_t tty;
    memset(&tty, 0, sizeof(tty));
    tty.path = str("/dev/ttys004");

    es_process_t proc;
    memset(&proc, 0, sizeof(proc));
    proc.audit_token = token(400, 7);
    proc.parent_audit_token = token(1, 1);
    proc.responsible_audit_token = token(300, 2);
    proc.ppid = 1;
    proc.session_id = 100005;
    proc.is_platform_binary = true;
    proc.executable = &exe;
    proc.signing_id = str("com.apple.zsh");
    proc.team_id = str("");
    proc.tty = &tty;
    proc.start_time.tv_sec = 1760000000;
    proc.start_time.tv_usec = 250000;
    memset(proc.cdhash, 0xab, sizeof(proc.cdhash));

    es_process_t child;
    memset(&child, 0, sizeof(child));
    child.audit_token = token(401, 1);

    es_message_t m;
    memset(&m, 0, sizeof(m));
    m.mach_time = 123456;
    m.seq_num = 9;
    m.global_seq_num = 99;
    m.time.tv_sec = 1760000100;
    m.time.tv_nsec = 5;
    m.process = &proc;
    m.event_type = ES_EVENT_TYPE_NOTIFY_FORK;
    m.event.fork.child = &child;

    static pl_raw_event_t out;
    memset(&out, 0xee, sizeof(out));

    CHECK(pl_es_classify(ES_EVENT_TYPE_NOTIFY_EXEC) == PL_EV_EXEC);
    CHECK(pl_es_classify(ES_EVENT_TYPE_NOTIFY_FORK) == PL_EV_FORK);
    CHECK(pl_es_classify(ES_EVENT_TYPE_NOTIFY_EXIT) == PL_EV_EXIT);
    CHECK(pl_es_classify(ES_EVENT_TYPE_NOTIFY_OPEN) == PL_EV_NONE);

    pl_es_copy(&m, PL_EV_FORK, &out);
    CHECK(out.version == PL_RAW_VERSION);
    CHECK(out.event_type == PL_EV_FORK);
    CHECK(out.mach_time == 123456 && out.seq_num == 9 && out.global_seq_num == 99);
    CHECK(out.wall_sec == 1760000100 && out.wall_nsec == 5);
    CHECK(out.process.token.val[5] == 400 && out.process.token.val[7] == 7);
    CHECK(out.process.parent_token.val[5] == 1);
    CHECK(out.process.responsible_token.val[5] == 300);
    CHECK(strcmp(out.process.path, "/bin/zsh") == 0);
    CHECK(strcmp(out.process.signing_id, "com.apple.zsh") == 0);
    CHECK(out.process.team_id[0] == '\0');
    CHECK(strcmp(out.process.tty, "/dev/ttys004") == 0);
    CHECK(out.process.flags == (PL_PF_PLATFORM | PL_PF_HAS_RESPONSIBLE | PL_PF_HAS_TTY));
    CHECK(out.process.cdhash[0] == 0xab && out.process.cdhash[19] == 0xab);
    CHECK(out.process.start_sec == 1760000000 && out.process.start_usec == 250000);
    CHECK(out.u.fork.child.val[5] == 401 && out.u.fork.child.val[7] == 1);

    exe.path = str(long_path);
    proc.tty = NULL;
    m.event_type = ES_EVENT_TYPE_NOTIFY_EXIT;
    m.event.exit.stat = 256;
    pl_es_copy(&m, PL_EV_EXIT, &out);
    CHECK(out.event_type == PL_EV_EXIT);
    CHECK(out.u.exit.stat == 256);
    CHECK((out.process.flags & PL_PF_PATH_TRUNC) != 0);
    CHECK(strlen(out.process.path) == PL_PATH_MAX - 1);
    CHECK((out.process.flags & PL_PF_HAS_TTY) == 0 && out.process.tty[0] == '\0');

    exe.path = str("/bin/zsh");
    exe.path_truncated = true;
    pl_es_copy(&m, PL_EV_EXIT, &out);
    CHECK((out.process.flags & PL_PF_PATH_TRUNC) != 0);

    return failures;
}
