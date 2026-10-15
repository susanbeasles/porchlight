/*
 * PLRawEvent: the fixed-layout record the ES handler copies an es_message_t into
 * (SPEC §4.4, §4.5). No pointers, no heap. Mirrored by `pl_raw::PlRawEvent`
 * in Rust; both sides assert size and offsets, so layout drift fails the build or the tests.
 *
 * Strings are NUL-terminated inside fixed buffers. A copy that did not fit sets the
 * matching *_TRUNC flag. Event types are Porchlight's own small integers, not
 * es_event_type_t values, so this header and the Rust side never need the ES SDK.
 */
#ifndef PORCHLIGHT_RAWEVENT_H
#define PORCHLIGHT_RAWEVENT_H

#include <stddef.h>
#include <stdint.h>

#define PL_RAW_VERSION 1u

#define PL_PATH_MAX 1024
#define PL_SIGNING_ID_MAX 256
#define PL_TEAM_ID_MAX 32
#define PL_TTY_MAX 128
#define PL_CDHASH_LEN 20
#define PL_EXEC_BUF 16384

/* Porchlight event types. M2 maps EXEC, FORK and EXIT; M3 appends the rest. */
enum {
    PL_EV_NONE = 0,
    PL_EV_EXEC = 1,
    PL_EV_FORK = 2,
    PL_EV_EXIT = 3,
};
/* Size of per-type counter arrays (drops, sequence tracking). */
#define PL_EV_SLOTS 64

/* pl_process_t.flags */
#define PL_PF_PLATFORM 0x01u
#define PL_PF_ES_CLIENT 0x02u
#define PL_PF_HAS_RESPONSIBLE 0x04u
#define PL_PF_HAS_TTY 0x08u
#define PL_PF_PATH_TRUNC 0x10u
#define PL_PF_SIGNING_ID_TRUNC 0x20u
#define PL_PF_TEAM_ID_TRUNC 0x40u
#define PL_PF_TTY_TRUNC 0x80u

/* pl_exec_t.flags */
#define PL_XF_ARGS_TRUNC 0x01u
#define PL_XF_ENV_TRUNC 0x02u
#define PL_XF_HAS_CWD 0x04u
#define PL_XF_HAS_SCRIPT 0x08u
#define PL_XF_CWD_TRUNC 0x10u
#define PL_XF_SCRIPT_TRUNC 0x20u

/* audit_token_t, verbatim: val[0]=auid [1]=euid [2]=egid [3]=ruid [4]=rgid
 * [5]=pid [6]=asid [7]=pidversion (the libbsm audit_token_to_* mapping). */
typedef struct {
    uint32_t val[8];
} pl_token_t;

typedef struct {
    pl_token_t token;
    pl_token_t parent_token;
    pl_token_t responsible_token;
    int32_t ppid;
    int32_t session_id;
    uint32_t flags;
    uint32_t _pad0;
    int64_t start_sec;
    int64_t start_usec;
    uint8_t cdhash[PL_CDHASH_LEN];
    uint8_t _pad1[4];
    char path[PL_PATH_MAX];
    char signing_id[PL_SIGNING_ID_MAX];
    char team_id[PL_TEAM_ID_MAX];
    char tty[PL_TTY_MAX];
} pl_process_t;

typedef struct {
    pl_process_t target;
    uint32_t argc;     /* arguments copied */
    uint32_t envc;     /* environment entries copied */
    uint32_t args_len; /* bytes of buf holding NUL-separated args */
    uint32_t env_len;  /* bytes of buf after args holding NUL-separated env */
    uint32_t flags;
    uint32_t _pad;
    char cwd[PL_PATH_MAX];
    char script[PL_PATH_MAX];
    char buf[PL_EXEC_BUF];
} pl_exec_t;

typedef struct {
    pl_token_t child;
} pl_fork_t;

typedef struct {
    int32_t stat;
    int32_t _pad;
} pl_exit_t;

typedef union {
    pl_exec_t exec;
    pl_fork_t fork;
    pl_exit_t exit;
} pl_event_body_t;

typedef struct {
    uint32_t version; /* PL_RAW_VERSION */
    uint32_t event_type;
    uint64_t mach_time;
    uint64_t seq_num;
    uint64_t global_seq_num;
    int64_t wall_sec;
    int64_t wall_nsec;
    pl_process_t process;
    pl_event_body_t u;
} pl_raw_event_t;

#define PL_RAW_EVENT_SIZE 21688u
#define PL_PROCESS_SIZE 1592u

_Static_assert(sizeof(pl_process_t) == PL_PROCESS_SIZE, "pl_process_t layout changed");
_Static_assert(sizeof(pl_raw_event_t) == PL_RAW_EVENT_SIZE, "pl_raw_event_t layout changed");
_Static_assert(offsetof(pl_raw_event_t, u) == 1640, "pl_raw_event_t.u moved");

/* Layout probe for the Rust-side tests: fills out[] with sizes and offsets. Returns count. */
size_t pl_raw_layout(size_t *out, size_t cap);

#endif
