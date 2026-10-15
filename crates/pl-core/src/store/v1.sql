-- Porchlight event store, schema version 1 (SPEC §5.6). Forward-only.
CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;

CREATE TABLE events (
    id             INTEGER PRIMARY KEY,
    mach_time      INTEGER NOT NULL,
    wall_time      INTEGER NOT NULL,
    seq_num        INTEGER NOT NULL,
    global_seq_num INTEGER NOT NULL,
    source         TEXT    NOT NULL,
    kind           TEXT    NOT NULL,
    process_token  TEXT    NOT NULL,
    parent_token   TEXT    NOT NULL,
    json           TEXT    NOT NULL
) STRICT;
CREATE INDEX events_kind_mach_time ON events (kind, mach_time);
CREATE INDEX events_process_token  ON events (process_token);
CREATE INDEX events_wall_time      ON events (wall_time);

CREATE TABLE processes (
    token             TEXT PRIMARY KEY,
    parent_token      TEXT    NOT NULL,
    responsible_token TEXT,
    first_seen_id     INTEGER NOT NULL,
    exited_mach_time  INTEGER,
    seeded            INTEGER NOT NULL DEFAULT 0,
    json              TEXT    NOT NULL
) STRICT;

CREATE TABLE ipc_edges (
    id            INTEGER PRIMARY KEY,
    src           TEXT    NOT NULL,
    dst           TEXT    NOT NULL,
    kind          TEXT    NOT NULL,
    first_seen_id INTEGER NOT NULL,
    last_seen_id  INTEGER NOT NULL
) STRICT;
CREATE INDEX ipc_edges_src ON ipc_edges (src);
CREATE INDEX ipc_edges_dst ON ipc_edges (dst);

CREATE TABLE inventory (
    id              INTEGER PRIMARY KEY,
    category        TEXT    NOT NULL,
    key             TEXT    NOT NULL,
    present         INTEGER NOT NULL,
    first_seen_id   INTEGER NOT NULL,
    last_changed_id INTEGER NOT NULL,
    changed_by      TEXT    NOT NULL,
    json            TEXT    NOT NULL,
    UNIQUE (category, key)
) STRICT;

CREATE TABLE inventory_history (
    id           INTEGER PRIMARY KEY,
    inventory_id INTEGER NOT NULL REFERENCES inventory (id),
    event_id     INTEGER NOT NULL,
    change       TEXT    NOT NULL,
    json         TEXT    NOT NULL
) STRICT;

CREATE TABLE findings (
    id                TEXT PRIMARY KEY,
    created_at        INTEGER NOT NULL,
    first_evidence_at INTEGER NOT NULL,
    severity          TEXT    NOT NULL,
    state             TEXT    NOT NULL,
    json              TEXT    NOT NULL
) STRICT;

CREATE TABLE drops (
    event_id     INTEGER PRIMARY KEY REFERENCES events (id),
    event_type   TEXT    NOT NULL,
    expected_seq INTEGER NOT NULL,
    got_seq      INTEGER NOT NULL,
    count        INTEGER NOT NULL,
    reason       TEXT    NOT NULL
) STRICT;
