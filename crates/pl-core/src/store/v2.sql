-- Preserve legacy observations without claiming they were captured completely.
UPDATE events SET json = json_set(json, '$.schema_version', 2, '$.capture', NULL);
ALTER TABLE events ADD COLUMN stored_at INTEGER NOT NULL DEFAULT 0;
UPDATE events SET stored_at = unixepoch();
CREATE INDEX events_stored_at ON events (stored_at);
