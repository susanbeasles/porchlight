//! `scripts/record-fixture.sh` must subscribe to exactly the events in
//! `ES_NOTIFY_EVENT_NAMES`, and `docs/schema.md` must document every kind discriminator.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use pl_core::schema::Kind;
use pl_core::schema::es_events::ES_NOTIFY_EVENT_NAMES;
use std::collections::BTreeSet;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

#[test]
fn record_script_event_list_matches_core() {
    let script = std::fs::read_to_string(repo_root().join("scripts/record-fixture.sh")).unwrap();
    let start = script.find("events=(").unwrap() + "events=(".len();
    let end = script[start..].find(')').unwrap() + start;
    let in_script: BTreeSet<&str> = script[start..end].split_whitespace().collect();
    let in_core: BTreeSet<&str> = ES_NOTIFY_EVENT_NAMES.iter().copied().collect();
    assert_eq!(in_script, in_core);
}

#[test]
fn schema_doc_lists_every_discriminator() {
    let doc = std::fs::read_to_string(repo_root().join("docs/schema.md")).unwrap();
    for d in Kind::DISCRIMINATORS {
        assert!(
            doc.contains(&format!("`{d}`")),
            "docs/schema.md is missing `{d}`"
        );
    }
}
