//! Findings (SPEC §3.4). `consequence` is the sentence a non-technical reader acts on.

use serde::{Deserialize, Serialize};

use super::identity::AuditToken;
use super::time::WallTime;

/// Finding identifier. Must be derived deterministically from the rule id and the first
/// evidence event id (C7); a random UUID would break byte-identical replay. Derivation lands
/// with the rule engine in M6.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FindingId(pub String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Open,
    Acknowledged,
    Dismissed,
}

/// The only remediation actions in v0 (SPEC §0).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Action {
    RevealInFinder { path: String },
    OpenSystemSettings { pane: String },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub id: FindingId,
    pub created_at: WallTime,
    pub first_evidence_at: WallTime,
    pub severity: Severity,
    /// 0.0 to 1.0.
    pub confidence: f64,
    /// Plain language, at most 80 characters.
    pub title: String,
    /// Plain language, one sentence: what this means for the user.
    pub consequence: String,
    pub technical_summary: String,
    /// ATT&CK technique ids such as `T1543.001`.
    pub attack_techniques: Vec<String>,
    /// Event ids.
    pub evidence: Vec<u64>,
    pub subjects: Vec<AuditToken>,
    pub rule_ids: Vec<String>,
    pub suggested_actions: Vec<Action>,
    pub state: State,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finding_round_trip() {
        let f = Finding {
            id: FindingId("r1:17".to_owned()),
            created_at: WallTime(5),
            first_evidence_at: WallTime(4),
            severity: Severity::High,
            confidence: 0.9,
            title: "Something set itself up to start at login".to_owned(),
            consequence: "A program will now run every time you log in.".to_owned(),
            technical_summary: "LaunchAgent written by osascript".to_owned(),
            attack_techniques: vec!["T1543.001".to_owned()],
            evidence: vec![17, 18],
            subjects: vec![AuditToken {
                pid: 7,
                pidversion: 1,
                ..Default::default()
            }],
            rule_ids: vec!["r1".to_owned()],
            suggested_actions: vec![Action::RevealInFinder {
                path: "/x".to_owned(),
            }],
            state: State::Open,
        };
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains(r#""severity":"high""#));
        assert!(json.contains(r#""action":"reveal_in_finder""#));
        let back: Finding = serde_json::from_str(&json).unwrap();
        assert_eq!(back, f);
    }

    #[test]
    fn severity_orders() {
        assert!(Severity::Info < Severity::Low && Severity::Low < Severity::High);
    }
}
