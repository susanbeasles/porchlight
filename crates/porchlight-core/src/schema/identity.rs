//! Process identity (SPEC §3.1). Audit tokens, never PIDs, are the key (C4).

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};

use super::time::WallTime;

/// `audit_token_t` decomposed. Equality, ordering and hashing use `(pid, pidversion)` only;
/// the credential fields are data carried along with the identity.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditToken {
    pub pid: i32,
    pub pidversion: i32,
    pub auid: u32,
    pub euid: u32,
    pub ruid: u32,
    pub egid: u32,
    pub rgid: u32,
    pub asid: u32,
}

impl AuditToken {
    /// Stable text key used in SQL columns and logs: `pid:pidversion`.
    pub fn key(&self) -> String {
        format!("{}:{}", self.pid, self.pidversion)
    }
}

impl PartialEq for AuditToken {
    fn eq(&self, other: &Self) -> bool {
        self.pid == other.pid && self.pidversion == other.pidversion
    }
}

impl Eq for AuditToken {}

impl Hash for AuditToken {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.pid.hash(state);
        self.pidversion.hash(state);
    }
}

impl PartialOrd for AuditToken {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AuditToken {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.pid, self.pidversion).cmp(&(other.pid, other.pidversion))
    }
}

impl fmt::Display for AuditToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.pid, self.pidversion)
    }
}

/// Everything ES tells us about a process image (SPEC §3.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessIdentity {
    pub token: AuditToken,
    pub parent_token: AuditToken,
    pub responsible_token: Option<AuditToken>,
    pub executable_path: String,
    pub signing_id: Option<String>,
    pub team_id: Option<String>,
    /// Hex-encoded code directory hash.
    pub cdhash: String,
    pub is_platform_binary: bool,
    pub is_es_client: bool,
    pub tty: Option<String>,
    pub session_id: i32,
    pub start_time: WallTime,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn identity_is_pid_and_pidversion_only() {
        let a = AuditToken {
            pid: 10,
            pidversion: 3,
            auid: 501,
            ..Default::default()
        };
        let b = AuditToken {
            pid: 10,
            pidversion: 3,
            auid: 0,
            ..Default::default()
        };
        let c = AuditToken {
            pid: 10,
            pidversion: 4,
            auid: 501,
            ..Default::default()
        };
        assert_eq!(a, b);
        assert_ne!(a, c);
        let set: BTreeSet<AuditToken> = [a, b, c].into_iter().collect();
        assert_eq!(set.len(), 2);
        assert_eq!(a.key(), "10:3");
    }

    #[test]
    fn token_round_trip() {
        let a = AuditToken {
            pid: 1,
            pidversion: 2,
            auid: 3,
            euid: 4,
            ruid: 5,
            egid: 6,
            rgid: 7,
            asid: 8,
        };
        let json = serde_json::to_string(&a).unwrap();
        assert_eq!(
            json,
            r#"{"pid":1,"pidversion":2,"auid":3,"euid":4,"ruid":5,"egid":6,"rgid":7,"asid":8}"#
        );
        let back: AuditToken = serde_json::from_str(&json).unwrap();
        assert_eq!(back.auid, 3);
    }
}
