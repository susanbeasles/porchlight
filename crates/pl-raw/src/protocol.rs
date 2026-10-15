//! XPC vocabulary between the app and the extension (SPEC §4.7). Messages are
//! `xpc_dictionary`s carrying `v` (protocol version) and `op`; payloads are JSON in `data`
//! values. The C shim moves bytes; this module owns the meaning.

use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: i64 = 1;

/// Mach service published by the extension. System extensions must prefix the name with
/// the Team ID (`NSEndpointSecurityMachServiceName`); ADR-0005.
pub const MACH_SERVICE: &str = "2VB7966G7R.dev.susanb.porchlight.extension.xpc";

pub const TEAM_ID: &str = "2VB7966G7R";
pub const APP_BUNDLE_ID: &str = "dev.susanb.porchlight";
pub const EXTENSION_BUNDLE_ID: &str = "dev.susanb.porchlight.extension";

/// Code-signing requirement the extension applies to connecting peers.
pub fn app_requirement() -> String {
    format!(
        "anchor apple generic and identifier \"{APP_BUNDLE_ID}\" and certificate leaf[subject.OU] = \"{TEAM_ID}\""
    )
}

/// Code-signing requirement the app applies to the extension.
pub fn extension_requirement() -> String {
    format!(
        "anchor apple generic and identifier \"{EXTENSION_BUNDLE_ID}\" and certificate leaf[subject.OU] = \"{TEAM_ID}\""
    )
}

/// Dictionary keys.
pub mod key {
    pub const VERSION: &str = "v";
    pub const OP: &str = "op";
    pub const EVENTS: &str = "events";
    pub const STATUS: &str = "status";
    pub const WATCH_LIST_VERSION: &str = "watch_list_version";
    pub const PATHS: &str = "paths";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    // app -> extension
    Status,
    StartStreaming,
    StopStreaming,
    UpdateWatchList,
    // extension -> app
    Batch,
    StatusChanged,
}

impl Op {
    pub const ALL: [Op; 6] = [
        Op::Status,
        Op::StartStreaming,
        Op::StopStreaming,
        Op::UpdateWatchList,
        Op::Batch,
        Op::StatusChanged,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Op::Status => "status",
            Op::StartStreaming => "start_streaming",
            Op::StopStreaming => "stop_streaming",
            Op::UpdateWatchList => "update_watch_list",
            Op::Batch => "batch",
            Op::StatusChanged => "status_changed",
        }
    }

    pub fn parse(s: &str) -> Option<Op> {
        Op::ALL.into_iter().find(|op| op.as_str() == s)
    }
}

/// Endpoint Security client state, as the app shows it (SPEC §6 Status screen).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EsState {
    Starting,
    Running,
    /// `ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED`
    NotEntitled,
    /// `ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED`: Full Disk Access not granted.
    NotPermitted,
    /// `ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED`
    NotPrivileged,
    TooManyClients,
    InvalidArgument,
    Internal,
}

impl EsState {
    /// Maps the C shim's start result (see `es_shim.h`).
    pub fn from_shim(code: i32) -> EsState {
        match code {
            0 => EsState::Running,
            1 => EsState::NotEntitled,
            2 => EsState::NotPermitted,
            3 => EsState::NotPrivileged,
            4 => EsState::TooManyClients,
            5 => EsState::InvalidArgument,
            _ => EsState::Internal,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EsStatus {
    pub protocol_version: i64,
    pub state: EsState,
    pub streaming: bool,
    pub ring_capacity: u32,
    pub producer_overlaps: u64,
    pub queued_while_disconnected: u64,
    pub bridge: crate::bridge::BridgeStats,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ops_round_trip() {
        for op in Op::ALL {
            assert_eq!(Op::parse(op.as_str()), Some(op));
        }
        assert_eq!(Op::parse("nope"), None);
    }

    #[test]
    fn shim_codes_map() {
        assert_eq!(EsState::from_shim(0), EsState::Running);
        assert_eq!(EsState::from_shim(2), EsState::NotPermitted);
        assert_eq!(EsState::from_shim(-1), EsState::Internal);
    }

    #[test]
    fn status_json_is_stable() {
        let s = EsStatus {
            protocol_version: PROTOCOL_VERSION,
            state: EsState::NotPermitted,
            streaming: false,
            ring_capacity: 8192,
            producer_overlaps: 0,
            queued_while_disconnected: 3,
            bridge: Default::default(),
        };
        let json = serde_json::to_string(&s).unwrap();
        assert!(
            json.starts_with(r#"{"protocol_version":1,"state":"not_permitted","streaming":false"#),
            "{json}"
        );
        assert_eq!(serde_json::from_str::<EsStatus>(&json).unwrap(), s);
    }

    #[test]
    fn requirements_pin_team_and_identifier() {
        assert!(app_requirement().contains("identifier \"dev.susanb.porchlight\""));
        assert!(extension_requirement().contains("identifier \"dev.susanb.porchlight.extension\""));
        assert!(app_requirement().contains("2VB7966G7R"));
        assert!(MACH_SERVICE.starts_with(TEAM_ID));
    }
}
