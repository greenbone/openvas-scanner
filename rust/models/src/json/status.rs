use std::fmt::Display;

use serde::{Deserialize, Serialize};

use super::host_info::HostInfo;

/// Status information about a scan
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Status {
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Timestamp for the start of a scan
    pub start_time: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Timestamp for the end of a scan
    pub end_time: Option<i32>,
    /// The phase, a scan is currently in
    pub status: Phase,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Information about the hosts of a running scan
    pub host_info: Option<HostInfo>,
}

/// Enum of the possible phases of a scan
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Phase {
    #[serde(rename = "requested")]
    /// A scan has been requested, but not started yet
    Requested,
    #[serde(rename = "running")]
    /// A scan is currently running
    Running,
    #[serde(rename = "stopped")]
    /// A scan has been stopped by a client
    Stopped,
    #[serde(rename = "failed")]
    /// A scan could not finish due to an error while scanning
    Failed,
    #[serde(rename = "succeeded")]
    /// A scan has been successfully finished
    Succeeded,
}

impl Display for Phase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Requested => write!(f, "requested"),
            Self::Running => write!(f, "running"),
            Self::Stopped => write!(f, "stopped"),
            Self::Failed => write!(f, "failed"),
            Self::Succeeded => write!(f, "succeeded"),
        }
    }
}
