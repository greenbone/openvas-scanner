use std::fmt::Display;

use serde::{Deserialize, Serialize};

use super::host_info::HostInfo;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Status {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_time: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_time: Option<i32>,
    pub status: Phase,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_info: Option<HostInfo>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Phase {
    #[serde(rename = "requested")]
    Requested,
    #[serde(rename = "running")]
    Running,
    #[serde(rename = "stopped")]
    Stopped,
    #[serde(rename = "failed")]
    Failed,
    #[serde(rename = "succeeded")]
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
