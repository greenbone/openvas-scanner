use serde::{Deserialize, Serialize};

/// Action to perform on a scan
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ScanAction {
    pub action: Action,
}

/// Enum representing possible actions
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Action {
    #[serde(rename = "start")]
    /// Start a scan
    Start,
    #[serde(rename = "stop")]
    /// Stop a scan
    Stop,
}
