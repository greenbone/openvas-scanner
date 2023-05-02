/// Action to perform on a scan
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct ScanAction {
    pub action: Action,
}

/// Enum representing possible actions
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(feature = "serde_support", serde(rename_all = "snake_case"))]
pub enum Action {
    /// Start a scan
    Start,
    /// Stop a scan
    Stop,
}
