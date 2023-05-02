use serde::{Deserialize, Serialize};

/// Information about hosts of a running scan
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HostInfo {
    /// Number of all hosts, that are contained in a target
    pub all: i32,
    /// Number of hosts, that are excluded from the target
    pub excluded: i32,
    /// Number of hosts, that are not reachable (alive-test failed)
    pub dead: i32,
    /// Number of hosts, that are reachable (alive-test succeeded)
    pub alive: i32,
    /// Number of hosts, that are currently queued for scanning
    pub queued: i32,
    /// Number of hosts, that are already finished scanning
    pub finished: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// IPs of hosts, that are currently scanned.
    pub scanning: Option<Vec<String>>,
}
