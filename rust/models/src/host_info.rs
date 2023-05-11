// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

/// Information about hosts of a running scan
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize)
)]
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
    #[cfg_attr(
        feature = "serde_support",
        serde(skip_serializing_if = "Vec::is_empty")
    )]
    /// IPs of hosts, that are currently scanned.
    pub scanning: Vec<String>,
}
