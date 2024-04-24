// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::collections::HashMap;

/// Information about hosts of a running scan
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct HostInfo {
    /// Number of all hosts, that are contained in a target
    pub all: u32,
    /// Number of hosts, that are excluded from the target
    pub excluded: u32,
    /// Number of hosts, that are not reachable (alive-test failed)
    pub dead: u32,
    /// Number of hosts, that are reachable (alive-test succeeded)
    pub alive: u32,
    /// Number of hosts, that are currently queued for scanning
    pub queued: u32,
    /// Number of hosts, that are already finished scanning
    pub finished: u32,
    #[cfg_attr(
        feature = "serde_support",
        serde(skip_serializing_if = "Option::is_none")
    )]
    /// IPs of hosts, that are currently scanned.
    pub scanning: Option<HashMap<String, i32>>,
}
