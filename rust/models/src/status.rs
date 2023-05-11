// Copyright (C) 2023 Greenbone Networks GmbH
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::fmt::Display;

use super::host_info::HostInfo;

/// Status information about a scan
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct Status {
    #[cfg_attr(
        feature = "serde_support",
        serde(skip_serializing_if = "Option::is_none")
    )]
    /// Timestamp for the start of a scan
    pub start_time: Option<i32>,
    #[cfg_attr(
        feature = "serde_support",
        serde(skip_serializing_if = "Option::is_none")
    )]
    /// Timestamp for the end of a scan
    pub end_time: Option<i32>,
    /// The phase, a scan is currently in
    pub status: Phase,
    #[cfg_attr(
        feature = "serde_support",
        serde(skip_serializing_if = "Option::is_none")
    )]
    /// Information about the hosts of a running scan
    pub host_info: Option<HostInfo>,
}

/// Enum of the possible phases of a scan
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(feature = "serde_support", serde(rename_all = "snake_case"))]
pub enum Phase {
    /// A scan has been requested, but not started yet
    Requested,
    /// A scan is currently running
    Running,
    /// A scan has been stopped by a client
    Stopped,
    /// A scan could not finish due to an error while scanning
    Failed,
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
