// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{fmt::Display, str::FromStr};

use super::host_info::HostInfo;

/// Status information about a scan
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Status {
    /// Timestamp for the start of a scan
    pub start_time: Option<u64>,
    /// Timestamp for the end of a scan
    pub end_time: Option<u64>,
    /// The phase, a scan is currently in
    pub status: Phase,
    /// Information about the hosts of a running scan
    pub host_info: Option<HostInfo>,
}

impl Status {
    pub fn is_running(&self) -> bool {
        self.status.is_running()
    }

    pub fn is_done(&self) -> bool {
        !self.is_running() && self.status != Phase::Stored
    }

    pub fn update_with(&mut self, status: &Status) {
        if let Some(ref host_info) = status.host_info {
            self.host_info = Some(
                self.host_info
                    .clone()
                    .unwrap_or_default()
                    .update_with(host_info),
            );
        }

        // Update start and end time if set from openvas
        if status.start_time.is_some() {
            self.start_time = status.start_time;
        }

        if status.end_time.is_some() {
            self.end_time = status.end_time;
        }
    }
}

/// Enum of the possible phases of a scan
#[derive(
    Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize, PartialOrd, Ord,
)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// A scan has been stored but not started yet
    #[default]
    Stored,
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

impl Phase {
    pub fn is_running(&self) -> bool {
        matches!(self, Self::Running | Self::Requested)
    }
}

#[derive(thiserror::Error, Debug, Clone)]
pub enum PhaseError {
    #[error("Unknown phase: {0}")]
    UnknownPhase(String),
}

impl FromStr for Phase {
    type Err = PhaseError;

    fn from_str(status: &str) -> Result<Phase, PhaseError> {
        match status {
            "requested" => Ok(Phase::Requested),
            "running" => Ok(Phase::Running),
            "stopped" => Ok(Phase::Stopped),
            "failed" => Ok(Phase::Failed),
            "succeeded" => Ok(Phase::Succeeded),
            "stored" => Ok(Phase::Stored),
            a => Err(PhaseError::UnknownPhase(a.to_string())),
        }
    }
}

impl AsRef<str> for Phase {
    fn as_ref(&self) -> &str {
        match self {
            Self::Requested => "requested",
            Self::Running => "running",
            Self::Stopped => "stopped",
            Self::Failed => "failed",
            Self::Succeeded => "succeeded",
            Self::Stored => "stored",
        }
    }
}
impl Display for Phase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_ref())
    }
}
