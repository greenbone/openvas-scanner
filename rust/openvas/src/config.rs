// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::time::Duration;

#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize),
    serde(deny_unknown_fields)
)]
pub struct Config {
    pub max_queued_scans: Option<usize>,
    pub max_running_scans: Option<usize>,
    pub min_free_mem: Option<u64>,
    pub check_interval: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_queued_scans: Default::default(),
            max_running_scans: Default::default(),
            min_free_mem: Default::default(),
            check_interval: Duration::from_secs(1),
        }
    }
}
