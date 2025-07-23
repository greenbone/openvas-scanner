// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::time::Duration;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    max_queued_scans: Option<usize>,
    max_running_scans: Option<usize>,
    min_free_mem: Option<u64>,
    check_interval: Duration,
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
