// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::collections::HashMap;

use crate::Host;

#[derive(Default)]
pub struct HostInfoBuilder {
    pub all: u64,
    pub excluded: u64,
    pub dead: u64,
    pub alive: u64,
    pub queued: u64,
    pub finished: u64,
}

impl HostInfoBuilder {
    pub fn build(self) -> HostInfo {
        HostInfo {
            all: self.all,
            excluded: self.excluded,
            dead: self.dead,
            alive: self.alive,
            queued: self.queued,
            finished: self.finished,
            scanning: HashMap::new(),
        }
    }
}

/// Information about hosts of a running scan
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct HostInfo {
    all: u64,
    excluded: u64,
    dead: u64,
    alive: u64,
    queued: u64,
    finished: u64,
    // Hosts that are currently being scanned. The second entry is the number of
    // remaining VTs for this host.
    scanning: HashMap<String, usize>,
}

impl HostInfo {
    pub fn from_hosts_and_num_vts(hosts: &[Host], num_vts: usize) -> Self {
        Self {
            all: hosts.len() as u64,
            queued: hosts.len() as u64,
            scanning: hosts.iter().map(|host| (host.clone(), num_vts)).collect(),
            ..Default::default()
        }
    }

    pub fn register_finished_script(&mut self, target: &Host) {
        if let Some(num_vts) = self.scanning.get_mut(target) {
            *num_vts -= 1;
            if *num_vts == 0 {
                self.finished += 1;
                self.queued -= 1;
                self.scanning.remove(target);
            }
        }
    }

    pub fn finish(&mut self) {
        self.scanning.clear();
        assert_eq!(self.queued, 0);
    }

    pub fn queued(&self) -> u64 {
        self.queued
    }

    pub fn finished(&self) -> u64 {
        self.finished
    }

    pub fn update_with(mut self, other: &HostInfo) -> Self {
        // total hosts value is sent once
        if other.all != 0 {
            self.all = other.all;
        }
        // excluded hosts value is sent once
        if self.excluded == 0 {
            self.excluded = other.excluded;
        }
        // if new dead/alive/finished hosts are found during the scan,
        // the new count must be added to the previous one
        self.dead += other.dead;
        self.alive += other.alive;
        self.finished += other.finished;
        self.scanning = other.scanning.clone();
        self
    }
}
