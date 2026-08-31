// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::collections::HashMap;

use super::Host;

/// Information about hosts of a running scan
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HostInfo {
    pub all: u64,
    pub excluded: u64,
    pub dead: u64,
    pub alive: u64,
    pub queued: u64,
    pub finished: u64,
    // Hosts that are currently being scanned. The second entry is the host
    // scan progress. Required for Openvas Scanner type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanning: Option<HashMap<String, i32>>,
    // Hosts that are currently being scanned. The second entry is the number of
    // remaining VTs for this host.
    #[serde(skip_serializing, default)]
    pub remaining_vts_per_host: HashMap<String, usize>,
}

impl HostInfo {
    pub fn from_hosts_and_num_vts<'a>(
        targets: impl Iterator<Item = &'a str>,
        num_vts: usize,
    ) -> Self {
        let hosts: HashMap<_, _> = targets
            .map(|target| (target.to_string(), num_vts))
            .collect();
        Self {
            all: hosts.len() as u64,
            queued: hosts.len() as u64,
            remaining_vts_per_host: hosts,
            ..Default::default()
        }
    }

    pub fn register_started_host(&mut self, target: &Host) {
        if !self.remaining_vts_per_host.contains_key(target) {
            return;
        }
        let scanning = self.scanning.get_or_insert_with(HashMap::new);
        if scanning.contains_key(target) {
            return;
        }
        scanning.insert(target.clone(), 0);
        self.queued = self.queued.saturating_sub(1);
    }

    pub fn register_finished_script(&mut self, target: &Host) -> bool {
        if let Some(num_vts) = self.remaining_vts_per_host.get_mut(target) {
            *num_vts -= 1;
            if *num_vts == 0 {
                self.finished += 1;
                self.alive += 1;
                self.remaining_vts_per_host.remove(target);
                // one host less in the queued counter, even if it was not scanned (no vts, dead)
                if let Some(scanning) = self.scanning.as_mut() {
                    if scanning.remove(target).is_none() {
                        self.queued = self.queued.saturating_sub(1);
                    }
                } else {
                    self.queued = self.queued.saturating_sub(1);
                }
                return true;
            }
        }
        false
    }

    pub fn finish(&mut self) {
        self.remaining_vts_per_host.clear();
    }

    // Used by openvasd scanner when using Boreas.
    pub fn mark_hosts_dead<'a>(&mut self, hosts: impl Iterator<Item = &'a str>) {
        for host in hosts {
            if self.remaining_vts_per_host.remove(host).is_some() {
                self.dead += 1;
                self.queued -= 1;
            }
        }
    }

    pub fn update_with(mut self, other: &HostInfo) -> Self {
        // total hosts value is sent once and only once must be updated
        if other.all != 0 {
            self.all = other.all;
        }
        // excluded hosts value is sent once and only once must be updated
        if self.excluded == 0 {
            self.excluded = other.excluded;
        }
        // new dead/alive/finished hosts are found during the scan.
        // the new count must be added to the previous one
        self.dead += other.dead;
        self.alive += other.alive;
        self.finished += other.finished;

        // Update each single host status. Remove it if finished.
        // Openvas doesn't keep the previous progress. Therefore
        // the values already stored in Openvasd must be updated
        // and never completely replaced.
        let mut hs = other.scanning.clone().unwrap_or_default();
        for (host, progress) in self.scanning.clone().unwrap_or_default().iter() {
            if *progress == 100 || *progress == -1 {
                hs.remove(host);
            } else {
                hs.insert(host.to_string(), *progress);
            }
        }
        self.scanning = Some(hs);
        self
    }
}
