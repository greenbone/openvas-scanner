// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use super::{credential::Credential, port::Port};

/// Information about a target of a scan
#[derive(Default, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct Target {
    /// List of hosts to scan
    pub hosts: Vec<String>,
    /// List of ports used for scanning
    pub ports: Vec<Port>,
    #[cfg_attr(feature = "serde_support", serde(default))]
    /// List of excluded hosts to scan
    pub excluded_hosts: Vec<String>,
    #[cfg_attr(feature = "serde_support", serde(default))]
    /// List of credentials used to get access to a system
    pub credentials: Vec<Credential>,
    #[cfg_attr(feature = "serde_support", serde(default))]
    /// List of ports used for alive testing
    pub alive_test_ports: Vec<Port>,
    #[cfg_attr(feature = "serde_support", serde(default))]
    /// Methods used for alive testing
    pub alive_test_methods: Vec<AliveTestMethods>,
    #[cfg_attr(feature = "serde_support", serde(default))]
    /// If multiple IP addresses resolve to the same DNS name the DNS name will only get scanned
    /// once.
    pub reverse_lookup_unify: Option<bool>,
    #[cfg_attr(feature = "serde_support", serde(default))]
    /// Only scan IP addresses that can be resolved into a DNS name.
    pub reverse_lookup_only: Option<bool>,
}

/// Enum of possible alive test methods
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(feature = "serde_support", serde(rename_all = "snake_case"))]
pub enum AliveTestMethods {
    TcpAck = 0x01,
    Icmp = 0x02,
    Arp = 0x04,
    ConsiderAlive = 0x08,
    TcpSyn = 0x10,
}
