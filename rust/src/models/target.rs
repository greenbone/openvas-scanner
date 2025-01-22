// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::fmt::{Display, Formatter};

use super::{credential::Credential, port::Port};

pub type Host = String;

/// Information about a target of a scan
#[derive(Default, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct Target {
    /// List of hosts to scan
    pub hosts: Vec<Host>,
    /// List of ports used for scanning
    pub ports: Vec<Port>,
    #[cfg_attr(feature = "serde_support", serde(default))]
    /// List of excluded hosts to scan
    pub excluded_hosts: Vec<Host>,
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

#[derive(Debug, thiserror::Error)]
pub enum AliveTestMethodsError {
    #[error("Invalid value for AliveTestMethods: {0:#04x}")]
    InvalidValue(u8),
}

impl TryFrom<u8> for AliveTestMethods {
    type Error = AliveTestMethodsError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(AliveTestMethods::TcpAck),
            0x02 => Ok(AliveTestMethods::Icmp),
            0x04 => Ok(AliveTestMethods::Arp),
            0x08 => Ok(AliveTestMethods::ConsiderAlive),
            0x10 => Ok(AliveTestMethods::TcpSyn),
            _ => Err(AliveTestMethodsError::InvalidValue(value)),
        }
    }
}

impl Display for AliveTestMethods {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            AliveTestMethods::TcpAck => write!(f, "tcp_ack"),
            AliveTestMethods::Icmp => write!(f, "icmp"),
            AliveTestMethods::Arp => write!(f, "arp"),
            AliveTestMethods::ConsiderAlive => write!(f, "consider_alive"),
            AliveTestMethods::TcpSyn => write!(f, "tcp_syn"),
        }
    }
}
