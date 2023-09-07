// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later
use std::fmt::Display;

/// Represents a port representation for scanning.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(feature = "bincode_support", derive(bincode::Encode, bincode::Decode))]
pub struct Port {
    #[cfg_attr(
        feature = "serde_support",
        serde(skip_serializing_if = "Option::is_none")
    )]
    /// Protocol for the given port range. If empty, prot range applies to UDP and TCP
    pub protocol: Option<Protocol>,
    /// Range for ports to scan.
    pub range: Vec<PortRange>,
}

/// Range for ports to scan.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(feature = "bincode_support", derive(bincode::Encode, bincode::Decode))]
pub struct PortRange {
    /// The required start port.
    ///
    /// It is an inclusive range.
    pub start: usize,
    /// The optional end port.
    ///
    /// It is an inclusive range.
    /// When the end port is not set, only the start port is used.
    #[cfg_attr(
        feature = "serde_support",
        serde(skip_serializing_if = "Option::is_none")
    )]
    pub end: Option<usize>,
}

impl Display for PortRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.end {
            Some(end) => write!(f, "{}-{}", self.start, end),
            None => write!(f, "{}", self.start),
        }
    }
}

/// Enum representing the protocol used for scanning a port.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(feature = "bincode_support", derive(bincode::Encode, bincode::Decode))]
#[cfg_attr(feature = "serde_support", serde(rename_all = "lowercase"))]
pub enum Protocol {
    UDP,
    TCP,
}

impl TryFrom<&str> for Protocol {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.to_lowercase().as_str() {
            "udp" => Ok(Protocol::UDP),
            "tcp" => Ok(Protocol::TCP),
            _ => Err(format!("Invalid protocol: {}", value)),
        }
    }
}
