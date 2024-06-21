// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception
use std::fmt::Display;

/// Represents a port representation for scanning.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize)
)]
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

pub fn ports_to_openvas_port_list(ports: Vec<Port>) -> Option<String> {
    fn add_range_to_list(list: &mut String, start: usize, end: Option<usize>) {
        // Add range
        if let Some(end) = end {
            for p in start..=end {
                list.push_str(p.to_string().as_str());
                list.push(',');
            }

        // Add single port
        } else {
            list.push_str(start.to_string().as_str());
            list.push(',');
        }
    }
    if ports.is_empty() {
        return None;
    }

    let mut udp = String::from("U:");
    let mut tcp = String::from("T:");

    ports.iter().for_each(|p| match p.protocol {
        Some(Protocol::TCP) => {
            p.range
                .iter()
                .for_each(|r| add_range_to_list(&mut tcp, r.start, r.end));
        }
        Some(Protocol::UDP) => {
            p.range
                .iter()
                .for_each(|r| add_range_to_list(&mut udp, r.start, r.end));
        }
        None => {
            p.range
                .iter()
                .for_each(|r| add_range_to_list(&mut tcp, r.start, r.end));
            p.range
                .iter()
                .for_each(|r| add_range_to_list(&mut udp, r.start, r.end));
        }
    });
    let mut port_list = String::new();
    // both TCP and UDP
    if tcp != *"T:" && udp != *"U:" {
        port_list.push_str(&tcp);
        port_list.push_str(&udp);
    }
    // only UDP
    else if tcp == *"T:" && udp != *"U:" {
        port_list.push_str(&udp);
    } else if tcp != *"T:" && udp == *"U:" {
        port_list.push_str(&tcp);
    }

    Some(port_list)
}

#[cfg(test)]
mod tests {

    use crate::{ports_to_openvas_port_list, Port, PortRange, Protocol};

    #[test]
    fn test_port_conversion_to_string() {
        let ports = vec![
            Port {
                protocol: Some(Protocol::TCP),
                range: vec![
                    PortRange {
                        start: 22,
                        end: Some(25),
                    },
                    PortRange {
                        start: 80,
                        end: None,
                    },
                ],
            },
            Port {
                protocol: Some(Protocol::UDP),
                range: vec![
                    PortRange {
                        start: 30,
                        end: Some(40),
                    },
                    PortRange {
                        start: 5060,
                        end: None,
                    },
                ],
            },
            Port {
                protocol: None,
                range: vec![PortRange {
                    start: 1000,
                    end: None,
                }],
            },
        ];
        assert_eq!(
            ports_to_openvas_port_list(ports),
            Some("T:22,23,24,25,80,1000,U:30,31,32,33,34,35,36,37,38,39,40,5060,1000,".to_string())
        );
    }
}
