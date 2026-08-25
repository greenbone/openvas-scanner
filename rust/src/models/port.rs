// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception
use std::{collections::BTreeSet, fmt::Display, str::FromStr};

/// Represents a port representation for scanning.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Port {
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Protocol for the given port range. If empty, prot range applies to UDP and TCP
    pub protocol: Option<Protocol>,
    /// Range for ports to scan.
    pub range: Vec<PortRange>,
}

/// Range for ports to scan.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PortRange {
    /// The required start port.
    ///
    /// It is an inclusive range.
    pub start: usize,
    /// The optional end port.
    ///
    /// It is an inclusive range.
    /// When the end port is not set, only the start port is used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end: Option<usize>,
}

impl IntoIterator for PortRange {
    type Item = u16;

    type IntoIter = std::ops::RangeInclusive<u16>;

    fn into_iter(self) -> Self::IntoIter {
        let start = self.start as u16;
        let end = self.end.map(|end| end as u16).unwrap_or(start);
        start..=end
    }
}

impl From<PortRange> for Vec<u16> {
    fn from(port_range: PortRange) -> Self {
        port_range.into_iter().collect()
    }
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    UDP,
    TCP,
}

impl FromStr for Protocol {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "udp" => Ok(Protocol::UDP),
            "tcp" => Ok(Protocol::TCP),
            _ => Err(format!("Invalid protocol: {s}")),
        }
    }
}

impl Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::UDP => write!(f, "udp"),
            Protocol::TCP => write!(f, "tcp"),
        }
    }
}

impl AsRef<str> for Protocol {
    fn as_ref(&self) -> &str {
        match self {
            Protocol::TCP => "tcp",
            Protocol::UDP => "udp",
        }
    }
}

pub fn ports_to_openvas_port_list(ports: Vec<Port>) -> Option<String> {
    // This function creates the most compact representation of ports
    // for nmap. This is necessary, as nmap is called as an executable
    // during a scan on NASL side (feed). If the port list is too long,
    // nmap will fail to start, as the argument list is too long.
    // Check https://github.com/greenbone/openvas-scanner/issues/2223
    // for more details.
    fn compact(ports: &BTreeSet<usize>) -> String {
        let mut parts: Vec<String> = Vec::new();
        let mut start: Option<usize> = None;
        let mut prev: Option<usize> = None;
        for &port in ports {
            match prev {
                Some(p) if port == p + 1 => {}
                _ => {
                    if let (Some(s), Some(e)) = (start, prev) {
                        parts.push(if s == e {
                            s.to_string()
                        } else {
                            format!("{s}-{e}")
                        });
                    }
                    start = Some(port);
                }
            }
            prev = Some(port);
        }
        if let (Some(s), Some(e)) = (start, prev) {
            parts.push(if s == e {
                s.to_string()
            } else {
                format!("{s}-{e}")
            });
        }
        parts.join(",")
    }

    if ports.is_empty() {
        return None;
    }

    let mut tcp = BTreeSet::new();
    let mut udp = BTreeSet::new();

    for p in &ports {
        for r in &p.range {
            let range = r.start..=r.end.unwrap_or(r.start);
            match p.protocol {
                Some(Protocol::TCP) => tcp.extend(range),
                Some(Protocol::UDP) => udp.extend(range),
                None => {
                    tcp.extend(range.clone());
                    udp.extend(range);
                }
            }
        }
    }

    let mut port_list = String::new();
    if !tcp.is_empty() {
        port_list.push_str("T:");
        port_list.push_str(&compact(&tcp));
    }
    if !udp.is_empty() {
        if !port_list.is_empty() {
            port_list.push(',');
        }
        port_list.push_str("U:");
        port_list.push_str(&compact(&udp));
    }

    Some(port_list)
}

#[cfg(test)]
mod tests {

    use crate::models::{Port, PortRange, Protocol, ports_to_openvas_port_list};

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
                    PortRange {
                        start: 2000,
                        end: None,
                    },
                    PortRange {
                        start: 2001,
                        end: None,
                    },
                    PortRange {
                        start: 2002,
                        end: None,
                    },
                    PortRange {
                        start: 2003,
                        end: None,
                    },
                    PortRange {
                        start: 2004,
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
            Port {
                protocol: None,
                range: vec![PortRange {
                    start: 22,
                    end: None,
                }],
            },
            Port {
                protocol: None,
                range: vec![PortRange {
                    start: 24,
                    end: Some(32),
                }],
            },
        ];
        assert_eq!(
            ports_to_openvas_port_list(ports),
            Some("T:22-32,80,1000,2000-2004,U:22,24-40,1000,5060".to_string())
        );
    }

    #[test]
    fn test_very_deranged_ports() {
        let mut ports = vec![];
        for i in 1..=1000 {
            ports.push(Port {
                protocol: Some(Protocol::TCP),
                range: vec![PortRange {
                    start: i,
                    end: None,
                }],
            });
            ports.push(Port {
                protocol: Some(Protocol::TCP),
                range: vec![PortRange {
                    start: 65535 - i + 1,
                    end: None,
                }],
            });
        }

        assert_eq!(
            ports_to_openvas_port_list(ports),
            Some("T:1-1000,64536-65535".to_string())
        );
    }
}
