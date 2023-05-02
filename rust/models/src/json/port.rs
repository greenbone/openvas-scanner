use serde::{Deserialize, Serialize};

/// Represents a port representation for scanning.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Port {
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Protocol for the given port range. If empty, prot range applies to UDP and TCP
    protocol: Option<Protocol>,
    /// Range for ports to scan. A range is defined by
    /// range => <number>[-<number>][,<range>]
    range: String,
}

/// Enum representing the protocol used for scanning a port.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Protocol {
    #[serde(rename = "udp")]
    UDP,
    #[serde(rename = "tcp")]
    TCP,
}
