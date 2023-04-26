use serde::{Deserialize, Serialize};

use super::port::Protocol;

/// Scan result
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Result {
    /// Incremental ID of a result
    pub id: usize,
    #[serde(rename = "type")]
    /// Type of the result
    pub r_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// IP address
    pub ip_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// DNS
    pub hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// ID of the VT, which generated the result
    pub oid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Port
    pub port: Option<i16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Protocol the port corresponds to
    pub protocol: Option<Protocol>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Additional information
    pub message: Option<String>,
}

/// Enum of possible types of results
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ResultType {
    #[serde(rename = "alarm")]
    /// Vulnerability
    Alarm,
    #[serde(rename = "log")]
    /// Log message
    Log,
    #[serde(rename = "error")]
    /// Some error occurred during a scan
    Error,
    #[serde(rename = "host_start")]
    /// Information about the scan start of a host
    HostStart,
    #[serde(rename = "host_stop")]
    /// Information about the scan end of a host
    HostEnd,
}
