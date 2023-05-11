// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use super::port::Protocol;

/// Scan result
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct Result {
    /// Incremental ID of a result
    pub id: usize,
    #[cfg_attr(feature = "serde_support", serde(rename = "type"))]
    /// Type of the result
    pub r_type: String,
    #[cfg_attr(
        feature = "serde_support",
        serde(skip_serializing_if = "Option::is_none")
    )]
    /// IP address
    pub ip_address: Option<String>,
    #[cfg_attr(
        feature = "serde_support",
        serde(skip_serializing_if = "Option::is_none")
    )]
    /// DNS
    pub hostname: Option<String>,
    #[cfg_attr(
        feature = "serde_support",
        serde(skip_serializing_if = "Option::is_none")
    )]
    /// ID of the VT, which generated the result
    pub oid: Option<String>,
    #[cfg_attr(
        feature = "serde_support",
        serde(skip_serializing_if = "Option::is_none")
    )]
    /// Port
    pub port: Option<i16>,
    #[cfg_attr(
        feature = "serde_support",
        serde(skip_serializing_if = "Option::is_none")
    )]
    /// Protocol the port corresponds to
    pub protocol: Option<Protocol>,
    #[cfg_attr(
        feature = "serde_support",
        serde(skip_serializing_if = "Option::is_none")
    )]
    /// Additional information
    pub message: Option<String>,
}

/// Enum of possible types of results
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(feature = "serde_support", serde(rename_all = "snake_case"))]
pub enum ResultType {
    /// Vulnerability
    Alarm,
    /// Log message
    Log,
    /// Some error occurred during a scan
    Error,
    /// Information about the scan start of a host
    HostStart,
    /// Information about the scan end of a host
    HostEnd,
}
