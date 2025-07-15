// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{collections::HashMap, ffi::os_str::Display};

use crate::models::Specifier;

use super::port::Protocol;

/// Scan result
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct Result {
    /// Incremental ID of a result
    pub id: usize,
    #[serde(rename = "type")]
    /// Type of the result
    pub r_type: ResultType,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    /// IP address
    pub ip_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    /// DNS
    pub hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    /// ID of the VT, which generated the result
    pub oid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    /// Port
    pub port: Option<i16>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    /// Protocol the port corresponds to
    pub protocol: Option<Protocol>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    /// Additional information
    pub message: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none", default)]
    /// Details are only set on status and can be ignored
    pub detail: Option<Detail>,
}

impl std::fmt::Display for ResultType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                ResultType::Alarm => "alarm",
                ResultType::Log => "log",
                ResultType::Error => "error",
                ResultType::HostStart => "host_start",
                ResultType::HostEnd => "host_end",
                ResultType::DeadHost => "dead_host",
                ResultType::HostDetail => "host_detail",
            }
        )
    }
}

impl From<&str> for ResultType {
    fn from(s: &str) -> Self {
        match s {
            "alarm" => ResultType::Alarm,
            "log" => ResultType::Log,
            "error" => ResultType::Error,
            "host_start" => ResultType::HostStart,
            "host_end" => ResultType::HostEnd,
            "dead_host" => ResultType::DeadHost,
            "host_detail" => ResultType::HostDetail,
            _ => ResultType::Log,
        }
    }
}

impl From<String> for ResultType {
    fn from(value: String) -> Self {
        ResultType::from(&value as &str)
    }
}

/// Host Details information
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct Detail {
    /// Descriptive name of a Host Detail
    pub name: String,
    /// Detected detail information
    pub value: String,
    /// Information about the source of the information
    pub source: Source,
}

/// Host details source information
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct Source {
    #[serde(rename = "type")]
    /// type of the source
    pub s_type: String,
    /// source reference, e.g. an OID in case of a nvt type
    pub name: String,
    /// description about the source
    pub description: String,
}

// is used for enumerate handling
impl<T: Into<Result>> From<(usize, T)> for Result {
    fn from(value: (usize, T)) -> Self {
        let mut result = value.1.into();
        result.id = value.0;
        result
    }
}

/// Enum of possible types of results
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultType {
    /// Vulnerability
    Alarm,
    /// Log message
    #[default]
    Log,
    /// Some error occurred during a scan
    Error,
    /// Information about the scan start of a host
    HostStart,
    /// Information about the scan end of a host
    HostEnd,
    /// Information about the scan dead host
    DeadHost,
    /// Detail information about the host
    HostDetail,
}

/// Notus Results are a Map from OIDs to vulnerable Packages
pub type NotusResults = HashMap<String, Vec<VulnerablePackage>>;

#[derive(serde::Serialize, Debug)]
pub struct VulnerablePackage {
    pub name: String,
    pub installed_version: String,
    pub fixed_version: FixedVersion,
}

#[derive(serde::Serialize, Debug)]
#[serde(untagged)]
pub enum FixedVersion {
    Single {
        version: String,
        specifier: Specifier,
    },
    Range {
        start: String,
        end: String,
    },
}
