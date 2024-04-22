// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::collections::HashMap;

use crate::Specifier;

use super::port::Protocol;

/// Scan result
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct Result {
    /// Incremental ID of a result
    pub id: usize,
    #[cfg_attr(feature = "serde_support", serde(rename = "type"))]
    /// Type of the result
    pub r_type: ResultType,
    #[cfg_attr(
        feature = "serde_support",
        serde(skip_serializing_if = "Option::is_none", default)
    )]
    /// IP address
    pub ip_address: Option<String>,
    #[cfg_attr(
        feature = "serde_support",
        serde(skip_serializing_if = "Option::is_none", default)
    )]
    /// DNS
    pub hostname: Option<String>,
    #[cfg_attr(
        feature = "serde_support",
        serde(skip_serializing_if = "Option::is_none", default)
    )]
    /// ID of the VT, which generated the result
    pub oid: Option<String>,
    #[cfg_attr(
        feature = "serde_support",
        serde(skip_serializing_if = "Option::is_none", default)
    )]
    /// Port
    pub port: Option<i16>,
    #[cfg_attr(
        feature = "serde_support",
        serde(skip_serializing_if = "Option::is_none", default)
    )]
    /// Protocol the port corresponds to
    pub protocol: Option<Protocol>,
    #[cfg_attr(
        feature = "serde_support",
        serde(skip_serializing_if = "Option::is_none", default)
    )]
    /// Additional information
    pub message: Option<String>,

    #[cfg_attr(
        feature = "serde_support",
        serde(skip_serializing_if = "Option::is_none", default)
    )]
    pub detail: Option<Detail>,
}

/// Host Details information
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize)
)]

pub struct Detail {
    /// Descriptive name of a Host Detail
    pub name: String,
    /// Detected detail information
    pub value: String,
    /// Information about the source of the information
    pub source: Source,
}

/// Host details source information
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize)
)]
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
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(feature = "serde_support", serde(rename_all = "snake_case"))]
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

#[cfg_attr(feature = "serde_support", derive(serde::Serialize))]
#[derive(Debug)]
pub struct VulnerablePackage {
    pub name: String,
    pub installed_version: String,
    pub fixed_version: FixedVersion,
}

#[cfg_attr(feature = "serde_support", derive(serde::Serialize), serde(untagged))]
#[derive(Debug)]
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
