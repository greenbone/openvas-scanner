// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

/// Represents an product json file for notus
#[derive(serde::Deserialize, Debug)]
pub struct Product {
    /// Version of the file, some version might not be supported by notus
    pub version: String,
    /// Package type, important for parsing the corresponding package
    pub package_type: PackageType,
    /// List of vulnerability tests for product
    #[serde(rename = "advisories")]
    pub vulnerability_tests: Vec<VulnerabilityTest>,
}

/// Enum of supported package types
#[derive(serde::Deserialize, Debug)]
pub enum PackageType {
    #[serde(rename = "deb")]
    DEB,
    #[serde(rename = "ebuild")]
    EBUILD,
    #[serde(rename = "rpm")]
    RPM,
    #[serde(rename = "slack")]
    SLACK,
    #[serde(rename = "msp")]
    MSP,
}

/// Representing a single Vulnerability Test entry
#[derive(serde::Deserialize, Debug)]
pub struct VulnerabilityTest {
    /// OID to identify vulnerability
    pub oid: String,
    /// List of affected packages, including the fixed version
    pub fixed_packages: Vec<FixedPackage>,
}

/// Version entry
#[derive(serde::Deserialize)]
#[serde(untagged)]
#[derive(Debug)]
pub enum FixedPackage {
    ByFullName {
        full_name: String,
        specifier: Specifier,
    },
    /// Contains a version and a specifier
    ByNameAndFullVersion {
        name: String,
        full_version: String,
        specifier: Specifier,
    },

    /// Contains a version Range
    ByRange { name: String, range: Range },
}

/// A specifier can be one of: >, <, >=, <=, =
#[derive(serde::Deserialize, serde::Serialize, Clone, Debug)]
pub enum Specifier {
    /// >
    #[serde(rename = ">")]
    GT,
    /// <
    #[serde(rename = "<")]
    LT,
    /// >=
    #[serde(rename = ">=")]
    GE,
    /// <=
    #[serde(rename = "<=")]
    LE,
    /// =
    #[serde(rename = "=")]
    EQ,
}

/// Version range
#[derive(serde::Deserialize, Debug)]
pub struct Range {
    pub start: String,
    pub end: String,
}
