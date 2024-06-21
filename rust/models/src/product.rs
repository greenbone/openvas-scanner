// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

/// Represents an product json file for notus
#[cfg_attr(feature = "serde_support", derive(serde::Deserialize))]
#[derive(Debug)]
pub struct Product {
    /// Version of the file, some version might not be supported by notus
    pub version: String,
    /// Package type, important for parsing the corresponding package
    pub package_type: PackageType,
    /// List of vulnerability tests for product
    #[cfg_attr(feature = "serde_support", serde(rename = "advisories"))]
    pub vulnerability_tests: Vec<VulnerabilityTest>,
}

/// Enum of supported package types
#[cfg_attr(feature = "serde_support", derive(serde::Deserialize))]
#[derive(Debug)]
pub enum PackageType {
    #[cfg_attr(feature = "serde_support", serde(rename = "deb"))]
    DEB,
    #[cfg_attr(feature = "serde_support", serde(rename = "ebuild"))]
    EBUILD,
    #[cfg_attr(feature = "serde_support", serde(rename = "rpm"))]
    RPM,
    #[cfg_attr(feature = "serde_support", serde(rename = "slack"))]
    SLACK,
    #[cfg_attr(feature = "serde_support", serde(rename = "msp"))]
    MSP,
}

/// Representing a single Vulnerability Test entry
#[cfg_attr(feature = "serde_support", derive(serde::Deserialize))]
#[derive(Debug)]
pub struct VulnerabilityTest {
    /// OID to identify vulnerability
    pub oid: String,
    /// List of affected packages, including the fixed version
    pub fixed_packages: Vec<FixedPackage>,
}

/// Version entry
#[cfg_attr(feature = "serde_support", derive(serde::Deserialize), serde(untagged))]
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
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Deserialize, serde::Serialize)
)]
#[derive(Clone, Debug)]
pub enum Specifier {
    /// >
    #[cfg_attr(feature = "serde_support", serde(rename = ">"))]
    GT,
    /// <
    #[cfg_attr(feature = "serde_support", serde(rename = "<"))]
    LT,
    /// >=
    #[cfg_attr(feature = "serde_support", serde(rename = ">="))]
    GE,
    /// <=
    #[cfg_attr(feature = "serde_support", serde(rename = "<="))]
    LE,
    /// =
    #[cfg_attr(feature = "serde_support", serde(rename = "="))]
    EQ,
}

/// Version range
#[cfg_attr(feature = "serde_support", derive(serde::Deserialize))]
#[derive(Debug)]
pub struct Range {
    pub start: String,
    pub end: String,
}
