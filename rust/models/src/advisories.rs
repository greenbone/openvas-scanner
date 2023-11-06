// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

/// Represents an Advisories json file for notus
#[cfg_attr(feature = "serde_support", derive(serde::Deserialize))]
#[derive(Debug)]
pub struct Advisories {
    /// Version of the file, some version might not be supported by notus
    pub version: String,
    /// Package type, important for parsing the corresponding package
    pub package_type: PackageType,
    /// List of advisories
    pub advisories: Vec<Advisory>,
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
}

/// Representing a single Advisory entry
#[cfg_attr(feature = "serde_support", derive(serde::Deserialize))]
#[derive(Debug)]
pub struct Advisory {
    /// OID to identify vulnerability
    pub oid: String,
    /// List of affected packages, including the fixed version
    pub fixed_packages: Vec<FixedPackage>,
}

/// Fixed Package entry
#[cfg_attr(feature = "serde_support", derive(serde::Deserialize))]
#[derive(Debug)]
pub struct FixedPackage {
    /// Name of the affected package
    pub name: String,
    /// Field containing information about vulnerable package version
    #[cfg_attr(feature = "serde_support", serde(flatten))]
    pub version: VersionEntry,
}

/// Version entry
#[cfg_attr(feature = "serde_support", derive(serde::Deserialize), serde(untagged))]
#[derive(Debug)]
pub enum VersionEntry {
    ByFullName {
        specifier: Specifier,
    },
    /// Contains a version and a specifier
    ByNameAndFullVersion {
        full_version: String,
        specifier: Specifier,
    },

    /// Contains a version Range
    ByRange {
        range: Range,
    },
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
