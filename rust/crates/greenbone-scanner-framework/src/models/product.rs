// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::fmt::Display;

use serde::Deserialize;

/// Represents an product json file for notus
#[derive(Deserialize, Debug)]
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
#[derive(Deserialize, Debug)]
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
    #[serde(rename = "alpm")]
    ALPM,
}

/// Representing a single Vulnerability Test entry
#[derive(Deserialize, Debug)]
pub struct VulnerabilityTest {
    /// OID to identify vulnerability
    pub oid: String,
    /// List of affected packages, including the fixed version
    pub fixed_packages: Vec<FixedPackage>,
}

/// Version entry
#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub enum FixedPackage {
    ByFullName {
        full_name: String,
        specifier: Specifier,
        module: Option<Module>,
    },
    /// Contains a version and a specifier
    ByNameAndFullVersion {
        name: String,
        full_version: String,
        specifier: Specifier,
        module: Option<Module>,
    },

    /// Contains a version Range
    ByRange {
        name: String,
        range: Range,
        module: Option<Module>,
    },
}

#[derive(Deserialize, Debug)]
pub struct Module {
    pub name: String,
    pub stream: String,
}

/// A specifier can be one of: >, <, >=, <=, =
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
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

impl AsRef<str> for Specifier {
    fn as_ref(&self) -> &str {
        match self {
            Specifier::GT => ">",
            Specifier::LT => "<",
            Specifier::GE => ">=",
            Specifier::LE => "<=",
            Specifier::EQ => "=",
        }
    }
}

impl Display for Specifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_ref())
    }
}

/// Version range
#[derive(Deserialize, Debug)]
pub struct Range {
    pub start: String,
    pub end: String,
}
