// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use super::parameter::Parameter;

/// A VT to execute during a scan, including its parameters
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Default,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct VT {
    /// The ID of the VT to execute
    pub oid: String,
    #[serde(default)]
    /// The list of parameters for the VT
    pub parameters: Vec<Parameter>,
}

/// Describes the type of the feed
#[derive(Clone, Debug, PartialEq, Eq, Copy, Hash)]
pub enum FeedType {
    /// Notus products
    Products,
    /// Notus advisories
    Advisories,
    /// NASL scripts
    NASL,
}

impl AsRef<str> for FeedType {
    fn as_ref(&self) -> &str {
        match self {
            FeedType::Products => "products",
            FeedType::Advisories => "advisories",
            FeedType::NASL => "nasl",
        }
    }
}

impl std::fmt::Display for FeedType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_ref())
    }
}

impl From<&str> for FeedType {
    fn from(value: &str) -> Self {
        match value {
            "products" => FeedType::Products,
            "advisories" => FeedType::Advisories,
            _ => FeedType::NASL,
        }
    }
}

impl From<String> for FeedType {
    fn from(value: String) -> Self {
        FeedType::from(&value as &str)
    }
}
