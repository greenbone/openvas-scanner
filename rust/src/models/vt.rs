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
