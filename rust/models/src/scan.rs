// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use super::{scanner_preference::ScannerPreference, target::Target, vt::VT};

/// Struct for creating and getting a scan
#[derive(Default, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize),
    serde(deny_unknown_fields)
)]
pub struct Scan {
    #[cfg_attr(
        feature = "serde_support",
        serde(skip_serializing_if = "Option::is_none", skip_deserializing)
    )]
    /// Unique ID of a scan
    pub scan_id: Option<String>,
    /// Information about the target to scan
    pub target: Target,
    #[cfg_attr(
        feature = "serde_support",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    /// Configuration options for the scanner
    pub scanner_preferences: Vec<ScannerPreference>,
    /// List of VTs to execute for the target
    pub vts: Vec<VT>,
}
