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
#[cfg_attr(feature = "bincode_support", derive(bincode::Encode, bincode::Decode))]
pub struct Scan {
    #[cfg_attr(feature = "serde_support", serde(default))]
    /// Unique ID of a scan
    pub scan_id: Option<String>,
    /// Information about the target to scan
    pub target: Target,
    #[cfg_attr(feature = "serde_support", serde(default))]
    /// Configuration options for the scanner
    pub scanner_preferences: Vec<ScannerPreference>,
    /// List of VTs to execute for the target
    pub vts: Vec<VT>,
}
