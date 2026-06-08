// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use super::{scanner_preference::ScanPreference, target::Target, vt::VT};

type ScanId = String;

/// Struct for creating and getting a scan
#[derive(Default, Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scan {
    #[serde(default)]
    /// Unique ID of a scan
    pub scan_id: ScanId,
    /// Information about the target to scan
    pub target: Target,
    #[serde(default, alias = "scanner_preferences")]
    /// Configuration options for a scan
    pub scan_preferences: Vec<ScanPreference>,
    /// List of VTs to execute for the target
    #[serde(default)]
    pub vts: Vec<VT>,
}
