// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::scanner::preferences::preference::ScanPrefs;

use super::{target::Target, vt::VT};

pub type ScanID = String;

/// Struct for creating and getting a scan
#[derive(Default, Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Scan {
    #[serde(default)]
    /// Unique ID of a scan
    pub scan_id: ScanID,
    /// Information about the target to scan
    pub target: Target,
    #[serde(default, alias = "scanner_preferences")]
    /// Configuration options for a scan
    pub scan_preferences: ScanPrefs,
    /// List of VTs to execute for the target
    pub vts: Vec<VT>,
}
