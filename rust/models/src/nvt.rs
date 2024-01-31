// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use core::fmt;

/// A VT to execute during a scan, including its parameters
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(feature = "bincode_support", derive(bincode::Encode, bincode::Decode))]
pub struct NVTI {
    pub name: String,
    pub custom: String,
    pub vt_params: String,
    pub vt_refs: String,
    pub vt_dependencies: String,
    pub creation_time: String,
    pub modification_time: String,
    pub summary: String,
    pub impact: String,
    pub affected: String,
    pub insight: String,
    pub solution: String,
    pub solution_method: String,
    pub detection: String,
    pub qod_type: Option<QodType>,
    pub qod: Option<String>,
    pub severity: NvtSeverity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(feature = "bincode_support", derive(bincode::Encode, bincode::Decode))]
pub enum SeverityType {
    CvssBaseV3,
    CvssBaseV2,

}
       
impl Default for SeverityType {
    fn default() -> Self { Self::CvssBaseV2 }
}

impl fmt::Display for SeverityType {
    fn fmt(&self, f:&mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::CvssBaseV2 => write!(f, "cvss_base_v2"),
            Self::CvssBaseV3 => write!(f, "cvss_base_v3"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(feature = "bincode_support", derive(bincode::Encode, bincode::Decode))]
pub struct NvtSeverity
{
    severity_type: SeverityType,
    severity_vector: String,
    severity_date: String,
    severity_origin: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(feature = "bincode_support", derive(bincode::Encode, bincode::Decode))]
pub enum QodType {
    ExecutableVersion,
    ExecutableVersionUnreliable,
    Exploit,
    GeneralNote,
    Package,
    Registry,
    RemoteActive,
    RemoteAnalysis,
    RemoteApp,
    RemoteBanner,
    RemoteBannerUnreliable,
    RemoteProbe,
    RemoteVul,
    PackageUnreliable,
}

impl Default for QodType {
    fn default() -> Self { QodType::GeneralNote }
}

impl fmt::Display for QodType {
    fn fmt(&self, f:&mut fmt::Formatter) -> fmt::Result {
        match self {
            QodType::ExecutableVersion => write!(f, "ExecutableVersion"),
            QodType::ExecutableVersionUnreliable => write!(f, "ExecutableVersionUnreliable"),
            QodType::Exploit => write!(f, "Exploit"),
            QodType::GeneralNote => write!(f, "GeneralNote"),
            QodType::Package => write!(f, "Package"),
            QodType::Registry => write!(f, "Registry"),
            QodType::RemoteActive => write!(f, "RemoteActive"),
            QodType::RemoteAnalysis => write!(f, "RemoteAnalysis"),
            QodType::RemoteApp => write!(f, "RemoteApp"),
            QodType::RemoteBanner => write!(f, "RemoteBanner"),
            QodType::RemoteBannerUnreliable => write!(f, "RemoteBannerUnreliable"),
            QodType::RemoteProbe => write!(f, "RemoteProbe"),
            QodType::RemoteVul => write!(f, "RemoteVul"),
            QodType::PackageUnreliable => write!(f, "PackageUnreliable"),
        }
    }
}


pub enum NvtiPos {
    Filename,
    RequiredKeys,
    MandatoryKeys,
    ExcludedKeys,
    RequiredUDPPorts,
    RequiredPorts,
    Dependencies,
    Tags,
    Cves,
    Bids,
    Xrefs,
    Category,
    Family,
    Name,
}
