use serde::{Deserialize, Serialize};

use super::{scanner_parameter::ScannerParameter, target::Target, vt::VT};

/// Struct for creating and getting a scan
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Scan {
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Unique ID of a scan
    pub scan_id: Option<String>,
    /// Information about the target to scan
    pub target: Target,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Configuration options for the scanner
    pub scanner_parameters: Option<Vec<ScannerParameter>>,
    /// List of VTs to execute for the target
    pub vts: Vec<VT>,
}
