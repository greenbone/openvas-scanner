use serde::{Deserialize, Serialize};

use super::{scanner_parameter::ScannerParameter, target::Target, vt::VT};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Scan {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan_id: Option<String>,
    pub target: Target,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanner_parameters: Option<Vec<ScannerParameter>>,
    pub vts: Vec<VT>,
}
