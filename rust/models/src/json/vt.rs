use serde::{Deserialize, Serialize};

use super::parameter::Parameter;

/// A VT to execute during a scan, including its parameters
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VT {
    /// The ID of the VT to execute
    pub oid: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    /// The list of parameters for the VT
    pub parameters: Vec<Parameter>,
}
