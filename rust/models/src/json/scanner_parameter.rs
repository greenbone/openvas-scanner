use serde::{Deserialize, Serialize};

/// Represents a scanner parameter.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ScannerParameter {
    /// The ID of the parameter.
    pub id: String,
    /// The value of the parameter.
    pub value: String,
}
