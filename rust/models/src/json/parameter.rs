use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
/// Represents a parameter for a VTS configuration.
pub struct Parameter {
    /// The ID of the parameter.
    pub id: u16,
    /// The value of the parameter.
    pub value: String,
}
