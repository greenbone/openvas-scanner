#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize)
)]
/// Represents a parameter for a VTS configuration.
pub struct Parameter {
    /// The ID of the parameter.
    pub id: u16,
    /// The value of the parameter.
    pub value: String,
}
