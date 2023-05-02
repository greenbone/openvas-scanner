use super::parameter::Parameter;

/// A VT to execute during a scan, including its parameters
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct VT {
    /// The ID of the VT to execute
    pub oid: String,
    #[cfg_attr(
        feature = "serde_support",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    /// The list of parameters for the VT
    pub parameters: Vec<Parameter>,
}
