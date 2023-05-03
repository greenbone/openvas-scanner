/// Configuration parameter for the scanner
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct ScannerParameter {
    /// The ID of the parameter.
    pub id: String,
    /// The value of the parameter.
    pub value: String,
}
