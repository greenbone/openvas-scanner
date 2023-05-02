/// Represents a port representation for scanning.
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct Port {
    #[cfg_attr(
        feature = "serde_support",
        serde(skip_serializing_if = "Option::is_none")
    )]
    /// Protocol for the given port range. If empty, prot range applies to UDP and TCP
    pub protocol: Option<Protocol>,
    /// Range for ports to scan. A range is defined by
    /// range => <number>[-<number>][,<range>]
    pub range: String,
}

/// Enum representing the protocol used for scanning a port.
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(feature = "serde_support", serde(rename_all = "lowercase"))]
pub enum Protocol {
    UDP,
    TCP,
}
