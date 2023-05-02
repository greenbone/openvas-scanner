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
    /// Range for ports to scan.
    pub range: Vec<PortRange>,
}

/// Range for ports to scan.
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct PortRange {
    /// The required start port.
    ///
    /// It is an inclusive range.
    pub start: usize,
    /// The optional end port.
    ///
    /// It is an inclusive range.
    /// When the end port is not set, only the start port is used.
    #[cfg_attr(
        feature = "serde_support",
        serde(skip_serializing_if = "Option::is_none")
    )]
    pub end: Option<usize>,
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
