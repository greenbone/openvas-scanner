use super::{credential::Credential, port::Port};

/// Information about a target of a scan
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct Target {
    /// List of hosts to scan
    pub hosts: Vec<String>,
    /// List of ports used for scanning
    pub ports: Vec<Port>,
    #[cfg_attr(
        feature = "serde_support",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    /// List of credentials used to get access to a system
    pub credentials: Vec<Credential>,
    #[cfg_attr(
        feature = "serde_support",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    /// List of ports used for alive testing
    pub alive_test_ports: Vec<Port>,
    #[cfg_attr(
        feature = "serde_support",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    /// Methods used for alive testing
    pub alive_test_methods: Vec<AliveTestMethods>,
    #[cfg_attr(
        feature = "serde_support",
        serde(skip_serializing_if = "Option::is_none")
    )]
    /// If multiple IP addresses resolve to the same DNS name the DNS name will only get scanned
    /// once.
    pub reverse_lookup_unify: Option<bool>,
    #[cfg_attr(
        feature = "serde_support",
        serde(skip_serializing_if = "Option::is_none")
    )]
    /// Only scan IP addresses that can be resolved into a DNS name.
    pub reverse_lookup_only: Option<bool>,
}

/// Enum of possible alive test methods
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(feature = "serde_support", serde(rename_all = "snake_case"))]
pub enum AliveTestMethods {
    Icmp,
    TcpSyn,
    TcpAck,
    Arp,
    ConsiderAlive,
}
