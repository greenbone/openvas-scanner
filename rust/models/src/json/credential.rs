use serde::{Deserialize, Serialize};

/// Represents a set of credentials to be used for scanning to access a host.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Credential {
    /// Service to use for accessing a host
    pub service: Service,
    /// Port used for getting access. If missing a standard port is used
    pub port: Option<u16>,
    #[serde(flatten)]
    /// Type of the credential to get access. Different services support different types.
    pub credential_type: CredentialType,
}

/// Enum of available services
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Service {
    #[serde(rename = "ssh")]
    /// SSH, supports [UP](CredentialType::UP) and [USK](CredentialType::USK) as credential types
    SSH,
    #[serde(rename = "smb")]
    /// SMB, supports [UP](CredentialType::UP)
    SMB,
    #[serde(rename = "esxi")]
    /// ESXi, supports [UP](CredentialType::UP)
    ESXi,
    #[serde(rename = "snmp")]
    /// SNMP, supports [SNMP](CredentialType::SNMP)
    SNMP,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
/// Enum representing the type of credentials.
pub enum CredentialType {
    #[serde(rename = "up")]
    /// User/password credentials.
    UP {
        /// The username for authentication.
        username: String,
        /// The password for authentication.
        password: String,
    },
    #[serde(rename = "usk")]
    /// User/ssh-key credentials.
    USK {
        /// The username for authentication.
        username: String,
        /// The password for authentication.
        password: String,
        #[serde(rename = "private")]
        /// The private key for authentication.
        private_key: String,
    },
    #[serde(rename = "snmp")]
    /// SNMP credentials.
    SNMP {
        /// The SNMP username.
        username: String,
        /// The SNMP password.
        password: String,
        /// The SNMP community string.
        community: String,
        /// The SNMP authentication algorithm.
        auth_algorithm: String,
        /// The SNMP privacy password.
        privacy_password: String,
        /// The SNMP privacy algorithm.
        privacy_algorithm: String,
    },
}
