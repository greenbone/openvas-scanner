// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

/// Represents a set of credentials to be used for scanning to access a host.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Credential {
    /// Service to use for accessing a host
    pub service: Service,
    /// Port used for getting access. If missing a standard port is used
    pub port: Option<u16>,
    #[serde(flatten)]
    /// Type of the credential to get access. Different services support different types.
    pub credential_type: CredentialType,
}

impl Default for Credential {
    fn default() -> Self {
        Self {
            service: Service::SSH,
            port: Default::default(),
            credential_type: CredentialType::UP {
                username: "root".to_string(),
                password: "".to_string(),
                privilege: None,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PrivilegeInformation {
    #[serde(rename = "privilege_username")]
    pub username: String,
    #[serde(rename = "privilege_password")]
    pub password: String,
}

/// Enum of available services
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
    #[serde(rename = "krb5")]
    /// SNMP, supports [SNMP](CredentialType::SNMP)
    KRB5,
    #[serde(rename = "generic")]
    Generic,
}

impl AsRef<str> for Service {
    fn as_ref(&self) -> &str {
        match self {
            Service::SSH => "ssh",
            Service::SMB => "smb",
            Service::ESXi => "esxi",
            Service::SNMP => "snmp",
            Service::KRB5 => "krb5",
            Service::Generic => "generic",
        }
    }
}

impl TryFrom<&str> for Service {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(match value {
            "ssh" => Service::SSH,
            "smb" => Service::SMB,
            "esxi" => Service::ESXi,
            "snmp" => Service::SNMP,
            "krb5" => Service::KRB5,
            "generic" => Service::Generic,
            value => return Err(value.to_string()),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
/// Enum representing the type of credentials.
pub enum CredentialType {
    #[serde(rename = "up")]
    /// User/password credentials.
    UP {
        /// The username for authentication.
        username: String,
        /// The password for authentication.
        password: String,
        /// privilege credential only use for SSH service
        #[serde(default, flatten, skip_serializing_if = "Option::is_none")]
        privilege: Option<PrivilegeInformation>,
    },
    #[serde(rename = "usk")]
    /// User/ssh-key credentials.
    USK {
        /// The username for authentication.
        username: String,
        /// The password for authentication.
        // A key without passphrase can be expected
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<String>,
        #[serde(rename = "private")]
        /// The private key for authentication.
        private_key: String,
        /// privilege credential only use for SSH service
        #[serde(default, flatten, skip_serializing_if = "Option::is_none")]
        privilege: Option<PrivilegeInformation>,
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
    KRB5 {
        username: String,
        password: String,
        realm: String,
        kdc: String,
    },
}

impl AsRef<str> for CredentialType {
    fn as_ref(&self) -> &str {
        match self {
            CredentialType::UP { .. } => "up",
            CredentialType::USK { .. } => "usk",
            CredentialType::SNMP { .. } => "snmp",
            CredentialType::KRB5 { .. } => "krb5",
        }
    }
}
