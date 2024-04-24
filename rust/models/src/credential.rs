// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

/// Represents a set of credentials to be used for scanning to access a host.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct Credential {
    /// Service to use for accessing a host
    pub service: Service,
    /// Port used for getting access. If missing a standard port is used
    pub port: Option<u16>,
    #[cfg_attr(feature = "serde_support", serde(flatten))]
    /// Type of the credential to get access. Different services support different types.
    pub credential_type: CredentialType,
}

impl Credential {
    /// Maps the password of the credential using the given closure.
    pub fn map_password<F, E>(self, f: F) -> Result<Self, E>
    where
        F: Fn(String) -> Result<String, E>,
    {
        Ok(Credential {
            service: self.service,
            port: self.port,
            credential_type: self.credential_type.map_password(f)?,
        })
    }

    /// Gets the password of the credential.
    pub fn password(&self) -> &str {
        match &self.credential_type {
            CredentialType::UP { password, .. } => password,
            CredentialType::USK { password, .. } => password,
            CredentialType::SNMP { password, .. } => password,
        }
    }
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

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct PrivilegeInformation {
    #[cfg_attr(feature = "serde_support", serde(rename = "privilege_username"))]
    pub username: String,
    #[cfg_attr(feature = "serde_support", serde(rename = "privilege_password"))]
    pub password: String,
}

/// Enum of available services
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize)
)]
pub enum Service {
    #[cfg_attr(feature = "serde_support", serde(rename = "ssh"))]
    /// SSH, supports [UP](CredentialType::UP) and [USK](CredentialType::USK) as credential types
    SSH,
    #[cfg_attr(feature = "serde_support", serde(rename = "smb"))]
    /// SMB, supports [UP](CredentialType::UP)
    SMB,
    #[cfg_attr(feature = "serde_support", serde(rename = "esxi"))]
    /// ESXi, supports [UP](CredentialType::UP)
    ESXi,
    #[cfg_attr(feature = "serde_support", serde(rename = "snmp"))]
    /// SNMP, supports [SNMP](CredentialType::SNMP)
    SNMP,
}

impl AsRef<str> for Service {
    fn as_ref(&self) -> &str {
        match self {
            Service::SSH => "ssh",
            Service::SMB => "smb",
            Service::ESXi => "esxi",
            Service::SNMP => "snmp",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize)
)]
/// Enum representing the type of credentials.
pub enum CredentialType {
    #[cfg_attr(feature = "serde_support", serde(rename = "up"))]
    /// User/password credentials.
    UP {
        /// The username for authentication.
        username: String,
        /// The password for authentication.
        password: String,
        /// privilege credential only use for SSH service
        #[cfg_attr(
            feature = "serde_support",
            serde(default, flatten, skip_serializing_if = "Option::is_none")
        )]
        privilege: Option<PrivilegeInformation>,
    },
    #[cfg_attr(feature = "serde_support", serde(rename = "usk"))]
    /// User/ssh-key credentials.
    USK {
        /// The username for authentication.
        username: String,
        /// The password for authentication.
        password: String,
        #[cfg_attr(feature = "serde_support", serde(rename = "private"))]
        /// The private key for authentication.
        private_key: String,
        /// privilege credential only use for SSH service
        #[cfg_attr(
            feature = "serde_support",
            serde(default, flatten, skip_serializing_if = "Option::is_none")
        )]
        privilege: Option<PrivilegeInformation>,
    },
    #[cfg_attr(feature = "serde_support", serde(rename = "snmp"))]
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

impl CredentialType {
    /// Uses given closure to transform the password of the credential.
    pub fn map_password<F, E>(self, f: F) -> Result<Self, E>
    where
        F: Fn(String) -> Result<String, E>,
    {
        Ok(match self {
            CredentialType::UP {
                username,
                password,
                privilege,
            } => CredentialType::UP {
                username,
                password: f(password)?,
                privilege: match privilege {
                    Some(p) => Some(PrivilegeInformation {
                        username: p.username,
                        password: f(p.password)?,
                    }),
                    None => None,
                },
            },
            CredentialType::USK {
                username,
                password,
                private_key,
                privilege,
            } => CredentialType::USK {
                username,
                password: f(password)?,
                private_key: f(private_key)?,
                privilege: match privilege {
                    Some(p) => Some(PrivilegeInformation {
                        username: p.username,
                        password: f(p.password)?,
                    }),
                    None => None,
                },
            },
            CredentialType::SNMP {
                username,
                password,
                community,
                auth_algorithm,
                privacy_password,
                privacy_algorithm,
            } => CredentialType::SNMP {
                username,
                password: f(password)?,
                community,
                auth_algorithm,
                privacy_password: f(privacy_password)?,
                privacy_algorithm,
            },
        })
    }
}

impl AsRef<str> for CredentialType {
    fn as_ref(&self) -> &str {
        match self {
            CredentialType::UP { .. } => "up",
            CredentialType::USK { .. } => "usk",
            CredentialType::SNMP { .. } => "snmp",
        }
    }
}
