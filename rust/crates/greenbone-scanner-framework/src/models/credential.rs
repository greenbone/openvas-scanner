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
    /// KRB5, supports [KRB5](CredentialType::KRB5)
    KRB5,
    #[serde(rename = "generic")]
    Generic,
}

impl Service {
    pub fn to_str(&self) -> &str {
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

impl std::fmt::Display for Service {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_str())
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
    #[serde(rename = "krb5")]
    /// KRB5 credentials.
    KRB5 {
        username: String,
        password: String,
        realm: String,
        kdc: String,
    },
}

impl CredentialType {
    pub fn to_str(&self) -> &str {
        match self {
            CredentialType::UP { .. } => "up",
            CredentialType::USK { .. } => "usk",
            CredentialType::SNMP { .. } => "snmp",
            CredentialType::KRB5 { .. } => "krb5",
        }
    }
}

impl std::fmt::Display for CredentialType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

impl CredentialType {
    pub fn hide_pass(&mut self) -> Self {
        match self {
            CredentialType::UP {
                username,
                privilege,
                ..
            } => {
                let pr = match privilege {
                    Some(x) => Some(PrivilegeInformation {
                        username: x.username.clone(),
                        password: "".to_string(),
                    }),
                    None => None,
                };

                Self::UP {
                    username: username.to_string(),
                    password: "".to_string(),
                    privilege: pr,
                }
            }
            CredentialType::USK {
                username,
                password,
                privilege,
                private_key,
            } => {
                let pr = match privilege {
                    Some(x) => Some(PrivilegeInformation {
                        username: x.username.clone(),
                        password: "".to_string(),
                    }),
                    None => None,
                };
                if let Some(p) = password.as_mut() {
                    p.clear();
                };

                CredentialType::USK {
                    username: username.to_string(),
                    password: password.clone(),
                    privilege: pr,
                    private_key: private_key.to_string(),
                }
            }
            CredentialType::SNMP {
                username,
                auth_algorithm,
                privacy_algorithm,
                community,
                ..
            } => CredentialType::SNMP {
                username: username.to_string(),
                password: "".to_string(),
                privacy_password: "".to_string(),
                privacy_algorithm: privacy_algorithm.to_string(),
                auth_algorithm: auth_algorithm.to_string(),
                community: community.to_string(),
            },

            CredentialType::KRB5 {
                username,
                realm,
                kdc,
                ..
            } => CredentialType::KRB5 {
                username: username.to_string(),
                password: String::new(),
                realm: realm.to_string(),
                kdc: kdc.to_string(),
            },
        }
    }
}

impl Credential {
    pub fn hide_pass(mut self) -> Self {
        Self {
            credential_type: self.credential_type.hide_pass(),
            ..self
        }
    }
}
