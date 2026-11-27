pub(crate) mod docker_v2_registry;
use std::fmt::Display;

use futures::{Stream, StreamExt};
use sqlx::{Row, sqlite::SqliteRow};

use crate::{
    crypt::{Crypt, Encrypted},
    database::dao::DAOError,
};
use scannerlib::models;

pub(crate) use super::PackedLayer;

#[derive(Clone, Debug, PartialEq)]
pub struct Credential {
    pub username: String,
    pub password: String,
}

impl Credential {
    pub async fn from_sqlrow<C: Crypt>(
        row: &SqliteRow,
        crypter: &C,
    ) -> anyhow::Result<Vec<Credential>> {
        let auth_data: String = row.get("auth_data");
        let encrypted = Encrypted::try_from(auth_data)?;
        let auth_data = crypter
            .decrypt(encrypted)
            .await
            .map_err(|_| DAOError::Corrupt)?;
        let credentials = serde_json::from_slice::<Vec<models::Credential>>(&auth_data)?
            .iter()
            .filter_map(|x| match &x.credential_type {
                models::CredentialType::UP {
                    username,
                    password,
                    #[allow(unused_variables)]
                    privilege,
                } => Some(Credential {
                    username: username.clone(),
                    password: password.clone(),
                }),
                _ => None,
            })
            .collect();

        Ok(credentials)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum RegistryPreference {
    /// Allows falling back to an insecure connection when HTTPS is unavailable
    Insecure,
    /// Allows the usage of invalid certificates
    AcceptInvalidCerts,
}

impl RegistryPreference {
    #[cfg(test)]
    pub fn key(&self) -> &str {
        match self {
            RegistryPreference::Insecure => "registry_allow_insecure",
            RegistryPreference::AcceptInvalidCerts => "accept_invalid_certs",
        }
    }
}

impl RegistryPreference {
    pub(crate) fn parse_preference_entry(key: &str, value: &str) -> Option<RegistryPreference> {
        match key {
            "registry_allow_insecure" if value.parse().unwrap_or_default() => Some(Self::Insecure),
            "accept_invalid_certs" if value.parse().unwrap_or_default() => {
                Some(Self::AcceptInvalidCerts)
            }
            _ => None,
        }
    }

    pub async fn parse_preferences(
        preferences: impl Stream<Item = (String, String)>,
    ) -> Vec<RegistryPreference> {
        preferences
            .filter_map(
                |(k, v)| async move { Self::parse_preference_entry(k.as_ref(), v.as_ref()) },
            )
            .collect()
            .await
    }
}

#[derive(Debug)]
pub enum InvalidData {
    NoRepositoryInformation,
    MissingTag,
}

impl Display for InvalidData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InvalidData::NoRepositoryInformation => {
                f.write_str("No repository (image) information provided.")
            }
            InvalidData::MissingTag => f.write_str("Missing tag information."),
        }
    }
}

#[derive(Debug)]
pub enum RegistryErrorKind {
    InvalidData(InvalidData),
    Authentication { scope: String },
    Catalog,
    Tag,
    Blob,
    Manifest,
}

impl Display for RegistryErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegistryErrorKind::Authentication { scope } => write!(f, "authentication ({scope})"),
            RegistryErrorKind::Catalog => f.write_str("catalog"),
            RegistryErrorKind::Tag => f.write_str("tag"),
            RegistryErrorKind::Blob => f.write_str("blob"),
            RegistryErrorKind::Manifest => f.write_str("manifest"),
            RegistryErrorKind::InvalidData(invalid_data) => {
                write!(f, "Invalid data provided: {invalid_data}")
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub struct RegistryError {
    pub registry: Option<String>,
    pub kind: RegistryErrorKind,
    pub status_code: Option<u16>,
}

impl RegistryError {
    pub fn invalid_data(id: InvalidData) -> Self {
        Self {
            registry: None,
            kind: RegistryErrorKind::InvalidData(id),
            status_code: None,
        }
    }

    pub fn no_repository() -> RegistryError {
        Self::invalid_data(InvalidData::NoRepositoryInformation)
    }

    pub fn no_tag() -> RegistryError {
        Self::invalid_data(InvalidData::MissingTag)
    }

    pub fn needs_reauthentication(&self) -> bool {
        self.status_code
            .map(|x| x == 401 || x == 403)
            .unwrap_or_default()
    }

    pub fn can_retry(&self) -> bool {
        if let Some(sc) = self.status_code {
            // on 500 we retry
            sc > 499 && sc < 600 || self.needs_reauthentication()
        } else {
            // unfortunately we don't get a status code but a invalid body error back from the
            // library, hence that special treatment.
            matches!(self.kind, RegistryErrorKind::Blob)
        }
    }
}

impl Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = &self.kind;
        if let Some(registry) = self.registry.as_ref() {
            let registry_msg = format!("Error occurred on {registry} while operating on {kind}");
            if let Some(sc) = self.status_code {
                write!(f, "{registry_msg}: unexpected status code ({sc})")
            } else {
                write!(f, "{registry_msg}")
            }
        } else {
            write!(f, "Error occurred while operating on {kind}")
        }
    }
}

#[cfg(test)]
pub mod tests {
    use scannerlib::models;

    use crate::{
        config::SqliteConfiguration,
        container_image_scanner::{image::Credential, scheduling::db::tests::create_pool},
        crypt::{Crypt, Crypter},
    };

    #[tokio::test]
    async fn multiple_credentials_storage() {
        let (pool, _guard) = create_pool().await;
        let crypter = Crypter::from_config(&SqliteConfiguration::default(), &pool)
            .await
            .unwrap();

        let credentials = vec![
            models::Credential {
                service: models::Service::Generic,
                port: None,
                credential_type: models::CredentialType::UP {
                    username: "user".to_string(),
                    password: "pass".to_string(),
                    privilege: None,
                },
            },
            models::Credential {
                service: models::Service::Generic,
                port: None,
                credential_type: models::CredentialType::UP {
                    username: "foo".to_string(),
                    password: "bar".to_string(),
                    privilege: None,
                },
            },
        ];

        let bytes = serde_json::to_vec(&credentials).unwrap();
        let auth_data = crypter.encrypt(bytes).await.unwrap().to_string();

        let id = sqlx::query("INSERT INTO scans(scan_id, client_id, status, auth_data, host_all, host_queued, host_alive, host_dead) VALUES (?, ?, 'running', ?, 3, 0, 2, 1)")
            .bind("scan1")
            .bind("client1")
            .bind(auth_data)
            .execute(&pool)
            .await
            .unwrap()
            .last_insert_rowid();

        let row = sqlx::query("SELECT auth_data FROM scans WHERE id = ?")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();

        // conversion from [models::Credential] to [image::Credential]
        let result = Credential::from_sqlrow(&row, &crypter).await.unwrap();
        assert_eq!(
            result,
            vec![
                Credential {
                    username: "user".to_string(),
                    password: "pass".to_string()
                },
                Credential {
                    username: "foo".to_string(),
                    password: "bar".to_string()
                },
            ]
        )
    }
}
