pub(crate) mod docker_v2;
use std::fmt::Display;

pub use docker_v2::Registry as DockerV2;

use super::Image;
pub(crate) use super::PackedLayer;
use crate::container_image_scanner::{ParsePreferences, PinBoxFutRef, Streamer};

#[derive(Clone, Debug)]
pub struct Credential {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Setting {
    /// Allows the usage of insecure connections
    Insecure,
    /// Allows the usage of invalid certificates
    AcceptInvalidCerts,
}

impl Setting {
    #[cfg(test)]
    pub fn preference_key(&self) -> &str {
        match self {
            Setting::Insecure => "registry_allow_insecure",
            Setting::AcceptInvalidCerts => "accept_invalid_certs",
        }
    }
}

impl ParsePreferences<Setting> for Setting {
    fn parse_preference_entry(key: &str, value: &str) -> Option<Setting> {
        match key {
            "registry_allow_insecure" if value.parse().unwrap_or_default() => Some(Self::Insecure),
            "accept_invalid_certs" if value.parse().unwrap_or_default() => {
                Some(Self::AcceptInvalidCerts)
            }
            _ => None,
        }
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
            let registry_msg = format!("Error occured on {registry} while operating on {kind}");
            if let Some(sc) = self.status_code {
                write!(f, "{registry_msg}: unexpected status code ({sc})")
            } else {
                write!(f, "{registry_msg}")
            }
        } else {
            todo!()
        }
    }
}

pub trait Registry {
    fn initialize(
        credential: Option<Credential>,
        settings: Vec<Setting>,
    ) -> Result<Self, RegistryError>
    where
        Self: Sized + Send + Sync;

    /// Resolves all images if the given image is not complete.
    ///
    /// This means that if only the registry is set then it tries to get all images of that
    /// registry. If the tag is missing it tries to get all tag variations. If everything is set it
    /// will just return the given image.
    fn resolve_image(&self, image: Image) -> PinBoxFutRef<'_, Vec<Result<Image, RegistryError>>>;

    fn pull_image(&self, image: Image) -> Streamer<Result<PackedLayer, RegistryError>>;
}
