pub(crate) mod docker_v2;
pub use docker_v2::Registry as DockerV2;

use super::Image;
pub(crate) use super::PackedLayer;
use crate::container_image_scanner::{ExternalError, ParsePreferences, PinBoxFutRef, Streamer};

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

pub trait Registry {
    fn initialize(
        credential: Option<Credential>,
        settings: Vec<Setting>,
    ) -> Result<Self, ExternalError>
    where
        Self: Sized + Send + Sync;

    /// Resolves all images if the given image is not complete.
    ///
    /// This means that if only the registry is set then it tries to get all images of that
    /// registry. If the tag is missing it tries to get all tag variations. If everything is set it
    /// will just return the given image.
    //TODO: define useable errors
    fn resolve_image(&self, image: Image) -> PinBoxFutRef<'_, Vec<Result<Image, ExternalError>>>;

    fn pull_image(&self, image: Image) -> Streamer<Result<PackedLayer, ExternalError>>;
}
