use std::{convert::Infallible, fmt::Display, str::FromStr, sync::LazyLock, time::Duration};

use regex::Regex;

mod registry;

pub use registry::docker_v2_registry::DockerV2Registry;
pub use registry::{Credential, RegistryError, RegistryPreference};
pub mod extractor;
#[cfg(test)]
pub use registry::docker_v2_registry::fake::RegistryMock as DockerRegistryV2Mock;

pub mod packages;

#[derive(Clone, Debug, PartialEq, PartialOrd, Eq)]
pub struct Image {
    pub registry: String,
    pub image: Option<String>,
    pub tag: Option<String>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ImageState {
    Pending,
    Scanning,
    Stopped,
    Failed,
    Succeeded,
    Excluded,
}

impl AsRef<str> for ImageState {
    fn as_ref(&self) -> &str {
        match self {
            ImageState::Pending => "pending",
            ImageState::Scanning => "scanning",
            ImageState::Stopped => "stopped",
            ImageState::Failed => "failed",
            ImageState::Succeeded => "succeeded",
            ImageState::Excluded => "excluded",
        }
    }
}

impl FromStr for ImageState {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "scanning" => ImageState::Scanning,
            "stopped" => ImageState::Stopped,
            "failed" => ImageState::Failed,
            "succeeded" => ImageState::Succeeded,
            "excluded" => ImageState::Excluded,
            _ => ImageState::Pending,
        })
    }
}

impl Image {
    pub fn image(&self) -> Option<&str> {
        self.image.as_ref().map(|x| x as &str)
    }

    fn is_digest(&self) -> bool {
        self.tag
            .as_ref()
            .map(|x| x.contains(':'))
            .unwrap_or_default()
    }

    pub fn tag(&self) -> Option<&str> {
        self.tag.as_ref().map(|x| x as &str)
    }

    pub fn replace_tag(mut self, new_tag: String) -> Self {
        self.tag = Some(new_tag);
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ImageParseError {
    #[error("Empty input")]
    Empty,
    #[error("No registry found")]
    NoRegistry,
    #[error("Invalid registry: {0}")]
    InvalidRegistry(String),
    #[error("Invalid repository: {0}")]
    InvalidRepository(String),
    #[error("Invalid tag: {0}")]
    InvalidTag(String),
    #[error("Invalid digest: {0}")]
    InvalidDigest(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Digest(String);

impl AsRef<str> for Digest {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<String> for Digest {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<Digest> for String {
    fn from(value: Digest) -> Self {
        value.0
    }
}

impl From<&str> for Digest {
    fn from(value: &str) -> Self {
        Self::from(value.to_owned())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackedLayer {
    pub data: Vec<u8>,
    pub index: usize,
    pub digest: Option<Digest>,
    pub arch: String,
    pub download_time: Duration,
}

#[derive(Debug, Clone)]
pub struct ImageID {
    pub id: String,
    // TODO: store Image instead of String
    pub image: String,
}

impl ImageID {
    pub fn id(&self) -> &str {
        &self.id
    }

    // TODO: return Image instead of &str
    pub fn image(&self) -> &str {
        &self.image
    }
}

impl Display for Image {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Image {
                registry,
                image: None,
                tag: _,
            } => write!(f, "oci://{registry}"),
            Image {
                registry,
                image: Some(image),
                tag: None,
            } => write!(f, "oci://{registry}/{image}"),
            Image {
                registry,
                image: Some(image),
                tag: Some(tag),
            } => {
                if self.is_digest() {
                    write!(f, "oci://{registry}/{}@{}", image, tag)
                } else {
                    write!(f, "oci://{registry}/{image}:{tag}")
                }
            }
        }
    }
}

impl FromStr for Image {
    type Err = ImageParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.is_empty() {
            return Err(ImageParseError::Empty);
        }
        let value = value.strip_prefix("oci://").unwrap_or(value);
        if value.is_empty() {
            return Err(ImageParseError::NoRegistry);
        }

        let parts: Vec<_> = value.split('/').collect();
        if parts.iter().any(|part| part.is_empty()) {
            return Err(ImageParseError::InvalidRepository(value.to_owned()));
        }

        let registry = parts.first().ok_or(ImageParseError::NoRegistry)?;
        validate_registry(registry)?;
        let registry = match *registry {
            "index.docker.io" => "docker.io",
            registry => registry,
        };
        let image_parts = &parts[1..];
        let mut result = Image {
            registry: registry.to_owned(),
            image: None,
            tag: None,
        };
        if image_parts.is_empty() {
            return Ok(result);
        }

        let full_image = image_parts.join("/");
        let (mut image, tag) = if let Some((repository, digest)) = full_image.split_once('@') {
            if repository.contains('@') || digest.contains('@') {
                return Err(ImageParseError::InvalidDigest(digest.to_owned()));
            }
            validate_digest(digest)?;
            (repository.to_owned(), Some(digest.to_owned()))
        } else if let Some((repository, tag)) = full_image.rsplit_once(':') {
            validate_tag(tag)?;
            (repository.to_owned(), Some(tag.to_owned()))
        } else {
            (full_image, None)
        };
        validate_repository(&image)?;
        if registry == "docker.io" && !image.contains('/') {
            image = format!("library/{image}");
        }
        result.image = Some(image);
        result.tag = tag;
        Ok(result)
    }
}

static REPOSITORY_COMPONENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$")
        .expect("hardcoded repository regex is valid")
});

fn validate_registry(registry: &str) -> Result<(), ImageParseError> {
    let url = url::Url::parse(&format!("https://{registry}"))
        .map_err(|_| ImageParseError::InvalidRegistry(registry.to_owned()))?;
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(ImageParseError::InvalidRegistry(registry.to_owned()));
    }
    Ok(())
}

fn validate_repository(repository: &str) -> Result<(), ImageParseError> {
    if repository.len() > 255
        || repository
            .split('/')
            .any(|component| !REPOSITORY_COMPONENT.is_match(component))
    {
        return Err(ImageParseError::InvalidRepository(repository.to_owned()));
    }
    Ok(())
}

fn validate_tag(tag: &str) -> Result<(), ImageParseError> {
    let valid = !tag.is_empty()
        && tag.len() <= 128
        && tag.is_ascii()
        && tag
            .bytes()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == b'_')
        && tag
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'));
    if !valid {
        return Err(ImageParseError::InvalidTag(tag.to_owned()));
    }
    Ok(())
}

fn validate_digest(digest: &str) -> Result<(), ImageParseError> {
    let Some((algorithm, encoded)) = digest.split_once(':') else {
        return Err(ImageParseError::InvalidDigest(digest.to_owned()));
    };
    let valid = algorithm == "sha256"
        && encoded.len() == 64
        && encoded.bytes().all(|c| c.is_ascii_hexdigit());
    if !valid {
        return Err(ImageParseError::InvalidDigest(digest.to_owned()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Image, ImageParseError};

    fn image(registry: &str, repository: Option<&str>, reference: Option<&str>) -> Image {
        Image {
            registry: registry.to_owned(),
            image: repository.map(str::to_owned),
            tag: reference.map(str::to_owned),
        }
    }

    #[test]
    fn parse_tag() {
        let user_input = "oci://myregistry/myimage:mytag";
        let parsed = user_input.parse();
        assert_eq!(
            parsed,
            Ok(Image {
                registry: "myregistry".to_owned(),
                image: Some("myimage".to_owned()),
                tag: Some("mytag".to_owned())
            })
        );
    }

    #[test]
    fn parse_shasum() {
        let digest = format!("sha256:{}", "a".repeat(64));
        let user_input = format!("narf.io/myuser/myimage@{digest}");
        let parsed = user_input.parse();
        assert_eq!(
            parsed,
            Ok(image("narf.io", Some("myuser/myimage"), Some(&digest)))
        );
        assert_eq!(parsed.unwrap().to_string(), format!("oci://{user_input}"));
    }

    #[test]
    fn parse_tag_with_port() {
        let user_input = "oci://myregistry:6969/myimage:mytag";
        let parsed = user_input.parse();
        assert_eq!(
            parsed,
            Ok(Image {
                registry: "myregistry:6969".to_owned(),
                image: Some("myimage".to_owned()),
                tag: Some("mytag".to_owned())
            })
        );
    }

    #[test]
    fn parse_without_oci() {
        let user_input = "myregistry/myimage:mytag";
        let parsed = user_input.parse();
        assert_eq!(
            parsed,
            Ok(Image {
                registry: "myregistry".to_owned(),
                image: Some("myimage".to_owned()),
                tag: Some("mytag".to_owned())
            })
        );
    }

    #[test]
    fn rejects_empty_path_components() {
        let user_input = "oci:////myregistry//////myimage:mytag";
        assert!(matches!(
            user_input.parse::<Image>(),
            Err(ImageParseError::InvalidRepository(_))
        ));
    }

    #[test]
    fn only_registry() {
        let user_input = "oci://myregistry";
        let parsed = user_input.parse();
        assert_eq!(
            parsed,
            Ok(Image {
                registry: "myregistry".to_owned(),
                image: None,
                tag: None,
            })
        );
    }

    #[test]
    fn without_tag() {
        let user_input = "oci://myregistry/myimage";
        let parsed = user_input.parse();
        assert_eq!(
            parsed,
            Ok(Image {
                registry: "myregistry".to_owned(),
                image: Some("myimage".to_owned()),
                tag: None,
            })
        );
    }

    #[test]
    fn normalizes_docker_hub_references_without_changing_selector_kind() {
        assert_eq!(
            "oci://docker.io/ubuntu:24.04".parse(),
            Ok(image("docker.io", Some("library/ubuntu"), Some("24.04")))
        );
        assert_eq!(
            "oci://docker.io/library/ubuntu:24.04".parse(),
            Ok(image("docker.io", Some("library/ubuntu"), Some("24.04")))
        );
        assert_eq!(
            "oci://docker.io/example/application:1.0".parse(),
            Ok(image("docker.io", Some("example/application"), Some("1.0")))
        );
        assert_eq!(
            "oci://index.docker.io/ubuntu:24.04".parse(),
            Ok(image("docker.io", Some("library/ubuntu"), Some("24.04")))
        );
        assert_eq!(
            "oci://docker.io/ubuntu".parse(),
            Ok(image("docker.io", Some("library/ubuntu"), None))
        );
        assert_eq!(
            "oci://docker.io".parse(),
            Ok(image("docker.io", None, None))
        );
    }

    #[test]
    fn leaves_compatible_registry_references_unchanged() {
        assert_eq!(
            "oci://registry-1.docker.io/library/ubuntu:24.04".parse(),
            Ok(image(
                "registry-1.docker.io",
                Some("library/ubuntu"),
                Some("24.04")
            ))
        );
        assert_eq!(
            "oci://quay.io/example/application:1.0".parse(),
            Ok(image("quay.io", Some("example/application"), Some("1.0")))
        );
        assert_eq!(
            "oci://localhost:5000/example/application:1.0".parse(),
            Ok(image(
                "localhost:5000",
                Some("example/application"),
                Some("1.0")
            ))
        );
        assert_eq!(
            "oci://localhost:5000".parse(),
            Ok(image("localhost:5000", None, None))
        );
    }

    #[test]
    fn validates_tags_and_repositories() {
        assert_eq!(
            "oci://docker.io/example/app:Release_1.0-rc".parse(),
            Ok(image(
                "docker.io",
                Some("example/app"),
                Some("Release_1.0-rc")
            ))
        );
        for invalid in [
            "oci://docker.io/Ubuntu:24.04",
            "oci://docker.io/example//application:1.0",
            "oci://docker.io/example/application:",
            "oci://docker.io/example/application:.bad",
            "oci://docker.io/example/application:bad!tag",
        ] {
            assert!(invalid.parse::<Image>().is_err(), "accepted {invalid}");
        }
        let too_long_tag = format!("oci://docker.io/example/application:{}", "a".repeat(129));
        assert!(matches!(
            too_long_tag.parse::<Image>(),
            Err(ImageParseError::InvalidTag(_))
        ));
    }

    #[test]
    fn validates_digests() {
        let digest = format!("sha256:{}", "a".repeat(64));
        assert_eq!(
            format!("oci://docker.io/ubuntu@{digest}").parse(),
            Ok(image("docker.io", Some("library/ubuntu"), Some(&digest)))
        );
        for invalid in [
            "oci://docker.io/ubuntu@sha256:abc",
            "oci://docker.io/ubuntu@sha256:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            "oci://docker.io/ubuntu@sha512:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "oci://docker.io/ubuntu@missing-colon",
            "oci://docker.io/ubuntu@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@extra",
        ] {
            assert!(matches!(
                invalid.parse::<Image>(),
                Err(ImageParseError::InvalidDigest(_))
            ));
        }
    }
}
