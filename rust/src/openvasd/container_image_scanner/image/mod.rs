use std::{convert::Infallible, fmt::Display, str::FromStr, time::Duration};

mod registry;

pub use registry::{
    Credential, DockerV2 as DockerRegistryV2, Registry, RegistryError, Setting as RegistrySetting,
};
pub mod extractor;
#[cfg(test)]
pub use registry::docker_v2::fake::RegistryMock as DockerRegistryV2Mock;
use scannerlib::SQLITE_LIMIT_VARIABLE_NUMBER;
use sqlx::{QueryBuilder, query};

pub mod packages;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Image {
    pub registry: String,
    image: Option<String>,
    tag: Option<String>,
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

    fn is_sha256(&self) -> bool {
        self.tag
            .as_ref()
            .map(|x| x.starts_with("sha256:"))
            .unwrap_or_default()
    }

    pub fn tag(&self) -> Option<&str> {
        self.tag.as_ref().map(|x| x as &str)
    }

    pub fn replace_tag(mut self, new_tag: String) -> Self {
        self.tag = Some(new_tag);
        self
    }

    pub async fn insert(
        tx: &mut sqlx::SqliteConnection,
        scan_id: i64,
        state: ImageState,
        images: Vec<String>,
    ) -> Result<(), sqlx::Error> {
        for image in images.chunks(SQLITE_LIMIT_VARIABLE_NUMBER / 2) {
            let mut builder = QueryBuilder::new("INSERT OR IGNORE INTO images (id, image, status)");
            builder.push_values(image, |mut b, img| {
                b.push_bind(scan_id)
                    .push_bind(img)
                    .push_bind(state.as_ref());
            });
            let query = builder.build();
            query.execute(&mut *tx).await?;
        }
        Ok(())
    }

    pub(crate) async fn is_digest_excluded(
        pool: &sqlx::Pool<sqlx::Sqlite>,
        id: &str,
        image: &Image,
        digest: Option<&String>,
    ) -> bool {
        if let Some(digest) = digest {
            let digest = image.clone().replace_tag(digest.clone()).to_string();
            match query("SELECT id FROM images WHERE id = ? AND image = ?")
                .bind(id)
                .bind(&digest)
                .fetch_optional(pool)
                .await
            {
                Err(error) => {
                    tracing::warn!(image=%digest, %error, "Unable to verify for excluded host.");
                    false
                }
                Ok(x) => x.is_some(),
            }
        } else {
            false
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ImageParseError {
    #[error("Empty input")]
    Empty,
    #[error("No registry found")]
    NoRegistry,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackedLayer {
    pub data: Vec<u8>,
    pub index: usize,
    pub digest: Option<String>,
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
                if self.is_sha256() {
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
        let mut parts = value.split('/').filter(|s| !s.is_empty());
        let registry = parts.next().ok_or(ImageParseError::NoRegistry)?;
        let image_parts: Vec<&str> = parts.collect();
        let mut result = Image {
            registry: registry.to_owned(),
            image: None,
            tag: None,
        };
        if image_parts.is_empty() {
            return Ok(result);
        }

        let full_image = image_parts.join("/");
        let (image, tag) = match full_image.rsplit_once(':') {
            Some((img, t)) => {
                if img.ends_with("@sha256") {
                    (
                        img.strip_suffix("@sha256").unwrap_or_default().to_string(),
                        Some(format!("sha256:{t}")),
                    )
                } else {
                    (img.to_string(), Some(t.to_string()))
                }
            }
            None => (full_image, None),
        };
        result.image = Some(image);
        result.tag = tag;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::Image;

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
        let user_input = "narf.io/myuser/myimage@sha256:abc1234def56789";
        let parsed = user_input.parse();
        assert_eq!(
            parsed,
            Ok(Image {
                registry: "narf.io".to_owned(),
                image: Some("myuser/myimage".to_owned()),
                tag: Some("sha256:abc1234def56789".to_owned())
            })
        );
        assert_eq!(
            parsed.unwrap().to_string(),
            "oci://narf.io/myuser/myimage@sha256:abc1234def56789"
        )
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
    fn skip_empty() {
        let user_input = "oci:////myregistry//////myimage:mytag";
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
    fn only_registry() {
        let user_input = "oci:////myregistry//////";
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
        let user_input = "oci:////myregistry//myimage";
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
}
