use std::{fmt::Display, str::FromStr};

mod registry;
pub use registry::{
    Credential, DockerV2 as DockerRegistryV2, Registry, Setting as RegistrySetting,
};
pub mod extractor;
#[cfg(test)]
pub use registry::docker_v2::fake::RegistryMock as DockerRegistryV2Mock;
pub mod packages;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Image {
    pub registry: String,
    image: Option<String>,
    tag: Option<String>,
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
    pub arch: String,
}

// #[derive(Debug, Clone)]
// pub struct ID {
//     pub scan_id: String,
//     pub client_id: String,
// }
//
// impl ID {
//     pub fn scan_id(&self) -> &str {
//         &self.scan_id
//     }
//
//     pub fn client_id(&self) -> &str {
//         &self.client_id
//     }
// }

#[derive(Debug, Clone)]
pub struct ImageID {
    pub id: String,
    pub image: String,
}

impl ImageID {
    pub fn id(&self) -> &str {
        &self.id
    }

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
            } => write!(f, "oci://{registry}/{image}:{tag}"),
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
            Some((img, t)) => (img.to_string(), Some(t.to_string())),
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
