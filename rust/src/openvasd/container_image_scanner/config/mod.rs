use std::{env, path::PathBuf, time::Duration};

use crate::config::SqliteConfiguration;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ImageExtractionLocation {
    File(PathBuf),
}

impl Default for ImageExtractionLocation {
    fn default() -> Self {
        let name = env!("CARGO_PKG_NAME");
        let cache_dir = if let Some(xdg_cache) = std::env::var_os("XDG_CACHE_HOME") {
            PathBuf::from(&xdg_cache)
        } else {
            PathBuf::from("/tmp")
        };
        let cache_dir = cache_dir.join(name);

        ImageExtractionLocation::File(cache_dir)
    }
}

impl From<&str> for ImageExtractionLocation {
    fn from(value: &str) -> Self {
        let file = value;
        Self::File(file.into())
    }
}

impl From<String> for ImageExtractionLocation {
    fn from(value: String) -> Self {
        Self::from(&value as &str)
    }
}

impl ImageExtractionLocation {
    fn config_deserialize<'de, D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(Self::from(s.as_str()))
    }

    // toml is not able to handle File(PathBuf) and it looks cleaner in toml when we flatten
    fn config_serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::File(path) => serializer.serialize_str(path.to_str().unwrap_or("")),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[serde(default)]
pub struct Image {
    #[serde(
        deserialize_with = "ImageExtractionLocation::config_deserialize",
        serialize_with = "ImageExtractionLocation::config_serialize"
    )]
    pub extract_to: ImageExtractionLocation,
    /// Controls how many images can be scanned concurrently.
    pub max_scanning: usize, // if 0 unlimited
    /// How many times an image scan should be retried on a failure that is retryable
    pub scanning_retries: usize,
    /// Controls the batch of picked up images that are scanned synchronously.
    pub batch_size: usize, // if 0 unlimited
    //
    #[serde(
        deserialize_with = "scannerlib::utils::duration::deserialize",
        serialize_with = "scannerlib::utils::duration::serialize"
    )]
    /// How long should it wait before retrying again
    pub retry_timeout: Duration,
}

impl Default for Image {
    fn default() -> Self {
        Self {
            extract_to: Default::default(),
            max_scanning: 10,
            batch_size: 2,
            scanning_retries: 3,
            retry_timeout: Duration::from_secs(1),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(default)]
pub struct Config {
    /// Defines how many scans can be resolved to images although another scan is running.
    ///
    /// This will effectively resolve whole catalogs or repositories in parallel, however it does
    /// not mean that they will be actually scanned yet as those images are then picked up and
    /// the concurrency of those are controlled by images.max_scanning.
    pub max_scans: usize,
    pub database: SqliteConfiguration,
    pub image: Image,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            database: Default::default(),
            image: Default::default(),
            max_scans: 5,
        }
    }
}

impl Config {
    pub fn image_extraction_location(&self) -> &PathBuf {
        match &self.image.extract_to {
            ImageExtractionLocation::File(path) => path,
        }
    }

    pub fn image_max_scanning(&self) -> usize {
        self.image.max_scanning
    }

    pub fn image_batch_size(&self) -> usize {
        self.image.batch_size
    }
}
