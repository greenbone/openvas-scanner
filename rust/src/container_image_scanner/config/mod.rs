use std::{env, path::PathBuf, str::FromStr, time::Duration};

use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqliteSynchronous;
pub mod duration;
pub mod logging;

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum DBLocation {
    #[default]
    InMemory,
    File(PathBuf),
}

impl DBLocation {
    pub fn sqlite_address(&self) -> String {
        match &self {
            Self::InMemory => "sqlite::memory:".to_owned(),
            Self::File(path_buf) => format!("sqlite:{}", path_buf.to_string_lossy()),
        }
    }

    pub fn default_file_location() -> Self {
        let cache_dir = if let Some(xdg_cache) = std::env::var_os("XDG_CACHE_HOME") {
            PathBuf::from(&xdg_cache)
        } else {
            PathBuf::from(".")
        };
        let cache_dir = cache_dir.join("container-image-scanner");
        let cache_dir = cache_dir.join("database.sql");

        Self::File(cache_dir)
    }
}

impl From<&str> for DBLocation {
    fn from(value: &str) -> Self {
        match value {
            "in-memory" => Self::InMemory,
            file => Self::File(file.into()),
        }
    }
}

impl DBLocation {
    // toml is not able to handle File(PathBuf) and it looks cleaner in toml when we flatten
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
            Self::InMemory => serializer.serialize_str("in-memory"),
            Self::File(path) => serializer.serialize_str(path.to_str().unwrap_or("")),
        }
    }
}

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
pub struct SqliteConfiguration {
    #[serde(
        deserialize_with = "DBLocation::config_deserialize",
        serialize_with = "DBLocation::config_serialize"
    )]
    pub location: DBLocation,
    #[serde(
        deserialize_with = "duration::deserialize",
        serialize_with = "duration::serialize"
    )]
    pub busy_timeout: Duration,
    pub max_connections: u32,
    pub credential_key: Option<String>,
}

impl Default for SqliteConfiguration {
    fn default() -> Self {
        Self {
            location: Default::default(),
            busy_timeout: Duration::from_secs(2),
            max_connections: 1,
            credential_key: None,
        }
    }
}

impl SqliteConfiguration {
    pub async fn create_pool(&self) -> Result<sqlx::Pool<sqlx::Sqlite>, sqlx::Error> {
        use sqlx::{
            Sqlite,
            pool::PoolOptions,
            sqlite::{SqliteConnectOptions, SqliteJournalMode},
        };

        let options = SqliteConnectOptions::from_str(&self.location.sqlite_address())?
            .journal_mode(SqliteJournalMode::Wal)
            .busy_timeout(self.busy_timeout)
            // Although this can lead to data loss in the case that the application crashes we usually
            // need to either restart that scan anyway.
            .synchronous(SqliteSynchronous::Off)
            .create_if_missing(true);
        PoolOptions::<Sqlite>::new()
            .max_connections(self.max_connections)
            .connect_with(options)
            .await
    }

    pub fn default_file_location() -> Self {
        Self {
            location: DBLocation::default_file_location(),
            ..Default::default()
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
    pub max_scanning: usize, // if 0 unlimited
    pub batch_size: usize,   // if 0 unlimited
}

impl Default for Image {
    fn default() -> Self {
        Self {
            extract_to: Default::default(),
            max_scanning: 1,
            batch_size: 1,
        }
    }
}

#[derive(Default, Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(default)]
pub struct Config {
    pub database: SqliteConfiguration,
    pub image: Image,
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

// #[cfg(test)]
// mod test_config {
//     use insta::assert_toml_snapshot;
//
//     use super::Config;
//
//     #[test]
//     fn default() {
//         let config = Config::default();
//         assert_toml_snapshot!(config);
//     }
//     #[test]
//     fn db_image_extraction_location_file() {
//         let db = super::DBLocation::File("/tmp/test.db".into());
//         let iel = super::ImageExtractionLocation::File("/tmp/images/".into());
//         let notus = super::Notus {
//             address: "https://localhost:4242/notus".into(),
//             certificate: "/tmp/cert.ca".parse().ok(),
//         };
//
//         let logging = super::logging::Logging {
//             level: tracing::Level::TRACE.into(),
//             additional: vec![("docker_registry".to_owned(), tracing::Level::WARN.into())]
//                 .into_iter()
//                 .collect(),
//         };
//         let config = Config {
//             image: super::Image {
//                 extract_to: iel,
//                 ..Default::default()
//             },
//             database: super::SqliteConfiguration {
//                 location: db,
//                 ..Default::default()
//             },
//             notus,
//             logging,
//         };
//
//         assert_toml_snapshot!(config);
//     }
// }
//
// #[cfg(test)]
// mod test_arguments {
//
//     use insta::assert_toml_snapshot;
//
//     use super::*;
//     use std::env;
//
//     fn clear_env_var() {
//         unsafe {
//             env::remove_var("DB");
//         }
//     }
//
//     #[test]
//     fn test_config_argument_provided() {
//         unsafe {
//             env::set_var("DB", "/tmp/config_test.db");
//         };
//         let config = Config::load();
//
//         clear_env_var();
//         assert_toml_snapshot!(config);
//     }
// }
