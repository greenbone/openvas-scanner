use std::{
    env,
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use clap::{ArgAction, Parser};
use serde::{Deserialize, Serialize};
mod duration;
mod logging;
use logging::Logging;

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
pub struct Notus {
    pub address: String,
    pub certificate: Option<PathBuf>,
}

impl Default for Notus {
    fn default() -> Self {
        Self {
            address: "http://localhost:3000/notus".to_owned(),
            certificate: Default::default(),
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
    location: DBLocation,
    #[serde(
        deserialize_with = "duration::deserialize",
        serialize_with = "duration::serialize"
    )]
    busy_timeout: Duration,
    max_connections: u32,
}

impl Default for SqliteConfiguration {
    fn default() -> Self {
        Self {
            location: Default::default(),
            busy_timeout: Duration::from_secs(2),
            max_connections: 1,
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
            .create_if_missing(true);
        PoolOptions::<Sqlite>::new()
            .max_connections(self.max_connections)
            .connect_with(options)
            .await
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[serde(default)]
pub struct Image {
    #[serde(
        deserialize_with = "ImageExtractionLocation::config_deserialize",
        serialize_with = "ImageExtractionLocation::config_serialize"
    )]
    extract_to: ImageExtractionLocation,
    max_scanning: usize, // if 0 unlimited
    batch_size: usize,   // if 0 unlimited
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
    pub logging: Logging,
    pub database: SqliteConfiguration,
    pub notus: Notus,
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

    fn config_path(path: Option<PathBuf>) -> Option<PathBuf> {
        if path.is_some() {
            // User set, don't control but let it fail later on when invalid
            return path;
        }
        let name = env!("CARGO_PKG_NAME");
        if let Some(xdg_config_home) = std::env::var_os("XDG_CONFIG_HOME") {
            let config_path = Path::new(&xdg_config_home).join(name).join("config.toml");
            if config_path.exists() && config_path.is_file() {
                return Some(config_path);
            }
        }

        let global_config_path = Path::new("/etc").join(name).join("config.toml");
        if global_config_path.exists() && global_config_path.is_file() {
            return Some(global_config_path);
        }

        None
    }

    pub fn config_from_path_or_default(path: Option<PathBuf>) -> Config {
        let try_parse_toml = |content: &str, path: &str| match toml::from_str(content) {
            Ok(x) => x,
            Err(e) => {
                eprintln!("Invalid toml({path}): {e}");
                std::process::exit(1);
            }
        };
        let try_read_file = |path: &Path| match std::fs::read_to_string(path) {
            Ok(x) => x,
            Err(_) => {
                tracing::error!(
                    path = path.to_string_lossy().as_ref(),
                    "Is not readable, please provide a valid config path"
                );
                std::process::exit(1);
            }
        };
        if let Some(path) = Self::config_path(path) {
            let content = try_read_file(&path);
            return try_parse_toml(&content, path.to_string_lossy().as_ref());
        }

        Config::default()
    }

    pub fn load() -> Config {
        let args = Args::parse();
        let verbosity = args.verbosity();
        let mut config = Self::config_from_path_or_default(args.config);
        if let Some(db) = args.db {
            config.database.location = DBLocation::from(&db as &str);
        }
        if let Some(max_conn) = args.db_max_connections {
            config.database.max_connections = max_conn;
        }
        if let Some(busy_timeout) = args.db_busy_timeout {
            config.database.busy_timeout = duration::parse(&busy_timeout).unwrap();
        }
        if let Some(iel) = args.image_extraction_location {
            config.image.extract_to = ImageExtractionLocation::from(iel);
        }
        if let Some(addr) = args.notus_address {
            config.notus.address = addr;
        }
        if let Some(certp) = args.notus_certificate {
            config.notus.certificate = Some(certp);
        }
        if verbosity != logging::SerLevel::default() {
            config.logging.level = verbosity;
        }
        config
    }
}

#[derive(Parser)]
struct Args {
    #[clap(short = 'c', long = "config", value_parser, env = "CONFIG")]
    config: Option<PathBuf>,

    #[clap(short = 'd', long = "db", value_parser, env = "DB")]
    db: Option<String>,

    #[clap(
        long = "image-extraction-location",
        value_parser,
        env = "IMAGE_EXTRACTION_LOCATION"
    )]
    image_extraction_location: Option<String>,

    #[clap(long = "db-max-connections", value_parser, env = "DB_MAX_CONNECTIONS")]
    db_max_connections: Option<u32>,

    #[clap(long = "db-busy-timeout", value_parser, env = "DB_BUSY_TIMEOUT")]
    db_busy_timeout: Option<String>,
    #[clap(long = "notus-address", value_parser, env = "NOTUS_ADDRESS")]
    notus_address: Option<String>,
    #[clap(long = "notus-certificate", value_parser, env = "NOTUS_CERTIFICATE")]
    notus_certificate: Option<PathBuf>,

    #[clap(short = 'v', long = "verbose", action = ArgAction::Count, help = "Increase verbosity (-v, -vv, etc.)")]
    verbose: u8,

    #[clap(short = 'q', long = "quiet", action = ArgAction::Count, help = "Decrease verbosity (-q, -qq, etc.)")]
    quiet: u8,
}

impl Args {
    fn resolve_verbosity(&self) -> i8 {
        if self.verbose == 0 && self.quiet == 0 {
            match env::var("VERBOSITY").map(|x| x.parse::<i8>().unwrap_or_default()) {
                Ok(val) => return val,
                Err(_) => return 0,
            }
        };

        self.verbose as i8 - self.quiet as i8
    }

    pub fn verbosity(&self) -> logging::SerLevel {
        let level = self.resolve_verbosity();
        use tracing::Level;
        match level {
            i8::MIN..=-2 => Level::ERROR,
            -1 => Level::WARN,
            0 => Level::INFO,
            1 => Level::DEBUG,
            2..=i8::MAX => Level::TRACE,
        }
        .into()
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
