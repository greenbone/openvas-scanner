// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::{
    fmt::{self, Display, Formatter},
    net::SocketAddr,
    path::PathBuf,
    time::Duration,
};

use clap::{builder::TypedValueParser, ArgAction};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Feed {
    pub path: PathBuf,
    pub check_interval: Duration,
    pub signature_check: bool,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Notus {
    pub advisory_path: PathBuf,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct OspdWrapper {
    pub result_check_interval: Duration,
    pub socket: PathBuf,
    pub read_timeout: Option<Duration>,
}

impl Default for OspdWrapper {
    fn default() -> Self {
        OspdWrapper {
            result_check_interval: Duration::from_secs(1),
            socket: PathBuf::from("/var/run/ospd/ospd.sock"),
            read_timeout: None,
        }
    }
}

impl Default for Feed {
    fn default() -> Self {
        Feed {
            path: PathBuf::from("/var/lib/openvas/plugins"),
            check_interval: Duration::from_secs(3600),
            signature_check: false,
        }
    }
}

impl Default for Notus {
    fn default() -> Self {
        Notus {
            advisory_path: PathBuf::from("/var/lib/notus/products"),
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Listener {
    pub address: SocketAddr,
}

impl Default for Listener {
    fn default() -> Self {
        Self {
            address: ([127, 0, 0, 1], 3000).into(),
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Clone, Default)]
pub struct Endpoints {
    pub enable_get_scans: bool,
    #[serde(default)]
    pub key: Option<String>,
}

#[derive(Deserialize, Serialize, Debug, Clone, Default)]
pub struct Tls {
    pub certs: Option<PathBuf>,
    pub key: Option<PathBuf>,
    pub client_certs: Option<PathBuf>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Logging {
    #[serde(default)]
    pub level: String,
}

impl Default for Logging {
    fn default() -> Self {
        Self {
            level: "INFO".to_string(),
        }
    }
}

#[derive(Deserialize, Serialize, Default, Debug, Clone, PartialEq, Eq)]
pub enum StorageType {
    #[default]
    #[serde(rename = "inmemory")]
    InMemory,
    #[serde(rename = "fs")]
    FileSystem,
}

impl TypedValueParser for StorageType {
    type Value = StorageType;

    fn parse_ref(
        &self,
        cmd: &clap::Command,
        _: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        Ok(match value.to_str().unwrap_or_default() {
            "fs" => StorageType::FileSystem,
            "inmemory" => StorageType::InMemory,
            _ => {
                let mut cmd = cmd.clone();
                let err = cmd.error(
                    clap::error::ErrorKind::InvalidValue,
                    "`{}` is not an storage type.",
                );
                return Err(err);
            }
        })
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct FileStorage {
    pub path: PathBuf,
    pub key: Option<String>,
}

impl Default for FileStorage {
    fn default() -> Self {
        Self {
            path: PathBuf::from("/var/lib/openvasd/storage"),
            key: None,
        }
    }
}

#[derive(Deserialize, Serialize, Default, Debug, Clone)]
pub struct Storage {
    #[serde(default, rename = "type")]
    pub storage_type: StorageType,
    #[serde(default)]
    pub fs: FileStorage,
}

#[derive(Deserialize, Serialize, Debug, Clone, Default)]
pub struct Config {
    #[serde(default)]
    pub feed: Feed,
    #[serde(default)]
    pub notus: Notus,
    #[serde(default)]
    pub endpoints: Endpoints,
    #[serde(default)]
    pub tls: Tls,
    #[serde(default)]
    pub ospd: OspdWrapper,
    #[serde(default)]
    pub listener: Listener,
    #[serde(default)]
    pub log: Logging,
    #[serde(default)]
    pub storage: Storage,
}

impl Display for Config {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", toml::to_string_pretty(self).unwrap_or_default())
    }
}

impl Config {
    fn load_etc() -> Option<Self> {
        let config = std::fs::read_to_string("/etc/openvasd/openvasd.toml").unwrap_or_default();
        toml::from_str(&config).ok()
    }

    fn load_user() -> Option<Self> {
        match std::env::var("HOME") {
            Ok(home) => {
                let path = format!("{}/.config/openvasd/openvasd.toml", home);
                let config = std::fs::read_to_string(path).unwrap_or_default();
                toml::from_str(&config).ok()
            }
            Err(_) => None,
        }
    }

    fn from_file<P>(path: P) -> Self
    where
        P: AsRef<std::path::Path> + std::fmt::Display,
    {
        let config = std::fs::read_to_string(path).unwrap();
        toml::from_str(&config).unwrap()
    }

    pub fn load() -> Self {
        let cmds = clap::Command::new("openvasd")
            .arg(
                clap::Arg::new("config")
                    .short('c')
                    .env("OPENVASD_CONFIG")
                    .long("config")
                    .action(ArgAction::Set)
                    .help("path to toml config file"),
            )
            .arg(
                clap::Arg::new("feed-path")
                    .env("FEED_PATH")
                    .long("feed-path")
                    .value_parser(clap::builder::PathBufValueParser::new())
                    .action(ArgAction::Set)
                    .help("path to openvas feed"),
            )
            .arg(
                clap::Arg::new("feed-signature-check")
                    .long("feed-signature-check")
                    .short('x')
                    .action(ArgAction::SetTrue)
                    .help("Enable feed signature check"),
            )

            .arg(
                clap::Arg::new("feed-check-interval")
                    .env("FEED_CHECK_INTERVAL")
                    .long("feed-check-interval")
                    .value_parser(clap::value_parser!(u64))
                    .value_name("SECONDS")
                    .help("interval to check for feed updates in seconds"),
            )
            .arg(
                clap::Arg::new("notus-advisories")
                    .env("NOTUS_SCANNER_PRODUCTS_DIRECTORY")
                    .long("products-directory")
                    .value_parser(clap::builder::PathBufValueParser::new())
                    .action(ArgAction::Set)
                    .help("Path containing the Notus products directory"))
            .arg(
                clap::Arg::new("tls-certs")
                    .env("TLS_CERTS")
                    .long("tls-certs")
                    .value_parser(clap::builder::PathBufValueParser::new())
                    .action(ArgAction::Set)
                    .help("path to server tls certs"),
            )
            .arg(
                clap::Arg::new("tls-key")
                    .env("TLS_KEY")
                    .long("tls-key")
                    .value_parser(clap::builder::PathBufValueParser::new())
                    .action(ArgAction::Set)
                    .help("path to server tls key"),
            )
            .arg(
                clap::Arg::new("tls-client-certs")
                    .env("TLS_CLIENT_CERTS")
                    .long("tls-client-certs")
                    .value_parser(clap::builder::PathBufValueParser::new())
                    .action(ArgAction::Set)
                    .help("path to client tls certs. Enables mtls."),
            )
            .arg(
                clap::Arg::new("enable-get-scans")
                    .env("ENABLE_GET_SCANS")
                    .long("enable-get-scans")
                    .action(ArgAction::SetTrue)
                    .help("enable get scans endpoint"),
            )
            .arg(
                clap::Arg::new("api-key")
                    .env("API_KEY")
                    .long("api-key")
                    .action(ArgAction::Set)
                    .help("API key that must be set as X-API-KEY header to gain access"),
            )
            .arg(
                clap::Arg::new("ospd-socket")
                    .env("OSPD_SOCKET")
                    .long("ospd-socket")
                    .help("socket to ospd")
                    .value_parser(clap::builder::PathBufValueParser::new()),
            )
            .arg(
                clap::Arg::new("read-timeout")
                    .env("READ_TIMEOUT")
                    .long("read-timeout")
                    .value_parser(clap::value_parser!(u64))
                    .value_name("SECONDS")
                    .help("read timeout in seconds on the ospd-openvas socket"),
            )
            .arg(
                clap::Arg::new("result-check-interval")
                    .env("RESULT_CHECK_INTERVAL")
                    .long("result-check-interval")
                    .value_parser(clap::value_parser!(u64))
                    .value_name("SECONDS")
                    .help("interval to check for new results in seconds"),
            )
            .arg(
                clap::Arg::new("listening")
                    .env("LISTENING")
                    .long("listening")
                    .short('l')
                    .value_name("IP:PORT")
                    .value_parser(clap::value_parser!(SocketAddr))
                    .help("the address to listen to (e.g. 127.0.0.1:3000 or 0.0.0.0:3000)."),
            )
            .arg(
                clap::Arg::new("storage_type")
                    .env("STORAGE_TYPE")
                    .long("storage-type")
                    .value_name("fs,inmemory")
                    .value_parser(StorageType::InMemory)
                    .help("either be stored in memory or on the filesystem."),
            )
            .arg(
                clap::Arg::new("storage_path")
                    .env("STORAGE_PATH")
                    .long("storage-path")
                    .value_name("PATH")
                    .value_parser(clap::builder::PathBufValueParser::new())
                    .help("the path that contains the files when type is set to fs."),
            )
            .arg(
                clap::Arg::new("storage_key")
                    .env("STORAGE_KEY")
                    .long("storage-key")
                    .value_name("KEY")
                    .help("the password to use for encryption when type is set to fs. If not set the files are not encrypted."),
            )
            .arg(
                clap::Arg::new("log-level")
                    .env("OPENVASD_LOG")
                    .long("log-level")
                    .short('L')
                    .help("Level of log messages to be shown. TRACE > DEBUG > INFO > WARN > ERROR"),
            )
            .get_matches();
        let mut config = match cmds.get_one::<String>("config") {
            Some(path) => Self::from_file(path),
            None => {
                if let Some(config) = Self::load_user() {
                    config
                } else {
                    Self::load_etc().unwrap_or_default()
                }
            }
        };
        if let Some(interval) = cmds.get_one::<u64>("feed-check-interval") {
            config.feed.check_interval = Duration::from_secs(*interval);
        }
        if let Some(interval) = cmds.get_one::<u64>("result-check-interval") {
            config.ospd.result_check_interval = Duration::from_secs(*interval);
        }
        if let Some(path) = cmds.get_one::<PathBuf>("ospd-socket") {
            config.ospd.socket = path.clone();
        }
        if let Some(interval) = cmds.get_one::<u64>("read-timeout") {
            config.ospd.read_timeout = Some(Duration::from_secs(*interval));
        }

        if let Some(path) = cmds.get_one::<PathBuf>("feed-path") {
            config.feed.path = path.clone();
        }
        if let Some(path) = cmds.get_one::<PathBuf>("notus-advisories") {
            config.notus.advisory_path = path.clone();
        }
        if let Some(path) = cmds.get_one::<PathBuf>("tls-certs") {
            config.tls.certs = Some(path.clone());
        }
        if let Some(path) = cmds.get_one::<PathBuf>("tls-key") {
            config.tls.key = Some(path.clone());
        }
        if let Some(path) = cmds.get_one::<PathBuf>("tls-client-certs") {
            config.tls.client_certs = Some(path.clone());
        }
        if let Some(enable) = cmds.get_one::<bool>("enable-get-scans") {
            config.endpoints.enable_get_scans = *enable;
        }
        if let Some(api_key) = cmds.get_one::<String>("api-key") {
            config.endpoints.key = Some(api_key.clone());
        }
        if let Some(ip) = cmds.get_one::<SocketAddr>("listening") {
            config.listener.address = *ip;
        }
        if let Some(log_level) = cmds.get_one::<String>("log-level") {
            config.log.level = log_level.clone();
        }
        if let Some(stype) = cmds.get_one::<StorageType>("storage_type") {
            config.storage.storage_type = stype.clone();
        }
        if let Some(path) = cmds.get_one::<PathBuf>("storage_path") {
            config.storage.fs.path = path.clone();
        }
        if let Some(key) = cmds.get_one::<String>("storage_key") {
            if !key.is_empty() {
                config.storage.fs.key = Some(key.clone());
            }
        }
        config
    }
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, time::Duration};

    use crate::config::StorageType;

    #[test]
    fn defaults() {
        let config = super::Config::default();

        assert_eq!(
            config.feed.path,
            std::path::PathBuf::from("/var/lib/openvas/plugins")
        );
        assert_eq!(config.feed.check_interval, Duration::from_secs(3600));

        assert!(!config.endpoints.enable_get_scans);
        assert!(config.endpoints.key.is_none());

        assert!(config.tls.certs.is_none());
        assert!(config.tls.key.is_none());
        assert!(config.tls.client_certs.is_none());

        assert_eq!(config.ospd.result_check_interval, Duration::from_secs(1));
        assert_eq!(config.ospd.socket, PathBuf::from("/var/run/ospd/ospd.sock"));
        assert!(config.ospd.read_timeout.is_none());

        assert_eq!(config.listener.address, ([127, 0, 0, 1], 3000).into());

        assert_eq!(config.log.level, "INFO".to_string());
    }

    #[test]
    fn parse_toml() {
        let cfg = r#"[log]
        level = "DEBUG"
        [storage]
        type = "fs"
        [storage.fs]
        path = "/var/lib/openvasd/storage/test"
        key = "changeme"
        "#;
        let config: super::Config = toml::from_str(cfg).unwrap();
        assert_eq!(config.log.level, "DEBUG");
        assert_eq!(
            config.storage.fs.path,
            PathBuf::from("/var/lib/openvasd/storage/test")
        );
        assert_eq!(config.storage.fs.key, Some("changeme".to_string()));
        assert_eq!(config.storage.storage_type, StorageType::FileSystem);
    }
}
