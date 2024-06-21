// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

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
    pub products_path: PathBuf,
    pub advisories_path: PathBuf,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Redis {
    pub url: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Scheduler {
    #[serde(default)]
    pub max_queued_scans: Option<usize>,
    #[serde(default)]
    pub max_running_scans: Option<usize>,
    #[serde(default)]
    pub min_free_mem: Option<u64>,
    pub check_interval: Duration,
}

impl Default for Scheduler {
    fn default() -> Self {
        Self {
            check_interval: Duration::from_millis(500),
            max_queued_scans: None,
            max_running_scans: None,
            min_free_mem: None,
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Clone, Default)]
pub struct Scanner {
    #[serde(default, rename = "type")]
    pub scanner_type: ScannerType,
    #[serde(default)]
    pub ospd: OspdWrapper,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum ScannerType {
    #[serde(rename = "ospd")]
    OSPD,
    #[serde(rename = "openvas")]
    Openvas,
}

impl Default for ScannerType {
    fn default() -> Self {
        Self::OSPD
    }
}

impl TypedValueParser for ScannerType {
    type Value = ScannerType;

    fn parse_ref(
        &self,
        cmd: &clap::Command,
        _: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        Ok(match value.to_str().unwrap_or_default() {
            "ospd" => ScannerType::OSPD,
            "openvas" => ScannerType::Openvas,
            x => {
                let mut cmd = cmd.clone();
                let err = cmd.error(
                    clap::error::ErrorKind::InvalidValue,
                    format!("`{x}` is not a scanner type."),
                );
                return Err(err);
            }
        })
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct OspdWrapper {
    pub socket: PathBuf,
    pub read_timeout: Option<Duration>,
}

impl Default for OspdWrapper {
    fn default() -> Self {
        OspdWrapper {
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
            products_path: PathBuf::from("/var/lib/notus/products"),
            advisories_path: PathBuf::from("/var/lib/notus/advisories"),
        }
    }
}

impl Default for Redis {
    fn default() -> Self {
        Redis {
            url: "unix:///run/redis-openvas/redis.sock".to_string(),
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

#[derive(Deserialize, Serialize, Debug, Clone, Default, PartialEq, Eq)]
/// Describes different modes openvasd can be run as.
///
/// `Service` prefix means that openvasd is a http service used by others.
/// `Client` prefix means that openvasd is run as a client and  calls other services.
pub enum Mode {
    #[default]
    #[serde(rename = "service")]
    /// Enables all endpoints and monitors feed and active scans.
    Service,
    /// Disables everything but the notus endpoints
    #[serde(rename = "service_notus")]
    ServiceNotus,
}

impl TypedValueParser for Mode {
    type Value = Self;

    fn parse_ref(
        &self,
        cmd: &clap::Command,
        _arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        Ok(match value.to_str().unwrap_or_default() {
            "service" => Self::Service,
            "service_notus" => Self::ServiceNotus,
            _ => {
                let mut cmd = cmd.clone();
                let err = cmd.error(
                    clap::error::ErrorKind::InvalidValue,
                    "`{}` is not a scanner type.",
                );
                return Err(err);
            }
        })
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
    #[serde(rename = "redis")]
    Redis,
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
            "redis" => StorageType::Redis,
            x => {
                let mut cmd = cmd.clone();
                let err = cmd.error(
                    clap::error::ErrorKind::InvalidValue,
                    format!("`{x}` is not a storage type."),
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
    #[serde(default)]
    pub redis: Redis,
}

#[derive(Deserialize, Serialize, Debug, Clone, Default)]
pub struct Config {
    #[serde(default)]
    pub mode: Mode,
    #[serde(default)]
    pub feed: Feed,
    #[serde(default)]
    pub notus: Notus,
    #[serde(default)]
    pub endpoints: Endpoints,
    #[serde(default)]
    pub tls: Tls,
    #[serde(default)]
    pub scanner: Scanner,
    #[serde(default)]
    pub listener: Listener,
    #[serde(default)]
    pub log: Logging,
    #[serde(default)]
    pub storage: Storage,
    #[serde(default)]
    pub scheduler: Scheduler,
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
                    .env("NOTUS_ADVISORIES")
                    .long("advisories")
                    .value_parser(clap::builder::PathBufValueParser::new())
                    .action(ArgAction::Set)
                    .help("Path containing the Notus advisories directory"))
            .arg(
                clap::Arg::new("notus-products")
                    .env("NOTUS_PRODUCTS")
                    .long("products")
                    .value_parser(clap::builder::PathBufValueParser::new())
                    .action(ArgAction::Set)
                    .help("Path containing the Notus products directory"))
            .arg(
                clap::Arg::new("redis-url")
                    .long("redis-url")
                    .env("REDIS_URL")
                    //.value_parser(clap::builder::PathBufValueParser::new())
                    .action(ArgAction::Set)
                    .help("Redis url. Either unix:// or redis://"))
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
                clap::Arg::new("scanner-type")
                    .env("SCANNER_TYPE")
                    .long("scanner-type")
                    .value_name("ospd,openvas")
                    .value_parser(ScannerType::OSPD)
                    .help("Type of scanner used to manage scans")
            )
            .arg(
                clap::Arg::new("max-queued-scans")
                    .env("MAX_QUEUED_SCANS")
                    .long("max-queued-scans")
                    .action(ArgAction::Set)
                    .help("Maximum number of queued scans")
            )
            .arg(
                clap::Arg::new("max-running-scans")
                    .env("MAX_RUNNING_SCANS")
                    .long("max-running-scans")
                    .action(ArgAction::Set)
                    .help("Maximum number of active running scans, omit for no limits")

            )
            .arg(
                clap::Arg::new("min-free-mem")
                    .env("MIN_FREE_MEMORY")
                    .long("min-free-mem")
                    .action(ArgAction::Set)
                    .help("Minimum memory available to start a new scan")
            )
            .arg(
                clap::Arg::new("check-interval")
                    .env("SCHEDULER_CHECK_INTERVAL")
                    .long("check_interval")
                    .value_parser(clap::value_parser!(u64))
                    .value_name("SECONDS")
                    .help("Check interval of the Scheduler if a new scan can be started")
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
                    .value_parser(StorageType::InMemory)
                    .value_name("redis,inmemory,fs")
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
            .arg(
                clap::Arg::new("mode")
                    .env("OPENVASD_MODE")
                    .long("mode")
                    .value_name("service,service_notus")
                    .value_parser(Mode::Service)
                    .help("Sets the openvasd mode"),
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
        if let Some(scanner_type) = cmds.get_one::<ScannerType>("scanner-type") {
            config.scanner.scanner_type = scanner_type.clone()
        }
        if let Some(max_queued_scans) = cmds.get_one::<usize>("max-queued-scans") {
            config.scheduler.max_queued_scans = Some(*max_queued_scans)
        }
        if let Some(max_running_scans) = cmds.get_one::<usize>("max-running-scans") {
            config.scheduler.max_running_scans = Some(*max_running_scans)
        }
        if let Some(min_free_mem) = cmds.get_one::<u64>("min-free-mem") {
            config.scheduler.min_free_mem = Some(*min_free_mem)
        }
        if let Some(check_interval) = cmds.get_one::<u64>("check-interval") {
            config.scheduler.check_interval = Duration::from_millis(*check_interval)
        }
        if let Some(path) = cmds.get_one::<PathBuf>("ospd-socket") {
            config.scanner.ospd.socket.clone_from(path);
        }
        if let Some(interval) = cmds.get_one::<u64>("read-timeout") {
            config.scanner.ospd.read_timeout = Some(Duration::from_secs(*interval));
        }

        if let Some(path) = cmds.get_one::<PathBuf>("feed-path") {
            config.feed.path.clone_from(path);
        }
        if let Some(path) = cmds.get_one::<PathBuf>("notus-products") {
            config.notus.products_path.clone_from(path);
        }
        if let Some(path) = cmds.get_one::<PathBuf>("notus-advisories") {
            config.notus.advisories_path.clone_from(path);
        }
        if let Some(path) = cmds.get_one::<String>("redis-url") {
            config.storage.redis.url.clone_from(path);
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
            config.log.level.clone_from(log_level);
        }
        if let Some(stype) = cmds.get_one::<StorageType>("storage_type") {
            config.storage.storage_type = stype.clone();
        }
        if let Some(path) = cmds.get_one::<PathBuf>("storage_path") {
            config.storage.fs.path.clone_from(path);
        }
        if let Some(mode) = cmds.get_one::<Mode>("mode") {
            config.mode = mode.clone();
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

        assert_eq!(config.scheduler.check_interval, Duration::from_millis(500));
        assert_eq!(
            config.scanner.ospd.socket,
            PathBuf::from("/var/run/ospd/ospd.sock")
        );
        assert!(config.scanner.ospd.read_timeout.is_none());

        assert_eq!(config.listener.address, ([127, 0, 0, 1], 3000).into());

        assert_eq!(config.log.level, "INFO".to_string());
        // this is used to verify the default config manually.
        // se to true to write the default configuration to `tmp`
        if false {
            let mut cf = std::fs::File::create("/tmp/openvas.default.example.toml").unwrap();
            use std::io::Write;
            cf.write_all(toml::to_string_pretty(&config).unwrap().as_bytes())
                .unwrap();
        }
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
