// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::{
    fmt::{self, Display, Formatter},
    net::SocketAddr,
    path::PathBuf,
    time::Duration,
};

use clap::ArgAction;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Feed {
    pub path: PathBuf,
    pub check_interval: Duration,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct OspdWrapper {
    pub result_check_interval: Duration,
    pub socket: PathBuf,
}

impl Default for OspdWrapper {
    fn default() -> Self {
        OspdWrapper {
            result_check_interval: Duration::from_secs(1),
            socket: PathBuf::from("/var/run/ospd/ospd.sock"),
        }
    }
}

impl Default for Feed {
    fn default() -> Self {
        Feed {
            path: PathBuf::from("/var/lib/openvas/plugins"),
            check_interval: Duration::from_secs(60 * 60),
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

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Tls {
    pub certs: PathBuf,
    pub key: PathBuf,
    pub client_certs: PathBuf,
}

impl Default for Tls {
    fn default() -> Self {
        Self {
            certs: PathBuf::from("/etc/openvasd/tls/certs.pem"),
            key: PathBuf::from("/var/lib/openvasd/tls/key.pem"),
            client_certs: PathBuf::from("/etc/openvasd/tls/clients"),
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Clone, Default)]
pub struct Config {
    #[serde(default)]
    pub feed: Feed,
    #[serde(default)]
    pub endpoints: Endpoints,
    #[serde(default)]
    pub tls: Tls,
    #[serde(default)]
    pub ospd: OspdWrapper,
    #[serde(default)]
    pub listener: Listener,
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
        tracing::debug!("loading config from {}", path);
        let config = std::fs::read_to_string(path).unwrap_or_default();
        toml::from_str(&config).unwrap_or_default()
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
                    .env("FEEED_PATH")
                    .long("feed-path")
                    .value_parser(clap::builder::PathBufValueParser::new())
                    .action(ArgAction::Set)
                    .help("path to openvas feed"),
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

        if let Some(path) = cmds.get_one::<PathBuf>("feed-path") {
            config.feed.path = path.clone();
        }
        if let Some(path) = cmds.get_one::<PathBuf>("tls-certs") {
            config.tls.certs = path.clone();
        }
        if let Some(path) = cmds.get_one::<PathBuf>("tls-key") {
            config.tls.key = path.clone();
        }
        if let Some(path) = cmds.get_one::<PathBuf>("tls-client-certs") {
            config.tls.client_certs = path.clone();
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

        config
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn defaults() {
        let config = super::Config::default();
        assert_eq!(
            config.feed.path,
            std::path::PathBuf::from("/var/lib/openvas/plugins")
        );
        assert!(!config.endpoints.enable_get_scans);
        assert_eq!(
            config.tls.certs,
            std::path::PathBuf::from("/etc/openvasd/tls/certs.pem")
        );
        assert_eq!(
            config.tls.key,
            std::path::PathBuf::from("/var/lib/openvasd/tls/key.pem")
        );
        assert_eq!(
            config.tls.client_certs,
            std::path::PathBuf::from("/etc/openvasd/tls/clients")
        );
    }
}
