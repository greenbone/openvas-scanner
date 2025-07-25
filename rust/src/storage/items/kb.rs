// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Defines an KB item with its corresponding key in storage.

use std::{collections::HashMap, fmt::Display, hash::Hash, net::IpAddr};

use crate::storage::{ScanID, Target};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
/// List defined KbKeys. For all kb keys that are not defined by
/// a NASL user should use a variant from the enum, that is not
/// custom.
pub enum KbKey {
    /// Contains SSL/TLS Kb keys
    Ssl(Ssl),

    /// Contains Port related Kb keys
    Port(Port),

    /// Contains Transport related Kb keys
    Transport(Transport),

    /// Contains Kb Keys for internal communication
    Internals(Internals),

    /// Contains Host related Kb keys
    Host(Host),

    /// Contains Service related Kb keys
    Service(Service),

    /// Contains FindService related Kb keys
    FindService(FindService),

    /// Known TCP ports
    KnownTcp(String),

    /// Number of timeouts for a given IP address and port. After a failed attempt
    /// this number is increased by 1 and logged.
    ConnectTimeout(IpAddr, String),

    /// Kdc Secrets
    Kdc(Kdc),

    // Constants
    TimeoutRetry,

    // Global Settings
    GlobalSettings(GlobalSettings),

    /// This is used for a completely custom key
    Custom(String),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ssl {
    Cert,
    Key,
    Password,
    Ca,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Port {
    Tcp(String),
    Udp(String),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Tcp(String),
    Ssl,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Internals {
    Results,
    ScanId,
    Vhosts,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GlobalSettings {
    HttpUserAgent,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Host {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Service {
    Wrapped,
    Unknown,
    ThreeDigits,
    Custom(String),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindService {
    CnxTime1000(String),
    CnxTime(String),
    RwTime1000(String),
    RwTime(String),
    TcpGetHttp(String),
    TcpSpontaneous(String),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kdc {
    Hostname,
    Port,
    Protocol,
}

impl Default for KbKey {
    fn default() -> Self {
        KbKey::Custom("".to_string())
    }
}

impl Display for KbKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KbKey::Ssl(Ssl::Cert) => write!(f, "SSL/cert"),
            KbKey::Ssl(Ssl::Key) => write!(f, "SSL/key"),
            KbKey::Ssl(Ssl::Password) => write!(f, "SSL/password"),
            KbKey::Ssl(Ssl::Ca) => write!(f, "SSL/ca"),

            KbKey::Port(Port::Tcp(port)) => write!(f, "Ports/tcp/{port}"),
            KbKey::Port(Port::Udp(port)) => write!(f, "Ports/udp/{port}"),

            KbKey::Transport(Transport::Tcp(transport)) => write!(f, "Transports/TCP/{transport}"),
            KbKey::Transport(Transport::Ssl) => write!(f, "Transport/SSL"),

            KbKey::Internals(Internals::Results) => write!(f, "internal/results"),
            KbKey::Internals(Internals::ScanId) => write!(f, "internal/scanid"),
            KbKey::Internals(Internals::Vhosts) => write!(f, "internal/vhosts"),

            KbKey::Host(Host::Tcp) => write!(f, "Host/scanned"),
            KbKey::Host(Host::Udp) => write!(f, "Host/udp_scanned"),

            KbKey::Service(Service::Wrapped) => write!(f, "Service/wrapped"),
            KbKey::Service(Service::Unknown) => write!(f, "Service/unknown"),
            KbKey::Service(Service::ThreeDigits) => write!(f, "Service/three_digits"),
            KbKey::Service(Service::Custom(service)) => write!(f, "Services/{service}"),

            KbKey::FindService(FindService::CnxTime(port)) => {
                write!(f, "FindService/CnxTime1000/{port}")
            }
            KbKey::FindService(FindService::CnxTime1000(port)) => {
                write!(f, "FindService/CnxTime/{port}")
            }
            KbKey::FindService(FindService::RwTime1000(port)) => {
                write!(f, "FindService/RwTime1000/{port}")
            }
            KbKey::FindService(FindService::RwTime(port)) => {
                write!(f, "FindService/RwTime/{port}")
            }
            KbKey::FindService(FindService::TcpGetHttp(port)) => {
                write!(f, "FindService/tcp/{port}/get_http")
            }
            KbKey::FindService(FindService::TcpSpontaneous(port)) => {
                write!(f, "FindService/tcp/{port}/spontaneous")
            }
            KbKey::KnownTcp(port) => write!(f, "Known/tcp/{port}"),

            KbKey::ConnectTimeout(ip, port) => write!(f, "ConnectTimeout/{ip}/{port}"),

            KbKey::Kdc(Kdc::Hostname) => write!(f, "Secret/kdc_hostname"),
            KbKey::Kdc(Kdc::Port) => write!(f, "Secret/kdc_port"),
            KbKey::Kdc(Kdc::Protocol) => write!(f, "Secret/kdc_use_tcp"),

            KbKey::TimeoutRetry => write!(f, "timeout_retry"),

            KbKey::GlobalSettings(GlobalSettings::HttpUserAgent) => {
                write!(f, "global_settings/http_user_agent")
            }

            KbKey::Custom(key) => write!(f, "{key}"),
        }
    }
}

impl KbKey {
    pub fn is_pattern(&self) -> bool {
        self.to_string().contains('*')
    }

    pub fn matches(&self, pattern: &Self) -> bool {
        let s = self.to_string();
        if let Some((p1, p2)) = pattern.to_string().split_once('*') {
            return s.starts_with(p1) && s.ends_with(p2);
        }
        false
    }
}

impl PartialEq for KbKey {
    fn eq(&self, other: &Self) -> bool {
        self.to_string() == other.to_string()
    }
}

impl Eq for KbKey {}

impl Hash for KbKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.to_string().hash(state);
    }
}

impl From<&str> for KbKey {
    fn from(value: &str) -> Self {
        KbKey::Custom(value.to_string())
    }
}

impl From<String> for KbKey {
    fn from(value: String) -> Self {
        KbKey::Custom(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Default, Hash, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
/// Allowed type definitions
pub enum KbItem {
    /// String value
    String(String),
    /// Data value
    Data(Vec<u8>),
    /// Number value
    Number(i64),
    /// Array value
    Array(Vec<KbItem>),
    /// Array value
    Dict(Vec<(String, KbItem)>),
    /// Boolean value
    Boolean(bool),
    /// Null value
    #[default]
    Null,
}

impl From<Vec<u8>> for KbItem {
    fn from(s: Vec<u8>) -> Self {
        Self::Data(s)
    }
}

impl From<bool> for KbItem {
    fn from(b: bool) -> Self {
        KbItem::Boolean(b)
    }
}

impl From<Vec<String>> for KbItem {
    fn from(s: Vec<String>) -> Self {
        Self::Array(s.into_iter().map(|x| x.into()).collect())
    }
}

impl From<&str> for KbItem {
    fn from(s: &str) -> Self {
        Self::String(s.to_owned())
    }
}

impl From<String> for KbItem {
    fn from(s: String) -> Self {
        Self::String(s)
    }
}

impl From<i32> for KbItem {
    fn from(n: i32) -> Self {
        Self::Number(n as i64)
    }
}

impl From<i64> for KbItem {
    fn from(n: i64) -> Self {
        Self::Number(n)
    }
}

impl From<usize> for KbItem {
    fn from(n: usize) -> Self {
        Self::Number(n as i64)
    }
}

impl From<HashMap<String, KbItem>> for KbItem {
    fn from(x: HashMap<String, KbItem>) -> Self {
        KbItem::Dict(x.into_iter().collect())
    }
}

impl From<KbItem> for bool {
    fn from(value: KbItem) -> Self {
        match value {
            KbItem::String(string) => !string.is_empty() && string != "0",
            KbItem::Array(v) => !v.is_empty(),
            KbItem::Data(v) => !v.is_empty(),
            KbItem::Boolean(boolean) => boolean,
            KbItem::Null => false,
            KbItem::Number(number) => number != 0,
            KbItem::Dict(v) => !v.is_empty(),
        }
    }
}

impl From<&KbItem> for i64 {
    fn from(value: &KbItem) -> Self {
        match value {
            KbItem::String(_) => 1,
            &KbItem::Number(x) => x,
            KbItem::Array(_) => 1,
            KbItem::Data(_) => 1,
            KbItem::Dict(_) => 1,
            &KbItem::Boolean(x) => x as i64,
            KbItem::Null => 0,
        }
    }
}

impl From<&KbItem> for Vec<u8> {
    fn from(value: &KbItem) -> Vec<u8> {
        match value {
            KbItem::String(x) => x.as_bytes().to_vec(),
            &KbItem::Number(x) => x.to_ne_bytes().to_vec(),
            KbItem::Data(x) => x.to_vec(),
            _ => Vec::new(),
        }
    }
}

impl From<KbItem> for i64 {
    fn from(nv: KbItem) -> Self {
        i64::from(&nv)
    }
}

impl std::fmt::Display for KbItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KbItem::String(x) => write!(f, "{x}"),
            KbItem::Number(x) => write!(f, "{x}"),
            KbItem::Array(x) => write!(
                f,
                "{}",
                x.iter()
                    .enumerate()
                    .map(|(i, v)| format!("{i}: {v}"))
                    .collect::<Vec<String>>()
                    .join(",")
            ),
            KbItem::Data(x) => {
                write!(f, "{}", x.iter().map(|x| *x as char).collect::<String>())
            }
            KbItem::Dict(x) => write!(
                f,
                "{}",
                x.iter()
                    .map(|(k, v)| format!("{k}: {v}"))
                    .collect::<Vec<String>>()
                    .join(",")
            ),
            KbItem::Boolean(true) => write!(f, "1"),
            KbItem::Boolean(false) => write!(f, "0"),
            KbItem::Null => write!(f, "\0"),
        }
    }
}

pub type KbContext = (ScanID, Target);

#[derive(Debug, Clone, Default)]
pub struct KbContextKey(pub KbContext, pub KbKey);

impl Display for KbContextKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Scan: {}, Target: {}, KbKey: {}",
            self.0.0, self.0.1, self.1
        )
    }
}
#[derive(Debug, Clone, Default)]
pub struct GetKbContextKey(pub KbContext, pub KbKey);
