// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Defines an KB item with its corresponding key in storage.

use std::{collections::HashMap, fmt::Display, hash::Hash, net::IpAddr};

use crate::storage::{ScanID, Target};

#[derive(Eq, Debug, Clone)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "snake_case")
)]
/// List of keys for the KnowledgeBase
pub enum KbKey {
    // SSL/TLS
    SslCert,
    SslKey,
    SslPassword,
    SslCa,

    // Ports
    PortTcp(String),
    PortUdp(String),
    Port(String, String),
    PortsTcp,

    // Transport
    Transport(String),
    TransportSsl,

    // Internals
    Results,
    ScanId,
    Vhosts,

    // Host
    HostTcp,
    HostUdp,

    // Services
    ServiceWrapped,
    ServiceUnknown,
    ServiceThreeDigits,
    Services(String),

    // FindService
    FindServiceCnxTime1000(String),
    FindServiceCnxTime(String),
    FindServiceRwTime1000(String),
    FindServiceRwTime(String),
    FindServiceTcpGetHttp(String),
    FindServiceTcpSpontaneous(String),
    KnownTcp(String),

    // Connect
    /// Number of timeouts for a given IP address and port. After a failed attempt
    /// this number is increased by 1 and logged.
    ConnectTimeout(IpAddr, String),

    // Secrets
    SecretKdcHostname,
    SecretKdcPort,
    SecretKdcProtocol,

    // Constants
    TimeoutRetry,

    // Custom
    /// This is used for a completely custom key
    Custom(String),
}

impl Default for KbKey {
    fn default() -> Self {
        KbKey::Custom("".to_string())
    }
}

impl Display for KbKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KbKey::SslCert => write!(f, "SSL/cert"),
            KbKey::SslKey => write!(f, "SSL/key"),
            KbKey::SslPassword => write!(f, "SSL/password"),
            KbKey::SslCa => write!(f, "SSL/ca"),

            KbKey::PortTcp(port) => write!(f, "Ports/tcp/{port}"),
            KbKey::PortUdp(port) => write!(f, "Ports/udp/{port}"),
            KbKey::Port(protocol, port) => write!(f, "Ports/{protocol}/{port}"),
            KbKey::PortsTcp => write!(f, "Ports/tcp/*"),

            KbKey::Transport(transport) => write!(f, "Transport/TCP/{transport}"),
            KbKey::TransportSsl => write!(f, "Transport/SSL"),

            KbKey::Results => write!(f, "internal/results"),
            KbKey::ScanId => write!(f, "internal/scanid"),
            KbKey::Vhosts => write!(f, "internal/vhosts"),

            KbKey::HostTcp => write!(f, "Host/scanned"),
            KbKey::HostUdp => write!(f, "Host/udp_scanned"),

            KbKey::ServiceWrapped => write!(f, "Service/wrapped"),
            KbKey::ServiceUnknown => write!(f, "Service/unknown"),
            KbKey::ServiceThreeDigits => write!(f, "Service/three_digits"),
            KbKey::Services(service) => write!(f, "Services/{service}"),

            KbKey::FindServiceCnxTime1000(port) => write!(f, "FindService/CnxTime1000/{}", port),
            KbKey::FindServiceCnxTime(port) => write!(f, "FindService/CnxTime/{}", port),
            KbKey::FindServiceRwTime1000(port) => write!(f, "FindService/RwTime1000/{}", port),
            KbKey::FindServiceRwTime(port) => write!(f, "FindService/RwTime/{}", port),
            KbKey::FindServiceTcpGetHttp(port) => write!(f, "FindService/tcp/{}/get_http", port),
            KbKey::FindServiceTcpSpontaneous(port) => {
                write!(f, "FindService/tcp/{}/spontaneous", port)
            }
            KbKey::KnownTcp(port) => write!(f, "Known/tcp/{}", port),

            KbKey::ConnectTimeout(ip, port) => write!(f, "ConnectTimeout/{}/{}", ip, port),

            KbKey::SecretKdcHostname => write!(f, "Secret/kdc_hostname"),
            KbKey::SecretKdcPort => write!(f, "Secret/kdc_port"),
            KbKey::SecretKdcProtocol => write!(f, "Secret/kdc_use_tcp"),

            KbKey::TimeoutRetry => write!(f, "timeout_retry"),

            KbKey::Custom(key) => write!(f, "{}", key),
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

#[derive(Clone, Debug, PartialEq, Eq, Default, Hash)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize),
    serde(untagged)
)]
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
                    .map(|(i, v)| format!("{}: {}", i, v))
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
                    .map(|(k, v)| format!("{}: {}", k, v))
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
            self.0 .0, self.0 .1, self.1
        )
    }
}
#[derive(Debug, Clone, Default)]
pub struct GetKbContextKey(pub KbContext, pub KbKey);
