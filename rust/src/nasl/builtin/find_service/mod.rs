// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{
    collections::HashMap,
    io::{self, Write},
    net::IpAddr,
    time::Duration,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::nasl::prelude::*;
use crate::storage::items::kb::{self, KbItem, KbKey};

use super::network::socket::{NaslSocket, SocketError, make_tcp_socket};

const TIMEOUT_MILLIS: u64 = 5000;

#[derive(Debug, Error)]
pub enum FindServiceError {
    #[error("{0}")]
    Socket(#[from] SocketError),
    #[error("JSON parsing error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Regex error: {0}")]
    Regex(#[from] regex::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceDefinitions {
    pub version: String,
    pub description: String,
    pub services: Vec<Service>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Service {
    pub name: String,
    pub service_key: Option<String>,
    pub description: String,
    pub detections: Vec<Detection>,
    pub ports: Vec<u16>,
    pub save_banner: bool,
    pub generate_result: GenerateResult,
    pub kb_entries: HashMap<String, String>,
}

impl Service {
    fn key(&self) -> String {
        self.service_key.as_ref().unwrap_or(&self.name).clone()
    }
}

pub type ServiceId = String;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Detection {
    Banner(BannerDetection),
    Https,
    Http,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "banner_detection_type", rename_all = "snake_case")]
pub enum BannerDetection {
    Contains {
        value: String,
        #[serde(default)]
        case_sensitive: bool,
    },
    StartsWith {
        value: String,
        #[serde(default)]
        case_sensitive: bool,
    },
    Equals {
        value: String,
        #[serde(default)]
        case_sensitive: bool,
    },
    ContainsHex {
        value: String,
        position: Option<usize>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateResult {
    pub enabled: bool,
    pub is_vulnerability: bool,
    pub message: String,
}

enum ReadResult {
    Data(Vec<u8>),
    Timeout,
}

struct DetectedService {
    id: ServiceId,
    banner: Vec<u8>,
}

enum ScanPortResult {
    Service(DetectedService),
    Timeout,
    NoMatch,
}

impl BannerDetection {
    fn matches(&self, banner: &[u8]) -> bool {
        let banner_str = String::from_utf8_lossy(banner);
        match self {
            BannerDetection::Contains {
                value,
                case_sensitive,
            } => {
                if *case_sensitive {
                    banner_str.contains(value)
                } else {
                    banner_str.to_lowercase().contains(&value.to_lowercase())
                }
            }
            BannerDetection::StartsWith {
                value,
                case_sensitive,
            } => {
                if *case_sensitive {
                    banner_str.starts_with(value)
                } else {
                    banner_str.to_lowercase().starts_with(&value.to_lowercase())
                }
            }
            BannerDetection::Equals {
                value,
                case_sensitive,
            } => {
                if *case_sensitive {
                    banner_str.trim() == *value
                } else {
                    banner_str.trim().to_lowercase() == value.to_lowercase()
                }
            }
            BannerDetection::ContainsHex { value, position } => match hex::decode(value) {
                Ok(hex_bytes) => {
                    if let Some(pos) = position {
                        banner.len() > pos + hex_bytes.len()
                            && banner[*pos..*pos + hex_bytes.len()] == hex_bytes
                    } else {
                        banner
                            .windows(hex_bytes.len())
                            .any(|window| window == hex_bytes)
                    }
                }
                Err(_) => false,
            },
        }
    }
}

impl Detection {
    fn matches(&self, banner_or_http_response: &[u8]) -> Result<bool, FindServiceError> {
        match self {
            Detection::Banner(banner_pattern) => {
                Ok(banner_pattern.matches(banner_or_http_response))
            }
            Detection::Https => Ok(Self::detect_https(banner_or_http_response)),
            Detection::Http => Ok(Self::detect_http_response(banner_or_http_response)),
        }
    }

    fn detect_https(_: &[u8]) -> bool {
        todo!()
    }

    fn detect_http_response(banner: &[u8]) -> bool {
        let response = String::from_utf8_lossy(banner);
        response.contains("HTTP/1.0")
            || response.contains("HTTP/1.1")
            || response.contains("HTTP/2")
    }
}

struct ServiceDetector {
    services: ServiceDefinitions,
}

impl ServiceDetector {
    fn new() -> Result<Self, FindServiceError> {
        let json_content = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/data/service_definitions.json"
        ));
        let definitions: ServiceDefinitions = serde_json::from_str(json_content)?;
        Ok(ServiceDetector {
            services: definitions,
        })
    }

    fn detect_service(
        &self,
        banner: &[u8],
        port: u16,
    ) -> Result<Option<DetectedService>, FindServiceError> {
        for service in &self.services.services {
            if !service.ports.is_empty() && !service.ports.contains(&port) {
                continue;
            }

            for pattern in &service.detections {
                if pattern.matches(banner)? {
                    return Ok(Some(DetectedService {
                        id: service.name.clone(),
                        banner: banner.to_vec(),
                    }));
                }
            }
        }
        Ok(None)
    }

    fn handle_detected_service(
        &self,
        context: &ScanCtx<'_>,
        service: DetectedService,
        port: u16,
    ) -> Result<(), FnError> {
        let banner = service.banner;
        // The following lookup is in O(n^2). However, since the
        // number of services is likely to be small, this is very
        // unlikely to become a performance problem, so that I prefer
        // the simplicity of this approach (as opposed to using a
        // HashMap).
        let service = self
            .services
            .services
            .iter()
            .find(|s| s.name == service.id)
            .unwrap();

        add_kb_entries(context, service, port, banner)?;

        if service.generate_result.enabled {
            if service.generate_result.is_vulnerability {
                tracing::warn!(
                    "Security alert on port {}: {}",
                    port,
                    service.generate_result.message
                );
            } else {
                tracing::info!(
                    "Service detected on port {}: {}",
                    port,
                    service.generate_result.message
                );
            }
        }

        Ok(())
    }
}

fn add_kb_entries(
    context: &ScanCtx<'_>,
    service: &Service,
    port: u16,
    banner: Vec<u8>,
) -> Result<(), FnError> {
    for (key_template, value_template) in &service.kb_entries {
        let key = key_template.replace("{port}", &port.to_string());
        let value = value_template.replace("{port}", &port.to_string());

        context.set_kb_item(KbKey::Custom(key), KbItem::String(value))?;
    }

    context.set_kb_item(
        KbKey::Service(kb::Service::Custom(service.key())),
        KbItem::String(format!("{port}/tcp")),
    )?;

    context.set_kb_item(KbKey::KnownTcp(port), KbItem::String(service.key()))?;

    if service.save_banner {
        let banner_key = format!("Banner/{port}");
        context.set_kb_item(KbKey::Custom(banner_key), KbItem::Data(banner))?;
    }

    Ok(())
}

fn read_from_tcp_at_port(target: IpAddr, port: u16) -> Result<ReadResult, FindServiceError> {
    let mut socket = make_tcp_socket(target, port, 0)?;
    let mut buf = vec![0; 1024];
    let result = socket.read_with_timeout(&mut buf, Duration::from_millis(TIMEOUT_MILLIS));
    match result {
        Ok(pos) => {
            buf.truncate(pos);
            Ok(ReadResult::Data(buf))
        }
        Err(e) if e.kind() == io::ErrorKind::TimedOut => Ok(ReadResult::Timeout),
        Err(e) => Err(SocketError::IO(e).into()),
    }
}

fn try_http_request(target: IpAddr, port: u16) -> Result<Vec<u8>, FindServiceError> {
    // TODO: Use a more robust approach that also takes HTTP2 into
    // account (such as using h2)
    let mut socket = make_tcp_socket(target, port, 0)?;
    let http_request = b"GET / HTTP/1.0\r\n\r\n";
    match socket {
        NaslSocket::Tcp(ref mut tcp_conn) => {
            tcp_conn.write_all(http_request).map_err(SocketError::IO)?;

            let mut buf = vec![0; 1024];
            let result =
                tcp_conn.read_with_timeout(&mut buf, Duration::from_millis(TIMEOUT_MILLIS));
            match result {
                Ok(pos) => {
                    buf.truncate(pos);
                    Ok(buf)
                }
                Err(e) => Err(SocketError::IO(e).into()),
            }
        }
        _ => unreachable!(),
    }
}

fn scan_port(
    detector: &ServiceDetector,
    target: IpAddr,
    port: u16,
) -> Result<ScanPortResult, FindServiceError> {
    let needs_http_request = detector.services.services.iter().any(|service| {
        (service.ports.is_empty() || service.ports.contains(&port))
            && service
                .detections
                .iter()
                .any(|d| matches!(d, Detection::Http))
    });

    // For services that need HTTP request, try HTTP first, then fallback to banner
    let banner = if needs_http_request && let Ok(http_response) = try_http_request(target, port) {
        http_response
    } else {
        match read_from_tcp_at_port(target, port)? {
            ReadResult::Data(data) => data,
            ReadResult::Timeout => return Ok(ScanPortResult::Timeout),
        }
    };

    match detector.detect_service(&banner, port)? {
        Some(service) => Ok(ScanPortResult::Service(service)),
        None => Ok(ScanPortResult::NoMatch),
    }
}

#[nasl_function]
fn plugin_run_find_service(context: &ScanCtx<'_>) -> NaslResult {
    let detector = ServiceDetector::new()?;
    let open_ports = context.get_open_tcp_ports()?;
    for port in open_ports {
        match scan_port(&detector, context.target().ip_addr(), port) {
            Ok(ScanPortResult::Service(service)) => {
                detector.handle_detected_service(context, service, port)?;
            }
            Ok(ScanPortResult::Timeout) => {
                tracing::debug!("Timeout reading from port {}", port);
            }
            Ok(ScanPortResult::NoMatch) => {
                tracing::debug!("No service match found for port {}", port);
            }
            Err(e) => {
                tracing::warn!("Error scanning port {}: {}", port, e);
            }
        }
    }

    Ok(NaslValue::Null)
}

#[derive(Default)]
pub struct FindService;

function_set! {
    FindService,
    (
        plugin_run_find_service
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_file_valid() {
        // Implicitly check if the JSON is valid by
        // creating the ServiceDetector
        let detector = ServiceDetector::new();
        detector.unwrap();
    }
}
