// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{collections::HashMap, io, net::IpAddr, time::Duration};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::nasl::prelude::*;
use crate::storage::items::kb::{KbItem, KbKey};

use super::network::socket::{SocketError, make_tcp_socket};

const TIMEOUT_MILLIS: u64 = 5000;

#[derive(Debug, Error)]
pub enum FindServiceError {
    #[error("{0}")]
    SocketError(#[from] SocketError),
    #[error("JSON parsing error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("IO error: {0}")]
    IoError(#[from] io::Error),
    #[error("Regex error: {0}")]
    RegexError(#[from] regex::Error),
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
    pub description: String,
    pub patterns: Vec<Pattern>,
    pub ports: Vec<u16>,
    pub save_banner: bool,
    pub generate_result: GenerateResult,
    pub kb_entries: HashMap<String, String>,
}

pub type ServiceId = String;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Pattern {
    BannerContains {
        value: String,
        #[serde(default)]
        case_sensitive: bool,
    },
    BannerStartsWith {
        value: String,
        #[serde(default)]
        case_sensitive: bool,
    },
    BannerEquals {
        value: String,
        #[serde(default)]
        case_sensitive: bool,
    },
    BannerContainsHex {
        value: String,
        position: Option<usize>,
    },
    SslDetection,
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

impl Pattern {
    fn matches(&self, banner: &[u8]) -> Result<bool, FindServiceError> {
        let banner_str = String::from_utf8_lossy(banner);

        match self {
            Pattern::BannerContains {
                value,
                case_sensitive,
            } => Ok(if *case_sensitive {
                banner_str.contains(value)
            } else {
                banner_str.to_lowercase().contains(&value.to_lowercase())
            }),
            Pattern::BannerStartsWith {
                value,
                case_sensitive,
            } => Ok(if *case_sensitive {
                banner_str.starts_with(value)
            } else {
                banner_str.to_lowercase().starts_with(&value.to_lowercase())
            }),
            Pattern::BannerEquals {
                value,
                case_sensitive,
            } => Ok(if *case_sensitive {
                banner_str.trim() == *value
            } else {
                banner_str.trim().to_lowercase() == value.to_lowercase()
            }),
            Pattern::BannerContainsHex { value, position } => match hex::decode(value) {
                Ok(hex_bytes) => {
                    if let Some(pos) = position {
                        Ok(banner.len() > pos + hex_bytes.len()
                            && banner[*pos..*pos + hex_bytes.len()] == hex_bytes)
                    } else {
                        Ok(banner
                            .windows(hex_bytes.len())
                            .any(|window| window == hex_bytes))
                    }
                }
                Err(_) => Ok(false),
            },
            Pattern::SslDetection => {
                todo!()
            }
        }
    }
}

struct ServiceDetector {
    services: ServiceDefinitions,
}

impl ServiceDetector {
    fn new() -> Result<Self, FindServiceError> {
        let json_content = include_str!("../../../../data/service_definitions.json");
        let definitions: ServiceDefinitions = serde_json::from_str(&json_content)?;
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

            for pattern in &service.patterns {
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
        // This is O(n^2), but simpler than using a HashMap and performance
        // should really not matter here.
        let service = self
            .services
            .services
            .iter()
            .find(|s| s.name == service.id)
            .unwrap();
        for (key_template, value_template) in &service.kb_entries {
            let key = key_template.replace("{port}", &port.to_string());
            let value = value_template.replace("{port}", &port.to_string());

            context.set_kb_item(KbKey::Custom(key), KbItem::String(value))?;
        }

        if service.save_banner {
            let banner_key = format!("Banner/{}", port);
            context.set_kb_item(KbKey::Custom(banner_key), KbItem::Data(banner.clone()))?;
        }

        if service.generate_result.enabled {
            if service.generate_result.is_vulnerability {
                tracing::warn!(
                    "Security alert on port {}: {}",
                    port,
                    service.generate_result.message
                );
                // TODO:
            } else {
                tracing::info!(
                    "Service detected on port {}: {}",
                    port,
                    service.generate_result.message
                );
                // TODO
            }
        }

        Ok(())
    }
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

fn scan_port(
    target: IpAddr,
    port: u16,
    detector: &ServiceDetector,
) -> Result<ScanPortResult, FindServiceError> {
    let result = read_from_tcp_at_port(target, port)?;
    let banner = match result {
        ReadResult::Data(data) => data,
        ReadResult::Timeout => return Ok(ScanPortResult::Timeout),
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
        match scan_port(context.target().ip_addr(), port, &detector) {
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
