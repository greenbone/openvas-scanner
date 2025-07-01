// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{
    collections::HashMap,
    io,
    net::IpAddr,
    time::Duration,
};

use regex::Regex;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::nasl::prelude::*;
use crate::storage::items::kb::{self, KbItem, KbKey};

use super::network::socket::{SocketError, make_tcp_socket, NaslSocket};

const TIMEOUT_MILLIS: u64 = 10000;

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
    pub services: Vec<ServiceDefinition>,
    pub pattern_types: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceDefinition {
    pub name: String,
    pub description: String,
    pub patterns: Vec<Pattern>,
    pub ports: Vec<u16>,
    pub save_banner: bool,
    pub generate_result: GenerateResultConfig,
    pub kb_entries: HashMap<String, String>,
    pub special_behavior: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Pattern {
    BannerContains { 
        value: String, 
        #[serde(default)]
        case_sensitive: bool 
    },
    BannerStartsWith { 
        value: String, 
        #[serde(default)]
        case_sensitive: bool 
    },
    BannerEndsWith { 
        value: String, 
        #[serde(default)]
        case_sensitive: bool 
    },
    BannerEquals { 
        value: String, 
        #[serde(default)]
        case_sensitive: bool 
    },
    BannerRegex { 
        value: String 
    },
    BannerContainsHex { 
        value: String, 
        position: Option<usize> 
    },
    SslDetection,
    HttpResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateResultConfig {
    pub enabled: bool,
    pub is_vulnerability: bool,
    pub message: String,
}

struct Service {
    name: String,
    generate_result: GenerateResult,
    save_banner: bool,
    special_behavior: Option<SpecialBehavior>,
    banner: String,
    kb_entries: HashMap<String, String>,
    message: String,
}

enum GenerateResult {
    No,
    Yes { is_vulnerability: bool },
}

enum SpecialBehavior {
    HttpProbe,      // Send GET request and parse headers
    SslDetection,   // Attempt SSL handshake
    SecurityAlert,  // Generate security alerts for trojans/malware
    BinaryProtocol, // Handle complex binary protocols like MySQL
    MultiStep,      // Multi-command protocols requiring multiple exchanges
}

impl SpecialBehavior {
    fn from_string(s: &str) -> Option<Self> {
        match s {
            "http_probe" => Some(SpecialBehavior::HttpProbe),
            "ssl_detection" => Some(SpecialBehavior::SslDetection),
            "security_alert" => Some(SpecialBehavior::SecurityAlert),
            "binary_protocol" => Some(SpecialBehavior::BinaryProtocol),
            "multi_step" => Some(SpecialBehavior::MultiStep),
            _ => None,
        }
    }
}

enum ReadResult {
    Data(Vec<u8>),
    Timeout,
}

enum ScanPortResult {
    Service(Service),
    Timeout,
    NoMatch,
}

impl Pattern {
    fn matches(&self, banner: &[u8]) -> Result<bool, FindServiceError> {
        let banner_str = String::from_utf8_lossy(banner);
        
        match self {
            Pattern::BannerContains { value, case_sensitive } => {
                Ok(if *case_sensitive {
                    banner_str.contains(value)
                } else {
                    banner_str.to_lowercase().contains(&value.to_lowercase())
                })
            },
            Pattern::BannerStartsWith { value, case_sensitive } => {
                Ok(if *case_sensitive {
                    banner_str.starts_with(value)
                } else {
                    banner_str.to_lowercase().starts_with(&value.to_lowercase())
                })
            },
            Pattern::BannerEndsWith { value, case_sensitive } => {
                Ok(if *case_sensitive {
                    banner_str.ends_with(value)
                } else {
                    banner_str.to_lowercase().ends_with(&value.to_lowercase())
                })
            },
            Pattern::BannerEquals { value, case_sensitive } => {
                Ok(if *case_sensitive {
                    banner_str.trim() == *value
                } else {
                    banner_str.trim().to_lowercase() == value.to_lowercase()
                })
            },
            Pattern::BannerRegex { value } => {
                let regex = Regex::new(value)?;
                Ok(regex.is_match(&banner_str))
            },
            Pattern::BannerContainsHex { value, position } => {
                match hex::decode(value) {
                    Ok(hex_bytes) => {
                        if let Some(pos) = position {
                            Ok(banner.len() > pos + hex_bytes.len() && 
                               banner[*pos..*pos + hex_bytes.len()] == hex_bytes)
                        } else {
                            Ok(banner.windows(hex_bytes.len()).any(|window| window == hex_bytes))
                        }
                    },
                    Err(_) => Ok(false),
                }
            },
            Pattern::SslDetection => {
                // This should be handled by special behavior
                Ok(false)
            },
            Pattern::HttpResponse => {
                // This should be handled by special behavior
                Ok(false)
            },
        }
    }
}

struct ServiceDetector {
    definitions: ServiceDefinitions,
}

impl ServiceDetector {
    fn new() -> Result<Self, FindServiceError> {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let json_path = std::path::PathBuf::from(manifest_dir)
            .join("examples")
            .join("service_definitions.json");
        
        let json_content = std::fs::read_to_string(json_path)?;
        let definitions: ServiceDefinitions = serde_json::from_str(&json_content)?;
        
        Ok(ServiceDetector { definitions })
    }

    fn detect_service(&self, banner: &[u8], port: u16) -> Result<Option<Service>, FindServiceError> {
        for service_def in &self.definitions.services {
            // Check if port matches (if specified)
            if !service_def.ports.is_empty() && !service_def.ports.contains(&port) {
                continue;
            }

            // Check if any pattern matches
            for pattern in &service_def.patterns {
                if pattern.matches(banner)? {
                    return Ok(Some(self.create_service_from_definition(service_def, banner)));
                }
            }
        }
        Ok(None)
    }

    fn create_service_from_definition(&self, def: &ServiceDefinition, banner: &[u8]) -> Service {
        let special_behavior = def.special_behavior.as_ref()
            .and_then(|s| SpecialBehavior::from_string(s));

        let generate_result = if def.generate_result.enabled {
            GenerateResult::Yes { 
                is_vulnerability: def.generate_result.is_vulnerability 
            }
        } else {
            GenerateResult::No
        };

        Service {
            name: def.name.clone(),
            generate_result,
            save_banner: def.save_banner,
            special_behavior,
            banner: String::from_utf8_lossy(banner).to_string(),
            kb_entries: def.kb_entries.clone(),
            message: def.generate_result.message.clone(),
        }
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
        },
        Err(e) if e.kind() == io::ErrorKind::TimedOut => Ok(ReadResult::Timeout),
        Err(e) => Err(SocketError::IO(e).into()),
    }
}

fn scan_port(target: IpAddr, port: u16, detector: &ServiceDetector) -> Result<ScanPortResult, FindServiceError> {
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
    let detector = ServiceDetector::new().map_err(|e| {
        tracing::error!("Failed to initialize service detector: {}", e);
        FnError::from(e)
    })?;
    
    let open_ports = get_open_ports_from_kb(context)?;
    
    for port in open_ports {
        match scan_port(context.target().ip_addr(), port, &detector) {
            Ok(ScanPortResult::Service(service)) => {
                if let Err(e) = handle_detected_service(context, &service, port) {
                    tracing::warn!("Error handling detected service on port {}: {}", port, e);
                }
            },
            Ok(ScanPortResult::Timeout) => {
                tracing::debug!("Timeout reading from port {}", port);
            },
            Ok(ScanPortResult::NoMatch) => {
                tracing::debug!("No service match found for port {}", port);
            },
            Err(e) => {
                tracing::warn!("Error scanning port {}: {}", port, e);
            }
        }
    }
    
    Ok(NaslValue::Null)
}

fn get_open_ports_from_kb(context: &ScanCtx<'_>) -> Result<Vec<u16>, FnError> {
    // Get all TCP ports from KB using pattern matching
    let open_ports = context.get_kb_items_with_keys(&KbKey::Port(kb::Port::Tcp("*".to_string())))?;
    
    // Extract port numbers from the KB keys
    let port_numbers: Vec<u16> = open_ports
        .iter()
        .filter_map(|(key, _values)| {
            // Key format is "Ports/tcp/{port}"
            key.split('/').last().and_then(|port_str| port_str.parse().ok())
        })
        .collect();
    
    // If no ports found in KB, fall back to context port range
    if port_numbers.is_empty() {
        Ok(context.port_range().into_iter().collect())
    } else {
        Ok(port_numbers)
    }
}

fn handle_detected_service(context: &ScanCtx<'_>, service: &Service, port: u16) -> Result<(), FnError> {
    // Store service information in knowledge base
    for (key_template, value_template) in &service.kb_entries {
        let key = key_template.replace("{port}", &port.to_string());
        let value = value_template.replace("{port}", &port.to_string());
        
        // Store in KB using custom key
        context.set_kb_item(
            KbKey::Custom(key),
            KbItem::String(value)
        )?;
    }
    
    // Save banner if requested
    if service.save_banner {
        let banner_key = format!("Banner/{}", port);
        context.set_kb_item(
            KbKey::Custom(banner_key),
            KbItem::String(service.banner.clone())
        )?;
    }
    
    // Generate result if configured
    match &service.generate_result {
        GenerateResult::Yes { is_vulnerability } => {
            if *is_vulnerability {
                // Generate security alert
                tracing::warn!("Security alert on port {}: {}", port, service.message);
                // TODO: Use post_alarm() equivalent
            } else {
                // Generate info log
                tracing::info!("Service detected on port {}: {}", port, service.message);
                // TODO: Use post_log() equivalent
            }
        },
        GenerateResult::No => {
            // No result generation requested
        }
    }
    
    // Handle special behavior
    if let Some(ref special) = service.special_behavior {
        match special {
            SpecialBehavior::SecurityAlert => {
                tracing::warn!("Security alert: {} detected on port {}", service.name, port);
            },
            _ => {
                // Other special behaviors already handled in scan_port
            }
        }
    }
    
    Ok(())
}

#[derive(Default)]
pub struct FindService {
    services: Vec<Service>,
}

function_set! {
    FindService,
    (
        plugin_run_find_service
    )
}
