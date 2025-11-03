// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::{fmt::Display, net::IpAddr};

#[cfg(feature = "nasl-builtin-raw-ip")]
use crate::nasl::raw_ip_utils::raw_ip_utils;
use crate::{
    nasl::{prelude::*, utils::DefineGlobalVars},
    storage::items::kb::KbKey,
};

#[allow(clippy::module_inception)]
pub mod network;
mod network_utils;
pub mod socket;
mod tcp;
mod tls;
mod udp;

// 512 Bytes are typically supported by network devices. The ip header maximum size is 60 and a UDP
// header contains 8 bytes, which must be subtracted from the max size for UDP packages.
const MTU: usize = 512 - 60 - 8;

/// Standard port for networking functions
const DEFAULT_PORT: u16 = 33435;

// Get the max MTU possible for network communication
#[cfg(not(feature = "nasl-builtin-raw-ip"))]
fn mtu(_: IpAddr) -> usize {
    MTU
}
#[cfg(feature = "nasl-builtin-raw-ip")]
fn mtu(target_ip: IpAddr) -> usize {
    match raw_ip_utils::get_mtu(target_ip) {
        Ok(mtu) => mtu,
        Err(_) => MTU,
    }
}

#[derive(Clone)]
pub enum OpenvasEncaps {
    Auto = 0, /* Request auto detection.  */
    Ip,
    Ssl23, /* Ask for compatibility options */
    Ssl2,
    Ssl3,
    Tls1,
    Tls11,
    Tls12,
    Tls13,
    TlsCustom, /* SSL/TLS using custom priorities.  */
    Max,
}

impl OpenvasEncaps {
    fn from_i64(val: i64) -> Option<Self> {
        match val {
            0 => Some(Self::Auto),
            1 => Some(Self::Ip),
            2 => Some(Self::Ssl23),
            3 => Some(Self::Ssl2),
            4 => Some(Self::Ssl3),
            5 => Some(Self::Tls1),
            6 => Some(Self::Tls11),
            7 => Some(Self::Tls12),
            8 => Some(Self::Tls13),
            9 => Some(Self::TlsCustom),
            10 => Some(Self::Max),
            _ => None,
        }
    }
}

impl From<OpenvasEncaps> for i64 {
    fn from(value: OpenvasEncaps) -> Self {
        match value {
            OpenvasEncaps::Auto => 0,
            OpenvasEncaps::Ip => 1,
            OpenvasEncaps::Ssl23 => 2,
            OpenvasEncaps::Ssl2 => 3,
            OpenvasEncaps::Ssl3 => 4,
            OpenvasEncaps::Tls1 => 5,
            OpenvasEncaps::Tls11 => 6,
            OpenvasEncaps::Tls12 => 7,
            OpenvasEncaps::Tls13 => 8,
            OpenvasEncaps::TlsCustom => 9,
            OpenvasEncaps::Max => 10,
        }
    }
}

impl From<OpenvasEncaps> for String {
    fn from(value: OpenvasEncaps) -> String {
        match value {
            OpenvasEncaps::Ip => "None".to_string(),
            OpenvasEncaps::Ssl23 => "SSL 2.3".to_string(),
            OpenvasEncaps::Ssl2 => "SSL 2".to_string(),
            OpenvasEncaps::Ssl3 => "SSL 3".to_string(),
            OpenvasEncaps::Tls1 => "TLS 1".to_string(),
            OpenvasEncaps::Tls11 => "TLS 1.1".to_string(),
            OpenvasEncaps::Tls12 => "TLS 1.2".to_string(),
            OpenvasEncaps::Tls13 => "TLS 1.3".to_string(),
            _ => "None".to_string(),
        }
    }
}

impl Display for OpenvasEncaps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpenvasEncaps::Ip => write!(f, "None"),
            OpenvasEncaps::Ssl23 => write!(f, "SSL 2.3"),
            OpenvasEncaps::Ssl2 => write!(f, "SSL 2"),
            OpenvasEncaps::Ssl3 => write!(f, "SSL 3"),
            OpenvasEncaps::Tls1 => write!(f, "TLS 1"),
            OpenvasEncaps::Tls11 => write!(f, "TLS 1.1"),
            OpenvasEncaps::Tls12 => write!(f, "TLS 1.2"),
            OpenvasEncaps::Tls13 => write!(f, "TLS 1.3"),
            _ => write!(f, "unknown"),
        }
    }
}

fn get_retry(context: &ScanCtx) -> u8 {
    if let Ok(val) = context.get_single_kb_item(&KbKey::TimeoutRetry) {
        match val {
            NaslValue::String(val) => val.parse::<u8>().unwrap_or(2),
            NaslValue::Number(val) => {
                if !(1..=255).contains(&val) {
                    2
                } else {
                    val as u8
                }
            }
            _ => 2,
        }
    } else {
        2
    }
}

pub struct Port(u16);

impl From<Port> for u16 {
    fn from(value: Port) -> Self {
        value.0
    }
}

impl From<u16> for Port {
    fn from(value: u16) -> Self {
        Port(value)
    }
}

impl FromNaslValue<'_> for Port {
    fn from_nasl_value(value: &NaslValue) -> Result<Self, FnError> {
        let port = i64::from_nasl_value(value)?;
        if !(0..=65535).contains(&port) {
            Err(ArgumentError::WrongArgument(format!("{port} is not a valid port number")).into())
        } else {
            Ok(Port(port as u16))
        }
    }
}

pub struct Network;

impl DefineGlobalVars for Network {
    fn get_global_vars() -> Vec<(&'static str, NaslValue)> {
        socket::SocketFns::get_global_vars().into_iter().collect()
    }
}
