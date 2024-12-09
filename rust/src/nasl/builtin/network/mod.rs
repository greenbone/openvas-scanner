// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::{fmt::Display, net::IpAddr};

use crate::nasl::prelude::*;

#[allow(clippy::module_inception)]
pub mod network;
pub mod network_utils;
pub mod socket;
pub mod tcp;
pub mod tls;
pub mod udp;

// 512 Bytes are typically supported by network devices. The ip header maximum size is 60 and a UDP
// header contains 8 bytes, which must be subtracted from the max size for UDP packages.
const MTU: usize = 512 - 60 - 8;

/// Standard port for networking functions
const DEFAULT_PORT: u16 = 33435;

// Get the max MTU possible for network communication
// TODO: Calculate the MTU dynamically
pub fn mtu(_: IpAddr) -> usize {
    MTU
}

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
    pub fn from_i64(val: i64) -> Option<Self> {
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

pub fn get_retry(context: &Context) -> u8 {
    if let Ok(val) = context.get_single_kb_item("timeout_retry") {
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

struct Port(u16);

impl FromNaslValue<'_> for Port {
    fn from_nasl_value(value: &NaslValue) -> Result<Self, FnError> {
        let port = i64::from_nasl_value(value)?;
        if !(0..=65535).contains(&port) {
            Err(ArgumentError::WrongArgument(format!("{} is not a valid port number", port)).into())
        } else {
            Ok(Port(port as u16))
        }
    }
}
