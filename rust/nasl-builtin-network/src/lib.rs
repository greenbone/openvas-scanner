// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::fmt::Display;

use nasl_builtin_utils::{Context, FunctionErrorKind, Register};
use nasl_syntax::NaslValue;
use storage::Field;

pub mod network;
pub mod network_utils;
pub mod socket;

// 512 Bytes are typically supported by network devices. The ip header maximum size is 60 and a UDP
// header contains 8 bytes, which must be subtracted from the max size for UDP packages.
// TODO: Calculate the MTU dynamically
const MTU: usize = 512 - 60 - 8;

/// Standard port for networking functions
/// @return none
const DEFAULT_PORT: u16 = 33435;

pub fn mtu() -> usize {
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

fn get_named_value(r: &Register, name: &str) -> Result<NaslValue, FunctionErrorKind> {
    match r.named(name) {
        Some(x) => match x {
            nasl_builtin_utils::ContextType::Function(_, _) => Err(
                FunctionErrorKind::WrongArgument(format!("{name} is a function")),
            ),
            nasl_builtin_utils::ContextType::Value(val) => Ok(val.to_owned()),
        },
        None => Err(FunctionErrorKind::MissingArguments(vec![name.to_string()])),
    }
}

fn get_usize(r: &Register, name: &str) -> Result<usize, FunctionErrorKind> {
    match get_named_value(r, name)? {
        NaslValue::Number(num) => {
            if num < 0 {
                return Err(FunctionErrorKind::WrongArgument(format!(
                    "Argument {name} must be >= 0"
                )));
            }
            Ok(num as usize)
        }
        _ => Err(FunctionErrorKind::WrongArgument(
            "Wrong type for argument, expected a number".to_string(),
        )),
    }
}

fn get_data(r: &Register) -> Result<Vec<u8>, FunctionErrorKind> {
    Ok((get_named_value(r, "data")?).into())
}

fn get_opt_int(r: &Register, name: &str) -> Option<i64> {
    get_named_value(r, name)
        .map(|val| match val {
            NaslValue::Number(len) => Some(len),
            _ => None,
        })
        .unwrap_or_default()
}

pub fn get_kb_item(context: &Context, name: &str) -> Result<Option<NaslValue>, FunctionErrorKind> {
    context
        .retriever()
        .retrieve(context.key(), storage::Retrieve::KB(name.to_string()))
        .map(|r| {
            r.into_iter().find_map(|x| match x {
                Field::KB(kb) => kb.value.into(),
                _ => None,
            })
        })
        .map(|x| x.map(|x| x.into()))
        .map_err(|e| e.into())
}

pub fn get_pos_port(r: &Register) -> Result<u16, FunctionErrorKind> {
    match r
        .positional()
        .first()
        .ok_or(FunctionErrorKind::MissingPositionalArguments {
            expected: 1,
            got: 0,
        })? {
        NaslValue::Number(port) => {
            if *port < 0 || *port > 65535 {
                return Err(FunctionErrorKind::WrongArgument(format!(
                    "{} is not a valid port number",
                    *port
                )));
            }
            Ok(*port as u16)
        }
        x => Err(FunctionErrorKind::WrongArgument(format!(
            "{} is not a valid port number",
            x
        ))),
    }
}

pub fn verify_port(port: i64) -> Result<u16, FunctionErrorKind> {
    if !(0..=65535).contains(&port) {
        return Err(FunctionErrorKind::WrongArgument(format!(
            "{} is not a valid port number",
            port
        )));
    }
    Ok(port as u16)
}
