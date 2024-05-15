// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::fmt::Display;

use nasl_builtin_utils::{Context, FunctionErrorKind, NaslResult, Register};
use nasl_syntax::NaslValue;
use storage::Field;

pub mod socket;

macro_rules! i64_to_enum {
    ($(#[$meta:meta])* $vis:vis enum $name:ident {
        $($(#[$vmeta:meta])* $vname:ident $(= $val:expr)?,)*
    }) => {
        $(#[$meta])*
        $vis enum $name {
            $($(#[$vmeta])* $vname $(= $val)?,)*
        }

        impl std::convert::TryFrom<i64> for $name {
            type Error = ();

            fn try_from(v: i64) -> Result<Self, Self::Error> {
                match v {
                    $(x if x == $name::$vname as i64 => Ok($name::$vname),)*
                    _ => Err(()),
                }
            }
        }
    }
}

i64_to_enum! {
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
            nasl_builtin_utils::ContextType::Function(_, _) => {
                Err(FunctionErrorKind::MissingArguments(vec![name.to_string()]))
            }
            nasl_builtin_utils::ContextType::Value(val) => Ok(val.to_owned()),
        },
        None => Err(FunctionErrorKind::MissingArguments(vec![
            "socket".to_string()
        ])),
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
    Ok((&get_named_value(r, "data")?).into())
}

fn get_opt_int(r: &Register, name: &str) -> Option<i64> {
    get_named_value(r, name)
        .map(|val| match val {
            NaslValue::Number(len) => Some(len),
            _ => None,
        })
        .unwrap_or_default()
}

pub fn get_kb_item(context: &Context, name: &str) -> NaslResult {
    context
        .retriever()
        .retrieve(context.key(), storage::Retrieve::KB(name.to_string()))
        .map(|r| {
            r.into_iter().find_map(|x| match x {
                Field::NVT(_) | Field::NotusAdvisory(_) => None,
                Field::KB(kb) => kb.value.into(),
            })
        })
        .map(|x| match x {
            Some(x) => x.into(),
            None => NaslValue::Null,
        })
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
