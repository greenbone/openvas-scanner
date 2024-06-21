// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Defines commonly support data types

use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq, Eq, Default, Hash)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize),
    serde(untagged)
)]
/// Allowed type definitions
pub enum Primitive {
    /// String value
    String(String),
    /// Data value
    Data(Vec<u8>),
    /// Number value
    Number(i64),
    /// Array value
    Array(Vec<Primitive>),
    /// Array value
    Dict(Vec<(String, Primitive)>),
    /// Boolean value
    Boolean(bool),
    /// Null value
    #[default]
    Null,
}

impl From<Vec<u8>> for Primitive {
    fn from(s: Vec<u8>) -> Self {
        Self::Data(s)
    }
}

impl From<bool> for Primitive {
    fn from(b: bool) -> Self {
        Primitive::Boolean(b)
    }
}

impl From<Vec<String>> for Primitive {
    fn from(s: Vec<String>) -> Self {
        Self::Array(s.into_iter().map(|x| x.into()).collect())
    }
}

impl From<&str> for Primitive {
    fn from(s: &str) -> Self {
        Self::String(s.to_owned())
    }
}

impl From<String> for Primitive {
    fn from(s: String) -> Self {
        Self::String(s)
    }
}

impl From<i32> for Primitive {
    fn from(n: i32) -> Self {
        Self::Number(n as i64)
    }
}

impl From<i64> for Primitive {
    fn from(n: i64) -> Self {
        Self::Number(n)
    }
}

impl From<usize> for Primitive {
    fn from(n: usize) -> Self {
        Self::Number(n as i64)
    }
}

impl From<HashMap<String, Primitive>> for Primitive {
    fn from(x: HashMap<String, Primitive>) -> Self {
        Primitive::Dict(x.into_iter().collect())
    }
}

impl From<Primitive> for bool {
    fn from(value: Primitive) -> Self {
        match value {
            Primitive::String(string) => !string.is_empty() && string != "0",
            Primitive::Array(v) => !v.is_empty(),
            Primitive::Data(v) => !v.is_empty(),
            Primitive::Boolean(boolean) => boolean,
            Primitive::Null => false,
            Primitive::Number(number) => number != 0,
            Primitive::Dict(v) => !v.is_empty(),
        }
    }
}

impl From<&Primitive> for i64 {
    fn from(value: &Primitive) -> Self {
        match value {
            Primitive::String(_) => 1,
            &Primitive::Number(x) => x,
            Primitive::Array(_) => 1,
            Primitive::Data(_) => 1,
            Primitive::Dict(_) => 1,
            &Primitive::Boolean(x) => x as i64,
            Primitive::Null => 0,
        }
    }
}

impl From<&Primitive> for Vec<u8> {
    fn from(value: &Primitive) -> Vec<u8> {
        match value {
            Primitive::String(x) => x.as_bytes().to_vec(),
            &Primitive::Number(x) => x.to_ne_bytes().to_vec(),
            Primitive::Data(x) => x.to_vec(),
            _ => Vec::new(),
        }
    }
}

impl From<Primitive> for i64 {
    fn from(nv: Primitive) -> Self {
        i64::from(&nv)
    }
}

impl std::fmt::Display for Primitive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Primitive::String(x) => write!(f, "{x}"),
            Primitive::Number(x) => write!(f, "{x}"),
            Primitive::Array(x) => write!(
                f,
                "{}",
                x.iter()
                    .enumerate()
                    .map(|(i, v)| format!("{}: {}", i, v))
                    .collect::<Vec<String>>()
                    .join(",")
            ),
            Primitive::Data(x) => {
                write!(f, "{}", x.iter().map(|x| *x as char).collect::<String>())
            }
            Primitive::Dict(x) => write!(
                f,
                "{}",
                x.iter()
                    .map(|(k, v)| format!("{}: {}", k, v))
                    .collect::<Vec<String>>()
                    .join(",")
            ),
            Primitive::Boolean(true) => write!(f, "1"),
            Primitive::Boolean(false) => write!(f, "0"),
            Primitive::Null => write!(f, "\0"),
        }
    }
}
