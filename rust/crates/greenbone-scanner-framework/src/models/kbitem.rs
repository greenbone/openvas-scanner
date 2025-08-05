// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Defines an KB item with its corresponding key in storage.

use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq, Eq, Default, Hash, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
/// Allowed type definitions
// TODO: rename, KbItem is a bit confusing
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
