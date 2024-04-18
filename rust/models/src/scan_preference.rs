// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::fmt::Display;

/// Preference value
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize),
    serde(untagged)
)]
pub enum PreferenceValue {
    Bool(bool),
    Int(i64),
    String(String),
}

impl Default for PreferenceValue {
    fn default() -> Self {
        Self::Int(0)
    }
}

impl Display for PreferenceValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PreferenceValue::Bool(v) => write!(f, "{v}"),
            PreferenceValue::Int(v) => write!(f, "{v}"),
            PreferenceValue::String(v) => write!(f, "{v}"),
        }
    }
}
