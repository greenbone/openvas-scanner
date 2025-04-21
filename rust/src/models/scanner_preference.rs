// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

/// Configuration preference for the scanner
#[derive(Default, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct ScanPreference {
    /// The ID of a scan preference.
    pub id: String,
    /// The value of the scan preference.
    pub value: String,
}

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
    String(&'static str),
}

impl Default for PreferenceValue {
    fn default() -> Self {
        Self::Int(0)
    }
}

impl PreferenceValue {
    pub fn get_bool(&self) -> bool {
        match self {
            PreferenceValue::Bool(v) => *v,
            _ => false,
        }
    }
    pub fn get_string(&self) -> String {
        match self {
            PreferenceValue::String(v) => v.to_string(),
            _ => "".to_string(),
        }
    }
    pub fn get_int(&self) -> i64 {
        match self {
            PreferenceValue::Int(v) => *v,
            _ => 0,
        }
    }
}

/// Configuration preference information for a scan. The type can be derived from the default value.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct ScanPreferenceInformation {
    /// The ID of the scan preference
    pub id: &'static str,
    /// Display name of the scan preference
    pub name: &'static str,
    /// The value of the scan preference
    pub default: PreferenceValue,
    /// Description of the scan preference
    pub description: &'static str,
}
