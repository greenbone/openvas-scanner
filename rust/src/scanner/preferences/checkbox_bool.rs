// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// openvas encodes booleans as `yes` and `no`. This type
/// represents such booleans and serializes/deserializes them properly
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckboxBool(bool);

impl CheckboxBool {
    pub(crate) fn serialize_bool<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bool(self.0)
    }

    pub(crate) fn deserialize_bool<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        bool::deserialize(deserializer).map(Self)
    }
}

impl From<bool> for CheckboxBool {
    fn from(value: bool) -> Self {
        Self(value)
    }
}

impl FromStr for CheckboxBool {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value == "0" || value.eq_ignore_ascii_case("false") || value.eq_ignore_ascii_case("no") {
            Ok(Self(false))
        } else if value == "1"
            || value.eq_ignore_ascii_case("true")
            || value.eq_ignore_ascii_case("yes")
        {
            Ok(Self(true))
        } else {
            Err("expected a checkbox value: 0, 1, false, true, no, or yes")
        }
    }
}

impl fmt::Display for CheckboxBool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if self.0 { "yes" } else { "no" })
    }
}

impl Serialize for CheckboxBool {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for CheckboxBool {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::CheckboxBool;
    use crate::scanner::preferences::preference::ScanPrefValue;

    #[test]
    fn preference_booleans_preserve_config_encoding() {
        for (json, protocol) in [("true", "yes"), ("false", "no")] {
            let value: ScanPrefValue = serde_json::from_str(json).unwrap();
            assert!(matches!(value, ScanPrefValue::Bool(_)));
            assert_eq!(value.to_string(), protocol);
            assert_eq!(serde_json::to_string(&value).unwrap(), json);
        }
        for text in ["yes", "no", "true", "false", "1", "0"] {
            let json = serde_json::to_string(text).unwrap();
            let value: ScanPrefValue = serde_json::from_str(&json).unwrap();
            assert_eq!(value, ScanPrefValue::String(text.to_string()));
        }
    }

    #[test]
    fn checkbox_values_are_normalized() {
        for (inputs, expected) in [
            (["1", "true", "True", "TRUE", "yes", "Yes", "YES"], true),
            (["0", "false", "False", "FALSE", "no", "No", "NO"], false),
        ] {
            let checkbox = CheckboxBool::from(expected);
            let output = if expected { "yes" } else { "no" };
            for input in inputs {
                assert_eq!(input.parse::<CheckboxBool>(), Ok(checkbox));
                let json = serde_json::to_string(input).unwrap();
                assert_eq!(
                    serde_json::from_str::<CheckboxBool>(&json).unwrap(),
                    checkbox
                );
            }
            assert_eq!(checkbox.to_string(), output);
            assert_eq!(
                serde_json::to_string(&checkbox).unwrap(),
                format!("\"{output}\"")
            );
        }
    }

    #[test]
    fn invalid_checkbox_values_are_rejected() {
        for input in ["", " ", " yes ", "2", "-1", "on", "off", "nein", "truthy"] {
            assert!(input.parse::<CheckboxBool>().is_err(), "{input}");
            let json = serde_json::to_string(input).unwrap();
            assert!(
                serde_json::from_str::<CheckboxBool>(&json).is_err(),
                "{input}"
            );
        }
        for json in ["true", "false", "0", "1", "null", "[]", "{}"] {
            assert!(
                serde_json::from_str::<CheckboxBool>(json).is_err(),
                "{json}"
            );
        }
    }
}
