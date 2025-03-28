// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::time::Duration;

use crate::nasl::prelude::*;

/// `Some(string)` if constructed from either a `NaslValue::String`
/// or `NaslValue::Data`.
pub struct StringOrData(pub String);

impl<'a> FromNaslValue<'a> for StringOrData {
    fn from_nasl_value(value: &'a NaslValue) -> Result<Self, FnError> {
        match value {
            NaslValue::String(string) => Ok(Self(string.clone())),
            NaslValue::Data(buffer) => Ok(Self(bytes_to_str(buffer))),
            _ => Err(
                ArgumentError::WrongArgument("Expected string or byte buffer.".to_string()).into(),
            ),
        }
    }
}

pub fn bytes_to_str(bytes: &[u8]) -> String {
    bytes.iter().map(|x| *x as char).collect::<String>()
}

pub struct Seconds(pub u64);

impl Seconds {
    pub fn as_duration(&self) -> Duration {
        Duration::from_secs(self.0)
    }
}

impl<'a> FromNaslValue<'a> for Seconds {
    fn from_nasl_value(value: &'a NaslValue) -> Result<Self, FnError> {
        let value: i64 = i64::from_nasl_value(value)?;
        let value: u64 = value
            .try_into()
            .map_err(|_| ArgumentError::WrongArgument("Expected positive number".to_string()))?;
        Ok(Seconds(value))
    }
}
