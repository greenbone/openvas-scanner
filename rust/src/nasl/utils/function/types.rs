// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{borrow::Cow, time::Duration};

use crate::nasl::prelude::*;

/// Represents either a string slice or a byte slice, Based on
/// a given NaslValue.
pub enum StringOrData<'a> {
    String(&'a str),
    Data(&'a [u8]),
}

impl<'a> FromNaslValue<'a> for StringOrData<'a> {
    fn from_nasl_value(value: &'a NaslValue) -> Result<Self, FnError> {
        match value {
            NaslValue::String(string) => Ok(Self::String(string)),
            NaslValue::Data(buffer) => Ok(Self::Data(buffer)),
            _ => Err(
                ArgumentError::WrongArgument("Expected string or byte buffer.".to_string()).into(),
            ),
        }
    }
}

impl<'a> StringOrData<'a> {
    pub fn string(self) -> Cow<'a, str> {
        match self {
            StringOrData::String(s) => Cow::Borrowed(s),
            StringOrData::Data(b) => String::from_utf8_lossy(b),
        }
    }
    pub fn data(self) -> &'a [u8] {
        match self {
            StringOrData::String(s) => s.as_bytes(),
            StringOrData::Data(b) => b,
        }
    }
}

pub struct Seconds(pub u64);

impl Seconds {
    pub fn as_duration(&self) -> Duration {
        Duration::from_secs(self.0)
    }

    pub fn as_millis(&self) -> u64 {
        self.0 * 1000
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
