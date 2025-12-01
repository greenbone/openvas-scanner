// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::str::FromStr;

use crate::nasl::{prelude::*, utils::function::StringOrData};
use russh::{cipher, keys::Algorithm};

/// A list of items which are represented as a
/// NASL string which contains the items separated by
/// commas.
pub struct CommaSeparated<T>(pub Vec<T>);

impl<'a, T> FromNaslValue<'a> for CommaSeparated<T>
where
    T: for<'b> FromNaslValue<'b>,
{
    fn from_nasl_value(value: &'a NaslValue) -> Result<Self, FnError> {
        let s = StringOrData::from_nasl_value(value)?;
        Ok(Self(
            s.string()
                .split(",")
                .filter(|s| s != &"")
                .map(|substr| {
                    let nasl_val = NaslValue::String(substr.to_string());
                    T::from_nasl_value(&nasl_val)
                })
                .collect::<Result<Vec<_>, FnError>>()?,
        ))
    }
}

impl<'a> FromNaslValue<'a> for Algorithm {
    fn from_nasl_value(value: &'a NaslValue) -> Result<Self, FnError> {
        let s = String::from_nasl_value(value)?;
        Algorithm::from_str(&s).map_err(|_| {
            ArgumentError::WrongArgument(format!("Expected a valid SSH key algorithm, found '{s}'"))
                .into()
        })
    }
}

impl<'a> FromNaslValue<'a> for cipher::Name {
    fn from_nasl_value(value: &'a NaslValue) -> Result<Self, FnError> {
        let s = String::from_nasl_value(value)?;
        cipher::Name::try_from(&*s).map_err(|_| {
            ArgumentError::WrongArgument(format!("Expected a valid SSH cipher type, found '{s}'"))
                .into()
        })
    }
}
