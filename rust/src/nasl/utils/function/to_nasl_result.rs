// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::collections::HashMap;
use std::path::PathBuf;

use crate::nasl::syntax::NaslValue;
use crate::nasl::{ArgumentError, FnError, NaslResult};

/// A type that can be converted to a NaslResult.
/// The conversion is fallible to make it possible to convert from other Result
/// types. Most generic types should always succeed with the conversion.
pub trait ToNaslResult {
    /// Perform the conversion
    fn to_nasl_result(self) -> NaslResult;
}

impl ToNaslResult for NaslValue {
    fn to_nasl_result(self) -> NaslResult {
        Ok(self)
    }
}

impl<T: ToNaslResult> ToNaslResult for Option<T> {
    fn to_nasl_result(self) -> NaslResult {
        Ok(match self {
            Some(x) => x.to_nasl_result()?,
            None => NaslValue::Null,
        })
    }
}

impl<T: ToNaslResult, E: Into<FnError>> ToNaslResult for Result<T, E> {
    fn to_nasl_result(self) -> NaslResult {
        self.map_err(|e| e.into()).and_then(|x| x.to_nasl_result())
    }
}

impl ToNaslResult for () {
    fn to_nasl_result(self) -> NaslResult {
        Ok(NaslValue::Null)
    }
}

impl ToNaslResult for String {
    fn to_nasl_result(self) -> NaslResult {
        Ok(NaslValue::String(self))
    }
}

impl ToNaslResult for &str {
    fn to_nasl_result(self) -> NaslResult {
        Ok(NaslValue::String(self.to_owned()))
    }
}

impl ToNaslResult for &[u8] {
    fn to_nasl_result(self) -> NaslResult {
        Ok(NaslValue::Data(self.to_vec()))
    }
}

impl ToNaslResult for Vec<u8> {
    fn to_nasl_result(self) -> NaslResult {
        Ok(NaslValue::Data(self))
    }
}

impl ToNaslResult for Vec<&str> {
    fn to_nasl_result(self) -> NaslResult {
        Ok(NaslValue::Array(
            self.into_iter()
                .map(|s| s.to_nasl_result())
                .collect::<Result<Vec<_>, FnError>>()?,
        ))
    }
}

impl ToNaslResult for Vec<String> {
    fn to_nasl_result(self) -> NaslResult {
        Ok(NaslValue::Array(
            self.into_iter()
                .map(|s| s.to_nasl_result())
                .collect::<Result<Vec<_>, FnError>>()?,
        ))
    }
}

impl ToNaslResult for Vec<NaslValue> {
    fn to_nasl_result(self) -> NaslResult {
        Ok(NaslValue::Array(self))
    }
}

impl<T: ToNaslResult> ToNaslResult for HashMap<String, T> {
    fn to_nasl_result(self) -> NaslResult {
        Ok(NaslValue::Dict(
            self.into_iter()
                .map(|(key, s)| s.to_nasl_result().map(|res| (key, res)))
                .collect::<Result<HashMap<_, _>, FnError>>()?,
        ))
    }
}

impl ToNaslResult for bool {
    fn to_nasl_result(self) -> NaslResult {
        Ok(NaslValue::Boolean(self))
    }
}

impl ToNaslResult for PathBuf {
    fn to_nasl_result(self) -> NaslResult {
        self.to_str()
            .ok_or_else(|| {
                ArgumentError::WrongArgument("Expected valid UTF8 in path.".to_string()).into()
            })
            .map(|s| NaslValue::String(s.to_string()))
    }
}

macro_rules! impl_to_nasl_result_for_numeric_type {
    ($ty: ty, skip_vec_impl) => {
        impl ToNaslResult for $ty {
            fn to_nasl_result(self) -> NaslResult {
                Ok(NaslValue::Number(self as i64))
            }
        }
    };
    ($ty: ty) => {
        impl_to_nasl_result_for_numeric_type!($ty, skip_vec_impl);
        impl ToNaslResult for Vec<$ty> {
            fn to_nasl_result(self) -> NaslResult {
                let collected: Result<Vec<_>, FnError> =
                    self.into_iter().map(|x| x.to_nasl_result()).collect();
                Ok(NaslValue::Array(collected?))
            }
        }
    };
}

impl_to_nasl_result_for_numeric_type!(u8, skip_vec_impl);
impl_to_nasl_result_for_numeric_type!(u16);
impl_to_nasl_result_for_numeric_type!(i32);
impl_to_nasl_result_for_numeric_type!(i64);
impl_to_nasl_result_for_numeric_type!(u32);
impl_to_nasl_result_for_numeric_type!(u64);
impl_to_nasl_result_for_numeric_type!(isize);
impl_to_nasl_result_for_numeric_type!(usize);
