use std::collections::HashMap;

use crate::nasl::prelude::*;

/// A type that can be converted from a NaslValue.
/// The conversion may fail.
pub trait FromNaslValue<'a>: Sized {
    /// Perform the conversion
    fn from_nasl_value(value: &'a NaslValue) -> Result<Self, FunctionErrorKind>;
}

impl<'a> FromNaslValue<'a> for NaslValue {
    fn from_nasl_value(value: &'a NaslValue) -> Result<Self, FunctionErrorKind> {
        Ok(value.clone())
    }
}

impl<'a> FromNaslValue<'a> for &'a NaslValue {
    fn from_nasl_value(value: &'a NaslValue) -> Result<Self, FunctionErrorKind> {
        Ok(value)
    }
}

impl<'a> FromNaslValue<'a> for String {
    fn from_nasl_value(value: &NaslValue) -> Result<Self, FunctionErrorKind> {
        match value {
            NaslValue::String(string) => Ok(string.to_string()),
            _ => Err(FunctionErrorKind::WrongArgument(
                "Expected string.".to_string(),
            )),
        }
    }
}

impl<'a> FromNaslValue<'a> for &'a str {
    fn from_nasl_value(value: &'a NaslValue) -> Result<Self, FunctionErrorKind> {
        match value {
            NaslValue::String(string) => Ok(string),
            _ => Err(FunctionErrorKind::WrongArgument(
                "Expected string.".to_string(),
            )),
        }
    }
}

impl<'a> FromNaslValue<'a> for &'a [u8] {
    fn from_nasl_value(value: &'a NaslValue) -> Result<Self, FunctionErrorKind> {
        match value {
            NaslValue::Data(bytes) => Ok(bytes),
            _ => Err(FunctionErrorKind::WrongArgument(
                "Expected byte data.".to_string(),
            )),
        }
    }
}

impl<'a, T: FromNaslValue<'a>> FromNaslValue<'a> for Vec<T> {
    fn from_nasl_value(value: &'a NaslValue) -> Result<Self, FunctionErrorKind> {
        match value {
            NaslValue::Array(vals) => Ok(vals
                .iter()
                .map(T::from_nasl_value)
                .collect::<Result<Vec<T>, FunctionErrorKind>>()?),
            _ => Err(FunctionErrorKind::WrongArgument(
                "Expected an array..".to_string(),
            )),
        }
    }
}

impl<'a, T: FromNaslValue<'a>> FromNaslValue<'a> for HashMap<String, T> {
    fn from_nasl_value(value: &'a NaslValue) -> Result<Self, FunctionErrorKind> {
        match value {
            NaslValue::Dict(map) => Ok(map
                .iter()
                .map(|(k, v)| T::from_nasl_value(v).map(|v| (k.clone(), v)))
                .collect::<Result<HashMap<_, _>, _>>()?),
            _ => Err(FunctionErrorKind::WrongArgument(
                "Expected a dictionary.".to_string(),
            )),
        }
    }
}

impl<'a> FromNaslValue<'a> for bool {
    fn from_nasl_value(value: &'a NaslValue) -> Result<Self, FunctionErrorKind> {
        match value {
            NaslValue::Boolean(b) => Ok(*b),
            _ => Err(FunctionErrorKind::WrongArgument(
                "Expected bool.".to_string(),
            )),
        }
    }
}

macro_rules! impl_from_nasl_value_for_numeric_type {
    ($ty: ty) => {
        impl<'a> FromNaslValue<'a> for $ty {
            fn from_nasl_value(value: &NaslValue) -> Result<Self, FunctionErrorKind> {
                match value {
                    NaslValue::Number(num) => Ok(<$ty>::try_from(*num).map_err(|_| {
                        FunctionErrorKind::WrongArgument("Expected positive number.".into())
                    })?),
                    _ => Err(FunctionErrorKind::WrongArgument(
                        "Expected a number.".to_string(),
                    )),
                }
            }
        }
    };
}

impl_from_nasl_value_for_numeric_type!(u8);
impl_from_nasl_value_for_numeric_type!(i32);
impl_from_nasl_value_for_numeric_type!(i64);
impl_from_nasl_value_for_numeric_type!(u32);
impl_from_nasl_value_for_numeric_type!(u64);
impl_from_nasl_value_for_numeric_type!(isize);
impl_from_nasl_value_for_numeric_type!(usize);
