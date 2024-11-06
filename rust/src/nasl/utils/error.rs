// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Defines function error kinds
use thiserror::Error;

use crate::nasl::builtin::BuiltinError;
use crate::nasl::prelude::NaslValue;

use crate::storage::StorageError;

use super::ContextType;

#[derive(Debug, Clone, Error)]
/// Descriptive kind of error that can occur while calling a function
pub enum FunctionErrorKind {
    #[error("{0}")]
    Argument(#[from] ArgumentError),
    #[error("{0}")]
    Builtin(#[from] BuiltinError),
    #[error("{0}")]
    Internal(#[from] InternalError),
}

#[derive(Debug, Clone, PartialEq, Error)]
pub enum ArgumentError {
    #[error("Expected {expected} but got {got}")]
    MissingPositionals { expected: usize, got: usize },
    #[error("Expected {expected} but got {got}")]
    TrailingPositionals { expected: usize, got: usize },
    #[error("Missing arguments: {}", .0.join(", "))]
    MissingNamed(Vec<String>),
    #[error("Unknown named argument given to function: {}", .0)]
    UnexpectedArgument(String),
    #[error("Function was called with wrong arguments: {0}")]
    WrongArgument(String),
}

#[derive(Debug, Clone, PartialEq, Error)]
pub enum InternalError {
    #[error("{0}")]
    Storage(#[from] StorageError),
}

pub trait ReturnValue {
    fn with_return_value(self, return_value: impl Into<NaslValue>) -> Self;
    fn get_return_value(&self) -> Option<&NaslValue>;
}

impl ReturnValue for FunctionErrorKind {
    fn with_return_value(self, return_value: impl Into<NaslValue>) -> Self {
        match self {
            Self::Argument(_) => self,
            Self::Builtin(e) => Self::Builtin(e.with_return_value(return_value)),
            Self::Internal(_) => self,
        }
    }

    fn get_return_value(&self) -> Option<&NaslValue> {
        match self {
            Self::Argument(_) => None,
            Self::Builtin(e) => e.get_return_value(),
            Self::Internal(_) => None,
        }
    }
}

impl From<StorageError> for FunctionErrorKind {
    fn from(value: StorageError) -> Self {
        FunctionErrorKind::Internal(InternalError::Storage(value))
    }
}

impl TryFrom<FunctionErrorKind> for ArgumentError {
    type Error = ();

    fn try_from(value: FunctionErrorKind) -> Result<Self, Self::Error> {
        match value {
            FunctionErrorKind::Argument(e) => Ok(e),
            _ => Err(()),
        }
    }
}

impl TryFrom<FunctionErrorKind> for InternalError {
    type Error = ();

    fn try_from(value: FunctionErrorKind) -> Result<Self, Self::Error> {
        match value {
            FunctionErrorKind::Internal(e) => Ok(e),
            _ => Err(()),
        }
    }
}

impl TryFrom<FunctionErrorKind> for BuiltinError {
    type Error = ();

    fn try_from(value: FunctionErrorKind) -> Result<Self, Self::Error> {
        match value {
            FunctionErrorKind::Builtin(e) => Ok(e),
            _ => Err(()),
        }
    }
}

impl ArgumentError {
    /// Helper function to quickly construct a `WrongArgument` variant
    /// containing the name of the argument, the expected value and
    /// the actual value.
    pub fn wrong_argument(key: &str, expected: &str, got: &str) -> Self {
        ArgumentError::WrongArgument(format!("Expected {key} to be {expected} but it is {got}"))
    }
}

impl FunctionErrorKind {
    /// Helper function to quickly construct a `WrongArgument` variant
    /// containing the name of the argument, the expected value and
    /// the actual value.
    pub fn wrong_unnamed_argument(expected: &str, got: &str) -> Self {
        Self::Argument(ArgumentError::WrongArgument(format!(
            "Expected {expected} but {got}"
        )))
    }

    /// Helper function to quickly construct a `MissingArguments` variant
    /// for a single missing argument.
    pub fn missing_argument(val: &str) -> Self {
        Self::Argument(ArgumentError::MissingNamed(vec![val.to_string()]))
    }
}

impl From<(&str, &str, &NaslValue)> for FunctionErrorKind {
    fn from(value: (&str, &str, &NaslValue)) -> Self {
        let (key, expected, got) = value;
        let got: &str = &got.to_string();
        ArgumentError::wrong_argument(key, expected, got).into()
    }
}

impl From<(&str, &str, Option<&NaslValue>)> for FunctionErrorKind {
    fn from(value: (&str, &str, Option<&NaslValue>)) -> Self {
        match value {
            (key, expected, Some(x)) => (key, expected, x).into(),
            (key, expected, None) => ArgumentError::wrong_argument(key, expected, "NULL").into(),
        }
    }
}

impl From<(&str, &str, Option<&ContextType>)> for FunctionErrorKind {
    fn from(value: (&str, &str, Option<&ContextType>)) -> Self {
        match value {
            (key, expected, Some(ContextType::Value(x))) => (key, expected, x).into(),
            (key, expected, Some(ContextType::Function(_, _))) => {
                ArgumentError::wrong_argument(key, expected, "function").into()
            }
            (key, expected, None) => ArgumentError::wrong_argument(key, expected, "NULL").into(),
        }
    }
}

impl From<(&str, &NaslValue)> for FunctionErrorKind {
    fn from(value: (&str, &NaslValue)) -> Self {
        let (expected, got) = value;
        let got: &str = &got.to_string();
        FunctionErrorKind::wrong_unnamed_argument(expected, got)
    }
}
