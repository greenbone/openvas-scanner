// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Defines function error kinds
use thiserror::Error;

use crate::nasl::builtin::BuiltinError;
use crate::nasl::prelude::NaslValue;

use crate::storage::StorageError;

#[derive(Debug, Clone, Error)]
#[error("{kind}")]
pub struct FunctionErrorKind {
    #[source]
    pub kind: FEK,
    return_value: Option<NaslValue>,
}

impl FunctionErrorKind {
    pub fn return_value(&self) -> &Option<NaslValue> {
        &self.return_value
    }
}

impl From<FEK> for FunctionErrorKind {
    fn from(value: FEK) -> Self {
        FunctionErrorKind {
            kind: value,
            return_value: None,
        }
    }
}

impl From<ArgumentError> for FunctionErrorKind {
    fn from(value: ArgumentError) -> Self {
        FunctionErrorKind {
            kind: FEK::Argument(value),
            return_value: None,
        }
    }
}

impl From<BuiltinError> for FunctionErrorKind {
    fn from(value: BuiltinError) -> Self {
        FunctionErrorKind {
            kind: FEK::Builtin(value),
            return_value: None,
        }
    }
}

impl From<InternalError> for FunctionErrorKind {
    fn from(value: InternalError) -> Self {
        FunctionErrorKind {
            kind: FEK::Internal(value),
            return_value: None,
        }
    }
}

#[derive(Debug, Clone, Error)]
/// Descriptive kind of error that can occur while calling a function
pub enum FEK {
    #[error("{0}")]
    Argument(ArgumentError),
    #[error("{0}")]
    Builtin(BuiltinError),
    #[error("{0}")]
    Internal(InternalError),
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

pub trait WithErrorInfo<Info> {
    fn with(self, e: Info) -> Self;
}

pub struct ReturnValue<T>(pub T);

impl<T: Into<NaslValue>> WithErrorInfo<ReturnValue<T>> for FunctionErrorKind {
    fn with(mut self, val: ReturnValue<T>) -> Self {
        self.return_value = Some(val.0.into());
        self
    }
}

impl From<StorageError> for FunctionErrorKind {
    fn from(value: StorageError) -> Self {
        FEK::Internal(InternalError::Storage(value)).into()
    }
}

impl TryFrom<FunctionErrorKind> for ArgumentError {
    type Error = ();

    fn try_from(value: FunctionErrorKind) -> Result<Self, Self::Error> {
        match value.kind {
            FEK::Argument(e) => Ok(e),
            _ => Err(()),
        }
    }
}

impl TryFrom<FunctionErrorKind> for InternalError {
    type Error = ();

    fn try_from(value: FunctionErrorKind) -> Result<Self, Self::Error> {
        match value.kind {
            FEK::Internal(e) => Ok(e),
            _ => Err(()),
        }
    }
}

impl TryFrom<FunctionErrorKind> for BuiltinError {
    type Error = ();

    fn try_from(value: FunctionErrorKind) -> Result<Self, Self::Error> {
        match value.kind {
            FEK::Builtin(e) => Ok(e),
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
        FEK::Argument(ArgumentError::WrongArgument(format!(
            "Expected {expected} but {got}"
        )))
        .into()
    }

    /// Helper function to quickly construct a `MissingArguments` variant
    /// for a single missing argument.
    pub fn missing_argument(val: &str) -> Self {
        FEK::Argument(ArgumentError::MissingNamed(vec![val.to_string()])).into()
    }
}
