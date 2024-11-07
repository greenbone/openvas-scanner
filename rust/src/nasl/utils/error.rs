// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use thiserror::Error;

use crate::nasl::builtin::BuiltinError;
use crate::nasl::prelude::NaslValue;

use crate::storage::StorageError;

#[derive(Debug, Clone, Error)]
#[error("{kind}")]
pub struct FnError {
    #[source]
    pub kind: FnErrorKind,
    return_value: Option<NaslValue>,
}

impl FnError {
    pub fn return_value(&self) -> &Option<NaslValue> {
        &self.return_value
    }
}

impl From<FnErrorKind> for FnError {
    fn from(value: FnErrorKind) -> Self {
        FnError {
            kind: value,
            return_value: None,
        }
    }
}

impl From<ArgumentError> for FnError {
    fn from(value: ArgumentError) -> Self {
        FnError {
            kind: FnErrorKind::Argument(value),
            return_value: None,
        }
    }
}

impl From<BuiltinError> for FnError {
    fn from(value: BuiltinError) -> Self {
        FnError {
            kind: FnErrorKind::Builtin(value),
            return_value: None,
        }
    }
}

impl From<InternalError> for FnError {
    fn from(value: InternalError) -> Self {
        FnError {
            kind: FnErrorKind::Internal(value),
            return_value: None,
        }
    }
}

#[derive(Debug, Clone, Error)]
pub enum FnErrorKind {
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

impl<T: Into<NaslValue>> WithErrorInfo<ReturnValue<T>> for FnError {
    fn with(mut self, val: ReturnValue<T>) -> Self {
        self.return_value = Some(val.0.into());
        self
    }
}

impl From<StorageError> for FnError {
    fn from(value: StorageError) -> Self {
        FnErrorKind::Internal(InternalError::Storage(value)).into()
    }
}

impl TryFrom<FnError> for ArgumentError {
    type Error = ();

    fn try_from(value: FnError) -> Result<Self, Self::Error> {
        match value.kind {
            FnErrorKind::Argument(e) => Ok(e),
            _ => Err(()),
        }
    }
}

impl TryFrom<FnError> for InternalError {
    type Error = ();

    fn try_from(value: FnError) -> Result<Self, Self::Error> {
        match value.kind {
            FnErrorKind::Internal(e) => Ok(e),
            _ => Err(()),
        }
    }
}

impl TryFrom<FnError> for BuiltinError {
    type Error = ();

    fn try_from(value: FnError) -> Result<Self, Self::Error> {
        match value.kind {
            FnErrorKind::Builtin(e) => Ok(e),
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

impl FnError {
    /// Helper function to quickly construct a `WrongArgument` variant
    /// containing the name of the argument, the expected value and
    /// the actual value.
    pub fn wrong_unnamed_argument(expected: &str, got: &str) -> Self {
        FnErrorKind::Argument(ArgumentError::WrongArgument(format!(
            "Expected {expected} but {got}"
        )))
        .into()
    }

    /// Helper function to quickly construct a `MissingArguments` variant
    /// for a single missing argument.
    pub fn missing_argument(val: &str) -> Self {
        FnErrorKind::Argument(ArgumentError::MissingNamed(vec![val.to_string()])).into()
    }
}
