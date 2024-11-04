// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Defines function error kinds
use std::io;
use thiserror::Error;

use crate::nasl::builtin::{BuiltinError, SshError};
use crate::nasl::prelude::NaslValue;

use crate::storage::StorageError;

use super::ContextType;

/// Reuses the StorageError definitions as they should fit most cases.
pub type GeneralErrorType = StorageError;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ArgumentError {
    #[error("Expected {expected} but got {got}")]
    MissingPositionals { expected: usize, got: usize },
    #[error("Expected {expected} but got {got}")]
    TrailingPositionals { expected: usize, got: usize },
    #[error("Missing arguments: {}", .0.join(", "))]
    MissingNamed(Vec<String>),
    #[error("Unknown named argument given to function: {}", .0)]
    Unexpected(String),
    #[error("Function was called with wrong arguments: {0}")]
    Wrong(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum InternalError {
    #[error("{0}")]
    GeneralError(#[from] GeneralErrorType),
    #[error("{0}")]
    Dirty(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
/// Descriptive kind of error that can occur while calling a function
pub enum NaslError {
    /// Function called with additional, unexpected named arguments
    #[error("Unknown named argument given to function: {}", .0)]
    UnexpectedArgument(String),
    /// Wraps formatting error
    #[error("Formatting error: {0}")]
    FMTError(#[from] std::fmt::Error),
    /// Wraps io::Error
    #[error("IOError: {0}")]
    IOError(io::ErrorKind),
    /// Function was called with wrong arguments
    #[error("Function was called with wrong arguments: {0}")]
    WrongArgument(String),
    /// Authentication failed
    #[error("Authentication failed.")]
    Authentication,
    /// Diagnostic string is informational and the second arg is the return value for the user
    #[error("{0}")]
    Diagnostic(String, Option<NaslValue>),
    /// Generic error
    #[error("Generic error: {0}")]
    GeneralError(#[from] GeneralErrorType),
    /// There is a deeper problem
    /// An example would be that there is no free memory left in the system
    #[error("{0}")]
    Dirty(String),
    /// An Error originating from an SSH-specific NASL function
    #[error("SSH error: {0}")]
    Ssh(SshError),
    #[error("{0}")]
    Argument(#[from] ArgumentError),
    #[error("{0}")]
    Builtin(#[from] BuiltinError),
    #[error("{0}")]
    Internal(#[from] InternalError),
}

impl TryFrom<NaslError> for ArgumentError {
    type Error = ();

    fn try_from(value: NaslError) -> Result<Self, Self::Error> {
        match value {
            NaslError::Argument(e) => Ok(e),
            _ => Err(()),
        }
    }
}

impl TryFrom<NaslError> for InternalError {
    type Error = ();

    fn try_from(value: NaslError) -> Result<Self, Self::Error> {
        match value {
            NaslError::Internal(e) => Ok(e),
            _ => Err(()),
        }
    }
}

impl TryFrom<NaslError> for BuiltinError {
    type Error = ();

    fn try_from(value: NaslError) -> Result<Self, Self::Error> {
        match value {
            NaslError::Builtin(e) => Ok(e),
            _ => Err(()),
        }
    }
}

// It would be nicer to derive this using #[from] from
// thiserror, but io::Error does not impl `PartialEq`,
// `Eq` or `Clone`, so we wrap `io::ErrorKind` instead, which
// does not impl `Error` which is why this `From` impl exists.
impl From<io::Error> for NaslError {
    fn from(e: io::Error) -> Self {
        Self::IOError(e.kind())
    }
}

impl NaslError {
    /// Helper function to quickly construct a `WrongArgument` variant
    /// containing the name of the argument, the expected value and
    /// the actual value.
    pub fn wrong_argument(key: &str, expected: &str, got: &str) -> Self {
        Self::WrongArgument(format!("Expected {key} to be {expected} but it is {got}"))
    }

    /// Helper function to quickly construct a `WrongArgument` variant
    /// containing the name of the argument, the expected value and
    /// the actual value.
    pub fn wrong_unnamed_argument(expected: &str, got: &str) -> Self {
        Self::WrongArgument(format!("Expected {expected} but {got}"))
    }

    /// Helper function to quickly construct a `MissingArguments` variant
    /// for a single missing argument.
    pub fn missing_argument(val: &str) -> Self {
        Self::Argument(ArgumentError::MissingNamed(vec![val.to_string()]))
    }
}

impl From<(&str, &str, &NaslValue)> for NaslError {
    fn from(value: (&str, &str, &NaslValue)) -> Self {
        let (key, expected, got) = value;
        let got: &str = &got.to_string();
        NaslError::wrong_argument(key, expected, got)
    }
}

impl From<(&str, &str, Option<&NaslValue>)> for NaslError {
    fn from(value: (&str, &str, Option<&NaslValue>)) -> Self {
        match value {
            (key, expected, Some(x)) => (key, expected, x).into(),
            (key, expected, None) => NaslError::wrong_argument(key, expected, "NULL"),
        }
    }
}

impl From<(&str, &str, Option<&ContextType>)> for NaslError {
    fn from(value: (&str, &str, Option<&ContextType>)) -> Self {
        match value {
            (key, expected, Some(ContextType::Value(x))) => (key, expected, x).into(),
            (key, expected, Some(ContextType::Function(_, _))) => {
                NaslError::wrong_argument(key, expected, "function")
            }
            (key, expected, None) => NaslError::wrong_argument(key, expected, "NULL"),
        }
    }
}

impl From<(&str, &NaslValue)> for NaslError {
    fn from(value: (&str, &NaslValue)) -> Self {
        let (expected, got) = value;
        let got: &str = &got.to_string();
        NaslError::wrong_unnamed_argument(expected, got)
    }
}
