// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Defines function error kinds
use std::io;
use thiserror::Error;

use nasl_syntax::NaslValue;
use storage::StorageError;

use crate::context::ContextType;

/// Reuses the StorageError definitions as they should fit most cases.
pub type GeneralErrorType = StorageError;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
/// Descriptive kind of error that can occur while calling a function
pub enum FunctionErrorKind {
    /// Function called with insufficient arguments
    #[error("Expected {expected} but got {got}")]
    MissingPositionalArguments {
        /// Expected amount of arguments
        expected: usize,
        /// Actual amount of arguments
        got: usize,
    },
    /// Function called without required named arguments
    #[error("Missing arguments: {}", .0.join(", "))]
    MissingArguments(Vec<String>),
    /// Wraps formatting error
    #[error("Formatting error: {0}")]
    FMTError(#[from] std::fmt::Error),
    /// Wraps io::Error
    #[error("IOError: {0}")]
    IOError(io::ErrorKind),
    /// Function was called with wrong arguments
    #[error("Function was called with wrong arguments: {0}")]
    WrongArgument(String),
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
}

// It would be nicer to derive this using #[from] from
// thiserror, but io::Error does not impl `PartialEq`,
// `Eq` or `Clone`, so we wrap `io::ErrorKind` instead, which
// does not impl `Error` which is why this `From` impl exists.
impl From<io::Error> for FunctionErrorKind {
    fn from(e: io::Error) -> Self {
        Self::IOError(e.kind())
    }
}

impl From<(&str, &str, &str)> for FunctionErrorKind {
    fn from(value: (&str, &str, &str)) -> Self {
        let (key, expected, got) = value;
        FunctionErrorKind::WrongArgument(format!("Expected {key} to be {expected} but it is {got}"))
    }
}

impl From<&str> for FunctionErrorKind {
    fn from(value: &str) -> Self {
        FunctionErrorKind::MissingArguments(vec![value.to_owned()])
    }
}

impl From<(&str, &str)> for FunctionErrorKind {
    fn from(value: (&str, &str)) -> Self {
        let (expected, got) = value;
        FunctionErrorKind::WrongArgument(format!("Expected {expected} but got {got}"))
    }
}

impl From<(&str, &str, &NaslValue)> for FunctionErrorKind {
    fn from(value: (&str, &str, &NaslValue)) -> Self {
        let (key, expected, got) = value;
        let got: &str = &got.to_string();
        (key, expected, got).into()
    }
}

impl From<(&str, &str, Option<&NaslValue>)> for FunctionErrorKind {
    fn from(value: (&str, &str, Option<&NaslValue>)) -> Self {
        match value {
            (key, expected, Some(x)) => (key, expected, x).into(),
            (key, expected, None) => (key, expected, "NULL").into(),
        }
    }
}

impl From<(&str, &str, Option<&ContextType>)> for FunctionErrorKind {
    fn from(value: (&str, &str, Option<&ContextType>)) -> Self {
        match value {
            (key, expected, Some(ContextType::Value(x))) => (key, expected, x).into(),
            (key, expected, Some(ContextType::Function(_, _))) => {
                (key, expected, "function").into()
            }
            (key, expected, None) => (key, expected, "NULL").into(),
        }
    }
}
impl From<(&str, &NaslValue)> for FunctionErrorKind {
    fn from(value: (&str, &NaslValue)) -> Self {
        let (expected, got) = value;
        let got: &str = &got.to_string();
        (expected, got).into()
    }
}
