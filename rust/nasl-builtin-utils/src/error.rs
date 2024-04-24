// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Defines function error kinds
use std::{convert::Infallible, fmt::Display, io};

use nasl_syntax::NaslValue;
use storage::StorageError;

use crate::context::ContextType;

/// Reuses the StorageError definitions as they should fit most cases.
pub type GeneralErrorType = StorageError;

#[derive(Debug, Clone, PartialEq, Eq)]
/// Descriptive kind of error that can occur while calling a function
pub enum FunctionErrorKind {
    /// Function called with insufficient arguments
    MissingPositionalArguments {
        /// Expected amount of arguments
        expected: usize,
        /// Actual amount of arguments
        got: usize,
    },
    /// Function called without required named arguments
    MissingArguments(Vec<String>),
    /// Wraps formatting error
    FMTError(std::fmt::Error),
    /// Wraps Infallible
    Infallible(Infallible),
    /// Wraps io::ErrorKind
    IOError(io::ErrorKind),
    /// Function was called with wrong arguments
    WrongArgument(String),
    /// Diagnostic string is informational and the second arg is the return value for the user
    Diagnostic(String, Option<NaslValue>),
    /// Generic error
    GeneralError(GeneralErrorType),
    /// There is a deeper problem
    /// An example would be that there is no free memory left in the system
    Dirty(String),
}

impl From<GeneralErrorType> for FunctionErrorKind {
    fn from(e: GeneralErrorType) -> Self {
        FunctionErrorKind::GeneralError(e)
    }
}

impl Display for FunctionErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FunctionErrorKind::MissingPositionalArguments { expected, got } => {
                write!(f, "expected {expected} arguments but got {got}")
            }
            FunctionErrorKind::MissingArguments(x) => {
                write!(f, "missing arguments: {}", x.join(", "))
            }
            FunctionErrorKind::FMTError(e) => write!(f, "{e}"),
            FunctionErrorKind::Infallible(e) => write!(f, "{e}"),
            FunctionErrorKind::IOError(e) => write!(f, "{e}"),
            FunctionErrorKind::WrongArgument(x) => write!(f, "wrong argument: {x}"),
            FunctionErrorKind::Diagnostic(x, _) => write!(f, "{x}"),
            FunctionErrorKind::GeneralError(x) => write!(f, "{x}"),
            FunctionErrorKind::Dirty(x) => write!(f, "{x}"),
        }
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

impl From<Infallible> for FunctionErrorKind {
    fn from(se: Infallible) -> Self {
        Self::Infallible(se)
    }
}

impl From<std::fmt::Error> for FunctionErrorKind {
    fn from(fe: std::fmt::Error) -> Self {
        Self::FMTError(fe)
    }
}

impl From<io::ErrorKind> for FunctionErrorKind {
    fn from(iek: io::ErrorKind) -> Self {
        Self::IOError(iek)
    }
}

impl From<io::Error> for FunctionErrorKind {
    fn from(e: io::Error) -> Self {
        Self::IOError(e.kind())
    }
}
