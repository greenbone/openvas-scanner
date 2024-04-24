// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use nasl_interpreter::{InterpretError, LoadError};
use nasl_syntax::SyntaxError;
use storage::StorageError;

use crate::verify;

#[derive(Debug, Clone, PartialEq, Eq)]
/// Errors within feed handling
pub enum ErrorKind {
    /// An InterpretError occurred while interpreting
    InterpretError(InterpretError),
    /// NASL script contains an SyntaxError
    SyntaxError(SyntaxError),
    /// Storage is unable to handle operation
    StorageError(StorageError),
    /// Loader is unable to handle operation
    LoadError(LoadError),
    /// Description if block without exit
    MissingExit(String),
    /// Describes an error while verifying the file
    VerifyError(verify::Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// ErrorKind and key of error
pub struct Error {
    /// Used key for the operation
    pub key: String,
    /// The kind of error occurred
    pub kind: ErrorKind,
}

impl std::fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorKind::InterpretError(e) => write!(f, "Interpret Error: {}", e),
            ErrorKind::SyntaxError(e) => write!(f, "Syntax Error: {}", e),
            ErrorKind::StorageError(e) => write!(f, "Storage Error: {}", e),
            ErrorKind::LoadError(e) => write!(f, "Load Error: {}", e),
            ErrorKind::MissingExit(message) => write!(f, "Missing Exit: {}", message),
            ErrorKind::VerifyError(e) => write!(f, "Verify Error: {}", e),
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Error with key '{}': {}", self.key, self.kind)
    }
}

impl std::error::Error for Error {}

impl From<verify::Error> for Error {
    fn from(value: verify::Error) -> Self {
        let fin = match &value {
            crate::VerifyError::SumsFileCorrupt(x) => x.sum_file(),
            crate::VerifyError::LoadError(_) => "",
            crate::VerifyError::HashInvalid {
                expected: _,
                actual: _,
                key,
            } => key,
            crate::VerifyError::BadSignature(e) => e,
            crate::VerifyError::MissingKeyring => "",
        };
        Self {
            key: fin.to_string(),
            kind: ErrorKind::VerifyError(value),
        }
    }
}

impl From<LoadError> for ErrorKind {
    fn from(value: LoadError) -> Self {
        Self::LoadError(value)
    }
}

impl From<StorageError> for ErrorKind {
    fn from(value: StorageError) -> Self {
        Self::StorageError(value)
    }
}

impl From<SyntaxError> for ErrorKind {
    fn from(value: SyntaxError) -> Self {
        Self::SyntaxError(value)
    }
}

impl From<InterpretError> for ErrorKind {
    fn from(value: InterpretError) -> Self {
        Self::InterpretError(value)
    }
}
