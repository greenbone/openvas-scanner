// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::nasl::interpreter::InterpreterError;
use crate::nasl::syntax::LoadError;
use crate::nasl::syntax::ParseError;
use crate::storage::error::StorageError;
use thiserror::Error;

use crate::feed::{VerifyError, verify};

#[derive(Debug, Error)]
/// Errors within feed handling
pub enum ErrorKind {
    /// An InterpretError occurred while interpreting
    #[error("Interpreter error: {0}")]
    InterpretError(#[from] InterpreterError),
    /// NASL script contains SyntaxErrors
    #[error("Encountered syntax errors in scripts.")]
    SyntaxError(Vec<ParseError>),
    /// Storage is unable to handle operation
    #[error("Storage error: {0}")]
    StorageError(#[from] StorageError),
    /// Loader is unable to handle operation
    #[error("Load error: {0}")]
    LoadError(#[from] LoadError),
    /// Description if block without exit
    #[error("Missing exit: {0}")]
    MissingExit(String),
    /// Describes an error while verifying the file
    #[error("Verify error: {0}")]
    VerifyError(#[from] verify::Error),
}

#[derive(Debug, Error)]
#[error("Error with key '{key}': {kind}")]
/// ErrorKind and key of error
pub struct Error {
    /// Used key for the operation
    pub key: String,
    /// The kind of the error
    #[source]
    pub kind: ErrorKind,
}

impl From<verify::Error> for Error {
    fn from(value: verify::Error) -> Self {
        let key = match &value {
            VerifyError::SumsFileCorrupt(x) => x.sum_file(),
            VerifyError::LoadError(_) => "",
            VerifyError::HashInvalid {
                expected: _,
                actual: _,
                key,
            } => key,
            VerifyError::BadSignature(e) => e,
            VerifyError::MissingKeyring => "",
        };
        Self {
            key: key.to_string(),
            kind: ErrorKind::VerifyError(value),
        }
    }
}
