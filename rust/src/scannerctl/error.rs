// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::fmt::Display;
use std::path::{Path, PathBuf};

use feed::VerifyError;
use scannerlib::nasl::{interpreter::InterpretError, syntax::LoadError};
use scannerlib::storage::StorageError;
use scannerlib::{feed, notus};
use scannerlib::{
    nasl::syntax::{SyntaxError, Token},
    scanner::ExecuteError,
};

#[derive(Debug, thiserror::Error)]

pub enum CliErrorKind {
    #[error("Wrong action")]
    WrongAction,

    #[error("Plugin path ({0}) is not a directory.")]
    PluginPathIsNotADir(PathBuf),
    #[error("openvas ({args:?}) failed: {err_msg}.")]
    Openvas {
        args: Option<String>,
        err_msg: String,
    },
    #[error("{0}")]
    InterpretError(InterpretError),
    #[error("{0}")]
    ExecuteError(ExecuteError),
    #[error("{0}")]
    LoadError(LoadError),
    #[error("{0}")]
    StorageError(StorageError),
    #[error("{0}")]
    SyntaxError(SyntaxError),
    #[error("Missing arguments: {0:?}")]
    MissingArguments(Vec<String>),
    #[error("{0}")]
    Corrupt(String),
}

impl From<ExecuteError> for CliErrorKind {
    fn from(value: ExecuteError) -> Self {
        Self::ExecuteError(value)
    }
}

impl CliErrorKind {
    pub fn as_token(&self) -> Option<&Token> {
        match self {
            CliErrorKind::InterpretError(e) => match &e.origin {
                Some(s) => Some(s.as_token()),
                None => None,
            },
            CliErrorKind::SyntaxError(e) => e.as_token(),
            _ => None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub struct CliError {
    pub filename: String,
    pub kind: CliErrorKind,
}

impl Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if !self.filename.is_empty() {
            write!(f, "{}: ", self.filename)?;
        }
        write!(f, "{}", self.kind)
    }
}

impl CliError {
    pub fn load_error(err: std::io::Error, path: &Path) -> Self {
        Self {
            filename: path.to_owned().to_string_lossy().to_string(),
            kind: CliErrorKind::LoadError(LoadError::Dirty(err.to_string())),
        }
    }
}

impl From<std::io::Error> for CliError {
    fn from(value: std::io::Error) -> Self {
        CliError {
            filename: Default::default(),
            kind: CliErrorKind::Corrupt(value.to_string()),
        }
    }
}

impl From<serde_json::Error> for CliErrorKind {
    fn from(value: serde_json::Error) -> Self {
        CliErrorKind::Corrupt(value.to_string())
    }
}

impl From<serde_json::Error> for CliError {
    fn from(value: serde_json::Error) -> Self {
        CliError {
            filename: Default::default(),
            kind: value.into(),
        }
    }
}

impl From<notus::NotusError> for CliError {
    fn from(value: notus::NotusError) -> Self {
        CliError {
            filename: Default::default(),
            kind: CliErrorKind::Corrupt(value.to_string()),
        }
    }
}
impl From<VerifyError> for CliError {
    fn from(value: VerifyError) -> Self {
        let filename = match &value {
            VerifyError::SumsFileCorrupt(e) => e.sum_file(),
            VerifyError::LoadError(_) => "",
            VerifyError::HashInvalid {
                expected: _,
                actual: _,
                key,
            } => key,
            VerifyError::MissingKeyring => {
                "Signature check enabled but missing keyring. Set GNUPGHOME environment variable."
            }
            VerifyError::BadSignature(_) => "Bad signature",
        };
        Self {
            filename: filename.to_string(),
            kind: CliErrorKind::Corrupt(value.to_string()),
        }
    }
}

impl From<VerifyError> for CliErrorKind {
    fn from(value: VerifyError) -> Self {
        Self::Corrupt(value.to_string())
    }
}

impl From<LoadError> for CliErrorKind {
    fn from(value: LoadError) -> Self {
        Self::LoadError(value)
    }
}

impl From<InterpretError> for CliErrorKind {
    fn from(value: InterpretError) -> Self {
        Self::InterpretError(value)
    }
}

impl From<StorageError> for CliErrorKind {
    fn from(value: StorageError) -> Self {
        Self::StorageError(value)
    }
}

impl From<SyntaxError> for CliErrorKind {
    fn from(value: SyntaxError) -> Self {
        Self::SyntaxError(value)
    }
}

impl From<LoadError> for CliError {
    fn from(value: LoadError) -> Self {
        Self {
            filename: value.filename().to_string(),
            kind: value.into(),
        }
    }
}

impl From<feed::UpdateError> for CliError {
    fn from(value: feed::UpdateError) -> Self {
        let kind = match value.kind {
            feed::UpdateErrorKind::InterpretError(e) => CliErrorKind::InterpretError(e),
            feed::UpdateErrorKind::SyntaxError(e) => CliErrorKind::SyntaxError(e),
            feed::UpdateErrorKind::StorageError(e) => CliErrorKind::StorageError(e),
            feed::UpdateErrorKind::LoadError(e) => CliErrorKind::Corrupt(load_error_to_string(&e)),
            feed::UpdateErrorKind::MissingExit(_) => {
                CliErrorKind::Corrupt("description run without exit.".to_string())
            }
            feed::UpdateErrorKind::VerifyError(e) => CliErrorKind::Corrupt(e.to_string()),
        };
        CliError {
            filename: value.key,
            kind,
        }
    }
}

fn load_error_to_string(le: &LoadError) -> String {
    match le {
        LoadError::Retry(f) => f,
        LoadError::NotFound(f) => f,
        LoadError::PermissionDenied(f) => f,
        LoadError::Dirty(f) => f,
    }
    .to_owned()
}
