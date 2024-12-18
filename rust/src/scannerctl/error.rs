// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{
    fmt::Display,
    path::{Path, PathBuf},
};

use feed::VerifyError;
use scannerlib::nasl::{interpreter::InterpretError, syntax::LoadError};
use scannerlib::storage::StorageError;
use scannerlib::{feed, notus};
use scannerlib::{
    nasl::syntax::{SyntaxError, Token},
    scanner::ExecuteError,
};

#[derive(Debug)]
pub enum CliErrorKind {
    WrongAction,

    PluginPathIsNotADir(PathBuf),
    Openvas {
        args: Option<String>,
        err_msg: String,
    },
    InterpretError(InterpretError),
    ExecuteError(ExecuteError),
    LoadError(LoadError),
    StorageError(StorageError),
    SyntaxError(SyntaxError),
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

#[derive(Debug)]
pub struct CliError {
    pub filename: String,
    pub kind: CliErrorKind,
}

impl CliError {
    pub fn load_error(err: std::io::Error, path: &Path) -> Self {
        Self {
            filename: path.to_owned().to_string_lossy().to_string(),
            kind: CliErrorKind::LoadError(LoadError::Dirty(err.to_string())),
        }
    }
}

impl Display for CliErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CliErrorKind::WrongAction => write!(f, "wrong action."),
            CliErrorKind::PluginPathIsNotADir(e) => write!(f, "expected {e:?} to be a dir."),
            CliErrorKind::Openvas { args, err_msg } => write!(
                f,
                "openvas {} failed with: {err_msg}",
                args.clone().unwrap_or_default()
            ),
            CliErrorKind::InterpretError(e) => write!(f, "{e}"),
            CliErrorKind::LoadError(e) => write!(f, "{e}"),
            CliErrorKind::StorageError(e) => write!(f, "{e}"),
            CliErrorKind::SyntaxError(e) => write!(f, "{e}"),
            CliErrorKind::Corrupt(x) => write!(f, "Corrupt: {x}"),
            CliErrorKind::ExecuteError(x) => write!(f, "{x}"),
        }
    }
}

impl Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}{}: {}",
            self.filename,
            self.kind
                .as_token()
                .map(|x| { format!(", line: {}, col: {}", x.line_column.0, x.line_column.1) })
                .unwrap_or_default(),
            self.kind
        )
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

impl From<serde_json::Error> for CliError {
    fn from(value: serde_json::Error) -> Self {
        CliError {
            filename: Default::default(),
            kind: CliErrorKind::Corrupt(value.to_string()),
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
