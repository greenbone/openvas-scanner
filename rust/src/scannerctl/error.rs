// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::fmt;
use std::path::{Path, PathBuf};

use feed::VerifyError;
use quick_xml::DeError;
use scannerlib::nasl::WithErrorInfo;
use scannerlib::nasl::{interpreter::InterpretError, syntax::LoadError};
use scannerlib::storage::error::StorageError;
use scannerlib::{feed, notus};
use scannerlib::{nasl::syntax::SyntaxError, scanner::ExecuteError};

#[derive(Debug, thiserror::Error)]

pub enum CliErrorKind {
    #[error("openvas ({args:?}) failed: {err_msg}.")]
    Openvas {
        args: Option<String>,
        err_msg: String,
    },
    #[error("{0}")]
    InterpretError(InterpretError),
    #[error("{0}")]
    ExecuteError(#[from] ExecuteError),
    #[error("{0}")]
    VerifyError(VerifyError),
    #[error("{0}")]
    LoadError(LoadError),
    #[error("{0}")]
    StorageError(StorageError),
    #[error("{0}")]
    SyntaxError(SyntaxError),
    #[error("{0}")]
    Corrupt(String),
    #[error("Invalid XML: {0}")]
    InvalidXML(#[from] DeError),
}

pub struct Filename<T>(pub T);

impl From<CliErrorKind> for CliError {
    fn from(kind: CliErrorKind) -> Self {
        CliError {
            kind,
            filename: None,
        }
    }
}

impl WithErrorInfo<Filename<&PathBuf>> for CliErrorKind {
    type Error = CliError;

    fn with(self, filename: Filename<&PathBuf>) -> Self::Error {
        CliError {
            filename: Some(filename.0.to_owned()),
            kind: self,
        }
    }
}

impl WithErrorInfo<Filename<&'_ Path>> for CliErrorKind {
    type Error = CliError;

    fn with(self, filename: Filename<&Path>) -> Self::Error {
        CliError {
            filename: Some(filename.0.to_owned()),
            kind: self,
        }
    }
}

impl WithErrorInfo<Filename<PathBuf>> for CliErrorKind {
    type Error = CliError;

    fn with(self, filename: Filename<PathBuf>) -> Self::Error {
        CliError {
            filename: Some(filename.0.to_owned()),
            kind: self,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub struct CliError {
    pub filename: Option<PathBuf>,
    pub kind: CliErrorKind,
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.kind)?;
        if let Some(filename) = &self.filename {
            write!(f, " filename: {:?}", filename)?;
        }
        Ok(())
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
    fn from(error: VerifyError) -> Self {
        let filename = match &error {
            VerifyError::SumsFileCorrupt(e) => Some(Path::new(e.sum_file()).to_owned()),
            _ => None,
        };
        Self {
            filename,
            kind: CliErrorKind::VerifyError(error),
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
            filename: Some(Path::new(value.filename()).to_owned()),
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
        kind.into()
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
