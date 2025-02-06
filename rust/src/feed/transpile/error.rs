// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use thiserror::Error;

use crate::nasl::syntax::{LoadError, Statement};

use super::verify;
use super::Replace;

#[derive(Debug, Clone, PartialEq, Error)]
/// Error during transpiling
pub enum TranspileError {
    /// Loader is unable to handle operation
    #[error("Load error: {0}")]
    Load(#[from] LoadError),
    /// Describes an error while verifying the file
    #[error("Verify error: {0}")]
    Verify(#[from] verify::Error),
    /// Describes an error while verifying the file
    #[error("Replace error: {0}")]
    Replace(#[from] ReplaceError),
}

#[derive(Debug, Clone, PartialEq, Error)]
/// Error cases on a replace operation
pub enum ReplaceError {
    /// The replace operation is invalid on statement
    #[error("Operation {0} not allowed on {1}.")]
    Unsupported(Replace, Statement),
}
