// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{io, sync::PoisonError};

use thiserror::Error;

/// Defines abstract error cases
#[derive(Clone, Debug, PartialEq, Error)]
pub enum StorageError {
    /// Informs the caller to retry the call
    #[error("There was a temporary issue while reading: {0}")]
    Retry(String),
    #[error("Retries exhausted")]
    RetryExhausted,
    /// The connection to a DB was lost.
    ///
    /// The default solution in those cases are most of the times to try a reconnect.
    #[error("Connection lost: {0}")]
    ConnectionLost(String),
    /// Did expected a different kind of data and is unable to fulfil the request.
    ///
    /// This is usually a usage error.
    #[error("Unexpected data: {0}")]
    UnexpectedData(String),
    /// There is a deeper problem with the underlying DataBase
    ///
    /// An example would be that there is no free db left on redis and that it needs to be cleaned up.
    #[error("Unexpected issue: {0}")]
    Dirty(String),
    #[error("Not found: {0}")]
    /// Not found variant
    NotFound(String),
}

impl<S> From<PoisonError<S>> for StorageError {
    fn from(value: PoisonError<S>) -> Self {
        Self::Dirty(format!("{value:?}"))
    }
}

impl From<io::Error> for StorageError {
    fn from(value: io::Error) -> Self {
        let msg = format!("{:?}", value.kind());
        match value.kind() {
            io::ErrorKind::NotFound
            | io::ErrorKind::PermissionDenied
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::NotConnected
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::AlreadyExists
            | io::ErrorKind::AddrInUse
            | io::ErrorKind::AddrNotAvailable
            | io::ErrorKind::InvalidInput
            | io::ErrorKind::InvalidData
            | io::ErrorKind::UnexpectedEof
            | io::ErrorKind::Unsupported => StorageError::UnexpectedData(msg),
            io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::TimedOut
            | io::ErrorKind::Interrupted => StorageError::Retry(msg),
            _ => StorageError::Dirty(msg),
        }
    }
}
