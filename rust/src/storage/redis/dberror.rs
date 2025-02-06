// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::storage::StorageError;
use redis::*;
use thiserror::Error;

pub type RedisStorageResult<T> = std::result::Result<T, DbError>;

/// Error cases while working with redis.
#[derive(Debug, Error)]
pub enum DbError {
    /// The redis-library does not know about this error kind
    #[error("Unclassified error occurred on redis: {0}.")]
    Unknown(String),
    #[error("Unable to use redis due to wrong configuration: {0}.")]
    /// Indicates that redis is wrongfully configured for our use case
    ConfigurationError(String),
    /// An underlying IO Error within redis.
    #[error("IOError within redis: {0}.")]
    IoError(String),
    /// Poisoned lock
    #[error("Poisoned lock: {0}.")]
    PoisonedLock(String),
    /// Indicates issues within this library
    #[error("Library issue: {0}")]
    LibraryError(String),
    /// Lost connection to either cluster or master
    #[error("Connection lost: {0}")]
    ConnectionLost(String),
    /// Redis is currently not able to handle request and the caller needs to retry it
    #[error("Temporary issue: {0}")]
    Retry(String),
    /// Cannot find a DB to use; redis must be cleaned up to free available slots.
    #[error("No DB available.")]
    NoAvailDbErr,
}

impl From<RedisError> for DbError {
    fn from(err: RedisError) -> DbError {
        match err.kind() {
            ErrorKind::ResponseError
            | ErrorKind::AuthenticationFailed
            | ErrorKind::NoScriptError
            | ErrorKind::ReadOnly
            | ErrorKind::InvalidClientConfig
            | ErrorKind::Moved
            | ErrorKind::Ask => DbError::ConfigurationError(err.to_string()),
            ErrorKind::IoError => DbError::IoError(err.to_string()),
            ErrorKind::TypeError
            | ErrorKind::ClientError
            | ErrorKind::CrossSlot
            | ErrorKind::ExtensionError => DbError::LibraryError(err.to_string()),
            ErrorKind::ClusterDown | ErrorKind::MasterDown => {
                DbError::ConnectionLost(err.to_string())
            }
            ErrorKind::ExecAbortError | ErrorKind::BusyLoadingError | ErrorKind::TryAgain => {
                DbError::Retry(err.to_string())
            }
            _ => DbError::Unknown(err.to_string()),
        }
    }
}

impl From<DbError> for StorageError {
    fn from(err: DbError) -> Self {
        match err {
            DbError::Unknown(_)
            | DbError::ConfigurationError(_)
            | DbError::PoisonedLock(_)
            | DbError::IoError(_)
            | DbError::NoAvailDbErr => StorageError::Dirty(err.to_string()),
            DbError::ConnectionLost(_) => StorageError::ConnectionLost(err.to_string()),
            DbError::Retry(_) => StorageError::Retry(err.to_string()),
            DbError::LibraryError(_) => StorageError::UnexpectedData(err.to_string()),
        }
    }
}
