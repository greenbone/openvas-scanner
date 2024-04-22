// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use redis::*;
use std::fmt;
use storage::StorageError;

pub type RedisStorageResult<T> = std::result::Result<T, DbError>;

/// Error cases while working with redis.
#[derive(Debug)]
pub enum DbError {
    /// The redis-library does not know about this error kind
    Unknown(String),
    /// Indicates that redis is wrongfully configured for our use case
    ConfigurationError(String),
    /// Indicates that the system has insufficient resources available or is defect
    SystemError(String),
    /// Indicates issues within this library
    LibraryError(String),
    /// Lost connection to either cluster or master
    ConnectionLost(String),
    /// Redis is currently not able to handle request and the caller needs to retry it
    Retry(String),
    /// Cannot find a DB to use; redis must be cleaned up to free available slots.
    NoAvailDbErr,
}

impl fmt::Display for DbError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DbError::NoAvailDbErr => write!(f, "No DB available"),
            DbError::ConfigurationError(e) => {
                write!(f, "Unable to use redis due to wrong configuration: {}", e)
            }
            DbError::SystemError(e) => write!(f, "Operation system of redis has issues: {}", e),
            DbError::LibraryError(e) => write!(f, "Library issue: {}", e),
            DbError::ConnectionLost(e) => write!(f, "Connection lost: {}", e),
            DbError::Retry(e) => write!(f, "Temporary issue: {}", e),
            DbError::Unknown(e) => write!(f, "Unclassified error occurred on redis: {}", e),
        }
    }
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
            ErrorKind::IoError => DbError::SystemError(err.to_string()),
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
            | DbError::SystemError(_)
            | DbError::NoAvailDbErr => StorageError::Dirty(err.to_string()),
            DbError::ConnectionLost(_) => StorageError::ConnectionLost(err.to_string()),
            DbError::Retry(_) => StorageError::Retry(err.to_string()),
            DbError::LibraryError(_) => StorageError::UnexpectedData(err.to_string()),
        }
    }
}

impl std::error::Error for DbError {}
