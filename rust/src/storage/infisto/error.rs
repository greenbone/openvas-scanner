// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
/// The error type for the store.
pub enum Error {
    /// An IO Error
    #[error("IO Error. {0}. {1}")]
    IoError(IoErrorKind, std::io::ErrorKind),
    /// The index could not be serialized.
    #[error("Could not serialize index")]
    Serialize,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
/// An error during an IO operation.
pub enum IoErrorKind {
    /// The base directory could not be created.
    #[error("Could not create base directory.")]
    CreateBaseDir,
    /// The file could not be opened.
    #[error("Could not open file.")]
    FileOpen,
    /// The file could not be written to.
    #[error("Could not write to file.")]
    Write,
    /// The file could not be read from.
    #[error("Could not read from file.")]
    Read,
    /// The file could not be removed.
    #[error("Could not remove file.")]
    Remove,
    /// The file could not be sought.
    #[error("Could not seek in file.")]
    Seek,
}
