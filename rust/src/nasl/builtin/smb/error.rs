// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{io, net::AddrParseError};

use thiserror::Error;

pub type Result<T> = std::result::Result<T, SmbError>;

#[derive(Debug, Error)]
pub enum SmbError {
    #[error("Handle ID {0} not found.")]
    SMBHandleIdNotFound(i32),
    #[error("SMB error: {0}")]
    Smb(String),
    #[error("IO error during SMB: {0}")]
    IO(io::ErrorKind),
    #[error("Failed to parse host: {0}")]
    InvalidHost(String),
    #[error("SMB errror serializing response: {0}")]
    SerializeError(String),
    #[error("SMB query: {0}")]
    SmbQuery(String),
}

impl From<io::Error> for SmbError {
    fn from(value: io::Error) -> Self {
        Self::IO(value.kind())
    }
}

impl From<smb::Error> for SmbError {
    fn from(value: smb::Error) -> Self {
        Self::Smb(format!("{value}"))
    }
}

impl From<AddrParseError> for SmbError {
    fn from(value: AddrParseError) -> Self {
        Self::InvalidHost(value.to_string())
    }
}
