// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::fmt;

#[derive(Debug)]
pub(crate) enum CliError {
    Io(std::io::Error),
    Message(String),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::Io(error) => write!(f, "{error}"),
            CliError::Message(msg) => write!(f, "{msg}"),
        }
    }
}

impl From<std::io::Error> for CliError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<&str> for CliError {
    fn from(value: &str) -> Self {
        Self::Message(value.to_string())
    }
}

impl std::error::Error for CliError {}
