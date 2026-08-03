// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum OpenvasError {
    #[error("A scan with ID {0} not found.")]
    ScanNotFound(String),
    #[error("Unable to run command: {0}")]
    CmdError(io::Error),
}
