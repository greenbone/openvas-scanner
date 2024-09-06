// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum OpenvasError {
    #[error("A scan with ID {0} already exists.")]
    DuplicateScanID(String),
    #[error("Unable to launch openvas executable.")]
    MissingExec,
    #[error("A scan with ID {0} not found.")]
    ScanNotFound(String),
    #[error("Unable to run command: {0}")]
    CmdError(io::Error),
    #[error("Maximum number of queued scan reached.")]
    MaxQueuedScans,
    #[error("Unable to run openvas.")]
    UnableToRunExec,
}
