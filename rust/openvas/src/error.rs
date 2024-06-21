// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{fmt::Display, io};

pub enum OpenvasError {
    DuplicateScanID(String),
    MissingExec,
    ScanNotFound(String),
    CmdError(io::Error),
    MaxQueuedScans,
    UnableToRunExec,
}

impl Display for OpenvasError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpenvasError::DuplicateScanID(id) => write!(f, "a scan with ID {id} already exists"),
            OpenvasError::MissingExec => write!(f, "unable to launch openvas executable"),
            OpenvasError::ScanNotFound(id) => write!(f, "a scan with ID {id} not found"),
            OpenvasError::CmdError(e) => write!(f, "unable to run command: {e}"),
            OpenvasError::MaxQueuedScans => write!(f, "maximum number of queued scan reached"),
            OpenvasError::UnableToRunExec => write!(f, "unable to run openvas"),
        }
    }
}
