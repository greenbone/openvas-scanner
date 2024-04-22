// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
mod commands;
mod connection;
mod response;
mod scanner;
pub use commands::Error;
pub use commands::ScanCommand;
pub use connection::*;
pub use response::*;
pub use scanner::Scanner;

/// The id of a scan
pub type ScanID = String;
