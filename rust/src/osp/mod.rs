// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#![doc = include_str!("README.md")]
mod commands;
mod connection;
mod response;
mod scanner;

#[cfg(test)]
mod tests;

pub use commands::Error;
pub use commands::ScanCommand;
pub use connection::*;
pub use response::*;
pub use scanner::Scanner;

/// The id of a scan
pub type ScanID = String;
