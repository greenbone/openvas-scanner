// Copyright (C) 2023 Greenbone Networks GmbH
//
// SPDX-License-Identifier: GPL-2.0-or-later
#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
mod commands;
mod response;
mod connection;
pub use commands::ScanCommand;
pub use connection::*;
pub use commands::Error;
pub use response::*;


/// The id of a scan
pub type ScanID = String;
