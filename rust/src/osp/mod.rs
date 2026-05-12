// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! # OSP
//!
//! OSP is a Rust crate designed for sending commands to an OSPD socket. It enables the execution of the following commands:
//!
//! - Start: to initiate a scan
//! - Delete: to delete a specific scan
//! - Stop: to terminate a running scan
//! - Get: to retrieve scan results
//! - GetDelete: to fetch and delete scan results simultaneously

mod commands;
mod connection;
mod response;
mod scanner;

#[cfg(test)]
mod tests;

pub use response::ResultType as OspResultType;
pub use response::ScanResult as OspScanResult;
pub use scanner::Scanner;

#[cfg(test)]
use response::Response as OspResponse;
#[cfg(test)]
use response::Scan as OspScan;
#[cfg(test)]
use response::ScanStatus as OspScanStatus;
