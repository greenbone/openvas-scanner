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

pub use response::Response as OspResponse;
pub use response::ResultType as OspResultType;
pub use response::Scan as OspScan;
pub use response::ScanResult as OspScanResult;
pub use response::ScanStatus as OspScanStatus;
pub use response::StringF32;
pub use scanner::Scanner;
