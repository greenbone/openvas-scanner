// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#![doc = include_str!("README.md")]

mod loader;
mod packages;

mod error;
#[allow(clippy::module_inception)]
mod notus;
mod vts;

#[cfg(test)]
mod tests;

pub use error::Error as NotusError;
pub use loader::fs::FSProductLoader;
pub use loader::hashsum::HashsumAdvisoryLoader;
pub use loader::hashsum::HashsumProductLoader;
pub use loader::AdvisoryLoader;
pub use notus::Notus;
