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

pub mod advisories;
#[cfg(test)]
mod tests;

use std::path::Path;
use std::sync::Arc;

pub use error::Error as NotusError;
pub use loader::AdvisoryLoader;
pub use loader::fs::FSProductLoader;
pub use loader::hashsum::HashsumAdvisoryLoader;
pub use loader::hashsum::HashsumProductLoader;
pub use notus::Notus;
use tokio::sync::RwLock;

use crate::nasl::FSPluginLoader;

pub fn path_to_products<P>(
    path: P,
    signature_check: bool,
) -> Arc<RwLock<Notus<HashsumProductLoader>>>
where
    P: AsRef<Path>,
{
    let loader = FSPluginLoader::new(path);
    let loader = HashsumProductLoader::new(loader);
    Arc::new(RwLock::new(Notus::new(loader, signature_check)))
}
