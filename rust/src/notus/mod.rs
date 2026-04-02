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
pub use loader::advisory_loader;
pub use notus::Notus;
use tokio::sync::RwLock;

use crate::nasl::syntax::Loader;
pub use crate::notus::loader::ProductLoader;

pub fn products_loader<P>(path: P, signature_check: bool) -> Arc<RwLock<Notus>>
where
    P: AsRef<Path>,
{
    let loader = Loader::from_feed_path(path);
    let loader = ProductLoader::new(signature_check, loader);
    Arc::new(RwLock::new(Notus::new(loader)))
}
