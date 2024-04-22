// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::time::SystemTime;

use models::{Product, ProductsAdivisories};

use crate::error::Error;

pub mod fs;
pub mod hashsum;

#[derive(PartialEq, PartialOrd, Clone, Debug)]
pub enum FeedStamp {
    Time(SystemTime),
    Hashsum(String),
}

/// Trait for an ProductLoader
pub trait ProductLoader {
    /// Load product file corresponding to the given string. The given name must match the name of
    /// the product file without its extension. Also a stamp is returned to be able to check if the
    /// file has changed. This is useful when caching loaded products.
    fn load_product(&self, os: &str) -> Result<(Product, FeedStamp), Error>;
    /// Get a list of all available products. This list contains the exact strings, that can also be
    /// used for `load_product`.
    fn get_products(&self) -> Result<Vec<String>, Error>;
    /// Check if a requested product file has changed based on a stamp created with `load_product`.
    /// Useful for checking if a requested product has changed.
    fn has_changed(&self, os: &str, stamp: &FeedStamp) -> bool;
    /// Verify the signature of the Hashsum file
    fn verify_signature(&self) -> Result<(), feed::VerifyError>;
    /// Get the root directory of the notus products
    fn get_root_dir(&self) -> Result<String, Error>;
}

/// Trait for an AdvisoryLoader
pub trait AdvisoryLoader {
    /// Get a list of all available products. This list contains the exact strings, that can also be
    /// used for `load_product`.
    fn get_advisories(&self) -> Result<Vec<String>, Error>;
    /// Load advisories files present in the path.
    fn load_advisory(&self, os: &str) -> Result<ProductsAdivisories, Error>;
    /// Verify the signature of the Hashsum file
    fn verify_signature(&self) -> Result<(), feed::VerifyError>;
    /// Get the root directory of the notus products
    fn get_root_dir(&self) -> Result<String, Error>;
}
