// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::io;

use crate::models::FixedPackage;
use crate::nasl::syntax::LoadError;
use thiserror::Error;

use crate::feed::VerifyError;

/// Error types that can occur when unable to load a products file.
#[derive(Debug, Error)]
pub enum LoadProductErrorKind {
    #[error("{0}")]
    IOError(#[from] io::Error),
    #[error("{0}")]
    LoadError(#[from] LoadError),
}

/// Errors that might occur, when working with the notus library.
#[derive(Debug, Error)]
pub enum Error {
    /// The directory containing the notus products does not exist
    #[error("The directory {0}, which should contain the notus product does not exist")]
    MissingProductsDir(String),
    /// The given notus products directory is a file
    #[error("The given notus products directory {0} is a file")]
    ProductsDirIsFile(String),
    /// The given notus products directory is not readable
    #[error("The directory {0} is not readable: {1}")]
    UnreadableProductsDir(String, io::Error),
    /// There are no corresponding notus files for the given Operating System
    #[error( "the File {0} was not found, that is either due to a typo or missing notus product for the corresponding OS")]
    UnknownProduct(String),
    /// General error while loading notus product
    #[error("Unable to load product from {0}: {1}")]
    LoadProductError(String, LoadProductErrorKind),
    /// Unable to parse notus product file due to a JSON error
    #[error("unable to parse Notus file {0}. The corresponding parse error was: {1}")]
    JSONParseError(String, serde_json::Error),
    /// The version of the notus product file is not supported
    #[error( "the version of the parsed product file {0} is {1}. This version is currently not supported, the version {2} is required")]
    UnsupportedVersion(String, String, String),
    /// Unable to parse a given package
    #[error("Unable to parse the given package {0}")]
    PackageParseError(String),
    /// Unable to parse a package in the notus product file
    #[error("Unable to parse fixed package information {1:?} in the product {0}")]
    VulnerabilityTestParseError(String, FixedPackage),
    /// Some issues caused by a HashsumLoader
    #[error("Hashsum verification failed: {0}")]
    HashsumLoadError(VerifyError),
    /// Signature check error
    #[error("Signature check failed: {0}")]
    SignatureCheckError(VerifyError),
}
