// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{fmt::Display, io};

use models::FixedPackage;
use nasl_syntax::LoadError;

/// Error types that can occur, when unable to load a products file.
#[derive(Debug)]
pub enum LoadProductErrorKind {
    IOError(io::Error),
    LoadError(LoadError),
}

impl Display for LoadProductErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadProductErrorKind::IOError(e) => write!(f, "{e}"),
            LoadProductErrorKind::LoadError(e) => write!(f, "{e}"),
        }
    }
}

/// Errors that might occur, when working with the notus library.
#[derive(Debug)]
pub enum Error {
    // The directory containing the notus products does not exist
    MissingProductsDir(String),
    /// The given notus products directory is a file
    ProductsDirIsFile(String),
    /// The given notus products directory is not readable
    UnreadableProductsDir(String, io::Error),
    /// There are no corresponding notus files for the given Operating System
    UnknownProduct(String),
    /// General error while loading notus product
    LoadProductError(String, LoadProductErrorKind),
    /// Unable to parse notus product file due to a JSON error
    JSONParseError(String, serde_json::Error),
    /// The version of the notus product file is not supported
    UnsupportedVersion(String, String, String),
    /// Unable to parse a given package
    PackageParseError(String),
    /// Unable to parse a package in the notus product file
    VulnerabilityTestParseError(String, FixedPackage),
    /// Some issues caused by a HashsumLoader
    HashsumLoadError(feed::VerifyError),
    /// Signature check error
    SignatureCheckError(feed::VerifyError),
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::UnknownProduct(path) => write!(f, "the File {path} was not found, that is either due to a typo or missing notus product for the corresponding OS"),
            Error::JSONParseError(path, json_err) => write!(f, "unable to parse Notus file {path}. The corresponding parse error was: {json_err}"),
            Error::UnsupportedVersion(path, version1, version2) => write!(f, "the version of the parsed product file {path} is {version1}. This version is currently not supported, the version {version2} is required"),
            Error::MissingProductsDir(path) => write!(f, "The directory {path}, which should contain the notus product does not exist"),
            Error::ProductsDirIsFile(path) => write!(f, "The given notus products directory {path} is a file"),
            Error::LoadProductError(path, err) => write!(f, "Unable to load product from {path}: {err}"),
            Error::PackageParseError(pkg) => write!(f, "Unable to parse the given package {pkg}"),
            Error::VulnerabilityTestParseError(path, pkg) => write!(f, "Unable to parse fixed package information {:?} in the product {path}", pkg),
            Error::UnreadableProductsDir(path, err) => write!(f, "The directory {path} is not readable: {err}"),
            Error::HashsumLoadError(err) => write!(f, "Hashsum verification failed: {err}"),
            Error::SignatureCheckError(err) => write!(f, "Signature check failed: {err}"),
        }
    }
}

impl std::error::Error for Error {}
