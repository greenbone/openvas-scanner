// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::{fmt::Display, io};

use models::FixedPackage;
use nasl_syntax::LoadError;

#[derive(Debug)]
pub enum LoadAdvisoryErrorKind {
    IOError(io::Error),
    LoadError(LoadError),
}

impl Display for LoadAdvisoryErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadAdvisoryErrorKind::IOError(e) => write!(f, "{e}"),
            LoadAdvisoryErrorKind::LoadError(e) => write!(f, "{e}"),
        }
    }
}

#[derive(Debug)]
pub enum Error {
    // The directory containing the notus advisories does not exist
    MissingAdvisoryDir(String),
    /// The given notus advisory directory is a file
    AdvisoryDirIsFile(String),
    /// The given notus advisory directory is not readable
    UnreadableAdvisoryDir(String, io::Error),
    /// There are no corresponding notus files for the given Operating System
    UnknownOs(String),
    /// General error while loading notus advisories
    LoadAdvisoryError(String, LoadAdvisoryErrorKind),
    /// Unable to parse notus advisory file due to a JSON error
    JSONParseError(String, serde_json::Error),
    /// The version of the notus advisory file is not supported
    UnsupportedVersion(String, String, String),
    /// Unable to parse a given package
    PackageParseError(String),
    /// Unable to parse a package in the notus advisory file
    AdvisoryParseError(String, FixedPackage),
    /// Some issues caused by a HashsumLoader
    HashsumLoadError(feed::VerifyError),
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::UnknownOs(path) => write!(f, "the File {path} was not found, that is either due to a typo or missing notus advisories for the corresponding OS"),
            Error::JSONParseError(path, json_err) => write!(f, "unable to parse Notus file {path}. The corresponding parse error was: {json_err}"),
            Error::UnsupportedVersion(path, version1, version2) => write!(f, "the version of the parsed advisory file {path} is {version1}. This version is currently not supported, the version {version2} is required"),
            Error::MissingAdvisoryDir(path) => write!(f, "The directory {path}, which should contain the notus advisories does not exist"),
            Error::AdvisoryDirIsFile(path) => write!(f, "The given notus advisory directory {path} is a file"),
            Error::LoadAdvisoryError(path, err) => write!(f, "Unable to load advisories from {path}: {err}"),
            Error::PackageParseError(pkg) => write!(f, "Unable to parse the given package {pkg}"),
            Error::AdvisoryParseError(path, pkg) => write!(f, "Unable to parse fixed package information {:?} in the advisories {path}", pkg),
            Error::UnreadableAdvisoryDir(path, err) => write!(f, "The directory {path} is not readable: {err}"),
            Error::HashsumLoadError(err) => write!(f, "Hashsum verification failed: {err}"),
        }
    }
}

impl std::error::Error for Error {}
