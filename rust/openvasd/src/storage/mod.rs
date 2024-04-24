// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

pub mod file;
pub mod inmemory;
pub mod redis;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
};

use async_trait::async_trait;
use models::scanner::ScanResults;

use crate::{controller::ClientHash, crypt};

#[derive(Debug)]
pub enum Error {
    Serialization,
    NotFound,
    Storage(Box<dyn std::error::Error + Send + Sync>),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Error::*;
        match self {
            NotFound => write!(f, "not found"),
            Serialization => write!(f, "serialization error"),
            Storage(e) => write!(f, "storage error: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<serde_json::Error> for Error {
    fn from(_: serde_json::Error) -> Self {
        Self::Serialization
    }
}

impl From<crypt::ParseError> for Error {
    fn from(_: crypt::ParseError) -> Self {
        Self::Serialization
    }
}
impl From<std::string::FromUtf8Error> for Error {
    fn from(_: std::string::FromUtf8Error) -> Self {
        Self::Serialization
    }
}

impl From<crate::storage::Error> for models::scanner::Error {
    fn from(value: crate::storage::Error) -> Self {
        Self::Unexpected(format!("{value:?}"))
    }
}
#[async_trait]
pub trait ScanIDClientMapper {
    async fn add_scan_client_id(&self, scan_id: String, client_id: ClientHash)
        -> Result<(), Error>;
    async fn remove_scan_id<I>(&self, scan_id: I) -> Result<(), Error>
    where
        I: AsRef<str> + Send + 'static;

    async fn get_scans_of_client_id(&self, client_id: &ClientHash) -> Result<Vec<String>, Error>;

    async fn is_client_allowed<I>(&self, scan_id: I, client_id: &ClientHash) -> Result<bool, Error>
    where
        I: AsRef<str> + Send + 'static,
    {
        let scans = self.get_scans_of_client_id(client_id).await?;
        let sid = scan_id.as_ref();
        for id in scans {
            if id == sid {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[async_trait]
/// A trait for getting the progress of a scan, the scan itself with decrypted credentials and
/// encrypted as well as results.
///
/// The main usage of this trait is in the controller and when transforming a scan to a osp
pub trait ProgressGetter {
    /// Returns the scan.
    async fn get_scan(&self, id: &str) -> Result<(models::Scan, models::Status), Error>;
    /// Returns the scan with dcecrypted passwords.
    ///
    /// This method should only be used when the password is required. E.g.
    /// when transforming a scan to a osp command.
    async fn get_decrypted_scan(&self, id: &str) -> Result<(models::Scan, models::Status), Error>;
    /// Returns all scans.
    async fn get_scan_ids(&self) -> Result<Vec<String>, Error>;
    /// Returns the status of a scan.
    async fn get_status(&self, id: &str) -> Result<models::Status, Error>;
    /// Returns the results of a scan as json bytes.
    ///
    /// OpenVASD just stores to results without processing them therefore we
    /// can just return the json bytes.
    async fn get_results(
        &self,
        id: &str,
        from: Option<usize>,
        to: Option<usize>,
    ) -> Result<Box<dyn Iterator<Item = Vec<u8>> + Send>, Error>;
}

pub type Hash = String;
/// Describes the type of the feed
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FeedType {
    /// Notus products
    Products,
    /// Notus advisories
    Advisories,
    /// NASL scripts
    NASL,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Contains the hash values of the sha256sums for specific feeds
pub struct FeedHash {
    pub hash: Hash,
    pub path: PathBuf,
    pub typus: FeedType,
}

impl FeedHash {
    pub fn advisories<S>(p: S) -> Self
    where
        S: AsRef<Path>,
    {
        FeedHash {
            hash: String::new(),
            path: p.as_ref().to_path_buf(),
            typus: FeedType::Advisories,
        }
    }

    pub fn nasl<S>(p: S) -> Self
    where
        S: AsRef<Path>,
    {
        FeedHash {
            hash: String::new(),
            path: p.as_ref().to_path_buf(),
            typus: FeedType::NASL,
        }
    }
}

#[async_trait]
/// Handles NVT specifics.
///
/// Usually it parses nasl feed and notus feed to generate and store nvts.
pub trait NVTStorer {
    /// Synchronizes feed based on the given hash.
    ///
    /// This method is called when the sha256sums is changed. It will then go through the feed
    /// directories and update the meta information.
    async fn synchronize_feeds(&self, hash: Vec<FeedHash>) -> Result<(), Error>;

    /// Retrieves just all oids.
    async fn oids(&self) -> Result<Box<dyn Iterator<Item = String> + Send>, Error> {
        let vts = self.vts().await?;
        Ok(Box::new(vts.map(|x| x.oid)))
    }

    /// Retrieves NVTs.
    async fn vts<'a>(
        &self,
    ) -> Result<Box<dyn Iterator<Item = storage::item::Nvt> + Send + 'a>, Error>;

    /// Retrieves a NVT.
    ///
    async fn vt_by_oid(&self, oid: &str) -> Result<Option<storage::item::Nvt>, Error> {
        Ok(self.vts().await?.find(|x| x.oid == oid))
    }

    /// Returns the currently stored feed hash.
    async fn feed_hash(&self) -> Vec<FeedHash>;
}

#[async_trait]
/// A trait for storing scans.
///
/// The main usage of this trait is in the controller and when a user inserts or removes a scan.
pub trait ScanStorer {
    /// Inserts a scan.
    async fn insert_scan(&self, t: models::Scan) -> Result<(), Error>;
    /// Removes a scan.
    async fn remove_scan(&self, id: &str) -> Result<(), Error>;
    /// Updates a status of a scan.
    ///
    /// This is required when a scan is started or stopped.
    async fn update_status(&self, id: &str, status: models::Status) -> Result<(), Error>;
}

#[async_trait]
/// A trait for appending results from a different source.
///
/// This is used when a scan is started and the results are fetched from ospd.
pub trait AppendFetchResult {
    async fn append_fetched_result(&self, results: Vec<ScanResults>) -> Result<(), Error>;
}

#[async_trait]
/// Combines the traits `ProgressGetter`, `ScanStorer` and `AppendFetchResult`.
pub trait Storage:
    ProgressGetter + ScanStorer + AppendFetchResult + NVTStorer + ScanIDClientMapper
{
}

#[async_trait]
impl<T> Storage for T where
    T: ProgressGetter + ScanStorer + AppendFetchResult + NVTStorer + ScanIDClientMapper
{
}
