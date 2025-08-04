// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

pub mod file;
pub mod inmemory;
pub(crate) mod json_stream;
pub mod redis;
pub mod results;
pub mod sqlite;

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
};

use async_trait::async_trait;
use scannerlib::{
    models::{
        self, FeedType, Scan, Status, VulnerabilityData,
        scanner::{ScanResultKind, ScanResults},
    },
    storage::{Dispatcher, error::StorageError, inmemory::InMemoryStorage, items::nvt::Nvt},
};

use crate::{config::Config, controller::ClientHash, crypt};
use scannerlib::{
    feed::{self, HashSumNameLoader, Update},
    nasl::FSPluginLoader,
    notus::{AdvisoryLoader, HashsumAdvisoryLoader},
};

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

impl From<scannerlib::storage::infisto::Error> for Error {
    fn from(e: scannerlib::storage::infisto::Error) -> Self {
        Self::Storage(Box::new(e))
    }
}

impl From<scannerlib::storage::redis::DbError> for Error {
    fn from(value: scannerlib::storage::redis::DbError) -> Self {
        Error::Storage(Box::new(value))
    }
}

impl From<StorageError> for Error {
    fn from(value: StorageError) -> Self {
        Error::Storage(Box::new(value))
    }
}

pub type MappedID = String;

#[async_trait]
pub trait ScanIDClientMapper {
    async fn generate_mapped_id(
        &self,
        client: ClientHash,
        scan_id: String,
    ) -> Result<MappedID, Error>;
    async fn list_mapped_scan_ids(&self, client: &ClientHash) -> Result<Vec<String>, Error>;
    async fn get_mapped_id(&self, client: &ClientHash, scan_id: &str) -> Result<MappedID, Error>;
    async fn remove_mapped_id(&self, id: &str) -> Result<(), Error>;
}

#[async_trait]
/// A trait for getting the progress of a scan, the scan itself with decrypted credentials and
/// encrypted as well as results.
///
/// The main usage of this trait is in the controller and when transforming a scan to a osp
pub trait ProgressGetter {
    /// Returns the scan.
    async fn get_scan(&self, id: &str) -> Result<(Scan, Status), Error>;
    /// Returns the scan with decrypted passwords.
    ///
    /// This method should only be used when the password is required. E.g.
    /// when transforming a scan to a osp command.
    async fn get_decrypted_scan(&self, id: &str) -> Result<(Scan, Status), Error>;
    /// Returns all scans.
    async fn get_scan_ids(&self) -> Result<Vec<String>, Error>;
    /// Returns the status of a scan.
    async fn get_status(&self, id: &str) -> Result<Status, Error>;
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
    async fn oids(&self) -> Result<Vec<String>, Error>;

    /// Retrieves NVTs.
    async fn vts<'a>(&self) -> Result<Vec<Nvt>, Error>;

    /// Retrieves a NVT.
    ///
    async fn vt_by_oid(&self, oid: &str) -> Result<Option<Nvt>, Error>;

    /// Returns the currently stored feed hash.
    async fn feed_hash(&self) -> Vec<FeedHash>;

    /// Returns the current feed version, if any.
    async fn current_feed_version(&self) -> Result<String, Error>;
}

#[async_trait]
/// A trait for storing scans.
///
/// The main usage of this trait is in the controller and when a user inserts or removes a scan.
pub trait ScanStorer {
    /// Inserts a scan.
    async fn insert_scan(&self, t: Scan) -> Result<(), Error>;
    /// Removes a scan.
    async fn remove_scan(&self, id: &str) -> Result<(), Error>;
    /// Updates a status of a scan.
    ///
    /// This is required when a scan is started or stopped.
    async fn update_status(&self, id: &str, status: Status) -> Result<(), Error>;
}

#[async_trait]
/// A trait for appending results from a different source.
///
/// This is used when a scan is started and the results are fetched from ospd.
pub trait AppendFetchResult {
    async fn append_fetched_result(
        &self,
        kind: ScanResultKind,
        results: ScanResults,
    ) -> Result<(), Error>;
}
#[async_trait]
impl<T> AppendFetchResult for Arc<T>
where
    T: AppendFetchResult + Send + Sync,
{
    async fn append_fetched_result(
        &self,

        kind: ScanResultKind,

        results: ScanResults,
    ) -> Result<(), Error> {
        self.as_ref().append_fetched_result(kind, results).await
    }
}

#[async_trait]
impl<T> ProgressGetter for Arc<T>
where
    T: ProgressGetter + Send + Sync,
{
    async fn get_scan(&self, id: &str) -> Result<(Scan, Status), Error> {
        self.as_ref().get_scan(id).await
    }

    async fn get_decrypted_scan(&self, id: &str) -> Result<(Scan, Status), Error> {
        self.as_ref().get_decrypted_scan(id).await
    }

    async fn get_scan_ids(&self) -> Result<Vec<String>, Error> {
        self.as_ref().get_scan_ids().await
    }

    async fn get_status(&self, id: &str) -> Result<Status, Error> {
        self.as_ref().get_status(id).await
    }

    async fn get_results(
        &self,
        id: &str,
        from: Option<usize>,
        to: Option<usize>,
    ) -> Result<Box<dyn Iterator<Item = Vec<u8>> + Send>, Error> {
        self.as_ref().get_results(id, from, to).await
    }
}

#[async_trait]
impl<T> ScanStorer for Arc<T>
where
    T: ScanStorer + Send + Sync,
{
    async fn insert_scan(&self, t: Scan) -> Result<(), Error> {
        self.as_ref().insert_scan(t).await
    }
    async fn remove_scan(&self, id: &str) -> Result<(), Error> {
        self.as_ref().remove_scan(id).await
    }

    async fn update_status(&self, id: &str, status: Status) -> Result<(), Error> {
        self.as_ref().update_status(id, status).await
    }
}

#[async_trait]
impl<T> NVTStorer for Arc<T>
where
    T: NVTStorer + Send + Sync,
{
    async fn synchronize_feeds(&self, hash: Vec<FeedHash>) -> Result<(), Error> {
        self.as_ref().synchronize_feeds(hash).await
    }

    async fn oids(&self) -> Result<Vec<String>, Error> {
        self.as_ref().oids().await
    }

    async fn vts<'a>(&self) -> Result<Vec<Nvt>, Error> {
        self.as_ref().vts().await
    }

    async fn vt_by_oid(&self, oid: &str) -> Result<Option<Nvt>, Error> {
        self.as_ref().vt_by_oid(oid).await
    }

    async fn feed_hash(&self) -> Vec<FeedHash> {
        self.as_ref().feed_hash().await
    }

    async fn current_feed_version(&self) -> Result<String, Error> {
        self.as_ref().current_feed_version().await
    }
}

#[async_trait]
impl<T> ScanIDClientMapper for Arc<T>
where
    T: ScanIDClientMapper + Send + Sync,
{
    async fn generate_mapped_id(
        &self,
        client: ClientHash,
        scan_id: String,
    ) -> Result<MappedID, Error> {
        self.as_ref().generate_mapped_id(client, scan_id).await
    }
    async fn list_mapped_scan_ids(&self, client: &ClientHash) -> Result<Vec<String>, Error> {
        self.as_ref().list_mapped_scan_ids(client).await
    }
    async fn get_mapped_id(&self, client: &ClientHash, scan_id: &str) -> Result<MappedID, Error> {
        self.as_ref().get_mapped_id(client, scan_id).await
    }
    async fn remove_mapped_id(&self, id: &str) -> Result<(), Error> {
        self.as_ref().remove_mapped_id(id).await
    }
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

/// A storage type that can be created from a Config and a list of feeds.
pub trait FromConfigAndFeeds: ResultHandler + Storage + Sized {
    async fn from_config_and_feeds(
        config: &Config,
        feeds: Vec<FeedHash>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>>;
}

async fn update_notus_feed(p: PathBuf, store: Arc<InMemoryStorage>) -> Result<(), Error> {
    let notus_advisories_path = p;
    store.clean_advisories()?;

    tokio::task::spawn_blocking(move || {
        tracing::debug!("starting notus feed update");
        let loader = FSPluginLoader::new(notus_advisories_path);
        let advisories_files = HashsumAdvisoryLoader::new(loader.clone())?;
        for filename in advisories_files.get_advisories()?.iter() {
            let advisories = advisories_files.load_advisory(filename)?;

            for adv in advisories.advisories {
                let data = VulnerabilityData {
                    adv,
                    family: advisories.family.clone(),
                    filename: filename.to_owned(),
                };

                store.dispatch((), data)?;
            }
        }
        tracing::debug!("finished notus feed update");
        Ok(())
    })
    .await
    .expect("notus handler to be executed.")
}

async fn update_nasl_feed(p: PathBuf, store: Arc<InMemoryStorage>) -> Result<(), Error> {
    let nasl_feed_path = p;
    store.as_ref().clean_vts()?;

    tracing::debug!("starting nasl feed update");
    let oversion = "0.1";
    let loader = FSPluginLoader::new(nasl_feed_path);
    let verifier = HashSumNameLoader::sha256(&loader)?;

    let fu = Update::init(oversion, 5, &loader, &store, verifier);
    fu.perform_update().await?;
    tracing::debug!("finished nasl feed update");
    Ok(())
}

pub trait ResultHandler {
    fn underlying_storage(&self) -> &Arc<InMemoryStorage>;
    fn handle_result<E>(&self, key: &str, result: models::Result) -> Result<(), E>
    where
        E: From<StorageError>;
}
