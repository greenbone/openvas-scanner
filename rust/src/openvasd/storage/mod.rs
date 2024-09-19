// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

pub mod file;
pub mod inmemory;
pub mod redis;
pub use scannerlib::storage::Storage as NaslStorage;
use scannerlib::{
    models::{self, Scan, Status, VulnerabilityData},
    storage::{
        item::Nvt, ContextKey, DefaultDispatcher, Dispatcher, Field, FieldKeyResult, Kb, Remover,
        Retrieve, Retriever, StorageError,
    },
};

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
};

use async_trait::async_trait;
use scannerlib::models::scanner::ScanResults;

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
    async fn get_scan(&self, id: &str) -> Result<(Scan, Status), Error>;
    /// Returns the scan with dcecrypted passwords.
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
    async fn vts<'a>(&self) -> Result<Box<dyn Iterator<Item = Nvt> + Send + 'a>, Error>;

    /// Retrieves a NVT.
    ///
    async fn vt_by_oid(&self, oid: &str) -> Result<Option<Nvt>, Error> {
        Ok(self.vts().await?.find(|x| x.oid == oid))
    }

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
    async fn append_fetched_result(&self, results: Vec<ScanResults>) -> Result<(), Error>;
}
#[async_trait]
impl<T> AppendFetchResult for Arc<T>
where
    T: AppendFetchResult + Send + Sync,
{
    async fn append_fetched_result(&self, results: Vec<ScanResults>) -> Result<(), Error> {
        self.as_ref().append_fetched_result(results).await
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

    async fn oids(&self) -> Result<Box<dyn Iterator<Item = String> + Send>, Error> {
        self.as_ref().oids().await
    }

    async fn vts<'a>(&self) -> Result<Box<dyn Iterator<Item = Nvt> + Send + 'a>, Error> {
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
    async fn add_scan_client_id(
        &self,
        scan_id: String,
        client_id: ClientHash,
    ) -> Result<(), Error> {
        self.as_ref().add_scan_client_id(scan_id, client_id).await
    }
    async fn remove_scan_id<I>(&self, scan_id: I) -> Result<(), Error>
    where
        I: AsRef<str> + Send + 'static,
    {
        self.as_ref().remove_scan_id(scan_id).await
    }

    async fn get_scans_of_client_id(&self, client_id: &ClientHash) -> Result<Vec<String>, Error> {
        self.as_ref().get_scans_of_client_id(client_id).await
    }

    async fn is_client_allowed<I>(&self, scan_id: I, client_id: &ClientHash) -> Result<bool, Error>
    where
        I: AsRef<str> + Send + 'static,
    {
        self.as_ref().is_client_allowed(scan_id, client_id).await
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
    fn from_config_and_feeds(
        config: &Config,
        feeds: Vec<FeedHash>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>>;
}

async fn update_notus_feed(p: PathBuf, store: Arc<DefaultDispatcher>) -> Result<(), Error> {
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

                store.as_dispatcher().dispatch(
                    &ContextKey::FileName(filename.to_owned()),
                    Field::NotusAdvisory(Some(data).into()),
                )?;
            }
        }
        tracing::debug!("finished notus feed update");
        Ok(())
    })
    .await
    .expect("notus handler to be executed.")
}

async fn update_nasl_feed(p: PathBuf, store: Arc<DefaultDispatcher>) -> Result<(), Error> {
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
    fn underlying_storage(&self) -> &Arc<DefaultDispatcher>;
    fn handle_result<E>(&self, key: &ContextKey, result: models::Result) -> Result<(), E>
    where
        E: From<StorageError>;
    fn remove_result<E>(
        &self,
        key: &ContextKey,
        idx: Option<usize>,
    ) -> Result<Vec<models::Result>, E>
    where
        E: From<StorageError>;
}

/// Uses a Storage device to handle KB and VT elements when used within a
/// nasl-interpreter::Interpreter.
///
/// This is used for file storage and inmemeory storage.
pub struct UserNASLStorageForKBandVT<T>(T)
where
    T: Storage + ResultHandler + Sync + Send;

impl<T> UserNASLStorageForKBandVT<T>
where
    T: Storage + ResultHandler + Sync + Send,
{
    pub fn new(underlying: T) -> Self {
        Self(underlying)
    }
}

impl<T> ResultHandler for UserNASLStorageForKBandVT<T>
where
    T: Storage + ResultHandler + Sync + Send,
{
    fn underlying_storage(&self) -> &Arc<DefaultDispatcher> {
        self.0.underlying_storage()
    }
    fn handle_result<E>(&self, key: &ContextKey, result: models::Result) -> Result<(), E>
    where
        E: From<StorageError>,
    {
        self.0.handle_result(key, result)
    }

    fn remove_result<E>(
        &self,
        key: &ContextKey,
        idx: Option<usize>,
    ) -> Result<Vec<models::Result>, E>
    where
        E: From<StorageError>,
    {
        self.0.remove_result(key, idx)
    }
}

impl<T> Retriever for UserNASLStorageForKBandVT<T>
where
    T: Storage + ResultHandler + Sync + Send,
{
    fn retrieve(
        &self,
        key: &ContextKey,
        scope: Retrieve,
    ) -> Result<Box<dyn Iterator<Item = Field>>, StorageError> {
        // Although somebody may try to get a result through the Storage trait it is very
        // unlikely as this is a openvasd specific implementation and the results are fetched though
        // `get_results`. If that changes we need to:
        // - create a tokio thread,
        // - get scan progressa
        // - check for id or return all
        // - decrypt all results or the specific id and return it as a Field.
        // relatively similar to `dispatch`.
        self.underlying_storage().retrieve(key, scope)
    }

    fn retrieve_by_field(&self, field: Field, scope: Retrieve) -> FieldKeyResult {
        // We should never try to return results without an ID
        self.underlying_storage().retrieve_by_field(field, scope)
    }

    fn retrieve_by_fields(&self, field: Vec<Field>, scope: Retrieve) -> FieldKeyResult {
        // We should never try to return results without an ID
        self.underlying_storage().retrieve_by_fields(field, scope)
    }
}

impl<T> Dispatcher for UserNASLStorageForKBandVT<T>
where
    T: Storage + ResultHandler + Sync + Send,
{
    fn dispatch(&self, key: &ContextKey, scope: Field) -> Result<(), StorageError> {
        match scope {
            Field::Result(result) => {
                // we may already run in an specialized thread therefore we use current thread.
                self.handle_result(key, *result)
            }
            _ => self
                .underlying_storage()
                .as_dispatcher()
                .dispatch(key, scope),
        }
    }

    fn on_exit(&self, key: &ContextKey) -> Result<(), StorageError> {
        self.underlying_storage().on_exit(key)
    }

    fn dispatch_replace(&self, _: &ContextKey, _scope: Field) -> Result<(), StorageError> {
        Ok(())
    }
}

impl<T> Remover for UserNASLStorageForKBandVT<T>
where
    T: Storage + ResultHandler + Sync + Send,
{
    fn remove_kb(
        &self,
        key: &ContextKey,
        kb_key: Option<String>,
    ) -> Result<Option<Vec<Kb>>, StorageError> {
        self.underlying_storage().remove_kb(key, kb_key)
    }

    fn remove_result(
        &self,
        key: &ContextKey,
        result_id: Option<usize>,
    ) -> Result<Option<Vec<models::Result>>, StorageError> {
        self.underlying_storage().remove_result(key, result_id)
    }
}

#[async_trait]
impl<T> ProgressGetter for UserNASLStorageForKBandVT<T>
where
    T: Storage + ResultHandler + Send + Sync,
{
    async fn get_scan(&self, id: &str) -> Result<(Scan, Status), Error> {
        self.0.get_scan(id).await
    }
    async fn get_decrypted_scan(&self, id: &str) -> Result<(Scan, Status), Error> {
        self.0.get_decrypted_scan(id).await
    }

    async fn get_scan_ids(&self) -> Result<Vec<String>, Error> {
        self.0.get_scan_ids().await
    }
    /// Returns the status of a scan.
    async fn get_status(&self, id: &str) -> Result<Status, Error> {
        self.0.get_status(id).await
    }
    /// Returns the results of a scan as json bytes.
    ///
    /// OpenVASD just stores to results without processing them therefore we
    /// can just return the json bytes.
    async fn get_results(
        &self,
        id: &str,
        from: Option<usize>,
        to: Option<usize>,
    ) -> Result<Box<dyn Iterator<Item = Vec<u8>> + Send>, Error> {
        self.0.get_results(id, from, to).await
    }
}
#[async_trait]
impl<T> ScanStorer for UserNASLStorageForKBandVT<T>
where
    T: Storage + ResultHandler + Send + Sync,
{
    async fn insert_scan(&self, t: Scan) -> Result<(), Error> {
        self.0.insert_scan(t).await
    }
    async fn remove_scan(&self, id: &str) -> Result<(), Error> {
        self.0.remove_scan(id).await
    }
    async fn update_status(&self, id: &str, status: Status) -> Result<(), Error> {
        self.0.update_status(id, status).await
    }
}

#[async_trait]
impl<T> AppendFetchResult for UserNASLStorageForKBandVT<T>
where
    T: Storage + ResultHandler + Send + Sync,
{
    async fn append_fetched_result(&self, results: Vec<ScanResults>) -> Result<(), Error> {
        self.0.append_fetched_result(results).await
    }
}

#[async_trait]
impl<T> NVTStorer for UserNASLStorageForKBandVT<T>
where
    T: Storage + ResultHandler + Send + Sync,
{
    async fn synchronize_feeds(&self, hash: Vec<FeedHash>) -> Result<(), Error> {
        self.0.synchronize_feeds(hash).await
    }

    async fn oids(&self) -> Result<Box<dyn Iterator<Item = String> + Send>, Error> {
        self.0.oids().await
    }

    async fn vts<'a>(&self) -> Result<Box<dyn Iterator<Item = Nvt> + Send + 'a>, Error> {
        self.0.vts().await
    }

    async fn vt_by_oid(&self, oid: &str) -> Result<Option<Nvt>, Error> {
        self.0.vt_by_oid(oid).await
    }

    async fn feed_hash(&self) -> Vec<FeedHash> {
        self.0.feed_hash().await
    }

    async fn current_feed_version(&self) -> Result<String, Error> {
        self.0.current_feed_version().await
    }
}

#[async_trait]
impl<T> ScanIDClientMapper for UserNASLStorageForKBandVT<T>
where
    T: Storage + ResultHandler + Send + Sync,
{
    async fn add_scan_client_id(
        &self,
        scan_id: String,
        client_id: ClientHash,
    ) -> Result<(), Error> {
        self.0.add_scan_client_id(scan_id, client_id).await
    }
    async fn remove_scan_id<I>(&self, scan_id: I) -> Result<(), Error>
    where
        I: AsRef<str> + Send + 'static,
    {
        self.0.remove_scan_id(scan_id).await
    }

    async fn get_scans_of_client_id(&self, client_id: &ClientHash) -> Result<Vec<String>, Error> {
        self.0.get_scans_of_client_id(client_id).await
    }

    async fn is_client_allowed<I>(&self, scan_id: I, client_id: &ClientHash) -> Result<bool, Error>
    where
        I: AsRef<str> + Send + 'static,
    {
        self.0.is_client_allowed(scan_id, client_id).await
    }
}
