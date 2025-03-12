// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::sync::Arc;

use async_trait::async_trait;
use scannerlib::{
    models::{self, scanner::ScanResults, Scan, Status},
    storage::{
        error::StorageError,
        inmemory::InMemoryStorage,
        items::{
            kb::{GetKbContextKey, KbContextKey, KbItem},
            nvt::{Feed, FeedVersion, FileName, Nvt, Oid},
            result::{ResultContextKeyAll, ResultContextKeySingle, ResultItem},
        },
        ContextStorage, Dispatcher, Remover, Retriever, ScanID, SchedulerStorage,
    },
};

use crate::controller::ClientHash;

use super::{
    AppendFetchResult, Error, FeedHash, NVTStorer, ProgressGetter, ResultHandler,
    ScanIDClientMapper, ScanStorer, Storage,
};

/// Delegates all storage related operations to the underlying storage except for the results.
/// The results are handled by a openvasd storage.
///
/// This is used for file storage and inmemory storage.
pub struct ResultCatcher<T>(T)
where
    T: Storage + ResultHandler + Sync + Send;

impl<T> ResultCatcher<T>
where
    T: Storage + ResultHandler + Sync + Send,
{
    pub fn new(underlying: T) -> Self {
        Self(underlying)
    }
}

impl<T> ResultHandler for ResultCatcher<T>
where
    T: Storage + ResultHandler + Sync + Send,
{
    fn underlying_storage(&self) -> &Arc<InMemoryStorage> {
        self.0.underlying_storage()
    }
    fn handle_result<E>(&self, key: &str, result: models::Result) -> Result<(), E>
    where
        E: From<StorageError>,
    {
        self.0.handle_result(key, result)
    }

    fn remove_result<E>(&self, key: &str, idx: Option<usize>) -> Result<Vec<models::Result>, E>
    where
        E: From<StorageError>,
    {
        self.0.remove_result(key, idx)
    }
}

#[async_trait]
impl<T> ProgressGetter for ResultCatcher<T>
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
impl<T> ScanStorer for ResultCatcher<T>
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
impl<T> AppendFetchResult for ResultCatcher<T>
where
    T: Storage + ResultHandler + Send + Sync,
{
    async fn append_fetched_result(&self, results: Vec<ScanResults>) -> Result<(), Error> {
        self.0.append_fetched_result(results).await
    }
}

#[async_trait]
impl<T> NVTStorer for ResultCatcher<T>
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
impl<T> ScanIDClientMapper for ResultCatcher<T>
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

impl<T> Dispatcher<FileName> for ResultCatcher<T>
where
    T: Storage + ResultHandler + Send + Sync,
{
    type Item = Nvt;
    fn dispatch(&self, key: FileName, item: Nvt) -> Result<(), StorageError> {
        self.underlying_storage().dispatch(key, item)
    }
}

impl<T> Dispatcher<KbContextKey> for ResultCatcher<T>
where
    T: Storage + ResultHandler + Send + Sync,
{
    type Item = KbItem;
    fn dispatch(&self, key: KbContextKey, item: Self::Item) -> Result<(), StorageError> {
        self.underlying_storage().dispatch(key, item)
    }
}

impl<T> Dispatcher<ScanID> for ResultCatcher<T>
where
    T: Storage + ResultHandler + Send + Sync,
{
    type Item = ResultItem;
    fn dispatch(&self, key: ScanID, item: Self::Item) -> Result<(), StorageError> {
        self.handle_result(&key.0, item)
    }
}

impl<T> Dispatcher<FeedVersion> for ResultCatcher<T>
where
    T: Storage + ResultHandler + Send + Sync,
{
    type Item = String;
    fn dispatch(&self, key: FeedVersion, item: Self::Item) -> Result<(), StorageError> {
        self.underlying_storage().dispatch(key, item)
    }
}

impl<T> Retriever<KbContextKey> for ResultCatcher<T>
where
    T: Storage + ResultHandler + Send + Sync,
{
    type Item = Vec<KbItem>;
    fn retrieve(&self, key: &KbContextKey) -> Result<Option<Self::Item>, StorageError> {
        self.underlying_storage().retrieve(key)
    }
}

impl<T> Retriever<GetKbContextKey> for ResultCatcher<T>
where
    T: Storage + ResultHandler + Send + Sync,
{
    type Item = Vec<(String, Vec<KbItem>)>;
    fn retrieve(&self, key: &GetKbContextKey) -> Result<Option<Self::Item>, StorageError> {
        self.underlying_storage().retrieve(key)
    }
}

impl<T> Retriever<ResultContextKeySingle> for ResultCatcher<T>
where
    T: Storage + ResultHandler + Send + Sync,
{
    type Item = ResultItem;
    fn retrieve(&self, key: &ResultContextKeySingle) -> Result<Option<Self::Item>, StorageError> {
        self.underlying_storage().retrieve(key)
    }
}

impl<T> Retriever<ResultContextKeyAll> for ResultCatcher<T>
where
    T: Storage + ResultHandler + Send + Sync,
{
    type Item = Vec<ResultItem>;
    fn retrieve(&self, key: &ResultContextKeyAll) -> Result<Option<Self::Item>, StorageError> {
        self.underlying_storage().retrieve(key)
    }
}

impl<T> Retriever<FeedVersion> for ResultCatcher<T>
where
    T: Storage + ResultHandler + Send + Sync,
{
    type Item = String;
    fn retrieve(&self, key: &FeedVersion) -> Result<Option<Self::Item>, StorageError> {
        self.underlying_storage().retrieve(key)
    }
}

impl<T> Retriever<Feed> for ResultCatcher<T>
where
    T: Storage + ResultHandler + Send + Sync,
{
    type Item = Vec<Nvt>;
    fn retrieve(&self, key: &Feed) -> Result<Option<Self::Item>, StorageError> {
        self.underlying_storage().retrieve(key)
    }
}

impl<T> Retriever<Oid> for ResultCatcher<T>
where
    T: Storage + ResultHandler + Send + Sync,
{
    type Item = Nvt;
    fn retrieve(&self, key: &Oid) -> Result<Option<Self::Item>, StorageError> {
        self.underlying_storage().retrieve(key)
    }
}

impl<T> Retriever<FileName> for ResultCatcher<T>
where
    T: Storage + ResultHandler + Send + Sync,
{
    type Item = Nvt;
    fn retrieve(&self, key: &FileName) -> Result<Option<Self::Item>, StorageError> {
        self.underlying_storage().retrieve(key)
    }
}

impl<T> Remover<KbContextKey> for ResultCatcher<T>
where
    T: Storage + ResultHandler + Send + Sync,
{
    type Item = Vec<KbItem>;
    fn remove(&self, key: &KbContextKey) -> Result<Option<Self::Item>, StorageError> {
        self.underlying_storage().remove(key)
    }
}

impl<T> Remover<ResultContextKeySingle> for ResultCatcher<T>
where
    T: Storage + ResultHandler + Send + Sync,
{
    type Item = ResultItem;
    fn remove(&self, key: &ResultContextKeySingle) -> Result<Option<Self::Item>, StorageError> {
        let ret = self
            .0
            .remove_result::<StorageError>(&key.0 .0, Some(key.1))?;
        if ret.is_empty() {
            Ok(None)
        } else {
            Ok(Some(ret[0].clone()))
        }
    }
}

impl<T> Remover<ResultContextKeyAll> for ResultCatcher<T>
where
    T: Storage + ResultHandler + Send + Sync,
{
    type Item = Vec<ResultItem>;
    fn remove(&self, key: &ResultContextKeyAll) -> Result<Option<Self::Item>, StorageError> {
        let ret = self.0.remove_result::<StorageError>(&key.0, None)?;
        Ok(Some(ret))
    }
}

impl<T> SchedulerStorage for ResultCatcher<T> where T: Storage + ResultHandler + Send + Sync {}
impl<T> ContextStorage for ResultCatcher<T> where T: Storage + ResultHandler + Send + Sync {}
