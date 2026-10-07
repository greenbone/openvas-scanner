// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use sqlx::SqlitePool;

use scannerlib::{
    models::VTData,
    nasl::utils::ctx::MtimeCheck,
    scheduling::SchedulerStorage,
    storage::{
        Dispatcher, Remover, Retriever, ScanID,
        error::StorageError,
        inmemory::InMemoryStorage,
        items::{
            kb::{GetKbContextKey, KbContextKey, KbItem},
            nvt::{FeedVersion, FileName, Oid},
            result::{ResultContextKeySingle, ResultItem},
        },
    },
};

use super::vts::SqlPluginStorage;

#[derive(Clone)]
pub struct ScanStorage {
    vts: SqlPluginStorage,
    memory: Arc<InMemoryStorage>,
}

impl ScanStorage {
    /// Creates a `ScanStorage` that resolves on-disk VT file mtimes relative to `plugin_feed`
    /// (the directory the NASL feed is loaded from), so that [`MtimeCheck::check_mtime`] can
    /// detect files that were modified since their hashsum was last verified.
    ///
    /// `signature_check` must match the feed's configured signature checking setting: mtimes
    /// are only ever recorded while signature checking is enabled, so the check is only
    /// meaningful (and only performed) in that case.
    pub fn with_plugin_feed(pool: SqlitePool, plugin_feed: PathBuf, signature_check: bool) -> Self {
        Self {
            vts: SqlPluginStorage::with_plugin_feed(pool, plugin_feed, signature_check),
            memory: Arc::new(InMemoryStorage::new()),
        }
    }
}

#[async_trait]
impl MtimeCheck for ScanStorage {
    async fn check_mtime(&self, filename: &Path) -> Result<(), String> {
        self.vts
            .check_mtime(&filename.to_string_lossy())
            .await
            .map_err(|e| e.to_string())
    }
}

#[async_trait]
impl Retriever<Oid> for ScanStorage {
    type Item = VTData;
    async fn retrieve(&self, key: &Oid) -> Result<Option<Self::Item>, StorageError> {
        self.vts.retrieve(key).await
    }
}

#[async_trait]
impl Retriever<FileName> for ScanStorage {
    type Item = VTData;
    async fn retrieve(&self, key: &FileName) -> Result<Option<Self::Item>, StorageError> {
        self.vts.retrieve(key).await
    }
}

#[async_trait]
impl Dispatcher<FileName> for ScanStorage {
    type Item = VTData;
    async fn dispatch(&self, _key: FileName, _item: Self::Item) -> Result<(), StorageError> {
        Ok(())
    }
}

#[async_trait]
impl Dispatcher<FeedVersion> for ScanStorage {
    type Item = String;
    async fn dispatch(&self, _key: FeedVersion, _item: Self::Item) -> Result<(), StorageError> {
        Ok(())
    }
}

#[async_trait]
impl Dispatcher<KbContextKey> for ScanStorage {
    type Item = KbItem;
    async fn dispatch(&self, key: KbContextKey, item: Self::Item) -> Result<(), StorageError> {
        self.memory.dispatch(key, item).await
    }
}

#[async_trait]
impl Retriever<KbContextKey> for ScanStorage {
    type Item = Vec<KbItem>;
    async fn retrieve(&self, key: &KbContextKey) -> Result<Option<Self::Item>, StorageError> {
        self.memory.retrieve(key).await
    }
}

#[async_trait]
impl Retriever<GetKbContextKey> for ScanStorage {
    type Item = Vec<(String, Vec<KbItem>)>;
    async fn retrieve(&self, key: &GetKbContextKey) -> Result<Option<Self::Item>, StorageError> {
        self.memory.retrieve(key).await
    }
}

#[async_trait]
impl Remover<KbContextKey> for ScanStorage {
    type Item = Vec<KbItem>;
    async fn remove(&self, key: &KbContextKey) -> Result<Option<Self::Item>, StorageError> {
        self.memory.remove(key).await
    }
}

#[async_trait]
impl Dispatcher<ScanID> for ScanStorage {
    type Item = ResultItem;
    async fn dispatch(&self, key: ScanID, item: Self::Item) -> Result<(), StorageError> {
        self.memory.dispatch(key, item).await
    }
}

#[async_trait]
impl Retriever<ResultContextKeySingle> for ScanStorage {
    type Item = ResultItem;
    async fn retrieve(
        &self,
        key: &ResultContextKeySingle,
    ) -> Result<Option<Self::Item>, StorageError> {
        self.memory.retrieve(key).await
    }
}

#[async_trait]
impl Remover<ScanID> for ScanStorage {
    type Item = Vec<ResultItem>;
    async fn remove(&self, key: &ScanID) -> Result<Option<Self::Item>, StorageError> {
        self.memory.remove(key).await
    }
}

impl SchedulerStorage for ScanStorage {}
