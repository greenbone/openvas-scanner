// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::sync::Arc;

use async_trait::async_trait;
use sqlx::SqlitePool;

use scannerlib::{
    models::VTData,
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

/// Storage for the `Openvasd` scanner type.
///
/// VT metadata is read from SQLite (kept in sync by the feed orchestrator).
/// KB and results are kept in memory — they are ephemeral per-scan state.
#[derive(Clone)]
pub struct ScanStorage {
    vts: SqlPluginStorage,
    memory: Arc<InMemoryStorage>,
}

impl ScanStorage {
    pub fn new(pool: SqlitePool) -> Self {
        Self {
            vts: SqlPluginStorage::from(pool),
            memory: Arc::new(InMemoryStorage::new()),
        }
    }
}

// VT lookup — read from SQLite

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

// VT write — no-op; the scanner never writes VT metadata

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

// KB — delegate to in-memory

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

// Results — delegate to in-memory

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
