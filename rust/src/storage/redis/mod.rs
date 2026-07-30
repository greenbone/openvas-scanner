// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! # redis-storage
//!
//! Is the redis implementation for [storage](../../storage/).
//!
//! It is written in a downwards compatible way so that `ospd-openvas` is capable of reading and writing the data.
//!
/// Module with structures and methods to access redis.
mod connector;
/// Module to handle custom errors
mod dberror;

use std::sync::Mutex;

use async_trait::async_trait;
pub use connector::CACHE_KEY;
/// Default selector for feed update
pub use connector::FEEDUPDATE_SELECTOR;
pub use connector::NOTUS_KEY;
pub use connector::NOTUSUPDATE_SELECTOR;
pub use connector::NameSpaceSelector;
pub use connector::RedisCtx;
pub use dberror::{DbError, RedisStorageResult};

use super::Dispatcher;
use super::Remover;
use super::Retriever;
use super::ScanID;
use super::error::StorageError;
use super::inmemory::kb::InMemoryKbStorage;
use super::items::kb::GetKbContextKey;
use super::items::kb::KbContextKey;
use super::items::kb::KbItem;
use super::items::notus_advisory::NotusAdvisory;
use super::items::notus_advisory::NotusCache;
use super::items::nvt::FeedVersion;
use super::items::nvt::FileName;
use super::items::nvt::Oid;
//TODO: rename
use greenbone_scanner_framework::models::VTData;

use super::items::result::ResultContextKeySingle;
use super::items::result::ResultItem;

/// Cache implementation.
///
/// This implementation is thread-safe as it stored the underlying RedisCtx within a lockable arc reference.
///
/// We need a second level cache before redis due to NVT runs.
/// In this case we need to wait until we get the OID so that we can build the key additionally
/// we need to have all references and preferences to respect the order to be downwards compatible.
/// This should be changed when there is new OSP frontend available.
#[derive(Debug, Default)]
pub struct RedisStorage {
    cache: Mutex<RedisCtx>,
    kbs: InMemoryKbStorage,
}

impl RedisStorage {
    /// Initialize and return an NVT Cache Object
    ///
    /// The redis_url must be a complete url including the used protocol e.g.:
    /// `"unix:///run/redis/redis-server.sock"`.
    pub fn init(
        redis_url: &str,
        selector: &[NameSpaceSelector],
    ) -> RedisStorageResult<RedisStorage> {
        let rctx = RedisCtx::open(redis_url, selector)?;

        Ok(RedisStorage {
            cache: Mutex::new(rctx),
            kbs: InMemoryKbStorage::default(),
        })
    }
}

#[async_trait]
impl Dispatcher<KbContextKey> for RedisStorage {
    type Item = KbItem;
    async fn dispatch(&self, key: KbContextKey, item: Self::Item) -> Result<(), StorageError> {
        self.kbs.dispatch(key, item).await
    }
}

#[async_trait]
impl Retriever<KbContextKey> for RedisStorage {
    type Item = Vec<KbItem>;
    async fn retrieve(&self, key: &KbContextKey) -> Result<Option<Self::Item>, StorageError> {
        self.kbs.retrieve(key).await
    }
}

#[async_trait]
impl Retriever<GetKbContextKey> for RedisStorage {
    type Item = Vec<(String, Vec<KbItem>)>;
    async fn retrieve(&self, key: &GetKbContextKey) -> Result<Option<Self::Item>, StorageError> {
        self.kbs.retrieve(key).await
    }
}

#[async_trait]
impl Remover<KbContextKey> for RedisStorage {
    type Item = Vec<KbItem>;
    async fn remove(&self, key: &KbContextKey) -> Result<Option<Vec<KbItem>>, StorageError> {
        self.kbs.remove(key).await
    }
}

#[async_trait]
impl Dispatcher<FileName> for RedisStorage {
    type Item = VTData;
    async fn dispatch(
        &self,
        _: FileName,
        item: Self::Item,
    ) -> Result<(), crate::storage::error::StorageError> {
        let mut vts = self.cache.lock()?;
        vts.redis_add_nvt(item, "2".to_string(), String::new())?;
        Ok(())
    }
}

#[async_trait]
impl Dispatcher<FeedVersion> for RedisStorage {
    type Item = String;
    async fn dispatch(&self, _: FeedVersion, item: Self::Item) -> Result<(), StorageError> {
        let mut vts = self.cache.lock()?;
        vts.del(CACHE_KEY)?;
        vts.rpush(CACHE_KEY, &[&item])?;
        Ok(())
    }
}

#[async_trait]
impl Retriever<Oid> for RedisStorage {
    type Item = VTData;
    async fn retrieve(&self, _: &Oid) -> Result<Option<Self::Item>, StorageError> {
        unimplemented!()
    }
}

#[async_trait]
impl Retriever<FileName> for RedisStorage {
    type Item = VTData;
    async fn retrieve(&self, _: &FileName) -> Result<Option<Self::Item>, StorageError> {
        unimplemented!()
    }
}

#[async_trait]
impl Dispatcher<ScanID> for RedisStorage {
    type Item = ResultItem;
    async fn dispatch(&self, _: ScanID, _: Self::Item) -> Result<(), StorageError> {
        unimplemented!()
    }
}

#[async_trait]
impl Retriever<ResultContextKeySingle> for RedisStorage {
    type Item = ResultItem;
    async fn retrieve(
        &self,
        _: &ResultContextKeySingle,
    ) -> Result<Option<Self::Item>, StorageError> {
        unimplemented!()
    }
}

#[async_trait]
impl Remover<ScanID> for RedisStorage {
    type Item = Vec<ResultItem>;
    async fn remove(&self, _: &ScanID) -> Result<Option<Self::Item>, StorageError> {
        unimplemented!()
    }
}

#[async_trait]
impl Dispatcher<()> for RedisStorage {
    type Item = NotusAdvisory;
    async fn dispatch(&self, _: (), item: Self::Item) -> Result<(), StorageError> {
        let mut cache = self.cache.lock()?;
        cache.redis_add_advisory(Some(item))?;
        Ok(())
    }
}

#[async_trait]
impl Dispatcher<NotusCache> for RedisStorage {
    type Item = ();
    async fn dispatch(&self, _: NotusCache, _: Self::Item) -> Result<(), StorageError> {
        let mut cache = self.cache.lock()?;
        cache.redis_add_advisory(None)?;
        Ok(())
    }
}
