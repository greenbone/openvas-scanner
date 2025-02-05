// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#![doc = include_str!("README.md")]
/// Module with structures and methods to access redis.
mod connector;
/// Module to handle custom errors
mod dberror;

mod kb;
mod notus_advisory;
mod nvt;

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;

pub use connector::NameSpaceSelector;
/// Default selector for feed update
pub use connector::FEEDUPDATE_SELECTOR;
pub use connector::NOTUSUPDATE_SELECTOR;
pub use connector::{RedisAddAdvisory, RedisAddNvt, RedisCtx, RedisGetNvt, RedisWrapper};
pub use dberror::{DbError, RedisStorageResult};

use super::inmemory::kb::InMemoryKbStorage;
use super::item::CacheDispatcher;

/// Cache implementation.
///
/// This implementation is thread-safe as it stored the underlying RedisCtx within a lockable arc reference.
///
/// We need a second level cache before redis due to NVT runs.
/// In this case we need to wait until we get the OID so that we can build the key additionally
/// we need to have all references and preferences to respect the order to be downwards compatible.
/// This should be changed when there is new OSP frontend available.
#[derive(Debug, Default)]
pub struct RedisStorage<R>
where
    R: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt,
{
    cache: Arc<Mutex<R>>,
    kbs: InMemoryKbStorage,
}

impl<R: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt> RedisStorage<R> {
    fn lock_cache(&self) -> Result<MutexGuard<'_, R>, DbError> {
        self.cache
            .lock()
            .map_err(|e| DbError::PoisonedLock(format!("{e:?}")))
    }
}

impl RedisStorage<RedisCtx> {
    /// Initialize and return an NVT Cache Object
    ///
    /// The redis_url must be a complete url including the used protocol e.g.:
    /// `"unix:///run/redis/redis-server.sock"`.
    pub fn init(
        redis_url: &str,
        selector: &[NameSpaceSelector],
    ) -> RedisStorageResult<RedisStorage<RedisCtx>> {
        let rctx = RedisCtx::open(redis_url, selector)?;

        Ok(RedisStorage {
            cache: Arc::new(Mutex::new(rctx)),
            kbs: InMemoryKbStorage::default(),
        })
    }

    /// Creates a dispatcher to be used to update the feed for a ospd service
    ///
    /// Initializes a redis cache based on the given selector and url and clears the namespace
    /// before returning the underlying cache as a Dispatcher.
    pub fn as_dispatcher(
        redis_url: &str,
        selector: &[NameSpaceSelector],
    ) -> RedisStorageResult<CacheDispatcher<RedisStorage<RedisCtx>>> {
        let cache = Self::init(redis_url, selector)?;
        cache.flushdb()?;
        Ok(CacheDispatcher::new(cache))
    }

    /// Reset the NVT Cache and release the redis namespace
    pub fn reset(&self) -> RedisStorageResult<()> {
        self.lock_cache()?.delete_namespace()
    }

    /// Reset the NVT Cache. Do not release the namespace. Only ensure it is clean
    pub fn flushdb(&self) -> RedisStorageResult<()> {
        self.lock_cache()?.flush_namespace()
    }
}
