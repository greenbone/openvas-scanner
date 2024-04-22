// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use redis_storage::{
    dberror::{DbError, RedisStorageResult},
    RedisCtx, RedisGetNvt, RedisWrapper,
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use storage::item::Nvt;

#[derive(Debug, Default)]
pub struct RedisHelper<R>
where
    R: RedisWrapper,
{
    cache: Arc<Mutex<R>>,
    task_kb: Arc<Mutex<R>>,
}

impl<R> RedisHelper<R>
where
    R: RedisWrapper,
{
    /// Initialize a RedisHelper struct with the connection to access the NVT cache
    /// and a empty task knowledge base to store the scan configuration to be sent to openvas.
    pub fn new(
        nvti_cache: Arc<Mutex<RedisCtx>>,
        kb_cache: Arc<Mutex<RedisCtx>>,
    ) -> RedisHelper<RedisCtx> {
        RedisHelper::<RedisCtx> {
            cache: nvti_cache,
            task_kb: kb_cache,
        }
    }
}

pub trait KbAccess {
    fn push_kb_item<T: redis::ToRedisArgs>(
        &mut self,
        key: &str,
        value: T,
    ) -> RedisStorageResult<()>;
    fn scan_status(&mut self, _scan_id: String) -> RedisStorageResult<String> {
        Ok(String::new())
    }
    fn kb_id(&self) -> RedisStorageResult<u32>;
    fn results(&mut self) -> RedisStorageResult<Vec<String>> {
        Ok(Vec::new())
    }
    fn status(&mut self) -> RedisStorageResult<Vec<String>> {
        Ok(Vec::new())
    }
    fn release(&mut self) -> RedisStorageResult<()> {
        Ok(())
    }
}

impl KbAccess for RedisHelper<RedisCtx> {
    /// Provide access to the cache
    fn kb_id(&self) -> RedisStorageResult<u32> {
        let cache = Arc::as_ref(&self.task_kb)
            .lock()
            .map_err(|e| DbError::SystemError(format!("{e:?}")))?;
        Ok(cache.db)
    }
    /// Release the redis namespace and make it available again for other tasks
    fn release(&mut self) -> RedisStorageResult<()> {
        let mut kb = Arc::as_ref(&self.task_kb)
            .lock()
            .map_err(|e| DbError::SystemError(format!("{e:?}")))?;
        kb.delete_namespace()
    }
    fn push_kb_item<T: redis::ToRedisArgs>(
        &mut self,
        key: &str,
        value: T,
    ) -> RedisStorageResult<()> {
        let mut kb = Arc::as_ref(&self.task_kb)
            .lock()
            .map_err(|e| DbError::SystemError(format!("{e:?}")))?;

        kb.lpush(key, value)?;
        Ok(())
    }

    fn scan_status(&mut self, scan_id: String) -> RedisStorageResult<String> {
        let mut kb = Arc::as_ref(&self.task_kb)
            .lock()
            .map_err(|e| DbError::SystemError(format!("{e:?}")))?;
        kb.lindex(&format!("internal/{}", scan_id), 0)
    }

    fn results(&mut self) -> RedisStorageResult<Vec<String>> {
        let mut kb = Arc::as_ref(&self.task_kb)
            .lock()
            .map_err(|e| DbError::SystemError(format!("{e:?}")))?;
        kb.pop("internal/results")
    }

    fn status(&mut self) -> RedisStorageResult<Vec<String>> {
        let mut kb = Arc::as_ref(&self.task_kb)
            .lock()
            .map_err(|e| DbError::SystemError(format!("{e:?}")))?;
        kb.pop("internal/status")
    }
}

pub trait VtHelper {
    fn get_vt(&self, oid: &str) -> RedisStorageResult<Option<Nvt>>;
}

impl VtHelper for RedisHelper<RedisCtx> {
    fn get_vt(&self, oid: &str) -> RedisStorageResult<Option<Nvt>> {
        let mut cache = Arc::as_ref(&self.cache)
            .lock()
            .map_err(|e| DbError::SystemError(format!("{e:?}")))?;

        cache.redis_get_vt(oid)
    }
}

pub struct FakeRedis {
    pub data: HashMap<String, Vec<Vec<u8>>>,
}

impl FakeRedis {
    pub fn item_exists(&self, key: &str, value: &str) -> bool {
        let mut v: Vec<String> = Vec::new();
        if let Some(item) = self.data.get(key) {
            for i in item {
                v.push(String::from_utf8(i.to_vec()).unwrap());
            }
        }
        v.contains(&value.to_string())
    }
}

impl VtHelper for FakeRedis {
    fn get_vt(&self, _: &str) -> RedisStorageResult<Option<Nvt>> {
        Ok(None)
    }
}

impl KbAccess for FakeRedis {
    fn push_kb_item<T: redis::ToRedisArgs>(
        &mut self,
        key: &str,
        value: T,
    ) -> RedisStorageResult<()> {
        self.data.insert(key.to_string(), value.to_redis_args());
        Ok(())
    }
    fn kb_id(&self) -> RedisStorageResult<u32> {
        Ok(3)
    }
}
