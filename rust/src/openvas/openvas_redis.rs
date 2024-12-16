// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::nasl::syntax::ACT;
use crate::storage::item::{Nvt, NvtPreference, PreferenceType};
use crate::storage::redis::{DbError, RedisCtx, RedisGetNvt, RedisStorageResult, RedisWrapper};
use std::collections::BTreeMap;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard},
};

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

    fn lock_task_kb(&self) -> Result<MutexGuard<'_, R>, DbError> {
        self.task_kb
            .lock()
            .map_err(|e| DbError::PoisonedLock(format!("{e:?}")))
    }

    fn lock_cache(&self) -> Result<MutexGuard<'_, R>, DbError> {
        self.cache
            .lock()
            .map_err(|e| DbError::PoisonedLock(format!("{e:?}")))
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
        // TODO: Should this really be self.lock_task_kb? This seems
        // like it should be self.lock_cache, but I'm keeping it as it
        // was for now.
        Ok(self.lock_task_kb()?.db)
    }

    /// Release the redis namespace and make it available again for other tasks
    fn release(&mut self) -> RedisStorageResult<()> {
        self.lock_task_kb()?.delete_namespace()
    }

    fn push_kb_item<T: redis::ToRedisArgs>(
        &mut self,
        key: &str,
        value: T,
    ) -> RedisStorageResult<()> {
        self.lock_task_kb()?.lpush(key, value)?;
        Ok(())
    }

    fn scan_status(&mut self, scan_id: String) -> RedisStorageResult<String> {
        self.lock_task_kb()?
            .lindex(&format!("internal/{}", scan_id), 0)
    }

    fn results(&mut self) -> RedisStorageResult<Vec<String>> {
        self.lock_task_kb()?.pop("internal/results")
    }

    fn status(&mut self) -> RedisStorageResult<Vec<String>> {
        self.lock_task_kb()?.pop("internal/status")
    }
}

pub trait VtHelper {
    fn get_vt(&self, oid: &str) -> RedisStorageResult<Option<Nvt>>;
}

impl VtHelper for RedisHelper<RedisCtx> {
    fn get_vt(&self, oid: &str) -> RedisStorageResult<Option<Nvt>> {
        self.lock_cache()?.redis_get_vt(oid)
    }
}

pub struct FakeRedis {
    pub data: HashMap<String, Vec<Vec<u8>>>,
}

impl FakeRedis {
    #[cfg(test)]
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
    fn get_vt(&self, oid: &str) -> RedisStorageResult<Option<Nvt>> {
        match oid {
            "123" => Ok(Some(Nvt {
                oid: "123".to_string(),
                name: "test".to_string(),
                filename: "test.nasl".to_string(),
                tag: BTreeMap::new(),
                dependencies: Vec::new(),
                required_keys: Vec::new(),
                mandatory_keys: Vec::new(),
                excluded_keys: Vec::new(),
                required_ports: Vec::new(),
                required_udp_ports: Vec::new(),
                references: Vec::new(),
                preferences: vec![
                    NvtPreference {
                        id: Some(1),
                        class: PreferenceType::CheckBox,
                        name: "test1".to_string(),
                        default: "no".to_string(),
                    },
                    NvtPreference {
                        id: Some(2),
                        class: PreferenceType::Entry,
                        name: "test2".to_string(),
                        default: "".to_string(),
                    },
                ],
                category: ACT::Init,
                family: "test".to_string(),
            })),
            _ => Ok(None),
        }
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
