// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::marker::PhantomData;

use async_trait::async_trait;

use redis_storage::{RedisAddAdvisory, RedisAddNvt, RedisGetNvt, RedisWrapper, VtHelper};
use storage::StorageError;
use tokio::sync::RwLock;

use serde_json;

#[async_trait]
pub trait GetVts {
    async fn get_oids(&self) -> Result<Vec<String>, StorageError>;

    async fn get_vts(&self, vt_selection: Option<Vec<String>>)
        -> Result<Vec<String>, StorageError>;
}

#[derive(Debug, Default)]
pub struct GetVtsWrapper<R, K>
where
    R: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt + Sync + Send,
    K: AsRef<str> + Sync + Send,
{
    vthelper: RwLock<VtHelper<R, K>>,
    phantom: PhantomData<R>,
}

impl<R, K> GetVtsWrapper<R, K>
where
    R: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt + Sync + Send,
    K: AsRef<str> + Sync + Send,
{
    pub fn new(vthelper: VtHelper<R, K>) -> Self {
        Self {
            vthelper: RwLock::new(vthelper),
            phantom: PhantomData,
        }
    }
}


#[async_trait]
impl<R, K> GetVts for GetVtsWrapper<R, K>
where
    R: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt + Sync + Send,
    K: AsRef<str> + Sync + Send + 'static,
{
    async fn get_oids(&self) -> Result<Vec<String>, StorageError> {
        self.vthelper.read().await.get_oids()
    }

    async fn get_vts(
        &self,
        vt_selection: Option<Vec<String>>,
    ) -> Result<Vec<String>, StorageError> {

        let oids: Vec<String>;
        if let Some(selection) = vt_selection {
            oids = selection;
        } else {
            oids = self.get_oids().await?;
        }

        let mut nvts = Vec::new();
        for oid in oids {
            nvts.push(
                serde_json::to_string(
                    match &self.vthelper.read().await.retrieve_single_nvt(&oid)? {
                        Some(vt) => vt,
                        None => continue,
                    }
                )
                .unwrap(),
            );
        }
        Ok(nvts)
    }
}
