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
    //Result<Box<dyn Iterator<Item = String + Send>, StorageError>>

    async fn get_vts(&self, vt_selection: Option<Vec<String>>)
        -> Result<Vec<String>, StorageError>;
    //Result<Box<dyn Iterator<Item = String + Send>, StorageError>>
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

//pub struct NvtIterator<R,K>
//where
//    R: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt + Sync + Send,
//    K: AsRef<str> + Sync + Send,
//{
//    oids: Vec<String>,
//    index: usize,
//}
//
//impl<R,K> Iterator for NvtIterator<R,K>
//where
//    R: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt + Sync + Send,
//    K: AsRef<str> + Sync + Send,
//{
//    type Item = Nvt;
//
//    fn next(&mut self) -> Option<Nvt> {
//        if self.index < self.oids.len() {
//            let oid = self.oids[self.index];
//            self.index += 1;
//            self.getvts_wrapper.vthelper.read().await.retrieve_single_nvt(&oid).unwrap()
//        } else {
//            None
//        }
//    }
//}
//
//impl NvtIterator<R,K>
//where
//    R: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt + Sync + Send,
//    K: AsRef<str> + Sync + Send,
//{
//
//    pub fn iter(&self, oids: Vec<String>, getvt: GetVtsWrapper) -> NvtIterator<R,K> {
//        Self {
//
//        }
//    }
//}

#[async_trait]
impl<R, K> GetVts for GetVtsWrapper<R, K>
where
    R: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt + Sync + Send,
    K: AsRef<str> + Sync + Send + 'static,
{
    async fn get_oids(&self) -> Result<Vec<String>, StorageError> {
        Ok(self.vthelper.read().await.get_oids().unwrap())
    }

    async fn get_vts(
        &self,
        _vt_selection: Option<Vec<String>>,
    ) -> Result<Vec<String>, StorageError> {
        let oids = self.get_oids().await.unwrap();
        let mut nvts = Vec::new();
        for oid in oids {
            nvts.push(
                serde_json::to_string(
                    &self
                        .vthelper
                        .read()
                        .await
                        .retrieve_single_nvt(&oid)
                        .unwrap()
                        .unwrap(),
                )
                .unwrap(),
            );
        }

        Ok(nvts)
    }
}
