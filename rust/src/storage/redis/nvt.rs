// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::storage::{
    dispatch::Dispatcher,
    error::StorageError,
    items::nvt::{Feed, FeedVersion, FileName, Nvt, Oid},
    Retriever,
};

use super::{
    connector::CACHE_KEY, RedisAddAdvisory, RedisAddNvt, RedisGetNvt, RedisStorage, RedisWrapper,
};

impl<S: RedisAddNvt> Dispatcher<FileName> for RedisStorage<S>
where
    S: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt,
{
    type Item = Nvt;
    fn dispatch(
        &self,
        _: FileName,
        item: Self::Item,
    ) -> Result<(), crate::storage::error::StorageError> {
        let mut vts = self.cache.lock()?;
        vts.redis_add_nvt(item)?;
        Ok(())
    }
}

impl<S: RedisWrapper> Dispatcher<FeedVersion> for RedisStorage<S>
where
    S: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt,
{
    type Item = String;
    fn dispatch(&self, _: FeedVersion, item: Self::Item) -> Result<(), StorageError> {
        let mut vts = self.cache.lock()?;
        vts.del(CACHE_KEY)?;
        vts.rpush(CACHE_KEY, &[&item])?;
        Ok(())
    }
}

impl<S: RedisWrapper> Retriever<FeedVersion> for RedisStorage<S>
where
    S: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt,
{
    type Item = String;
    fn retrieve(&self, _: &FeedVersion) -> Result<Option<Self::Item>, StorageError> {
        unimplemented!()
    }
}

impl<S: RedisWrapper> Retriever<Feed> for RedisStorage<S>
where
    S: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt,
{
    type Item = Vec<Nvt>;
    fn retrieve(&self, _: &Feed) -> Result<Option<Self::Item>, StorageError> {
        unimplemented!()
    }
}
impl<S: RedisWrapper> Retriever<Oid> for RedisStorage<S>
where
    S: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt,
{
    type Item = Nvt;
    fn retrieve(&self, _: &Oid) -> Result<Option<Self::Item>, StorageError> {
        unimplemented!()
    }
}
impl<S: RedisWrapper> Retriever<FileName> for RedisStorage<S>
where
    S: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt,
{
    type Item = Nvt;
    fn retrieve(&self, _: &FileName) -> Result<Option<Self::Item>, StorageError> {
        unimplemented!()
    }
}
