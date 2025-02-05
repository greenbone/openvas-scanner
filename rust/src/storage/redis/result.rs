// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::storage::{
    dispatch::Dispatcher,
    error::StorageError,
    items::result::{ResultContextKeyAll, ResultContextKeySingle, ResultItem},
    remove::Remover,
    Retriever, ScanID,
};

use super::{RedisAddAdvisory, RedisAddNvt, RedisGetNvt, RedisStorage, RedisWrapper};

impl<S> Dispatcher<ScanID> for RedisStorage<S>
where
    S: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt,
{
    type Item = ResultItem;
    fn dispatch(&self, _: ScanID, _: Self::Item) -> Result<(), StorageError> {
        unimplemented!()
    }
}

impl<S> Retriever<ResultContextKeySingle> for RedisStorage<S>
where
    S: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt,
{
    type Item = ResultItem;
    fn retrieve(&self, _: &ResultContextKeySingle) -> Result<Option<Self::Item>, StorageError> {
        unimplemented!()
    }
}
impl<S> Retriever<ResultContextKeyAll> for RedisStorage<S>
where
    S: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt,
{
    type Item = Vec<ResultItem>;
    fn retrieve(&self, _: &ResultContextKeyAll) -> Result<Option<Self::Item>, StorageError> {
        unimplemented!()
    }
}
impl<S> Remover<ResultContextKeySingle> for RedisStorage<S>
where
    S: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt,
{
    type Item = ResultItem;
    fn remove(&self, _: &ResultContextKeySingle) -> Result<Option<Self::Item>, StorageError> {
        unimplemented!()
    }
}
impl<S> Remover<ResultContextKeyAll> for RedisStorage<S>
where
    S: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt,
{
    type Item = Vec<ResultItem>;
    fn remove(&self, _: &ResultContextKeyAll) -> Result<Option<Self::Item>, StorageError> {
        unimplemented!()
    }
}
