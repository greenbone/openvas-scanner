// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::storage::{
    dispatch::Dispatcher,
    error::StorageError,
    items::kb::{GetKbContextKey, KbContextKey, KbItem},
    remove::Remover,
    Retriever,
};

use super::{RedisAddAdvisory, RedisAddNvt, RedisGetNvt, RedisStorage, RedisWrapper};

impl<S> Dispatcher<KbContextKey> for RedisStorage<S>
where
    S: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt,
{
    type Item = KbItem;
    fn dispatch(&self, key: KbContextKey, item: Self::Item) -> Result<(), StorageError> {
        self.kbs.dispatch(key, item)
    }
}

impl<S> Retriever<KbContextKey> for RedisStorage<S>
where
    S: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt,
{
    type Item = Vec<KbItem>;
    fn retrieve(&self, key: &KbContextKey) -> Result<Option<Self::Item>, StorageError> {
        self.kbs.retrieve(key)
    }
}

impl<S> Retriever<GetKbContextKey> for RedisStorage<S>
where
    S: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt,
{
    type Item = Vec<(String, Vec<KbItem>)>;
    fn retrieve(&self, key: &GetKbContextKey) -> Result<Option<Self::Item>, StorageError> {
        self.kbs.retrieve(key)
    }
}

impl<S> Remover<KbContextKey> for RedisStorage<S>
where
    S: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt,
{
    type Item = Vec<KbItem>;
    fn remove(&self, key: &KbContextKey) -> Result<Option<Vec<KbItem>>, StorageError> {
        self.kbs.remove(key)
    }
}
