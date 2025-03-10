// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::storage::{
    dispatch::Dispatcher,
    error::StorageError,
    items::notus_advisory::{NotusAdvisory, NotusCache},
};

use super::{RedisAddAdvisory, RedisAddNvt, RedisGetNvt, RedisStorage, RedisWrapper};

impl<S: RedisAddAdvisory> Dispatcher<()> for RedisStorage<S>
where
    S: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt,
{
    type Item = NotusAdvisory;
    fn dispatch(&self, _: (), item: Self::Item) -> Result<(), StorageError> {
        let mut cache = self.cache.lock()?;
        cache.redis_add_advisory(Some(item))?;
        Ok(())
    }
}

impl<S: RedisAddAdvisory> Dispatcher<NotusCache> for RedisStorage<S>
where
    S: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt,
{
    type Item = ();
    fn dispatch(&self, _: NotusCache, _: Self::Item) -> Result<(), StorageError> {
        let mut cache = self.cache.lock()?;
        cache.redis_add_advisory(None)?;
        Ok(())
    }
}
