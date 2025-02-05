// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::{
    models,
    storage::{dispatch::Dispatcher, error::StorageError},
};

use super::{RedisAddAdvisory, RedisAddNvt, RedisGetNvt, RedisStorage, RedisWrapper};

impl<S: RedisAddAdvisory> Dispatcher<()> for RedisStorage<S>
where
    S: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt,
{
    type Item = models::VulnerabilityData;
    fn dispatch(&self, _: (), item: Self::Item) -> Result<(), StorageError> {
        let mut cache = self.cache.as_ref().lock()?;
        cache.redis_add_advisory(Some(item))?;
        Ok(())
    }
}
