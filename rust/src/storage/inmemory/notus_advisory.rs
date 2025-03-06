// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::storage::{
    dispatch::Dispatcher, error::StorageError, items::notus_advisory::NotusAdvisory,
};

use super::InMemoryStorage;

impl Dispatcher<()> for InMemoryStorage {
    type Item = NotusAdvisory;
    fn dispatch(&self, _: (), item: Self::Item) -> Result<(), StorageError> {
        self.cache_notus_advisory(item)
    }
}
