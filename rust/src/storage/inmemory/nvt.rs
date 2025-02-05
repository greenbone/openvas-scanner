// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::storage::{
    dispatch::Dispatcher,
    error::StorageError,
    items::nvt::{Feed, FeedVersion, FileName, Nvt, Oid},
    remove::Remover,
    Retriever,
};

use super::InMemoryStorage;

impl Dispatcher<FileName> for InMemoryStorage {
    type Item = Nvt;
    /// Dispatch a single NVT into the storage with a given Key
    fn dispatch(&self, key: FileName, item: Self::Item) -> Result<(), StorageError> {
        let mut vts = self.vts.write()?;
        let mut oid_lookup = self.oid_lookup.write()?;
        oid_lookup.insert(item.oid.clone(), key.0.clone());
        vts.insert(key.0, item);
        Ok(())
    }
}

impl Dispatcher<FeedVersion> for InMemoryStorage {
    type Item = String;
    /// Dispatch the feed version into the storage
    fn dispatch(&self, _: FeedVersion, item: Self::Item) -> Result<(), StorageError> {
        let mut feed_version = self.feed_version.write()?;
        *feed_version = item;
        Ok(())
    }
}

impl Retriever<FeedVersion> for InMemoryStorage {
    type Item = String;
    /// Retrieve the feed version from the storage
    fn retrieve(&self, _: &FeedVersion) -> Result<Option<Self::Item>, StorageError> {
        Ok(Some(self.feed_version.read()?.clone()))
    }
}

impl Retriever<Feed> for InMemoryStorage {
    type Item = Vec<Nvt>;
    /// Retrieve all NVTs from the storage
    fn retrieve(&self, _: &Feed) -> Result<Option<Self::Item>, StorageError> {
        self.all_vts().map(Some)
    }
}

impl Retriever<FileName> for InMemoryStorage {
    type Item = Nvt;
    fn retrieve(&self, key: &FileName) -> Result<Option<Self::Item>, StorageError> {
        let vts = self.vts.read()?;
        Ok(vts.get(&key.0).cloned())
    }
}

impl Retriever<Oid> for InMemoryStorage {
    type Item = Nvt;
    fn retrieve(&self, key: &Oid) -> Result<Option<Self::Item>, StorageError> {
        let vts = self.vts.read()?;
        let oid_lookup = self.oid_lookup.read()?;
        Ok(oid_lookup
            .get(&key.0)
            .and_then(|filename| vts.get(filename).cloned()))
    }
}

impl Remover<Feed> for InMemoryStorage {
    type Item = ();
    fn remove(&self, _: &Feed) -> Result<Option<Self::Item>, StorageError> {
        self.clean_vts()?;
        Ok(Some(()))
    }
}
