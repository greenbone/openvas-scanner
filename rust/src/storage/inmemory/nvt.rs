// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use itertools::Itertools;

use crate::storage::{
    dispatch::Dispatcher,
    error::StorageError,
    items::nvt::{Feed, FeedVersion, FileName, Nvt, Oid},
    remove::Remover,
    Retriever,
};

use super::InMemoryStorage;
// Artificial type for fetching all OIDs
pub struct OIDs;

impl Dispatcher<FileName> for InMemoryStorage {
    type Item = Nvt;
    /// Dispatch a single NVT into the storage with a given Key
    fn dispatch(&self, key: FileName, item: Self::Item) -> Result<(), StorageError> {
        let mut vts = self.vts.write()?;
        let mut oid_lookup = self.oid_lookup.write()?;
        oid_lookup.insert(Self::to_nasl_key(&item.oid), key.0.clone());
        vts.insert(Self::to_nasl_key(&key.0), item);
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

impl Retriever<OIDs> for InMemoryStorage {
    type Item = Vec<String>;
    /// Retrieve all OIDs from the storage
    fn retrieve(&self, _: &OIDs) -> Result<Option<Self::Item>, StorageError> {
        let vts = self.oid_lookup.read()?;

        let vts = vts.keys().map(|(_, oid)| oid.to_string()).collect_vec();
        Ok(Some(vts))
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
        // Duplicate Notus Nasl prevention, when notus available return that otherwise NASL
        Ok(
            if let Some(notus_result) = vts.get(&Self::to_notus_advisory_key(&key.0)) {
                Some(notus_result.clone())
            } else {
                vts.get(&Self::to_nasl_key(&key.0)).cloned()
            },
        )
    }
}

impl Retriever<Oid> for InMemoryStorage {
    type Item = Nvt;
    fn retrieve(&self, key: &Oid) -> Result<Option<Self::Item>, StorageError> {
        let oid_lookup = self.oid_lookup.read()?;
        // is it really better to use the filename as a key identifier?
        // I think in the most cases we would lookup oids?
        let lookup = |key| match oid_lookup.get(key) {
            None => Ok(None),
            Some(file_name) => {
                let vts = self.vts.read()?;
                let (ft, _) = key;
                Ok(vts.get(&(*ft, file_name.to_string())).cloned())
            }
        };
        match lookup(&Self::to_notus_advisory_key(&key.0)) {
            Ok(Some(vt)) => Ok(Some(vt)),
            Err(e) => Err(e),
            _ => lookup(&Self::to_nasl_key(&key.0)),
        }
    }
}

impl Remover<Feed> for InMemoryStorage {
    type Item = ();
    fn remove(&self, _: &Feed) -> Result<Option<Self::Item>, StorageError> {
        self.clean_vts()?;
        Ok(Some(()))
    }
}
