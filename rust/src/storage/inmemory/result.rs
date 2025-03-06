// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::storage::{
    dispatch::Dispatcher,
    error::StorageError,
    items::result::{ResultContextKeyAll, ResultContextKeySingle, ResultItem},
    remove::Remover,
    retrieve::Retriever,
    ScanID,
};

use super::InMemoryStorage;

impl Dispatcher<ScanID> for InMemoryStorage {
    type Item = ResultItem;
    fn dispatch(&self, key: ScanID, item: Self::Item) -> Result<(), StorageError> {
        let mut results = self.results.write()?;
        if let Some(scan_results) = results.get_mut(&key) {
            scan_results.push(item);
        } else {
            results.insert(key, vec![item]);
        }
        Ok(())
    }
}

impl Retriever<ResultContextKeySingle> for InMemoryStorage {
    type Item = ResultItem;
    fn retrieve(&self, key: &ResultContextKeySingle) -> Result<Option<Self::Item>, StorageError> {
        let results = self.results.read()?;
        if let Some(scan_results) = results.get(&key.0) {
            return Ok(scan_results.get(key.1).cloned());
        }
        Ok(None)
    }
}

impl Retriever<ResultContextKeyAll> for InMemoryStorage {
    type Item = Vec<ResultItem>;
    fn retrieve(&self, key: &ResultContextKeyAll) -> Result<Option<Self::Item>, StorageError> {
        let results = self.results.read()?;

        Ok(results.get(key).cloned())
    }
}

impl Remover<ResultContextKeyAll> for InMemoryStorage {
    type Item = Vec<ResultItem>;
    fn remove(&self, key: &ResultContextKeyAll) -> Result<Option<Self::Item>, StorageError> {
        let mut results = self.results.write()?;
        Ok(results.remove(key))
    }
}

impl Remover<ResultContextKeySingle> for InMemoryStorage {
    type Item = ResultItem;
    fn remove(&self, key: &ResultContextKeySingle) -> Result<Option<ResultItem>, StorageError> {
        let mut results = self.results.write()?;
        if let Some(results) = results.get_mut(&key.0) {
            return Ok(Some(results.remove(key.1)));
        }
        Ok(None)
    }
}
