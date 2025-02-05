// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::sync::Arc;

use super::error::StorageError;

/// Retrieves fields based on a key and scope.
pub trait Retriever<KEY> {
    type Item;
    /// Gets Fields find by key and scope. This is to get all instances.
    fn retrieve(&self, key: &KEY) -> Result<Option<Self::Item>, StorageError>;

    /// Calls retrieve and retries for max_tries time on StorageError::Retry
    fn retry_retrieve(
        &self,
        key: &KEY,
        max_tries: u64,
    ) -> Result<Option<Self::Item>, StorageError> {
        for _ in 0..max_tries {
            match self.retrieve(key) {
                Err(StorageError::Retry(_)) => continue,
                x => return x,
            }
        }
        Err(StorageError::RetryExhausted)
    }
}

impl<KEY, ITEM, T> Retriever<KEY> for Arc<T>
where
    T: Retriever<KEY, Item = ITEM>,
{
    type Item = ITEM;
    fn retrieve(&self, key: &KEY) -> Result<Option<Self::Item>, StorageError> {
        self.as_ref().retrieve(key)
    }
}
