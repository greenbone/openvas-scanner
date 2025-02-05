// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::sync::Arc;

use super::error::StorageError;

/// Defines the Dispatcher interface to distribute fields
pub trait Dispatcher<KEY: Clone> {
    type Item: Clone;
    /// Distributes given field under a key
    ///
    /// A key is usually a OID that was given when starting a script but in description run it is the filename.
    fn dispatch(&self, key: KEY, item: Self::Item) -> Result<(), StorageError>;

    /// Retries a dispatch for the amount of retries when a retrievable error occurs.
    fn retry_dispatch(
        &self,
        key: KEY,
        item: Self::Item,
        max_tries: usize,
    ) -> Result<(), StorageError> {
        for _ in 0..max_tries {
            match self.dispatch(key.clone(), item.clone()) {
                Err(StorageError::Retry(_)) => continue,
                x => return x,
            }
        }
        Err(StorageError::RetryExhausted)
    }
}

impl<KEY: Clone, ITEM: Clone, T> Dispatcher<KEY> for Arc<T>
where
    T: Dispatcher<KEY, Item = ITEM>,
{
    type Item = ITEM;
    fn dispatch(&self, key: KEY, item: Self::Item) -> Result<(), StorageError> {
        self.as_ref().dispatch(key, item)
    }
}
