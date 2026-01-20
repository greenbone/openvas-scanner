// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#![doc = include_str!("README.md")]

pub mod error;
pub mod infisto;
pub mod inmemory;
pub mod items;
pub mod redis;

use std::{fmt::Display, sync::Arc};

use async_trait::async_trait;
use error::StorageError;

// TODO: why?
/// The identifier of a Scan
///
/// Either created when creating a new scan or given via models::Scan#scan_id.
#[derive(Clone, Debug, Default, Eq, PartialEq, Hash)]
pub struct ScanID(pub String);

impl Display for ScanID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

///  The target of a scan run
///
///  This is necessary for target specific data, e.g. KB items that should be deleted when the
///  target is not scanned anymore.
#[derive(Clone, Debug, Default, Eq, PartialEq, Hash)]
pub struct Target(pub String);

impl Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Defines the Dispatcher interface to distribute fields
#[async_trait]
pub trait Dispatcher<KEY: Clone> {
    type Item: Clone;
    /// Distributes given field under a key
    ///
    /// A key is usually a OID that was given when starting a script but in description run it is the filename.
    async fn dispatch(&self, key: KEY, item: Self::Item) -> Result<(), StorageError>;

    /// Retries a dispatch for the amount of retries when a retrievable error occurs.
    async fn retry_dispatch(
        &self,
        key: KEY,
        item: Self::Item,
        max_tries: usize,
    ) -> Result<(), StorageError> {
        for _ in 0..max_tries {
            match self.dispatch(key.clone(), item.clone()).await {
                Err(StorageError::Retry(_)) => continue,
                x => return x,
            }
        }
        Err(StorageError::RetryExhausted)
    }
}

#[async_trait]
impl<KEY: Clone + Send + Sync, ITEM: Clone + Send + Sync, T> Dispatcher<KEY> for Arc<T>
where
    T: Dispatcher<KEY, Item = ITEM> + Send + Sync,
{
    type Item = ITEM;
    async fn dispatch(&self, key: KEY, item: Self::Item) -> Result<(), StorageError> {
        self.as_ref().dispatch(key, item).await
    }
}

/// Retrieves fields based on a key and scope.
#[async_trait]
pub trait Retriever<KEY> {
    type Item;
    /// Gets Fields find by key and scope. This is to get all instances.
    async fn retrieve(&self, key: &KEY) -> Result<Option<Self::Item>, StorageError>;

    /// Calls retrieve and retries for max_tries time on StorageError::Retry
    async fn retry_retrieve(
        &self,
        key: &KEY,
        max_tries: u64,
    ) -> Result<Option<Self::Item>, StorageError> {
        for _ in 0..max_tries {
            match self.retrieve(key).await {
                Err(StorageError::Retry(_)) => continue,
                x => return x,
            }
        }
        Err(StorageError::RetryExhausted)
    }
}

#[async_trait]
impl<KEY: Send + Sync, ITEM: Send + Sync, T> Retriever<KEY> for Arc<T>
where
    T: Retriever<KEY, Item = ITEM> + Send + Sync,
{
    type Item = ITEM;
    async fn retrieve(&self, key: &KEY) -> Result<Option<Self::Item>, StorageError> {
        self.as_ref().retrieve(key).await
    }
}

#[async_trait]
impl<KEY: Send + Sync, ITEM: Send + Sync, T> Retriever<KEY> for &T
where
    T: Retriever<KEY, Item = ITEM> + ?Sized + Sync,
{
    type Item = ITEM;
    async fn retrieve(&self, key: &KEY) -> Result<Option<Self::Item>, StorageError> {
        (*self).retrieve(key).await
    }
}

/// This trait defines methods to delete knowledge base items and results.
///
/// Kb (KnowledgeBase) are information that are shared between individual script (VT) runs and are
/// usually obsolete when a whole scan is finished.
///
/// Results are log_-, security- or error_messages send from a VT to inform our customer about
/// found information, vulnerabilities or unexpected errors. A customer can request to delete those
/// messages.
#[async_trait]
pub trait Remover<KEY> {
    type Item;
    /// Removes an Item from the storage.
    async fn remove(&self, key: &KEY) -> Result<Option<Self::Item>, StorageError>;
}

#[async_trait]
impl<KEY: Send + Sync, ITEM: Send + Sync, T> Remover<KEY> for Arc<T>
where
    T: Remover<KEY, Item = ITEM> + Send + Sync,
{
    type Item = ITEM;
    async fn remove(&self, key: &KEY) -> Result<Option<Self::Item>, StorageError> {
        self.as_ref().remove(key).await
    }
}
