// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#![doc = include_str!("README.md")]

pub mod dispatch;
pub mod error;
pub mod infisto;
pub mod inmemory;
pub mod items;
pub mod redis;
pub mod remove;

mod retrieve;
mod time;

use std::{fmt::Display, sync::Arc};

use dispatch::Dispatcher;
use error::StorageError;

use items::{
    kb::{KbContextKey, KbItem},
    notus_advisory::NotusCache,
    nvt::{Feed, FeedVersion, FileName, Nvt, Oid},
    result::{ResultContextKeyAll, ResultContextKeySingle, ResultItem},
};
use remove::Remover;
pub use retrieve::*;

use crate::models;

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

// /// Convenience trait to use a dispatcher and retriever implementation
// pub trait Storage: Dispatcher + Retriever + Remover {
//     /// Returns a reference to the retriever
//     fn as_retriever(&self) -> &dyn Retriever;
//     /// Returns a reference to the dispatcher
//     fn as_dispatcher(&self) -> &dyn Dispatcher;

//     /// Is called when the whole scan is finished.
//     ///
//     /// It has to remove all knowledge base items of that scan.
//     fn scan_finished(&self, key: &ContextKey) -> Result<(), StorageError> {
//         self.remove_kb(key, None)?;
//         Ok(())
//     }

//     /// Is called to remove the whole scan and returns its results.
//     ///
//     /// It has to remove all kb items as well as results of that scan.
//     fn remove_scan(&self, key: &ContextKey) -> Result<Vec<models::Result>, StorageError> {
//         self.remove_kb(key, None)?;
//         let results = self.remove_result(key, None)?;
//         Ok(results.unwrap_or_default())
//     }
// }

// impl<T, KEY, ITEM> Storage for T
// where
//     T: Dispatcher<KEY, ITEM> + Retriever<KEY, ITEM> + Remover<KEY, ITEM>,
// {
//     fn as_retriever(&self) -> &dyn Retriever<KEY, ITEM> {
//         self
//     }

//     fn as_dispatcher(&self) -> &dyn Dispatcher<KEY, ITEM> {
//         self
//     }
// }

pub trait NotusStorage:
    Dispatcher<(), Item = models::VulnerabilityData> + Dispatcher<NotusCache, Item = ()>
{
}

pub trait OspStorage: Retriever<Oid, Item = Nvt> + Retriever<Feed, Item = Vec<Nvt>> {}

pub trait SchedulerStorage: Retriever<Oid, Item = Nvt> + Retriever<FileName, Item = Nvt> {}

pub trait ContextStorage:
    Sync
    + Send
    // kb
    + Dispatcher<KbContextKey, Item = KbItem>
    + Retriever<KbContextKey, Item = Vec<KbItem>>
    + Remover<KbContextKey, Item = Vec<KbItem>>
    // results
    + Dispatcher<ScanID, Item = ResultItem>
    + Retriever<ResultContextKeySingle, Item = ResultItem>
    + Retriever<ResultContextKeyAll, Item = Vec<ResultItem>>
    + Remover<ResultContextKeySingle, Item = ResultItem>
    + Remover<ResultContextKeyAll, Item = Vec<ResultItem>>
    // nvt
    + Dispatcher<FileName, Item = Nvt>
    + Dispatcher<FeedVersion, Item = String>
    + Retriever<FeedVersion, Item = String>
    + Retriever<Feed, Item = Vec<Nvt>>
    + SchedulerStorage
{
    /// By default the KbKey can hold multiple values. When dispatch is used on an already existing
    /// KbKey, the value is appended to the existing list. This function is used to replace the
    /// existing entry with the new one.
    fn dispatch_replace(&self, key: KbContextKey, item: KbItem) -> Result<(), StorageError> {
        self.remove(&key)?;
        self.dispatch(key, item)
    }

}

// Macro to implement the trait for Arc<T>
macro_rules! impl_trait_for_arc {
    ($trait_name:ident) => {
        impl<T> $trait_name for Arc<T> where T: $trait_name {}
    };
}

impl_trait_for_arc!(ContextStorage);
impl_trait_for_arc!(SchedulerStorage);
