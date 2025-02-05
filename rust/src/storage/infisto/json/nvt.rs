// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::io::Write;

use crate::storage::{
    dispatch::Dispatcher,
    error::StorageError,
    items::nvt::{Feed, FeedVersion, FileName, Nvt, Oid},
    Retriever,
};

use super::JsonStorage;

impl<S: Write> Dispatcher<FileName> for JsonStorage<S> {
    type Item = Nvt;
    fn dispatch(&self, _: FileName, item: Self::Item) -> Result<(), StorageError> {
        self.as_json(item)
    }
}

impl<S: Write> Dispatcher<FeedVersion> for JsonStorage<S> {
    type Item = String;
    fn dispatch(&self, _: FeedVersion, _: Self::Item) -> Result<(), StorageError> {
        unimplemented!()
    }
}

impl<S: Write> Retriever<FeedVersion> for JsonStorage<S> {
    type Item = String;
    fn retrieve(&self, _: &FeedVersion) -> Result<Option<Self::Item>, StorageError> {
        unimplemented!()
    }
}

impl<S: Write> Retriever<Feed> for JsonStorage<S> {
    type Item = Vec<Nvt>;
    fn retrieve(&self, _: &Feed) -> Result<Option<Self::Item>, StorageError> {
        unimplemented!()
    }
}

impl<S: Write> Retriever<Oid> for JsonStorage<S> {
    type Item = Nvt;
    fn retrieve(&self, _: &Oid) -> Result<Option<Self::Item>, StorageError> {
        unimplemented!()
    }
}

impl<S: Write> Retriever<FileName> for JsonStorage<S> {
    type Item = Nvt;
    fn retrieve(&self, _: &FileName) -> Result<Option<Self::Item>, StorageError> {
        unimplemented!()
    }
}
