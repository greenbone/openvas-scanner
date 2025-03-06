// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::io::Write;

use crate::storage::{
    dispatch::Dispatcher,
    error::StorageError,
    items::result::{ResultContextKeyAll, ResultContextKeySingle, ResultItem},
    remove::Remover,
    Retriever, ScanID,
};

use super::JsonStorage;

impl<S: Write> Dispatcher<ScanID> for JsonStorage<S> {
    type Item = ResultItem;
    fn dispatch(&self, _: ScanID, _: Self::Item) -> Result<(), StorageError> {
        unimplemented!()
    }
}
impl<S: Write> Retriever<ResultContextKeySingle> for JsonStorage<S> {
    type Item = ResultItem;
    fn retrieve(&self, _: &ResultContextKeySingle) -> Result<Option<Self::Item>, StorageError> {
        unimplemented!()
    }
}
impl<S: Write> Retriever<ResultContextKeyAll> for JsonStorage<S> {
    type Item = Vec<ResultItem>;
    fn retrieve(&self, _: &ResultContextKeyAll) -> Result<Option<Self::Item>, StorageError> {
        unimplemented!()
    }
}
impl<S: Write> Remover<ResultContextKeySingle> for JsonStorage<S> {
    type Item = ResultItem;
    fn remove(&self, _: &ResultContextKeySingle) -> Result<Option<Self::Item>, StorageError> {
        unimplemented!()
    }
}
impl<S: Write> Remover<ResultContextKeyAll> for JsonStorage<S> {
    type Item = Vec<ResultItem>;
    fn remove(&self, _: &ResultContextKeyAll) -> Result<Option<Self::Item>, StorageError> {
        unimplemented!()
    }
}
