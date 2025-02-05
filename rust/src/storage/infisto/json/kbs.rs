// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::io::Write;

use crate::storage::{
    dispatch::Dispatcher,
    error::StorageError,
    items::kb::{KbContextKey, KbItem},
    remove::Remover,
    Retriever,
};

use super::JsonStorage;

impl<S: Write> Dispatcher<KbContextKey> for JsonStorage<S> {
    type Item = KbItem;
    fn dispatch(&self, key: KbContextKey, item: Self::Item) -> Result<(), StorageError> {
        self.kbs.dispatch(key, item)
    }
}

impl<S: Write> Retriever<KbContextKey> for JsonStorage<S> {
    type Item = Vec<KbItem>;
    fn retrieve(&self, key: &KbContextKey) -> Result<Option<Self::Item>, StorageError> {
        self.kbs.retrieve(key)
    }
}

impl<S: Write> Remover<KbContextKey> for JsonStorage<S> {
    type Item = Vec<KbItem>;
    fn remove(&self, key: &KbContextKey) -> Result<Option<Self::Item>, StorageError> {
        self.kbs.remove(key)
    }
}
