// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{collections::HashMap, sync::RwLock};

use crate::storage::{
    dispatch::Dispatcher,
    error::StorageError,
    items::kb::{KbContext, KbContextKey, KbItem, KbKey},
    remove::Remover,
    retrieve::Retriever,
};

use super::InMemoryStorage;

pub type Kb = HashMap<KbKey, Vec<KbItem>>;

/// Kbs are bound to a scan_id and a kb_key.
///
/// To make lookups easier KB items are fetched by a scan_id, followed by the kb key this should
/// make required_key verifications relatively simple.
type Kbs = HashMap<KbContext, Kb>;

#[derive(Debug, Default)]
pub struct InMemoryKbStorage(RwLock<Kbs>);

impl Dispatcher<KbContextKey> for InMemoryKbStorage {
    type Item = KbItem;
    fn dispatch(&self, key: KbContextKey, item: KbItem) -> Result<(), StorageError> {
        let mut kbs = self.0.write()?;
        if let Some(kb) = kbs.get_mut(&key.0) {
            if let Some(kb) = kb.get_mut(&key.1) {
                kb.push(item);
            } else {
                kb.insert(key.1, vec![item]);
            }
        } else {
            let mut kb = Kb::new();
            kb.insert(key.1, vec![item]);
            kbs.insert(key.0, kb);
        }
        Ok(())
    }
}

impl Retriever<KbContextKey> for InMemoryKbStorage {
    type Item = Vec<KbItem>;
    fn retrieve(&self, key: &KbContextKey) -> Result<Option<Self::Item>, StorageError> {
        let kbs = self.0.read()?;
        if let Some(kb) = kbs.get(&key.0) {
            if key.1.is_pattern() {
                let mut ret = vec![];
                for (kb_key, items) in kb {
                    if kb_key.matches(&key.1) {
                        ret.extend(items.clone());
                    }
                }
                Ok(Some(ret))
            } else {
                Ok(kb.get(&key.1).cloned())
            }
        } else {
            Ok(None)
        }
    }
}

impl Remover<KbContextKey> for InMemoryKbStorage {
    type Item = Vec<KbItem>;
    fn remove(&self, key: &KbContextKey) -> Result<Option<Self::Item>, StorageError> {
        let mut kbs = self.0.write().unwrap();
        if let Some(kb) = kbs.get_mut(&key.0) {
            Ok(kb.remove(&key.1))
        } else {
            Ok(None)
        }
    }
}

impl Dispatcher<KbContextKey> for InMemoryStorage {
    type Item = KbItem;
    fn dispatch(&self, key: KbContextKey, item: Self::Item) -> Result<(), StorageError> {
        self.kbs.dispatch(key, item)
    }
}

impl Retriever<KbContextKey> for InMemoryStorage {
    type Item = Vec<KbItem>;
    fn retrieve(&self, key: &KbContextKey) -> Result<Option<Self::Item>, StorageError> {
        self.kbs.retrieve(key)
    }
}

impl Remover<KbContextKey> for InMemoryStorage {
    type Item = Vec<KbItem>;
    fn remove(&self, key: &KbContextKey) -> Result<Option<Self::Item>, StorageError> {
        self.kbs.remove(key)
    }
}
