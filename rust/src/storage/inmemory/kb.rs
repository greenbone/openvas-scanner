// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{collections::HashMap, sync::RwLock};

use crate::storage::{
    Dispatcher, Remover, Retriever,
    error::StorageError,
    items::kb::{GetKbContextKey, KbContext, KbContextKey, KbItem, KbKey},
};

type Kb = HashMap<KbKey, Vec<KbItem>>;

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
        match kbs.get_mut(&key.0) {
            Some(kb) => {
                if let Some(kb) = kb.get_mut(&key.1) {
                    kb.push(item);
                } else {
                    kb.insert(key.1, vec![item]);
                }
            }
            _ => {
                let mut kb = Kb::new();
                kb.insert(key.1, vec![item]);
                kbs.insert(key.0, kb);
            }
        }
        Ok(())
    }
}

impl Retriever<KbContextKey> for InMemoryKbStorage {
    type Item = Vec<KbItem>;
    fn retrieve(&self, key: &KbContextKey) -> Result<Option<Self::Item>, StorageError> {
        let kbs = self.0.read()?;
        match kbs.get(&key.0) {
            Some(kb) => {
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
            }
            _ => Ok(None),
        }
    }
}

impl Retriever<GetKbContextKey> for InMemoryKbStorage {
    type Item = Vec<(String, Vec<KbItem>)>;
    fn retrieve(&self, key: &GetKbContextKey) -> Result<Option<Self::Item>, StorageError> {
        let kbs = self.0.read()?;
        match kbs.get(&key.0) {
            Some(kb) => {
                if key.1.is_pattern() {
                    let mut ret = vec![];
                    for (kb_key, items) in kb {
                        if kb_key.matches(&key.1) {
                            ret.push((kb_key.to_string(), items.clone()));
                        }
                    }
                    Ok(Some(ret))
                } else {
                    Ok(kb
                        .get(&key.1)
                        .map(|items| vec![(key.1.to_string(), items.clone())]))
                }
            }
            _ => Ok(None),
        }
    }
}

impl Remover<KbContextKey> for InMemoryKbStorage {
    type Item = Vec<KbItem>;
    fn remove(&self, key: &KbContextKey) -> Result<Option<Self::Item>, StorageError> {
        let mut kbs = self.0.write().unwrap();
        match kbs.get_mut(&key.0) {
            Some(kb) => Ok(kb.remove(&key.1)),
            _ => Ok(None),
        }
    }
}
