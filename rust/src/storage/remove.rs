// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::sync::Arc;

use super::error::StorageError;

/// This trait defines methods to delete knowledge base items and results.
///
/// Kb (KnowledgeBase) are information that are shared between individual script (VT) runs and are
/// usually obsolete when a whole scan is finished.
///
/// Results are log_-, security- or error_messages send from a VT to inform our customer about
/// found information, vulnerabilities or unexpected errors. A customer can request to delete those
/// messages.
pub trait Remover<KEY> {
    type Item;
    /// Removes an Item from the storage.
    fn remove(&self, key: &KEY) -> Result<Option<Self::Item>, StorageError>;
}

impl<KEY, ITEM, T> Remover<KEY> for Arc<T>
where
    T: Remover<KEY, Item = ITEM>,
{
    type Item = ITEM;
    fn remove(&self, key: &KEY) -> Result<Option<Self::Item>, StorageError> {
        self.as_ref().remove(key)
    }
}
