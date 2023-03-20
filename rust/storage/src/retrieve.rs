use std::marker::PhantomData;

// Copyright (C) 2023 Greenbone Networks GmbH
//
// SPDX-License-Identifier: GPL-2.0-or-later
use crate::{nvt::NVTKey, Field, StorageError};
/// Retrieve command for a given Field
///
/// Defines what kind of information needs to be gathered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Retrieve {
    /// Metadata of the NASL script.
    NVT(Option<NVTKey>),
    /// Knowledge Base item
    KB(String),
}

/// Retrieves fields based on a key and scope.
pub trait Retriever<K> {
    /// Gets Fields find by key and scope.
    fn retrieve(&self, key: &K, scope: &Retrieve) -> Result<Vec<Field>, StorageError>;
}

/// A NoOpRetriever is for cases that don't require a retriever but it is needed due to contract.
///
/// A use case may be when updating the feed. The context of an interpreter requires a Retriever
/// but since it is not needed for a description run it wouldn't make sense to instantiate a
/// reriever instance.
#[derive(Default)]
pub struct NoOpRetriever<K> {
    phantom: PhantomData<K>,
}

impl<K> Retriever<K> for NoOpRetriever<K> {
    fn retrieve(&self, _: &K, _: &Retrieve) -> Result<Vec<Field>, StorageError> {
        Ok(vec![])
    }
}
