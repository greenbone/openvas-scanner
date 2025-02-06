// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::{
    models,
    storage::{
        item::{NVTField, NVTKey, Nvt},
        ContextKey, Field, StorageError,
    },
};

/// Retrieve command for a given Field
///
/// Defines what kind of information needs to be gathered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Retrieve {
    /// Metadata of the NASL script.
    NVT(Option<NVTKey>),
    /// Knowledge Base item
    KB(String),
    /// Metadata of the Notus advisory
    NotusAdvisory(Option<String>),
    /// Result
    ///
    /// When None retrieve all results when set the result with matching index.
    Result(Option<usize>),
}

impl Retrieve {
    /// Returns the scope of the retrieve command.
    pub fn scope(&self) -> &str {
        match self {
            Retrieve::NVT(_) => "nvt",
            Retrieve::KB(_) => "kb",
            Retrieve::NotusAdvisory(_) => "notus",
            Retrieve::Result(_) => "result",
        }
    }

    /// Returns the key of the retrieve field.
    pub fn for_field(&self, field: &Field) -> bool {
        match self {
            Retrieve::NVT(None) => matches!(field, Field::NVT(_)),
            Retrieve::NVT(Some(k)) => match k {
                NVTKey::Oid => matches!(field, Field::NVT(NVTField::Oid(_))),
                NVTKey::FileName => matches!(field, Field::NVT(NVTField::FileName(_))),
                NVTKey::Version => matches!(field, Field::NVT(NVTField::Version(_))),
                NVTKey::Name => matches!(field, Field::NVT(NVTField::Name(_))),
                NVTKey::Tag => matches!(field, Field::NVT(NVTField::Tag(_, _))),
                NVTKey::Dependencies => {
                    matches!(field, Field::NVT(NVTField::Dependencies(_)))
                }
                NVTKey::RequiredKeys => {
                    matches!(field, Field::NVT(NVTField::RequiredKeys(_)))
                }
                NVTKey::MandatoryKeys => {
                    matches!(field, Field::NVT(NVTField::MandatoryKeys(_)))
                }
                NVTKey::ExcludedKeys => {
                    matches!(field, Field::NVT(NVTField::ExcludedKeys(_)))
                }
                NVTKey::RequiredPorts => {
                    matches!(field, Field::NVT(NVTField::RequiredPorts(_)))
                }
                NVTKey::RequiredUdpPorts => {
                    matches!(field, Field::NVT(NVTField::RequiredUdpPorts(_)))
                }
                NVTKey::Preference => {
                    matches!(field, Field::NVT(NVTField::Preference(_)))
                }
                NVTKey::Reference => matches!(field, Field::NVT(NVTField::Reference(_))),
                NVTKey::Category => matches!(field, Field::NVT(NVTField::Category(_))),
                NVTKey::Family => matches!(field, Field::NVT(NVTField::Family(_))),
                NVTKey::NoOp => matches!(field, Field::NVT(NVTField::NoOp)),
                // TODO: in memory and file should map in this case
                NVTKey::Nvt => matches!(field, Field::NVT(NVTField::Nvt(_))),
            },

            Retrieve::KB(s) => {
                if let Field::KB(kb) = field {
                    &kb.key == s
                } else {
                    false
                }
            }

            Retrieve::NotusAdvisory(_) => matches!(field, Field::NotusAdvisory(_)),
            Retrieve::Result(None) => matches!(field, Field::Result(_)),
            Retrieve::Result(Some(id)) => {
                if let Field::Result(r) = field {
                    &r.id == id
                } else {
                    false
                }
            }
        }
    }
}

/// Result of a heap stored iterator or StorageError
pub type FieldResult = Result<Box<dyn Iterator<Item = Field>>, StorageError>;

fn retry<T, F>(f: F, max: u64) -> Result<T, StorageError>
where
    F: Fn() -> Result<T, StorageError>,
{
    if max == 0 {
        return Err(StorageError::RetryExhausted);
    }
    let result = f();
    if let Err(StorageError::Retry(reason)) = result {
        tracing::debug!(reason, "retriever implementation returned retry error");
        retry(f, max - 1)
    } else {
        result
    }
}

/// Result of a heap stored iterator or StorageError
pub type FieldKeyResult = Result<Box<dyn Iterator<Item = (ContextKey, Field)>>, StorageError>;
/// Retrieves fields based on a key and scope.
pub trait Retriever: Send + Sync {
    /// Gets Fields find by key and scope. This is to get all instances.
    fn retrieve(
        &self,
        key: &ContextKey,
        scope: Retrieve,
    ) -> Result<Box<dyn Iterator<Item = Field>>, StorageError>;

    /// Calls retrieve and retries for max_tries time on StorageError::Retry
    fn retry_retrieve(
        &self,
        key: &ContextKey,
        scope: Retrieve,
        max_tries: u64,
    ) -> Result<Box<dyn Iterator<Item = Field>>, StorageError> {
        retry(|| self.retrieve(key, scope.clone()), max_tries)
    }

    /// Returns all vts as an iterator
    fn vts(&self) -> Result<Box<dyn Iterator<Item = Nvt>>, StorageError> {
        Ok(Box::new(
            self.retrieve(&ContextKey::default(), Retrieve::NVT(None))?
                .filter_map(|x| match x {
                    Field::NVT(NVTField::Nvt(nvt)) => Some(nvt),
                    _ => None,
                }),
        ))
    }

    /// Returns all results of a scan
    fn results(
        &self,
        key: &ContextKey,
    ) -> Result<Box<dyn Iterator<Item = models::Result>>, StorageError> {
        Ok(Box::new(
            self.retrieve(key, Retrieve::Result(None))?
                .filter_map(|x| match x {
                    Field::Result(r) => Some(*r),
                    _ => None,
                }),
        ))
    }

    /// Returns result with the given id
    fn result(&self, key: &ContextKey, id: usize) -> Result<Option<models::Result>, StorageError> {
        Ok(self
            .retrieve(key, Retrieve::Result(Some(id)))?
            .filter_map(|x| match x {
                Field::Result(r) => Some(*r),
                _ => None,
            })
            .next())
    }

    /// Gets Fields find by field and scope.
    fn retrieve_by_field(&self, field: Field, scope: Retrieve) -> FieldKeyResult;

    /// Calls retrieve_by_field and retries for max_tries time on StorageError::Retry
    fn retry_retrieve_by_field(
        &self,
        field: Field,
        scope: Retrieve,
        max_tries: u64,
    ) -> FieldKeyResult {
        retry(
            || self.retrieve_by_field(field.clone(), scope.clone()),
            max_tries,
        )
    }

    /// Gets Fields find by field and scope.
    fn retrieve_by_fields(&self, field: Vec<Field>, scope: Retrieve) -> FieldKeyResult;

    /// Calls retrieve_by_fields and retries for max_tries time on StorageError::Retry
    fn retry_retrieve_by_fields(
        &self,
        field: Vec<Field>,
        scope: Retrieve,
        max_tries: u64,
    ) -> FieldKeyResult {
        retry(
            || self.retrieve_by_fields(field.clone(), scope.clone()),
            max_tries,
        )
    }
}

/// A NoOpRetriever is for cases that don't require a retriever but it is needed due to contract.
///
/// A use case may be when updating the feed. The context of an interpreter requires a Retriever
/// but since it is not needed for a description run it wouldn't make sense to instantiate a
/// retriever instance.
#[derive(Default)]
pub struct NoOpRetriever {}

impl Retriever for NoOpRetriever {
    fn retrieve(&self, _: &ContextKey, _: Retrieve) -> FieldResult {
        Ok(Box::new(vec![].into_iter()))
    }

    fn retrieve_by_field(&self, _: Field, _: Retrieve) -> FieldKeyResult {
        Ok(Box::new(vec![].into_iter()))
    }

    fn retrieve_by_fields(&self, _: Vec<Field>, _: Retrieve) -> FieldKeyResult {
        Ok(Box::new(vec![].into_iter()))
    }
}
