// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::marker::PhantomData;

use crate::{
    item::{NVTField, NVTKey},
    Field, StorageError,
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
}

impl Retrieve {
    /// Returns the scope of the retrieve command.
    pub fn scope(&self) -> &str {
        match self {
            Retrieve::NVT(_) => "nvt",
            Retrieve::KB(_) => "kb",
            Retrieve::NotusAdvisory(_) => "notus",
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
        }
    }
}

/// Retrieves fields based on a key and scope.
// TODO: remove K infavor of a enum, as a user of that interface it is very hard to differentiate
// when to use an OID and when not. A better solution would be to use enums.
pub trait Retriever<K> {
    /// Gets Fields find by key and scope. This is to get all instances.
    fn retrieve(
        &self,
        key: &K,
        scope: Retrieve,
    ) -> Result<Box<dyn Iterator<Item = Field>>, StorageError>;

    /// Gets Fields find by field and scope.
    ///
    /// This is used to filter results.
    fn retrieve_by_field(
        &self,
        field: Field,
        scope: Retrieve,
    ) -> Result<Box<dyn Iterator<Item = (K, Field)>>, StorageError>;
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

impl<K: 'static> Retriever<K> for NoOpRetriever<K> {
    fn retrieve(
        &self,
        _: &K,
        _: Retrieve,
    ) -> Result<Box<dyn Iterator<Item = Field>>, StorageError> {
        Ok(Box::new(vec![].into_iter()))
    }

    fn retrieve_by_field(
        &self,
        _: Field,
        _: Retrieve,
    ) -> Result<Box<dyn Iterator<Item = (K, Field)>>, StorageError> {
        Ok(Box::new(vec![].into_iter()))
    }
}
