// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::marker::PhantomData;

use crate::{
    item::{NVTField, NVTKey, Nvt},
    Field, StorageError,
};



/// Retrieve command for a given Field
///
/// Defines what kind of information needs to be gathered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Retrieve{
    /// Metadata of the NASL script.
    NVT(Option<NVTKey>),
    /// Knowledge Base item
    KB(String),
    /// Metadata of the Notus advisory
    NOTUS(Option<String>)
}

impl Retrieve {
    /// Returns the scope of the retrieve command.
    pub fn scope(&self) -> &str {
        match self {
            Retrieve::NVT(_) => "nvt",
            Retrieve::KB(_) => "kb",
            Retrieve::NOTUS(_) => "notus",
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
            },

            Retrieve::KB(s) => {
                if let Field::KB(kb) = field {
                    &kb.key == s
                } else {
                    false
                }
            },

            Retrieve::NOTUS(None) =>matches!(field, Field::NOTUS(_)),
            Retrieve::NOTUS(Some(_)) => matches!(field, Field::NOTUS(_)),
        }
    }
}

/// Retrieves list of keys based on a key pattern.
pub trait ListRetriever {
        /// Gets Fields find by key and scope.
    fn retrieve_keys(&self, _pattern: &str) -> Result<Vec<String>, StorageError>;
}    


/// Retrieves fields based on a key and scope.
pub trait Retriever<K> {
    /// Returns VT's metainformation to be sent to a client.
    fn retrieve_nvt(&self, _oid: &str) -> Result<Option<Nvt>, StorageError>{
        Ok(Some(Nvt::default()))
    }
    /// Returns Advisories metainformation to be sent to a client.
    fn retrieve_advisory(&self, _oid: &str) -> Result<Option<Nvt>, StorageError>{
        Ok(Some(Nvt::default()))
    }

    /// Gets Fields find by key and scope.
    fn retrieve(&self, key: &K, scope: &Retrieve) -> Result<Vec<Field>, StorageError>;

    /// Gets Fields find by field and scope.
    fn retrieve_by_field(
        &self,
        field: &Field,
        scope: &Retrieve,
    ) -> Result<Vec<(K, Vec<Field>)>, StorageError>;
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

    fn retrieve_by_field(
        &self,
        _: &Field,
        _: &Retrieve,
    ) -> Result<Vec<(K, Vec<Field>)>, StorageError> {
        Ok(vec![])
    }
}
