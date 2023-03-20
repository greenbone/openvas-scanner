// Copyright (C) 2023 Greenbone Networks GmbH
//
// SPDX-License-Identifier: GPL-2.0-or-later

#![doc = include_str!("../README.md")]
#![warn(missing_docs)]

pub mod nvt;
pub mod time;
pub mod types;
use std::{
    fmt::Display,
    io,
    marker::PhantomData,
    sync::{Arc, Mutex, PoisonError},
};

use nvt::{NVTField, NVTKey};
use types::Primitive;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "snake_case")
)]
/// Structure to hold a knowledge base item
pub struct Kb {
    /// Key of the knowledge base entry
    pub key: String,
    /// Value of the knowledge base entry
    pub value: Primitive,
    /// If set it is the seconds the KB entry will expire
    ///
    /// When an entry expires `get_kb` will not find that entry anymore.
    /// When it is Null the KB entry will stay the whole run.
    pub expire: Option<i64>,
}

/// Describes various Fields of supported items.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Field {
    /// Metadata of the NASL script.
    NVT(NVTField),
    /// Knowledge Base item
    KB(Kb),
}

impl From<NVTField> for Field {
    fn from(value: NVTField) -> Self {
        Self::NVT(value)
    }
}

impl From<Kb> for Field {
    fn from(value: Kb) -> Self {
        Self::KB(value)
    }
}

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

/// Defines abstract error cases
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StorageError {
    /// Informs the caller to retry the call
    Retry(String),
    /// The connection to a DB was lost.
    ///
    /// The default solution in those cases are most of the times to try a reconnect.
    ConnectionLost(String),
    /// Did expected a different kind of data and is unable to fulfil the request.
    ///
    /// This is usually a usage error.
    UnexpectedData(String),
    /// There is a deeper problem with the underlying DataBase
    ///
    /// An example would be that there is no free db left on redis and that it needs to be cleaned up.
    Dirty(String),
}

impl<S> From<PoisonError<S>> for StorageError {
    fn from(value: PoisonError<S>) -> Self {
        Self::Dirty(format!("{value:?}"))
    }
}

impl From<io::Error> for StorageError {
    fn from(value: io::Error) -> Self {
        let msg = format!("{:?}", value.kind());
        match value.kind() {
            io::ErrorKind::NotFound
            | io::ErrorKind::PermissionDenied
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::NotConnected
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::AlreadyExists
            | io::ErrorKind::AddrInUse
            | io::ErrorKind::AddrNotAvailable
            | io::ErrorKind::InvalidInput
            | io::ErrorKind::InvalidData
            | io::ErrorKind::UnexpectedEof
            | io::ErrorKind::Unsupported => StorageError::UnexpectedData(msg),
            io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::TimedOut
            | io::ErrorKind::Interrupted => StorageError::Retry(msg),
            _ => StorageError::Dirty(msg),
        }
    }
}

impl Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageError::Retry(p) => write!(f, "There was a temporary issue while reading {p}."),
            StorageError::ConnectionLost(p) => write!(f, "Connection lost {p}."),
            StorageError::UnexpectedData(p) => write!(f, "Unexpected data {p}"),
            StorageError::Dirty(p) => write!(f, "Unexpected issue {p}"),
        }
    }
}

/// Defines the Dispatcher interface to distribute fields
pub trait Dispatcher<K> {
    /// Distributes given field under a key
    ///
    /// A key is usually a OID that was given when starting a script but in description run it is the filename.
    fn dispatch(&self, key: &K, scope: Field) -> Result<(), StorageError>;

    /// On exit is called when a script exit
    ///
    /// Some database require a cleanup therefore this method is called when a script finishes.
    fn on_exit(&self) -> Result<(), StorageError>;

    /// Retries a dispatch for the amount of retries when a retrieable error occurs.
    fn retry_dispatch(&self, retries: usize, key: &K, scope: Field) -> Result<(), StorageError> {
        match self.dispatch(key, scope.clone()) {
            Ok(r) => Ok(r),
            Err(e) => {
                if retries > 0 && matches!(e, StorageError::Retry(_)) {
                    self.retry_dispatch(retries - 1, key, scope)
                } else {
                    Err(e)
                }
            }
        }
    }
}

/// Contains a Vector of all stored items.
///
/// The first String statement is the used key while the Vector of Scope are the values.
type StoreItem = Vec<(String, Vec<Field>)>;

/// Is a in-memory dispatcher that behaves like a Storage.
#[derive(Default)]
pub struct DefaultDispatcher<K> {
    /// If dirty it will not clean the data on_exit
    dirty: bool,
    key: PhantomData<K>,
    /// The data storage
    ///
    /// The memory access is managed via an Arc while the Mutex ensures that only one consumer at a time is accessing it.
    data: Arc<Mutex<StoreItem>>,
}

impl<K> DefaultDispatcher<K> {
    /// Creates a new DefaultDispatcher
    pub fn new(dirty: bool) -> Self {
        Self {
            dirty,
            data: Default::default(),
            key: PhantomData,
        }
    }

    /// Cleanses stored data.
    pub fn cleanse(&self) {
        let mut data = Arc::as_ref(&self.data).lock().unwrap();
        data.clear();
        data.shrink_to_fit();
    }

    /// Get scopes found by key
    ///
    /// A key is usually a OID that was given when starting a script but in description run it is the filename.
    pub fn retrieve(&self, key: &str, scope: Retrieve) -> Result<Vec<Field>, StorageError> {
        let data = Arc::as_ref(&self.data).lock().unwrap();

        match data.iter().find(|(k, _)| k.as_str() == key) {
            Some((_, v)) => match scope {
                Retrieve::NVT(None) => Ok(v
                    .clone()
                    .into_iter()
                    .filter(|x| matches!(x, Field::NVT(_)))
                    .collect()),
                Retrieve::NVT(Some(nkey)) => {
                    let results: Vec<Field> = v
                        .clone()
                        .into_iter()
                        .filter(|v| match nkey {
                            NVTKey::Oid => matches!(v, Field::NVT(NVTField::Oid(_))),
                            NVTKey::FileName => matches!(v, Field::NVT(NVTField::FileName(_))),
                            NVTKey::Version => matches!(v, Field::NVT(NVTField::Version(_))),
                            NVTKey::Name => matches!(v, Field::NVT(NVTField::Name(_))),
                            NVTKey::Tag => matches!(v, Field::NVT(NVTField::Tag(_, _))),
                            NVTKey::Dependencies => {
                                matches!(v, Field::NVT(NVTField::Dependencies(_)))
                            }
                            NVTKey::RequiredKeys => {
                                matches!(v, Field::NVT(NVTField::RequiredKeys(_)))
                            }
                            NVTKey::MandatoryKeys => {
                                matches!(v, Field::NVT(NVTField::MandatoryKeys(_)))
                            }
                            NVTKey::ExcludedKeys => {
                                matches!(v, Field::NVT(NVTField::ExcludedKeys(_)))
                            }
                            NVTKey::RequiredPorts => {
                                matches!(v, Field::NVT(NVTField::RequiredPorts(_)))
                            }
                            NVTKey::RequiredUdpPorts => {
                                matches!(v, Field::NVT(NVTField::RequiredUdpPorts(_)))
                            }
                            NVTKey::Preference => {
                                matches!(v, Field::NVT(NVTField::Preference(_)))
                            }
                            NVTKey::Reference => matches!(v, Field::NVT(NVTField::Reference(_))),
                            NVTKey::Category => matches!(v, Field::NVT(NVTField::Category(_))),
                            NVTKey::Family => matches!(v, Field::NVT(NVTField::Family(_))),
                            NVTKey::NoOp => matches!(v, Field::NVT(NVTField::NoOp)),
                        })
                        .collect();
                    Ok(results)
                }
                Retrieve::KB(s) => Ok(v
                    .clone()
                    .into_iter()
                    .filter(|x| match x {
                        Field::NVT(_) => false,
                        Field::KB(Kb {
                            key,
                            value: _,
                            expire: _,
                        }) => key == &s,
                    })
                    .collect()),
            },
            None => Ok(vec![]),
        }
    }
}

impl<K> Dispatcher<K> for DefaultDispatcher<K>
where
    K: AsRef<str> + Display + Default + From<String>,
{
    fn dispatch(&self, key: &K, scope: Field) -> Result<(), StorageError> {
        let mut data = Arc::as_ref(&self.data).lock().unwrap();
        match data.iter_mut().find(|(k, _)| k.as_str() == key.as_ref()) {
            Some((_, v)) => v.push(scope),
            None => data.push((key.as_ref().to_owned(), vec![scope])),
        }
        Ok(())
    }

    fn on_exit(&self) -> Result<(), StorageError> {
        if !self.dirty {
            self.cleanse();
        }

        Ok(())
    }
}

impl<K> Default for Box<dyn Dispatcher<K>>
where
    K: AsRef<str> + Display + Default + From<String> + 'static,
{
    fn default() -> Self {
        Box::<DefaultDispatcher<K>>::default()
    }
}

#[cfg(test)]
mod tests {
    use super::Field::*;
    use super::NVTField::*;
    use super::*;

    #[test]
    pub fn default_storage() -> Result<(), StorageError> {
        let storage = DefaultDispatcher::default();
        storage.dispatch(&"moep".to_owned(), NVT(Oid("moep".to_owned())))?;
        assert_eq!(
            storage.retrieve("moep", Retrieve::NVT(None))?,
            vec![NVT(Oid("moep".to_owned()))]
        );
        assert_eq!(
            storage.retrieve("moep", Retrieve::NVT(Some(NVTKey::Oid)))?,
            vec![NVT(Oid("moep".to_owned()))]
        );
        assert_eq!(
            storage.retrieve("moep", Retrieve::NVT(Some(NVTKey::Family)))?,
            vec![]
        );
        Ok(())
    }
}
