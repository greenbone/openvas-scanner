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
    pub key: String,
    pub value: Primitive,
    pub expire: Option<i64>,
}

/// Dispatch command for a given Field
///
/// Defines what kind of information needs to be distributed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Dispatch {
    /// Metadata of the NASL script.
    NVT(NVTField),
    /// Knowledge Base item
    KB(Kb),
}

impl From<NVTField> for Dispatch {
    fn from(value: NVTField) -> Self {
        Self::NVT(value)
    }
}

impl From<Kb> for Dispatch {
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

/// Defines abstract SinkError cases
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SinkError {
    /// Informs the caller to retry the call
    Retry(String),
    /// The connection to a DB was lost.
    ///
    /// The default solution in those cases are most of the times to try a reconnect.
    ConnectionLost(String),
    /// The sink did expected a different kind of data and is unable to fulfil the request.
    ///
    /// This is usually a usage error.
    UnexpectedData(String),
    /// There is a deeper problem with the underlying DataBase
    ///
    /// An example would be that there is no free db left on redis and that it needs to be cleaned up.
    Dirty(String),
}

impl<S> From<PoisonError<S>> for SinkError {
    fn from(value: PoisonError<S>) -> Self {
        Self::Dirty(format!("{value:?}"))
    }
}

impl From<io::Error> for SinkError {
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
            | io::ErrorKind::Unsupported => SinkError::UnexpectedData(msg),
            io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::TimedOut
            | io::ErrorKind::Interrupted => SinkError::Retry(msg),
            _ => SinkError::Dirty(msg),
        }
    }
}

impl Display for SinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SinkError::Retry(p) => write!(f, "There was a temporary issue while reading {p}."),
            SinkError::ConnectionLost(p) => write!(f, "Connection lost {p}."),
            SinkError::UnexpectedData(p) => write!(f, "Unexpected data {p}"),
            SinkError::Dirty(p) => write!(f, "Unexpected issue {p}"),
        }
    }
}

/// Defines the Sink interface to distribute Scope
///
/// In NASL there are three different kind of data:
/// 1. nvt metadata handled as NVT
/// 2. knowledgebase, not implemented yet
/// 3. log (results), not implemented yet
///
/// While the knowledgebase lifetime is limited to the run of a scan
/// NVT as well as Log are consumed by our clients.
pub trait Sink {
    /// Stores given scope to key
    ///
    /// A key is usually a OID that was given when starting a script but in description run it is the filename.
    // TODO extend key to Option<host> - key
    fn dispatch(&self, key: &str, scope: Dispatch) -> Result<(), SinkError>;

    /// On exit is called when a script exit
    ///
    /// Some database require a cleanup therefore this method is called when a script finishes.
    fn on_exit(&self) -> Result<(), SinkError>;

    /// Retries a dispatch for the amount of retries when a retrieable error occurs.
    fn retry_dispatch(&self, retries: usize, key: &str, scope: Dispatch) -> Result<(), SinkError> {
        match self.dispatch(key, scope.clone()) {
            Ok(r) => Ok(r),
            Err(e) => {
                if retries > 0 && matches!(e, SinkError::Retry(_)) {
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
type StoreItem = Vec<(String, Vec<Dispatch>)>;

/// Is a in-memory sink that behaves like a Storage.
#[derive(Default)]
pub struct DefaultSink {
    /// If dirty it will not clean the data on_exit
    dirty: bool,
    /// The data storage
    ///
    /// The memory access is managed via an Arc while the Mutex ensures that only one consumer at a time is accessing it.
    data: Arc<Mutex<StoreItem>>,
}

impl DefaultSink {
    /// Creates a new DefaultSink
    pub fn new(dirty: bool) -> Self {
        Self {
            dirty,
            data: Default::default(),
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
    pub fn retrieve(&self, key: &str, scope: Retrieve) -> Result<Vec<Dispatch>, SinkError> {
        let data = Arc::as_ref(&self.data).lock().unwrap();

        match data.iter().find(|(k, _)| k.as_str() == key) {
            Some((_, v)) => match scope {
                Retrieve::NVT(None) => Ok(v
                    .clone()
                    .into_iter()
                    .filter(|x| matches!(x, Dispatch::NVT(_)))
                    .collect()),
                Retrieve::NVT(Some(nkey)) => {
                    let results: Vec<Dispatch> = v
                        .clone()
                        .into_iter()
                        .filter(|v| match nkey {
                            NVTKey::Oid => matches!(v, Dispatch::NVT(NVTField::Oid(_))),
                            NVTKey::FileName => matches!(v, Dispatch::NVT(NVTField::FileName(_))),
                            NVTKey::Version => matches!(v, Dispatch::NVT(NVTField::Version(_))),
                            NVTKey::Name => matches!(v, Dispatch::NVT(NVTField::Name(_))),
                            NVTKey::Tag => matches!(v, Dispatch::NVT(NVTField::Tag(_, _))),
                            NVTKey::Dependencies => {
                                matches!(v, Dispatch::NVT(NVTField::Dependencies(_)))
                            }
                            NVTKey::RequiredKeys => {
                                matches!(v, Dispatch::NVT(NVTField::RequiredKeys(_)))
                            }
                            NVTKey::MandatoryKeys => {
                                matches!(v, Dispatch::NVT(NVTField::MandatoryKeys(_)))
                            }
                            NVTKey::ExcludedKeys => {
                                matches!(v, Dispatch::NVT(NVTField::ExcludedKeys(_)))
                            }
                            NVTKey::RequiredPorts => {
                                matches!(v, Dispatch::NVT(NVTField::RequiredPorts(_)))
                            }
                            NVTKey::RequiredUdpPorts => {
                                matches!(v, Dispatch::NVT(NVTField::RequiredUdpPorts(_)))
                            }
                            NVTKey::Preference => {
                                matches!(v, Dispatch::NVT(NVTField::Preference(_)))
                            }
                            NVTKey::Reference => matches!(v, Dispatch::NVT(NVTField::Reference(_))),
                            NVTKey::Category => matches!(v, Dispatch::NVT(NVTField::Category(_))),
                            NVTKey::Family => matches!(v, Dispatch::NVT(NVTField::Family(_))),
                            NVTKey::NoOp => matches!(v, Dispatch::NVT(NVTField::NoOp)),
                        })
                        .collect();
                    Ok(results)
                }
                Retrieve::KB(s) => Ok(v
                    .clone()
                    .into_iter()
                    .filter(|x| match x {
                        Dispatch::NVT(_) => false,
                        Dispatch::KB(Kb {
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

impl Sink for DefaultSink {
    fn dispatch(&self, key: &str, scope: Dispatch) -> Result<(), SinkError> {
        let mut data = Arc::as_ref(&self.data).lock().unwrap();
        match data.iter_mut().find(|(k, _)| k.as_str() == key) {
            Some((_, v)) => v.push(scope),
            None => data.push((key.to_owned(), vec![scope])),
        }
        Ok(())
    }

    fn on_exit(&self) -> Result<(), SinkError> {
        if !self.dirty {
            self.cleanse();
        }

        Ok(())
    }
}

impl Default for Box<dyn Sink> {
    fn default() -> Self {
        Box::<DefaultSink>::default()
    }
}

#[cfg(test)]
mod tests {
    use super::Dispatch::*;
    use super::NVTField::*;
    use super::*;

    #[test]
    pub fn default_storage() -> Result<(), SinkError> {
        let storage = DefaultSink::default();
        storage.dispatch("moep", NVT(Oid("moep".to_owned())))?;
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
