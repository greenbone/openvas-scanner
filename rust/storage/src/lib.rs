// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#![doc = include_str!("../README.md")]
#![warn(missing_docs)]

pub mod item;
mod retrieve;
pub use retrieve::*;
pub mod time;
pub mod types;
use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
    io,
    sync::{Arc, PoisonError, RwLock},
};

use item::NVTField;
use types::Primitive;

/// Is a key used by a Storage to find data within a certain scope.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ContextKey {
    /// The context is used within a scan.
    ///
    /// This is used to limit kb items or results to a specific scan.
    Scan(String),
    /// The context is used within a feed update.
    ///
    /// The filename is used to know that a given information belongs to certain nasl script.
    FileName(String),
}

impl AsRef<str> for ContextKey {
    fn as_ref(&self) -> &str {
        match self {
            ContextKey::Scan(x) => x,
            ContextKey::FileName(x) => x,
        }
    }
}

impl Default for ContextKey {
    fn default() -> Self {
        ContextKey::FileName(Default::default())
    }
}

impl From<&str> for ContextKey {
    fn from(value: &str) -> Self {
        Self::FileName(value.into())
    }
}

impl ContextKey {
    /// Returns the owned inner value of ContextKey
    pub fn value(&self) -> String {
        match self {
            ContextKey::Scan(x) => x.to_string(),
            ContextKey::FileName(x) => x.to_string(),
        }
    }
}

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
    /// If set it is the unix timestamp the KB entry will expire
    ///
    /// When an entry expires `get_kb` will not find that entry anymore.
    /// When it is Null the KB entry will stay the whole run.
    pub expire: Option<u64>,
}

/// Redefine Vulnerability so that other libraries using that don't have to include models
pub type NotusAdvisory = models::VulnerabilityData;

/// Describes various Fields of supported items.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Field {
    /// Metadata of the NASL script.
    NVT(NVTField),
    /// Knowledge Base item
    KB(Kb),
    /// Notus advisories, when None then the impl can assume finish
    //  moving notusadvisory into the heap to reduce the size of the other enum members
    NotusAdvisory(Box<Option<NotusAdvisory>>),
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

impl From<item::Nvt> for Field {
    fn from(value: item::Nvt) -> Self {
        Field::NVT(NVTField::Nvt(value))
    }
}
impl From<models::VulnerabilityData> for Field {
    fn from(value: models::VulnerabilityData) -> Self {
        Self::NotusAdvisory(Some(value).into())
    }
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

impl TryFrom<Field> for item::Nvt {
    type Error = StorageError;

    fn try_from(value: Field) -> Result<Self, Self::Error> {
        match value {
            Field::NVT(value) => Ok(value.into()),
            _ => Err(StorageError::UnexpectedData(format!(
                "{:?} is not a NVT",
                value
            ))),
        }
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

impl std::error::Error for StorageError {}

/// Defines the Dispatcher interface to distribute fields
pub trait Dispatcher: Sync + Send {
    /// Distributes given field under a key
    ///
    /// A key is usually a OID that was given when starting a script but in description run it is the filename.
    fn dispatch(&self, key: &ContextKey, scope: Field) -> Result<(), StorageError>;

    /// On exit is called when a script exit
    ///
    /// Some database require a cleanup therefore this method is called when a script finishes.
    fn on_exit(&self) -> Result<(), StorageError>;

    /// Retries a dispatch for the amount of retries when a retrievable error occurs.
    fn retry_dispatch(
        &self,
        retries: usize,
        key: &ContextKey,
        scope: Field,
    ) -> Result<(), StorageError> {
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

impl<T> Dispatcher for Arc<T>
where
    T: Dispatcher,
{
    fn dispatch(&self, key: &ContextKey, scope: Field) -> Result<(), StorageError> {
        self.as_ref().dispatch(key, scope)
    }

    fn on_exit(&self) -> Result<(), StorageError> {
        self.as_ref().on_exit()
    }
}

/// Convenience trait to use a dispatcher and retriever implementation
pub trait Storage: Dispatcher + Retriever {
    /// Returns a reference to the retriever
    fn as_retriever(&self) -> &dyn Retriever;
    /// Returns a reference to the dispatcher
    fn as_dispatcher(&self) -> &dyn Dispatcher;
}

impl<T> Storage for T
where
    T: Dispatcher + Retriever,
{
    fn as_retriever(&self) -> &dyn Retriever {
        self
    }

    fn as_dispatcher(&self) -> &dyn Dispatcher {
        self
    }
}

/// Kbs are bound to a scan_id and a kb_key.
///
/// To make lookups easier KB items are fetched by a scan_id, followed by the kb key this should
/// make required_key verifications relatively simple.
type Kbs = HashMap<String, HashMap<String, Vec<Kb>>>;

/// Vts are using a relative file path as a key. This should make includes, script_dependency
/// lookups relative simple.
type Vts = HashMap<String, item::Nvt>;

/// Is a in-memory dispatcher that behaves like a Storage.
#[derive(Default)]
pub struct DefaultDispatcher {
    /// If dirty it will not clean the data on_exit
    dirty: bool,
    vts: Arc<RwLock<Vts>>,
    feed_version: Arc<RwLock<String>>,
    advisories: Arc<RwLock<HashSet<NotusAdvisory>>>,
    kbs: Arc<RwLock<Kbs>>,
}

impl DefaultDispatcher {
    /// Creates a new DefaultDispatcher
    pub fn new(dirty: bool) -> Self {
        Self {
            dirty,
            ..Default::default()
        }
    }

    /// Cleanses stored data.
    pub fn cleanse(&self) -> Result<(), StorageError> {
        // TODO cleanse at least kbs, may rest?
        // let mut data = Arc::as_ref(&self.data).write()?;
        // data.clear();
        // data.shrink_to_fit();

        Ok(())
    }

    fn cache_nvt_field(&self, filename: &str, field: NVTField) -> Result<(), StorageError> {
        let mut data = self.vts.as_ref().write()?;
        if let Some(vt) = data.get_mut(filename) {
            if let Err(feed_version) = vt.set_from_field(field) {
                let mut data = self.feed_version.as_ref().write()?;
                *data = feed_version;
            };
        } else {
            let mut nvt = item::Nvt::default();

            if let Err(feed_version) = nvt.set_from_field(field) {
                drop(data);
                let mut data = self.feed_version.as_ref().write()?;
                *data = feed_version;
            } else {
                if nvt.filename.is_empty() {
                    nvt.filename = filename.to_string();
                }
                data.insert(nvt.filename.clone(), nvt);
            }
        }
        Ok(())
    }

    fn cache_kb(&self, scan_id: &str, kb: Kb) -> Result<(), StorageError> {
        let mut data = self.kbs.as_ref().write()?;
        if let Some(scan_entry) = data.get_mut(scan_id) {
            if let Some(kb_entry) = scan_entry.get_mut(&kb.key) {
                kb_entry.push(kb);
            } else {
                scan_entry.insert(kb.key.clone(), vec![kb]);
            }
        } else {
            let mut scan_entry = HashMap::new();
            scan_entry.insert(kb.key.clone(), vec![kb]);
            data.insert(scan_id.to_string(), scan_entry);
        }
        Ok(())
    }

    fn cache_notus_advisory(&self, adv: NotusAdvisory) -> Result<(), StorageError> {
        let mut data = self.advisories.as_ref().write()?;
        data.insert(adv);
        Ok(())
    }

    fn all_vts(&self) -> Result<impl Iterator<Item = item::Nvt>, StorageError> {
        let vts = self.vts.as_ref().read()?.clone().into_values();
        let notus = self
            .advisories
            .as_ref()
            .read()?
            .clone()
            .into_iter()
            .map(item::Nvt::from);
        Ok(vts.chain(notus))
    }
}

impl Dispatcher for DefaultDispatcher {
    fn dispatch(&self, key: &ContextKey, scope: Field) -> Result<(), StorageError> {
        match scope {
            Field::NVT(x) => self.cache_nvt_field(key.as_ref(), x)?,
            Field::KB(x) => self.cache_kb(key.as_ref(), x)?,
            Field::NotusAdvisory(x) => {
                if let Some(x) = *x {
                    self.cache_notus_advisory(x)?
                }
            }
        }
        Ok(())
    }

    fn on_exit(&self) -> Result<(), StorageError> {
        if !self.dirty {
            self.cleanse()?;
        }

        Ok(())
    }
}

/// Holds iterator in memory
pub struct InMemoryDataWrapper<T> {
    inner: Box<dyn Iterator<Item = T>>,
}

impl<T> InMemoryDataWrapper<T>
where
    T: 'static,
{
    /// Creates a new instance based on a Vector
    pub fn new(v: Vec<T>) -> InMemoryDataWrapper<T> {
        Self {
            inner: Box::new(v.into_iter()),
        }
    }
}
impl<T> Iterator for InMemoryDataWrapper<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}

impl Retriever for DefaultDispatcher {
    fn retrieve(
        &self,
        key: &ContextKey,
        scope: Retrieve,
    ) -> Result<Box<dyn Iterator<Item = Field>>, StorageError> {
        match scope {
            Retrieve::NVT(None | Some(item::NVTKey::Nvt)) => {
                // narf, that cannot be efficient
                let vts = self.all_vts()?.map(|x| x.into());
                let data = InMemoryDataWrapper {
                    inner: Box::new(vts),
                };
                Ok(Box::new(data.into_iter()))
            }
            Retrieve::NVT(Some(item::NVTKey::Version)) => {
                let version = self.feed_version.as_ref().read()?.clone();
                let version = Field::NVT(NVTField::Version(version));
                let data = InMemoryDataWrapper::new(vec![version]);
                Ok(Box::new(data.into_iter()))
            }
            Retrieve::NVT(Some(x)) => {
                let vts = self
                    .all_vts()?
                    .flat_map(move |y| y.key_as_field(x))
                    .map(|x| x.into());
                let data = InMemoryDataWrapper {
                    inner: Box::new(vts),
                };
                Ok(Box::new(data.into_iter()))
            }
            Retrieve::KB(x) => {
                let kbs = self.kbs.as_ref().read()?;
                // TODO: maybe return all when x is empty?
                if let Some(kbs) = kbs.get(key.as_ref()) {
                    if let Some(kbs) = kbs.get(&x) {
                        let data = InMemoryDataWrapper {
                            inner: Box::new(kbs.clone().into_iter().map(|x| x.into())),
                        };
                        return Ok(Box::new(data.into_iter()));
                    }
                }
                Ok(Box::new(vec![].into_iter()))
            }
            Retrieve::NotusAdvisory(x) => {
                let data = self.advisories.as_ref().read()?.clone();
                match x {
                    None => {
                        let data = InMemoryDataWrapper {
                            inner: Box::new(data.into_iter().map(|x| x.into())),
                        };
                        Ok(Box::new(data.into_iter()))
                    }
                    Some(_) => {
                        let data = InMemoryDataWrapper {
                            inner: Box::new(data.into_iter().map(|x| x.into())),
                        };
                        Ok(Box::new(data.into_iter()))
                    }
                }
            }
        }
    }

    fn retrieve_by_field(
        &self,
        field: Field,
        scope: Retrieve,
    ) -> Result<Box<dyn Iterator<Item = (ContextKey, Field)>>, StorageError> {
        self.retrieve_by_fields(vec![field], scope)
    }

    fn retrieve_by_fields(
        &self,
        field: Vec<Field>,
        scope: Retrieve,
    ) -> Result<Box<dyn Iterator<Item = (ContextKey, Field)>>, StorageError> {
        match scope {
            Retrieve::NVT(x) => match x {
                None | Some(item::NVTKey::Nvt) => {
                    let vts = self
                        .all_vts()?
                        .filter(move |y| y.matches_any_field(&field))
                        .map(|x| (ContextKey::FileName(x.filename.clone()), x.into()));
                    let data = InMemoryDataWrapper {
                        inner: Box::new(vts),
                    };
                    Ok(Box::new(data.into_iter()))
                }

                Some(x) => {
                    let vts = self.vts.as_ref().read()?.clone().into_iter();
                    let notus = self
                        .advisories
                        .as_ref()
                        .read()?
                        .clone()
                        .into_iter()
                        .map(|x| (x.filename.clone(), item::Nvt::from(x)));
                    let vts = vts
                        .chain(notus)
                        .filter(move |(_, y)| y.matches_any_field(&field))
                        .flat_map(move |(k, y)| {
                            y.key_as_field(x)
                                .into_iter()
                                .map(move |x| (ContextKey::FileName(k.clone()), x.into()))
                        });
                    let data = InMemoryDataWrapper {
                        inner: Box::new(vts),
                    };
                    Ok(Box::new(data.into_iter()))
                }
            },
            Retrieve::NotusAdvisory(x) => {
                // are there use cases to get a KB outside of a scan?
                tracing::warn!(kb=?x, "currently it is assumed that notus advisories are handled as vt, please use Retrieve::NVT for now.");
                Ok(Box::new(vec![].into_iter()))
            }
            Retrieve::KB(x) => {
                // are there use cases to get a KB outside of a scan?
                tracing::warn!(
                    kb = x,
                    "trying to get kb without scan_id returning empty result"
                );
                Ok(Box::new(vec![].into_iter()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::item::NVTKey;

    use super::Field::*;
    use super::NVTField::*;
    use super::*;

    #[test]
    pub fn default_storage() -> Result<(), StorageError> {
        let storage = DefaultDispatcher::default();
        let key = ContextKey::FileName(String::new());
        storage.dispatch(&key, NVT(Oid("moep".to_owned())))?;
        assert_eq!(
            storage
                .retrieve(&key, Retrieve::NVT(None))?
                .collect::<Vec<_>>(),
            vec![NVT(Nvt(item::Nvt {
                oid: "moep".to_owned(),
                ..Default::default()
            }))]
        );
        assert_eq!(
            storage
                .retrieve(&key, Retrieve::NVT(Some(NVTKey::Oid)))?
                .collect::<Vec<_>>(),
            vec![NVT(Oid("moep".to_owned()))]
        );
        assert_eq!(
            storage
                .retrieve(&key, Retrieve::NVT(Some(NVTKey::Family)))?
                .collect::<Vec<_>>(),
            vec![]
        );
        assert_eq!(
            storage
                .retrieve_by_field(NVT(Oid("moep".to_owned())), Retrieve::NVT(None))?
                .collect::<Vec<_>>(),
            vec![(
                key.clone(),
                NVT(Nvt(item::Nvt {
                    oid: "moep".to_owned(),
                    ..Default::default()
                }))
            )]
        );
        Ok(())
    }
}
