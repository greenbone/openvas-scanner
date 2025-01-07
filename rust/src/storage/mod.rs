// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#![doc = include_str!("README.md")]

pub mod infisto;
pub mod json;
pub mod redis;

pub mod item;
mod retrieve;
mod time;
pub mod types;

pub use retrieve::*;

use item::NVTField;
use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
    io,
    sync::{Arc, PoisonError, RwLock},
};
use thiserror::Error;
use types::Primitive;

use crate::models::{self, VulnerabilityData};

/// The identifier of a Scan
///
/// Either created when creating a new scan or given via models::Scan#scan_id.
type ScanID = String;

///  The target of a scan run
///
///  This is necessary for target specific data, e.g. KB items that should be deleted when the
///  target is not scanned anymore.
type Target = Option<String>;

/// Is a key used by a Storage to find data within a certain scope.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ContextKey {
    /// The context is used within a scan.
    ///
    /// This is used to limit kb items or results to a specific scan. The kb items are limited to
    /// ScanID and Target while the results are limited to just the ScanID.
    Scan(ScanID, Target),
    /// The context is used within a feed update.
    ///
    /// The filename is used to know that a given information belongs to certain nasl script.
    FileName(String),
}

impl Display for ContextKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContextKey::Scan(id, None) => write!(f, "scan_id={id}"),
            ContextKey::Scan(id, Some(target)) => write!(f, "scan_id={id} target={target}"),
            ContextKey::FileName(name) => write!(f, "file={name}"),
        }
    }
}

impl AsRef<str> for ContextKey {
    fn as_ref(&self) -> &str {
        match self {
            ContextKey::Scan(x, _) => x,
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
            ContextKey::Scan(x, _) => x.to_string(),
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

impl<K, V> From<(K, V)> for Kb
where
    K: Into<String>,
    V: Into<Primitive>,
{
    fn from((key, value): (K, V)) -> Self {
        Kb {
            key: key.into(),
            value: value.into(),
            expire: None,
        }
    }
}

/// Redefine Vulnerability so that other libraries using that don't have to include models
pub type NotusAdvisory = VulnerabilityData;

/// Describes various Fields of supported items.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Field {
    /// Metadata of the NASL script.
    NVT(NVTField),
    /// Knowledge Base item
    KB(Kb),
    /// Result send by log_message, security_message, error_message
    Result(Box<models::Result>),
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
impl From<VulnerabilityData> for Field {
    fn from(value: VulnerabilityData) -> Self {
        Self::NotusAdvisory(Some(value).into())
    }
}

/// Defines abstract error cases
#[derive(Clone, Debug, PartialEq, Error)]
pub enum StorageError {
    /// Informs the caller to retry the call
    #[error("There was a temporary issue while reading: {0}")]
    Retry(String),
    #[error("Retries exhausted")]
    RetryExhausted,
    /// The connection to a DB was lost.
    ///
    /// The default solution in those cases are most of the times to try a reconnect.
    #[error("Connection lost: {0}")]
    ConnectionLost(String),
    /// Did expected a different kind of data and is unable to fulfil the request.
    ///
    /// This is usually a usage error.
    #[error("Unexpected data: {0}")]
    UnexpectedData(String),
    /// There is a deeper problem with the underlying DataBase
    ///
    /// An example would be that there is no free db left on redis and that it needs to be cleaned up.
    #[error("Unexpected issue: {0}")]
    Dirty(String),
    #[error("Not found: {0}")]
    /// Not found variant
    NotFound(String),
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

/// Defines the Dispatcher interface to distribute fields
pub trait Dispatcher: Sync + Send {
    /// Distributes given field under a key
    ///
    /// A key is usually a OID that was given when starting a script but in description run it is the filename.
    fn dispatch(&self, key: &ContextKey, scope: Field) -> Result<(), StorageError>;

    /// Replace all fields under a key with the new field
    ///
    fn dispatch_replace(&self, key: &ContextKey, scope: Field) -> Result<(), StorageError>;

    /// On exit is called when a script exit
    ///
    /// Some database require a cleanup therefore this method is called when a script finishes.
    fn on_exit(&self, key: &ContextKey) -> Result<(), StorageError>;

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

/// This trait defines methods to delete knowledge base items and results.
///
/// Kb (KnowledgeBase) are information that are shared between individual script (VT) runs and are
/// usually obsolete when a whole scan is finished.
///
/// Results are log_-, security- or error_messages send from a VT to inform our customer about
/// found information, vulnerabilities or unexpected errors. A customer can request to delete those
/// messages.
pub trait Remover: Sync + Send {
    /// Removes a knowledge base of a contextkye
    ///
    /// When kb_key is None all KBs of that key are deleted
    fn remove_kb(
        &self,
        key: &ContextKey,
        kb_key: Option<String>,
    ) -> Result<Option<Vec<Kb>>, StorageError>;

    /// Removes a result of a ContextKey
    ///
    /// When result_id is None all results of that CotnextKey get deleted.
    fn remove_result(
        &self,
        key: &ContextKey,
        result_id: Option<usize>,
    ) -> Result<Option<Vec<models::Result>>, StorageError>;
}

impl<T> Dispatcher for Arc<T>
where
    T: Dispatcher,
{
    fn dispatch(&self, key: &ContextKey, scope: Field) -> Result<(), StorageError> {
        self.as_ref().dispatch(key, scope)
    }

    fn dispatch_replace(&self, key: &ContextKey, scope: Field) -> Result<(), StorageError> {
        self.as_ref().dispatch_replace(key, scope)
    }

    fn on_exit(&self, key: &ContextKey) -> Result<(), StorageError> {
        self.as_ref().on_exit(key)
    }

    fn retry_dispatch(
        &self,
        retries: usize,
        key: &ContextKey,
        scope: Field,
    ) -> Result<(), StorageError> {
        self.as_ref().retry_dispatch(retries, key, scope)
    }
}

impl<T> Remover for Arc<T>
where
    T: Remover,
{
    fn remove_kb(
        &self,
        key: &ContextKey,
        kb_key: Option<String>,
    ) -> Result<Option<Vec<Kb>>, StorageError> {
        self.as_ref().remove_kb(key, kb_key)
    }

    fn remove_result(
        &self,
        key: &ContextKey,
        result_id: Option<usize>,
    ) -> Result<Option<Vec<models::Result>>, StorageError> {
        self.as_ref().remove_result(key, result_id)
    }
}

type FieldIter = Box<dyn Iterator<Item = Field>>;

impl<T> Retriever for Arc<T>
where
    T: Retriever + Sync,
{
    fn retrieve(&self, key: &ContextKey, scope: Retrieve) -> Result<FieldIter, StorageError> {
        self.as_ref().retrieve(key, scope)
    }

    fn retrieve_by_field(&self, field: Field, scope: Retrieve) -> FieldKeyResult {
        self.as_ref().retrieve_by_field(field, scope)
    }

    fn retrieve_by_fields(&self, field: Vec<Field>, scope: Retrieve) -> FieldKeyResult {
        self.as_ref().retrieve_by_fields(field, scope)
    }
}

/// Convenience trait to use a dispatcher and retriever implementation
pub trait Storage: Dispatcher + Retriever + Remover {
    /// Returns a reference to the retriever
    fn as_retriever(&self) -> &dyn Retriever;
    /// Returns a reference to the dispatcher
    fn as_dispatcher(&self) -> &dyn Dispatcher;

    /// Is called when the whole scan is finished.
    ///
    /// It has to remove all knowledge base items of that scan.
    fn scan_finished(&self, key: &ContextKey) -> Result<(), StorageError> {
        self.remove_kb(key, None)?;
        Ok(())
    }

    /// Is called to remove the whole scan and returns its results.
    ///
    /// It has to remove all kb items as well as results of that scan.
    fn remove_scan(&self, key: &ContextKey) -> Result<Vec<models::Result>, StorageError> {
        self.remove_kb(key, None)?;
        let results = self.remove_result(key, None)?;
        Ok(results.unwrap_or_default())
    }
}

impl<T> Storage for T
where
    T: Dispatcher + Retriever + Remover,
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
type Kbs = HashMap<ContextKey, HashMap<String, Vec<Kb>>>;

/// Vts are using a relative file path as a key. This should make includes, script_dependency
/// lookups relative simple.
pub type Vts = HashMap<String, item::Nvt>;

/// The results generated by log_, security_, error_message.
type Results = HashMap<String, Vec<models::Result>>;

/// Is a in-memory dispatcher that behaves like a Storage.
#[derive(Default, Debug)]
pub struct DefaultDispatcher {
    vts: Arc<RwLock<Vts>>,
    feed_version: Arc<RwLock<String>>,
    advisories: Arc<RwLock<HashSet<NotusAdvisory>>>,
    kbs: Arc<RwLock<Kbs>>,
    results: Arc<RwLock<Results>>,
}

impl DefaultDispatcher {
    /// Creates a new DefaultDispatcher
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }

    /// Stores an already existing Vts structure.
    pub fn set_vts(&self, vts: Vts) -> Result<(), StorageError> {
        let mut data = self.vts.as_ref().write()?;
        *data = vts;
        Ok(())
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

    fn cache_kb(&self, ck: ContextKey, kb: Kb) -> Result<(), StorageError> {
        let mut data = self.kbs.as_ref().write()?;
        if let Some(scan_entry) = data.get_mut(&ck) {
            if let Some(kb_entry) = scan_entry.get_mut(&kb.key) {
                if !kb_entry.iter().any(|x| x.value == kb.value) {
                    kb_entry.push(kb);
                };
            } else {
                scan_entry.insert(kb.key.clone(), vec![kb]);
            }
        } else {
            let mut scan_entry = HashMap::new();
            scan_entry.insert(kb.key.clone(), vec![kb]);
            data.insert(ck, scan_entry);
        }
        Ok(())
    }

    fn replace_kb(&self, ck: &ContextKey, kb: Kb) -> Result<(), StorageError> {
        let mut data = self.kbs.as_ref().write()?;
        if let Some(scan_entry) = data.get_mut(ck) {
            if let Some(kb_entry) = scan_entry.get_mut(&kb.key) {
                *kb_entry = vec![kb];
            } else {
                scan_entry.insert(kb.key.clone(), vec![kb]);
            }
        } else {
            let mut scan_entry = HashMap::new();
            scan_entry.insert(kb.key.clone(), vec![kb]);
            data.insert(ck.clone(), scan_entry);
        }
        Ok(())
    }

    fn cache_result(&self, scan_id: &str, result: models::Result) -> Result<(), StorageError> {
        let mut data = self.results.as_ref().write()?;
        if let Some(entry) = data.get_mut(scan_id) {
            entry.push(result)
        } else {
            data.insert(scan_id.to_string(), vec![result]);
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

    /// Removes all stored nasl_vts
    pub fn clean_vts(&self) -> Result<(), StorageError> {
        let mut vts = self.vts.write()?;
        vts.clear();
        let mut version = self.feed_version.write()?;
        *version = String::new();
        Ok(())
    }

    /// Removes all stored nasl_vts
    pub fn clean_advisories(&self) -> Result<(), StorageError> {
        let mut advisories = self.advisories.write()?;
        advisories.clear();
        Ok(())
    }
}

impl Remover for DefaultDispatcher {
    fn remove_kb(
        &self,
        key: &ContextKey,
        kb_key: Option<String>,
    ) -> Result<Option<Vec<Kb>>, StorageError> {
        let mut kbs = self.kbs.write().unwrap();
        Ok(match kb_key {
            None => kbs
                .remove(key)
                .map(|x| x.values().flat_map(|x| x.clone()).collect()),
            Some(x) => {
                if let Some(kbs) = kbs.get_mut(key) {
                    kbs.remove(&x)
                } else {
                    None
                }
            }
        })
    }

    fn remove_result(
        &self,
        key: &ContextKey,
        result_id: Option<usize>,
    ) -> Result<Option<Vec<models::Result>>, StorageError> {
        let mut results = self.results.write().unwrap();
        if let Some(idx) = result_id {
            if let Some(results) = results.get_mut(key.as_ref()) {
                if let Some(idx) = results.iter().position(|x| x.id == idx) {
                    return Ok(Some(vec![results.remove(idx)]));
                }
            }
            Ok(None)
        } else {
            Ok(results.remove(key.as_ref()))
        }
    }
}

impl Dispatcher for DefaultDispatcher {
    fn dispatch(&self, key: &ContextKey, scope: Field) -> Result<(), StorageError> {
        match scope {
            Field::NVT(x) => self.cache_nvt_field(key.as_ref(), x)?,
            Field::KB(x) => self.cache_kb(key.clone(), x)?,
            Field::NotusAdvisory(x) => {
                if let Some(x) = *x {
                    self.cache_notus_advisory(x)?
                }
            }
            Field::Result(x) => self.cache_result(key.as_ref(), *x)?,
        }
        Ok(())
    }

    fn dispatch_replace(&self, key: &ContextKey, scope: Field) -> Result<(), StorageError> {
        match scope {
            Field::NVT(x) => self.cache_nvt_field(key.as_ref(), x)?,
            Field::KB(x) => self.replace_kb(key, x)?,
            Field::NotusAdvisory(x) => {
                if let Some(x) = *x {
                    self.cache_notus_advisory(x)?
                }
            }
            Field::Result(x) => self.cache_result(key.as_ref(), *x)?,
        }
        Ok(())
    }

    fn on_exit(&self, _: &ContextKey) -> Result<(), StorageError> {
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
            Retrieve::KB(kb_id) => {
                let kbs = self.kbs.as_ref().read()?;
                // TODO: maybe return all when x is empty?
                if let Some(kbs) = kbs.get(key) {
                    if let Some(kbs) = kbs.get(&kb_id) {
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
            Retrieve::Result(None) => {
                let results = self.results.as_ref().read()?;
                let results = if let Some(x) = results.get(key.as_ref()) {
                    let mut y = Vec::with_capacity(x.len());
                    x.clone_into(&mut y);
                    y
                } else {
                    vec![]
                };
                Ok(Box::new(
                    results.into_iter().map(|x| Field::Result(x.into())),
                ))
            }
            Retrieve::Result(Some(id)) => {
                let results = self.results.as_ref().read()?;
                let results = if let Some(x) = results.get(key.as_ref()) {
                    let mut y = Vec::with_capacity(x.len());
                    x.clone_into(&mut y);
                    y
                } else {
                    vec![]
                };
                Ok(Box::new(
                    results
                        .into_iter()
                        .filter(move |x| x.id == id)
                        .map(|x| Field::Result(x.into())),
                ))
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
            Retrieve::Result(x) => {
                // are there use cases to get a KB outside of a scan?
                tracing::warn!(
                    result = x,
                    "trying to get results without scan_id returning empty result"
                );
                Ok(Box::new(vec![].into_iter()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::storage::item::NVTKey;

    use super::NVTField::*;
    use super::*;

    #[test]
    pub fn default_storage() -> Result<(), StorageError> {
        let storage = DefaultDispatcher::default();
        let key = ContextKey::FileName(String::new());
        use super::Field::*;
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
