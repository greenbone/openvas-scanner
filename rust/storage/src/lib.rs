// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#![doc = include_str!("../README.md")]
#![warn(missing_docs)]

pub mod item;
mod retrieve;
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
    NotusAdvisory(Option<NotusAdvisory>),
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
impl From<models::VulnerabilityData> for Field {
    fn from(value: models::VulnerabilityData) -> Self {
        Self::NotusAdvisory(Some(value))
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
        panic!("Unable to recover from a PoisonError: {}", value);
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

/// A WildcardKey are Keys that can contain a * as wildcard for ignoring parts of it.
pub type KbKey = String;

/// Convenience trait to use a dispatcher and retriever implementation
pub trait Storage {
    /// Caches field of a VT until it is finished.
    ///
    /// This is required for feed#updates. On a description run within a feed NASL scripts are
    /// executed within if(descriptiom) block that calls the functions defined in
    /// nasl-builtin-description. When a script is finished then description_script_run_finished
    /// must be called so that the storage can create a item::Nvt from those fields and store them.
    fn cache_nvt_field(&self, filename: &str, field: NVTField) -> Result<(), StorageError>;

    /// Creates item::Nvt out of the the cached NVTFields.
    ///
    /// This function must be called after each executed script when updating the feed.
    fn description_script_finished(&self) -> Result<(), StorageError>;

    /// Stores a VT.
    ///
    /// This function stores a given item::NVT. item::Nvt contains so called meta-information about
    /// a NASL script.
    fn store_vt(&self, vt: item::Nvt) -> Result<(), StorageError>;

    /// Returns an iterator over fields that match at least one given NVTField
    fn vts_by_fields(
        &self,
        keys: Vec<NVTField>,
    ) -> Result<impl Iterator<Item = item::Nvt>, StorageError>;

    /// Returns an iterator over all item::Nvt and converted NotusAdvisory
    fn all_vts(&self) -> Result<impl Iterator<Item = item::Nvt>, StorageError>;

    /// Stores a notus advisory
    ///
    /// Notus advisories are parsed from the notus data and should be handled like item::Nvt,
    /// however there are cases when they are different. As an example a NotusAdvisory will never
    /// be inserted as a `script_dependeny` while item::Nvt from a NASL script can be.
    fn store_notus_advisory(&self, advistory: NotusAdvisory) -> Result<(), StorageError>;

    /// Stores kb.
    ///
    /// A knowledge base item or kb are shared information between script runs that are valid as
    /// long as a scan is running.
    ///
    /// A typical value for kb are open ports. Keep in mind that multiple KB with the same key can
    /// exist.
    fn store_kb(&self, scan_id: &str, kb: Kb) -> Result<(), StorageError>;

    /// Gets a KB within a scan that contains or matches given kb_key.
    fn get_kb(&self, scan_id: &str, key: &KbKey) -> Result<impl Iterator<Item = Kb>, StorageError>;

    /// Verifies if one or more kbs exists for the given key
    fn has_kb(&self, scan_id: &str, key: &KbKey) -> Result<bool, StorageError>;

    /// Must be called when a scan is finished so that kb items can be cleaned up
    fn scan_finished(&self, scan_id: &str) -> Result<(), StorageError>;
}

/// Is a in-memory dispatcher that behaves like a Storage.
#[derive(Clone, Default, Debug)]
pub struct DefaultDispatcher {
    /// The data storage
    ///
    /// The memory access is managed via an Arc while the Mutex ensures that only one consumer at a time is accessing it.
    nvts: Arc<RwLock<HashMap<String, item::Nvt>>>,
    feed_version: Arc<RwLock<String>>,
    kb: Arc<RwLock<HashMap<String, HashMap<String, Vec<Kb>>>>>,
    advisories: Arc<RwLock<HashSet<item::Nvt>>>,
}

impl DefaultDispatcher {
    /// Creates a new DefaultDispatcher
    pub fn new(_dirty: bool) -> Self {
        Self {
            ..Default::default()
        }
    }

    /// Cleanses stored data.
    pub fn cleanse(&self) -> Result<(), StorageError> {
        Ok(())
    }
}

impl Storage for DefaultDispatcher {
    fn cache_nvt_field(&self, filename: &str, field: NVTField) -> Result<(), StorageError> {
        let mut data = self.nvts.as_ref().write()?;
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
                nvt.filename = filename.to_string();
                data.insert(filename.to_string(), nvt);
            }
        }
        Ok(())
    }

    fn description_script_finished(&self) -> Result<(), StorageError> {
        // we store the version immediately
        Ok(())
    }

    fn store_vt(&self, vt: item::Nvt) -> Result<(), StorageError> {
        let mut data = self.nvts.as_ref().write()?;
        if let Some(ovt) = data.get_mut(&vt.filename) {
            *ovt = vt;
        } else {
            data.insert(vt.filename.clone(), vt);
        }
        Ok(())
    }

    fn vts_by_fields(
        &self,
        keys: Vec<NVTField>,
    ) -> Result<impl Iterator<Item = item::Nvt>, StorageError> {
        let vts = self.nvts.read()?;
        Ok(vts
            .clone()
            .into_iter()
            .filter(move |(_, x)| x.matches_any_field(&keys))
            .map(|(_, x)| x))
    }

    fn all_vts(&self) -> Result<impl Iterator<Item = item::Nvt>, StorageError> {
        let vts = self.nvts.read()?.clone();
        let notus = self.advisories.read()?.clone();
        Ok(vts.into_iter().map(|(_, x)| x).chain(notus.into_iter()))
    }

    fn store_notus_advisory(&self, advistory: NotusAdvisory) -> Result<(), StorageError> {
        let mut data = self.advisories.as_ref().write()?;
        data.insert(advistory.into());
        Ok(())
    }

    fn store_kb(&self, scan_id: &str, kb: Kb) -> Result<(), StorageError> {
        let mut data = self.kb.as_ref().write()?;
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

    fn get_kb(&self, scan_id: &str, key: &KbKey) -> Result<impl Iterator<Item = Kb>, StorageError> {
        let data = self.kb.as_ref().read()?;
        if let Some(scan_entry) = data.get(scan_id) {
            if let Some(kb_entry) = scan_entry.get(key) {
                return Ok(kb_entry.clone().into_iter());
            }
        }
        // TODO: maybe Err(NotFound would be better
        Ok(vec![].into_iter())
    }

    fn has_kb(&self, scan_id: &str, key: &KbKey) -> Result<bool, StorageError> {
        let data = self.kb.as_ref().read()?;
        if let Some(scan_entry) = data.get(scan_id) {
            Ok(scan_entry.contains_key(key))
        } else {
            Ok(false)
        }
    }

    fn scan_finished(&self, scan_id: &str) -> Result<(), StorageError> {
        let mut data = self.kb.as_ref().write()?;
        data.remove(scan_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn vts() -> Result<(), StorageError> {
        let storage = DefaultDispatcher::default();
        storage.cache_nvt_field("test", NVTField::Oid("12".into()))?;
        storage.store_vt(item::Nvt::default())?;
        storage.store_notus_advisory(NotusAdvisory {
            filename: "test2".into(),
            ..Default::default()
        })?;

        assert_eq!(3, storage.all_vts()?.count());

        Ok(())
    }
}
