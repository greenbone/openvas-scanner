//#![warn(missing_docs)]
//! NASL Sink defines technology indepdent sink traits, structs ..{w;

pub mod nvt; 
use std::{
    sync::{Arc, Mutex},
};

use nvt::{NVTField, NVTKey};


/// Dispatch command for a given Field
///
/// Defines what kind of information needs to be distributed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Dispatch {
    /// Metadata of the NASL script.
    NVT(NVTField),
}

/// Retrieve command for a given Field
///
/// Defines what kind of information needs to be gathered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Retrieve {
    /// Metadata of the NASL script.
    NVT(Option<NVTKey>),
}

/// TBD errors
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SinkError {}

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
    fn dispatch(&self, key: &str, scope: Dispatch) -> Result<(), SinkError>;
    /// Get scopes found by key
    ///
    /// A key is usually a OID that was given when starting a script but in description run it is the filename.
    fn retrieve(&self, key: &str, scope: Retrieve) -> Result<Vec<Dispatch>, SinkError>;

    /// On exit is called when a script exit
    ///
    /// Some database require a cleanup therefore this method is called when a script finishes.
    fn on_exit(&self) -> Result<(), SinkError>;
}

/// Contains a Vector of all stored items.
///
/// The first String statement is the used key while the Vector of Scope are the values.
type StoreItem = Vec<(String, Vec<Dispatch>)>;

/// Is a inmemory sink that behaves like a Storage.
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

    fn retrieve(&self, key: &str, _scope: Retrieve) -> Result<Vec<Dispatch>, SinkError> {
        let data = Arc::as_ref(&self.data).lock().unwrap();

        match data.iter().find(|(k, _)| k.as_str() == key) {
            Some((_, v)) => Ok(v.clone()),
            None => Ok(vec![]),
        }
    }

    fn on_exit(&self) -> Result<(), SinkError> {
        if !self.dirty {
            self.cleanse();
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::Dispatch::*;
    use super::NVTField::*;


    #[test]
    pub fn default_storage() -> Result<(), SinkError> {
        let storage = DefaultSink::default();
        storage.dispatch("moep", NVT(Oid("moep".to_owned())))?;
        assert_eq!(
            storage.retrieve("moep", Retrieve::NVT(None))?,
            vec![NVT(Oid("moep".to_owned()))]
        );
        Ok(())
    }
}
