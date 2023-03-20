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

pub trait Retriever<K> {
    fn retrieve(&self, key: &K, scope: &Retrieve) -> Result<Vec<Field>, StorageError>;
}
