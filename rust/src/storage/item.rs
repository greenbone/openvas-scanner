use std::sync::{Arc, Mutex};

use super::{
    dispatch::Dispatcher,
    error::StorageError,
    items::nvt::{FileName, Nvt, NvtField},
};

/// This type of Dispatcher caches NVT fields first and dispatches them as a NVTs,
/// when the dispatcher is out of scope
pub struct CacheDispatcher<S>
where
    S: Dispatcher<FileName, Item = Nvt>,
{
    nvt: Arc<Mutex<Nvt>>,
    storage: S,
}

impl<S> CacheDispatcher<S>
where
    S: Dispatcher<FileName, Item = Nvt>,
{
    /// Creates a new Cache Dispatcher without a feed_version and nvt.
    pub fn new(dispatcher: S) -> Self {
        Self {
            nvt: Arc::new(Mutex::new(Nvt::default())),
            storage: dispatcher,
        }
    }

    fn store_nvt_field(&self, f: NvtField) -> Result<(), StorageError> {
        let mut data = Arc::as_ref(&self.nvt)
            .lock()
            .map_err(|x| StorageError::Dirty(format!("{x}")))?;
        let mut nvt = data.clone();

        match f {
            NvtField::Oid(oid) => nvt.oid = oid,
            NvtField::FileName(s) => nvt.filename = s,

            NvtField::Name(s) => nvt.name = s,
            NvtField::Tag(key, name) => {
                nvt.tag.insert(key, name);
            }
            NvtField::Dependencies(s) => nvt.dependencies.extend(s),
            NvtField::RequiredKeys(s) => nvt.required_keys.extend(s),
            NvtField::MandatoryKeys(s) => nvt.mandatory_keys.extend(s),
            NvtField::ExcludedKeys(s) => nvt.excluded_keys.extend(s),
            NvtField::RequiredPorts(s) => nvt.required_ports.extend(s),
            NvtField::RequiredUdpPorts(s) => nvt.required_udp_ports.extend(s),
            NvtField::Preference(s) => nvt.preferences.push(s),
            NvtField::Reference(s) => nvt.references.extend(s),
            NvtField::Category(s) => nvt.category = s,
            NvtField::Family(s) => nvt.family = s,
        };
        *data = nvt;
        Ok(())
    }

    fn dispatch_nvt(&self) -> Result<(), StorageError> {
        let mut data = Arc::as_ref(&self.nvt)
            .lock()
            .map_err(|x| StorageError::Dirty(format!("{x}")))?;
        let nvt = data.clone();
        self.storage.dispatch(FileName(nvt.filename.clone()), nvt)?;
        *data = Nvt::default();
        Ok(())
    }
}
