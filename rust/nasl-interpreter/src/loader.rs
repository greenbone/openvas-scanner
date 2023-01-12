//! This crate is used to load NASL code based on a name.

use std::{path::Path, fs};

use crate::error::InterpretError;

/// Defines abstract Loader error cases
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LoadError {
    /// Informs the caller to retry the call
    Retry(String),
    /// The given key was not found
    NotFound(String),
    /// Not allowed to read data of key
    PermissionDenied(String),
    /// There is a deeper problem with the underlying DataBase
    Dirty(String),
}

impl From<LoadError> for InterpretError {
    fn from(le: LoadError) -> Self {
        InterpretError { reason: format!("{:?}", le) }
    }
}

/// Loader is used to load NASL scripts based on relative paths (e.g. "http_func.inc" )
pub trait Loader {
    /// Resolves the given key to nasl code
    fn load(&self, key: &str) -> Result<String, LoadError>;
}

#[derive(Default)]
pub struct NoOpLoader {}

/// Is a no operation loader for test purposes.
impl Loader for NoOpLoader {
    fn load(&self, _: &str) -> Result<String, LoadError> {
        Ok(String::default())
    }
}

/// Is a plugin loader based on a root dir.
///
/// When load is called with e.g. plugin_feed_info.inc than the FSPluginLoader
/// expands `plugin_feed_info.inc` with the given root path.
/// 
/// So when the root path is `/var/lib/openvas/plugins` than it will be extended to
/// `/var/lib/openvas/plugins/plugin_feed_info.inc`.
struct FSPluginLoader<'a> {
    root: &'a Path,
}

impl<'a> Loader for FSPluginLoader<'a> {
    fn load(&self, key: &str) -> Result<String, LoadError> {
        let path = self.root.join(key);
        if !path.is_file() {
            return Err(LoadError::NotFound(format!(
                "{} does not exist or is not accessable.",
                path.as_os_str().to_str().unwrap_or_default()
            )));
        }
        // unfortunately NASL is not UTF-8 so we need to map it manually
        let result= fs::read(path.clone()).map(|bs| bs.iter().map(|&b| b as char).collect());
        match result {
            Ok(result) => Ok(result),
            Err(err) => {
                let pstr = path.to_str().unwrap_or_default().to_string();
                match err.kind() {
                    std::io::ErrorKind::NotFound => Err(LoadError::NotFound(pstr)),
                    std::io::ErrorKind::PermissionDenied => Err(LoadError::PermissionDenied(pstr)),
                    std::io::ErrorKind::TimedOut => Err(LoadError::Retry(format!("{} timed out.", pstr))),
                    std::io::ErrorKind::Interrupted => Err(LoadError::Retry(format!("{} interrupted.", pstr))),
                    _ => Err(LoadError::Dirty(format!("{}: {:?}", pstr, err))),
                }
            }
        }
    }
}
