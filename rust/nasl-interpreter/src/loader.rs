//! This crate is used to load NASL code based on a name.

use std::{fmt::Display, fs, path::Path};

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

impl Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::Retry(p) => write!(f, "There was a temporary issue while reading {}.", p),
            LoadError::NotFound(p) => write!(f, "{} not found.", p),
            LoadError::PermissionDenied(p) => write!(f, "Insufficient rights to read {}", p),
            LoadError::Dirty(p) => write!(f, "Unexpected issue while trying to read {}", p),
        }
    }
}

impl From<LoadError> for InterpretError {
    fn from(le: LoadError) -> Self {
        let reason = format!("Error while loading a file: {}", le);
        Self::new(reason)
    }
}

/// Loader is used to load NASL scripts based on relative paths (e.g. "http_func.inc" )
pub trait Loader {
    /// Resolves the given key to nasl code
    fn load(&self, key: &str) -> Result<String, LoadError>;
}

#[derive(Default)]
pub(crate) struct NoOpLoader {}

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
pub struct FSPluginLoader<'a> {
    root: &'a Path,
}

impl<'a> FSPluginLoader<'a> {
    /// Creates a new file system plugin loader based on the given root path
    pub fn new(root: &'a Path) -> Self {
        Self { root }
    }
}

impl<'a> Loader for FSPluginLoader<'a> {
    fn load(&self, key: &str) -> Result<String, LoadError> {
        let path = self.root.join(key);
        if !path.is_file() {
            return Err(LoadError::NotFound(format!(
                "{} does not exist or is not accessible.",
                path.as_os_str().to_str().unwrap_or_default()
            )));
        }
        // unfortunately NASL is not UTF-8 so we need to map it manually
        let result = fs::read(path.clone()).map(|bs| bs.iter().map(|&b| b as char).collect());
        match result {
            Ok(result) => Ok(result),
            Err(err) => {
                let pstr = path.to_str().unwrap_or_default().to_string();
                match err.kind() {
                    std::io::ErrorKind::NotFound => Err(LoadError::NotFound(pstr)),
                    std::io::ErrorKind::PermissionDenied => Err(LoadError::PermissionDenied(pstr)),
                    std::io::ErrorKind::TimedOut => {
                        Err(LoadError::Retry(format!("{} timed out.", pstr)))
                    }
                    std::io::ErrorKind::Interrupted => {
                        Err(LoadError::Retry(format!("{} interrupted.", pstr)))
                    }
                    _ => Err(LoadError::Dirty(format!("{}: {:?}", pstr, err))),
                }
            }
        }
    }
}
