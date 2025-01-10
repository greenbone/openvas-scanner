// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! This crate is used to load NASL code based on a name.

use std::{
    fs::{self, File},
    io,
    path::{Path, PathBuf},
};

use thiserror::Error;

/// Defines abstract Loader error cases
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum LoadError {
    /// Informs the caller to retry the call
    #[error("There was a temporary issue while reading {0}.")]
    Retry(String),
    /// The given key was not found
    #[error("{0} not found.")]
    NotFound(String),
    /// Not allowed to read data of key
    #[error("Insufficient rights to read {0}.")]
    PermissionDenied(String),
    /// There is a deeper problem with the underlying DataBase
    #[error("Unexpected issue while trying to read {0}")]
    Dirty(String),
}

impl LoadError {
    pub fn filename(&self) -> &str {
        match self {
            LoadError::Retry(x) => x,
            LoadError::NotFound(x) => x,
            LoadError::PermissionDenied(x) => x,
            LoadError::Dirty(x) => x,
        }
    }
}

/// Loads the content of the path to String by parsing each byte to a character.
///
/// Unfortunately the feed is not completely written in utf8 enforcing us to parse the content
/// bytewise.
pub fn load_non_utf8_path<P>(path: &P) -> Result<String, LoadError>
where
    P: AsRef<Path> + ?Sized,
{
    let result = fs::read(path).map(|bs| bs.iter().map(|&b| b as char).collect());
    match result {
        Ok(result) => Ok(result),
        Err(err) => Err((path.as_ref().to_str().unwrap_or_default(), err).into()),
    }
}

/// Loader is used to load NASL scripts based on relative paths (e.g. "http_func.inc" )
pub trait Loader: Sync + Send {
    /// Resolves the given key to nasl code
    fn load(&self, key: &str) -> Result<String, LoadError>;
    /// Return the root plugins folder
    fn root_path(&self) -> Result<String, LoadError>;
}

/// Returns given key as BufReader
pub trait AsBufReader<P> {
    /// Returns given key as BufReader
    fn as_bufreader(&self, key: &str) -> Result<io::BufReader<P>, LoadError>;
}

#[derive(Default)]
/// NoOpLoader is a loader for test purposes.
pub struct NoOpLoader {}

/// Is a no operation loader for test purposes.
impl Loader for NoOpLoader {
    fn load(&self, _: &str) -> Result<String, LoadError> {
        Ok(String::default())
    }
    fn root_path(&self) -> Result<String, LoadError> {
        Ok(String::default())
    }
}

impl Default for Box<dyn Loader> {
    fn default() -> Self {
        Box::<NoOpLoader>::default()
    }
}

/// Is a plugin loader based on a root dir.
///
/// When load is called with e.g. plugin_feed_info.inc than the FSPluginLoader
/// expands `plugin_feed_info.inc` with the given root path.
///
/// So when the root path is `/var/lib/openvas/plugins` than it will be extended to
/// `/var/lib/openvas/plugins/plugin_feed_info.inc`.
#[derive(Debug, Clone)]
pub struct FSPluginLoader {
    root: PathBuf,
}

impl From<(&Path, std::io::Error)> for LoadError {
    fn from(value: (&Path, std::io::Error)) -> Self {
        let (pstr, value) = value;
        (pstr.to_str().unwrap_or_default(), value).into()
    }
}

impl From<(&str, std::io::Error)> for LoadError {
    fn from(value: (&str, std::io::Error)) -> Self {
        let (pstr, value) = value;
        match value.kind() {
            std::io::ErrorKind::NotFound => LoadError::NotFound(pstr.to_owned()),
            std::io::ErrorKind::PermissionDenied => LoadError::PermissionDenied(pstr.to_owned()),
            std::io::ErrorKind::TimedOut => LoadError::Retry(format!("{} timed out.", pstr)),
            std::io::ErrorKind::Interrupted => LoadError::Retry(format!("{} interrupted.", pstr)),
            _ => LoadError::Dirty(format!("{}: {:?}", pstr, value)),
        }
    }
}

impl FSPluginLoader {
    /// Creates a new file system plugin loader based on the given root path
    pub fn new<P>(root: P) -> Self
    where
        P: AsRef<Path>,
    {
        Self {
            root: root.as_ref().to_owned(),
        }
    }

    /// Returns the used path
    pub fn root(&self) -> &Path {
        self.root.as_ref()
    }
}

impl AsBufReader<File> for FSPluginLoader {
    fn as_bufreader(&self, key: &str) -> Result<io::BufReader<File>, LoadError> {
        let path = self.root.join(key);
        match File::open(path).map_err(|e| LoadError::from((key, e))) {
            Ok(file) => Ok(io::BufReader::new(file)),
            Err(e) => Err(e),
        }
    }
}

impl Loader for FSPluginLoader {
    fn load(&self, key: &str) -> Result<String, LoadError> {
        let path = self.root.join(key);
        if !path.is_file() {
            return Err(LoadError::NotFound(format!(
                "{} does not exist or is not accessible.",
                path.as_os_str().to_str().unwrap_or_default()
            )));
        }
        // unfortunately nasl is still in iso-8859-1
        load_non_utf8_path(path.as_path())
    }
    /// Return the root path of the plugins directory
    fn root_path(&self) -> Result<String, LoadError> {
        let path = self.root.to_str().unwrap_or_default().to_string();
        Ok(path)
    }
}

impl<S> Loader for S
where
    S: Fn(&str) -> String + Sync + Send,
{
    fn load(&self, key: &str) -> Result<String, LoadError> {
        Ok((self)(key))
    }

    fn root_path(&self) -> Result<String, LoadError> {
        Ok(String::default())
    }
}
