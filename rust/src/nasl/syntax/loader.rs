// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! This crate is used to load NASL code based on a name.

use std::{
    collections::HashMap,
    fs::{self, File},
    io::{self, BufRead},
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

impl From<(&str, std::io::Error)> for LoadError {
    fn from(value: (&str, std::io::Error)) -> Self {
        let (pstr, value) = value;
        match value.kind() {
            std::io::ErrorKind::NotFound => LoadError::NotFound(pstr.to_owned()),
            std::io::ErrorKind::PermissionDenied => LoadError::PermissionDenied(pstr.to_owned()),
            std::io::ErrorKind::TimedOut => LoadError::Retry(format!("{pstr} timed out.")),
            std::io::ErrorKind::Interrupted => LoadError::Retry(format!("{pstr} interrupted.")),
            _ => LoadError::Dirty(format!("{pstr}: {value:?}")),
        }
    }
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

/// Reads the content of the file at `Path` to a String.
///
/// First attempts to read the file to UTF8 and then falls
/// back to non-UTF8 if that did not succeed.
fn read_utf8_or_non_utf8_path<P>(path: &P) -> Result<String, LoadError>
where
    P: AsRef<Path> + ?Sized,
{
    match fs::read_to_string(path) {
        Ok(x) => Ok(x),
        Err(_) => read_non_utf8_path(path),
    }
}

/// Loads the content of the path to String by parsing each byte to a character.
///
/// This is done since the feed is not completely written in UTF8, forcing us to parse
/// the content of some files bytewise.
pub fn read_non_utf8_path<P>(path: &P) -> Result<String, LoadError>
where
    P: AsRef<Path> + ?Sized,
{
    let result = fs::read(path).map(|bs| bs.iter().map(|&b| b as char).collect());
    match result {
        Ok(result) => Ok(result),
        Err(err) => Err((path.as_ref().to_str().unwrap_or_default(), err).into()),
    }
}

/// This trait exists as an abstraction to support loading NASL files
/// from files (during normal operation) and from hardcoded strings
/// (in some tests).
trait NaslLoader: Sync + Send + NaslLoaderClone {
    /// Resolves the given filename to NASL code
    fn load(&self, filename: &str) -> Result<String, LoadError>;

    /// Return the root plugins folder
    fn root_path(&self) -> &Path;

    fn as_bufreader(&self, filename: &str) -> Result<Box<dyn BufRead>, LoadError>;
}

#[derive(Clone)]
pub struct Loader {
    loader: Box<dyn NaslLoader>,
}

impl Loader {
    /// Create a new loader that loads files from the file system
    /// relative to the given feed path.
    pub fn from_feed_path(path: impl AsRef<Path>) -> Self {
        Self {
            loader: Box::new({
                FileSystemLoader {
                    root: path.as_ref().to_owned(),
                }
            }),
        }
    }

    /// Create an empty loader that returns a `LoadError::NotFound`
    /// for any given filename.
    pub fn test_empty() -> Self {
        Self::test().build()
    }

    /// Create a test loader. Test files can be added with the
    /// `.with_file` method and the result turned into a `Loader`
    /// with `.build()`.
    ///
    /// Example:
    ///
    /// ```
    /// # use scannerlib::nasl::Loader;
    /// Loader::test()
    ///     .with_file("foo.nasl", "display('hello world')".into())
    ///     .build();
    /// ```
    pub fn test() -> TestLoader {
        TestLoader {
            files: HashMap::new(),
        }
    }

    pub fn load(&self, filename: &str) -> Result<String, LoadError> {
        self.loader.load(filename)
    }

    pub fn root_path(&self) -> &Path {
        self.loader.root_path()
    }

    pub(crate) fn as_bufreader(&self, filename: &str) -> Result<Box<dyn BufRead>, LoadError> {
        self.loader.as_bufreader(filename)
    }
}

/// Loads files from the file system using paths relative to a root
/// directory.
///
/// This loader tries to load files in UTF8 first and then falls back
/// to non-UTF8 mode on failure.
#[derive(Debug, Clone)]
struct FileSystemLoader {
    root: PathBuf,
}

impl NaslLoader for FileSystemLoader {
    fn load(&self, filename: &str) -> Result<String, LoadError> {
        let path = self.root.join(filename);
        if !path.is_file() {
            return Err(LoadError::NotFound(format!(
                "{} does not exist or is not accessible.",
                path.as_os_str().to_str().unwrap_or_default()
            )));
        }
        // unfortunately nasl is still in iso-8859-1
        read_utf8_or_non_utf8_path(path.as_path())
    }

    /// Return the root path of the plugins directory
    fn root_path(&self) -> &Path {
        &self.root
    }

    fn as_bufreader(&self, filename: &str) -> Result<Box<dyn BufRead>, LoadError> {
        let path = self.root.join(filename);
        match File::open(path).map_err(|e| LoadError::from((filename, e))) {
            Ok(file) => Ok(Box::new(io::BufReader::new(file))),
            Err(e) => Err(e),
        }
    }
}

#[derive(Clone)]
pub struct TestLoader {
    files: HashMap<String, String>,
}

impl NaslLoader for TestLoader {
    fn load(&self, filename: &str) -> Result<String, LoadError> {
        Ok(self
            .files
            .get(filename)
            .ok_or_else(|| LoadError::NotFound(filename.into()))?
            .clone())
    }

    fn root_path(&self) -> &Path {
        todo!()
    }

    fn as_bufreader(&self, _: &str) -> Result<Box<dyn BufRead>, LoadError> {
        todo!()
    }
}

impl TestLoader {
    pub fn build(self) -> Loader {
        Loader {
            loader: Box::new(self),
        }
    }

    pub fn insert(&mut self, format: String, script: String) {
        self.files.insert(format, script);
    }

    pub fn with_file(mut self, file_name: &str, contents: String) -> Self {
        self.files.insert(file_name.into(), contents);
        self
    }
}

/// This trait exists only to make `Box<dyn Loader>` a cloneable object
/// and can be ignored otherwise.
/// This trick is necessary to circumvent `dyn` objects not being
/// able to implement `Clone` directly, since it is not a dyn-compatible trait.
trait NaslLoaderClone {
    fn clone_box(&self) -> Box<dyn NaslLoader>;
}

impl<T> NaslLoaderClone for T
where
    T: NaslLoader + Clone + 'static,
{
    fn clone_box(&self) -> Box<dyn NaslLoader> {
        Box::new(self.clone())
    }
}

impl Clone for Box<dyn NaslLoader> {
    fn clone(&self) -> Box<dyn NaslLoader> {
        (*self).clone_box()
    }
}
