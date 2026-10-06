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
#[error("Failed to load {path}. {kind}")]
pub struct LoadError {
    kind: LoadErrorKind,
    path: PathBuf,
}

/// Defines abstract Loader error cases
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum LoadErrorKind {
    #[error("Timed out.")]
    Timeout,
    #[error("Not found.")]
    NotFound,
    #[error("Permission denied")]
    PermissionDenied,
    #[error("Unknown error")]
    Unknown,
    #[error("Not a file.")]
    NotAFile,
}

impl LoadError {
    pub fn from_io(path: impl Into<PathBuf>, value: io::Error) -> Self {
        use LoadErrorKind::*;
        let kind = match value.kind() {
            io::ErrorKind::NotFound => NotFound,
            io::ErrorKind::PermissionDenied => PermissionDenied,
            io::ErrorKind::TimedOut | io::ErrorKind::Interrupted => Timeout,
            _ => Unknown,
        };
        Self {
            path: path.into(),
            kind,
        }
    }

    pub fn not_a_file(path: impl Into<PathBuf>) -> LoadError {
        Self {
            path: path.into(),
            kind: LoadErrorKind::NotAFile,
        }
    }

    pub fn not_found(path: impl Into<PathBuf>) -> LoadError {
        Self {
            path: path.into(),
            kind: LoadErrorKind::NotFound,
        }
    }
}

impl LoadError {
    pub fn kind(&self) -> &LoadErrorKind {
        &self.kind
    }

    pub fn path(&self) -> &Path {
        &self.path
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
        Err(err) => {
            // `InvalidData` means the file could be read but is not valid UTF-8
            // (some VTs are still stored as latin-1).
            if err.kind() == io::ErrorKind::InvalidData {
                tracing::warn!(
                    file = %path.as_ref().display(),
                    "File is not valid UTF-8; falling back to latin-1 decoding."
                );
            }
            read_non_utf8_path(path)
        }
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
        Err(err) => Err(LoadError::from_io(path.as_ref(), err)),
    }
}

/// This trait exists as an abstraction to support loading NASL files
/// from files (during normal operation) and from hardcoded strings
/// (in some tests).
trait NaslLoader: Sync + Send + NaslLoaderClone {
    fn load(&self, path: &Path) -> Result<String, LoadError>;

    /// Return the root plugins folder
    fn root_path(&self) -> &Path;

    fn as_bufreader(&self, path: &Path) -> Result<Box<dyn BufRead>, LoadError>;
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
            root: None,
        }
    }

    pub fn load(&self, file: impl AsRef<Path>) -> Result<String, LoadError> {
        let path = file.as_ref();
        self.loader.load(path)
    }

    pub fn root_path(&self) -> &Path {
        self.loader.root_path()
    }

    pub(crate) fn as_bufreader(
        &self,
        file: impl AsRef<Path>,
    ) -> Result<Box<dyn BufRead>, LoadError> {
        let path = file.as_ref();
        self.loader.as_bufreader(path)
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
    fn load(&self, filename: &Path) -> Result<String, LoadError> {
        let path = self.root.join(filename);
        if !path.is_file() {
            return Err(LoadError::not_a_file(path));
        }
        // unfortunately nasl is still in iso-8859-1
        read_utf8_or_non_utf8_path(path.as_path())
    }

    /// Return the root path of the plugins directory
    fn root_path(&self) -> &Path {
        &self.root
    }

    fn as_bufreader(&self, filename: &Path) -> Result<Box<dyn BufRead>, LoadError> {
        let path = self.root.join(filename);
        if !path.is_file() {
            return Err(LoadError::not_a_file(path));
        }
        match File::open(&path).map_err(|e| LoadError::from_io(path, e)) {
            Ok(file) => Ok(Box::new(io::BufReader::new(file))),
            Err(e) => Err(e),
        }
    }
}

#[derive(Clone)]
pub struct TestLoader {
    files: HashMap<PathBuf, String>,
    root: Option<PathBuf>,
}

impl NaslLoader for TestLoader {
    fn load(&self, path: &Path) -> Result<String, LoadError> {
        Ok(self
            .files
            .get(path)
            .ok_or_else(|| LoadError::not_found(path))?
            .clone())
    }

    fn root_path(&self) -> &Path {
        self.root.as_ref().unwrap()
    }

    fn as_bufreader(&self, _: &Path) -> Result<Box<dyn BufRead>, LoadError> {
        unimplemented!()
    }
}

impl TestLoader {
    pub fn build(self) -> Loader {
        Loader {
            loader: Box::new(self),
        }
    }

    pub fn with_file(mut self, file_name: &str, contents: String) -> Self {
        self.files.insert(file_name.into(), contents);
        self
    }

    #[cfg(test)]
    pub(crate) fn with_root(mut self, root: PathBuf) -> Self {
        self.root = Some(root);
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

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    #[test]
    fn reads_utf8_file_as_is() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all("script_name(\"Hütte\");".as_bytes())
            .unwrap();

        let content = read_utf8_or_non_utf8_path(file.path()).unwrap();

        assert_eq!(content, "script_name(\"Hütte\");");
    }

    #[test]
    fn reads_latin1_file_by_falling_back() {
        // 0xE9 is 'é' in latin-1 (ISO-8859-1) but not a valid UTF-8 byte on its
        // own, so `fs::read_to_string` fails and the latin-1 fallback is used.
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&[b'c', b'a', b'f', 0xE9]).unwrap();

        let content = read_utf8_or_non_utf8_path(file.path()).unwrap();

        // Every byte is mapped to its code point, so 0xE9 becomes 'é' and the
        // resulting string is valid UTF-8.
        assert_eq!(content, "café");
    }

    #[test]
    fn read_non_utf8_path_maps_every_byte_to_a_char() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&[0x41, 0xE9, 0xFF]).unwrap();

        let content = read_non_utf8_path(file.path()).unwrap();

        assert_eq!(content, "A\u{00E9}\u{00FF}");
    }

    #[test]
    fn read_utf8_or_non_utf8_path_reports_missing_file() {
        let result = read_utf8_or_non_utf8_path("does/not/exist.nasl");

        assert!(result.is_err());
    }
}
