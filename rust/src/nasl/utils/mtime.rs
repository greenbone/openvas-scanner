use async_trait::async_trait;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::UNIX_EPOCH;

/// Error returned by [`SqlPluginStorage::check_mtime`].
#[derive(Debug, thiserror::Error)]
pub enum MtimeCheckError {
    /// No hashsum/mtime has been recorded for the given file (e.g. signature checking was
    /// disabled during the feed sync, or the file is not part of the feed at all).
    #[error("No stored mtime for file {0}")]
    NotFound(String),
    /// The file's metadata could not be read from disk.
    #[error("Could not read metadata of file {0}: {1}")]
    Io(String, String),
}

/// Mtime return type. UpToDate is also expected when the signature check is disabled.
pub enum MtimeStatus {
    UpToDate,
    Modified {
        file: String,
        stored: i64,
        current: i64,
    },
}

/// Computes the mtime (seconds since epoch) of a `.nasl`/`.inc` file within a feed directory.
///
/// This is used, analogous to the redis storage, to cache that a file has already been
/// verified so that a complete signature check is not required on every single load. If
/// `hashsum` is empty (e.g. signature checking is disabled or the verification failed) there
/// is nothing worth caching and an empty string is returned instead.
pub fn compute_mtime(filename: &PathBuf, hashsum: Option<&str>) -> Result<i64, MtimeCheckError> {
    if let Some(hashsum) = hashsum
        && hashsum.is_empty()
    {
        return Ok(0);
    }

    Ok(fs::metadata(filename)
        .and_then(|m| m.modified())
        .map_err(|e| MtimeCheckError::Io(filename.clone().into_string().unwrap(), e.to_string()))?
        .duration_since(UNIX_EPOCH)
        .map_err(|e| MtimeCheckError::Io(filename.clone().into_string().unwrap(), e.to_string()))?
        .as_secs() as i64) // safe to convert UNIX_EPOCH duration to i64
}

#[async_trait]
pub trait MtimeCheck: Sync + Send {
    /// Checks whether vt script file mtime is newer than the mtime recorded in the storage
    /// It doesn't apply for redis storage.
    async fn check_mtime(&self, _filename: &Path) -> Result<MtimeStatus, String>;
}

#[async_trait]
impl<T: MtimeCheck> MtimeCheck for Arc<T> {
    async fn check_mtime(&self, filename: &Path) -> Result<MtimeStatus, String> {
        (**self).check_mtime(filename).await
    }
}
