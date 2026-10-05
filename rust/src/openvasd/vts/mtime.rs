use std::fs;
use std::path::Path;
use std::time::UNIX_EPOCH;

/// Error returned by [`SqlPluginStorage::check_mtime`].
#[derive(Debug, thiserror::Error)]
pub enum MtimeCheckError {
    /// No hashsum/mtime has been recorded for the given file (e.g. signature checking was
    /// disabled during the feed sync, or the file is not part of the feed at all).
    #[error("No stored mtime for file {0}")]
    NotFound(String),
    /// The file's on-disk mtime is newer than the mtime recorded when its hashsum was last
    /// verified, meaning it was modified since and can no longer be considered verified.
    #[error(
        "File {file} was modified since its hashsum was last verified (stored mtime {stored}, current mtime {current})"
    )]
    Modified {
        file: String,
        stored: u64,
        current: u64,
    },
    /// The file's metadata could not be read from disk.
    #[error("Could not read metadata of file {0}: {1}")]
    Io(String, String),
}

/// Computes the mtime (seconds since epoch) of a `.nasl`/`.inc` file within a feed directory.
///
/// This is used, analogous to the redis storage, to cache that a file has already been
/// verified so that a complete signature check is not required on every single load. If
/// `hashsum` is empty (e.g. signature checking is disabled or the verification failed) there
/// is nothing worth caching and an empty string is returned instead.
pub(crate) fn compute_mtime(
    feed_path: &Path,
    filename: &str,
    hashsum: Option<&str>,
) -> Result<u64, MtimeCheckError> {
    if let Some(hashsum) = hashsum
        && hashsum.is_empty()
    {
        return Ok(0);
    }

    let mut file = feed_path.to_path_buf();
    file.push(filename);
    Ok(fs::metadata(&file)
        .and_then(|m| m.modified())
        .map_err(|e| MtimeCheckError::Io(filename.to_string(), e.to_string()))?
        .duration_since(UNIX_EPOCH)
        .map_err(|e| MtimeCheckError::Io(filename.to_string(), e.to_string()))?
        .as_secs())
}
