use std::{
    fmt,
    path::{Path, PathBuf},
};

/// Path text exactly as written in an `include(...)` statement.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct IncludePath(String);

impl IncludePath {
    pub(crate) fn new(path: impl Into<String>) -> Self {
        Self(path.into())
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// Loader path and cache identity of a file after include-path resolution.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct ResolvedPath(PathBuf);

impl ResolvedPath {
    pub(crate) fn new(path: impl Into<PathBuf>) -> Self {
        Self(path.into())
    }

    pub(crate) fn as_path(&self) -> &Path {
        &self.0
    }
}

impl fmt::Display for ResolvedPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.display().fmt(formatter)
    }
}
