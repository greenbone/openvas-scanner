use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use scannerlib::nasl::{SourceFile, syntax::grammar::Ast};

use super::calls::FileCalls;

pub(crate) struct CachedFile {
    pub file: SourceFile,
    pub ast: Ast,
    pub includes: Vec<PathBuf>,
    pub calls: FileCalls,
}

#[derive(Default)]
pub(crate) struct Cache {
    files: HashMap<PathBuf, CachedFile>,
}

impl Cache {
    pub(crate) fn insert(&mut self, path: PathBuf, file: CachedFile) {
        self.files.insert(path, file);
    }

    pub(crate) fn get(&self, path: &Path) -> &CachedFile {
        &self.files[path]
    }

    pub(crate) fn paths(&self) -> Vec<PathBuf> {
        let mut paths: Vec<_> = self.files.keys().cloned().collect();
        paths.sort();
        paths
    }
}
