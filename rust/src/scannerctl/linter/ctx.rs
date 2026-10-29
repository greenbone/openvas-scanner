use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use scannerlib::nasl::{SourceFile, syntax::grammar::Ast};

pub(crate) struct CachedFile {
    pub file: SourceFile,
    pub ast: Ast,
    pub includes: Vec<PathBuf>,
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

pub(crate) struct LintCtx<'a> {
    pub ast: &'a Ast,
    pub includes: Vec<&'a Ast>,
}

impl<'a> LintCtx<'a> {
    pub fn new(ast: &'a Ast, includes: Vec<&'a Ast>) -> Self {
        Self { ast, includes }
    }
}
