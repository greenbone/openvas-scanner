use std::{
    collections::{HashMap, hash_map::Entry},
    path::{Path, PathBuf},
};

use scannerlib::nasl::{
    Code, SourceFile,
    syntax::{LoadError, ParseError, grammar::Ast},
};

pub(crate) struct CachedFile {
    pub file: SourceFile,
    pub ast: Result<Ast, Vec<ParseError>>,
}

#[derive(Default)]
pub(crate) struct Cache {
    files: HashMap<PathBuf, CachedFile>,
}

impl Cache {
    pub(crate) fn parse(
        &mut self,
        path: &Path,
        load: impl FnOnce() -> Result<Code, LoadError>,
    ) -> Result<&CachedFile, LoadError> {
        match self.files.entry(path.to_owned()) {
            Entry::Occupied(entry) => Ok(entry.into_mut()),
            Entry::Vacant(entry) => {
                let parsed = load()?.parse();
                Ok(entry.insert(CachedFile {
                    file: parsed.file().clone(),
                    ast: parsed.result(),
                }))
            }
        }
    }

    pub(crate) fn get(&self, path: &Path) -> &CachedFile {
        &self.files[path]
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
