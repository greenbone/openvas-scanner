use std::{
    collections::HashMap,
    fmt,
    ops::{Deref, Range},
    path::{Path, PathBuf},
    sync::{OnceLock, RwLockReadGuard},
};

use codespan_reporting::files::{Error, Files, SimpleFile};

use super::{
    Loader,
    error::{IntoDiagnostic, emit_errors},
    syntax::{DescriptionBlock, LoadError, ParseError, Parser, Tokenizer, grammar::Ast},
};

/// Identifies a NASL source within a loader's source registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FileId(usize);

/// A borrowed file handle. It holds no registry lock and owns no source data.
#[derive(Clone, Copy)]
pub struct NaslFile<'a> {
    id: FileId,
    loader: &'a Loader,
}

impl<'a> NaslFile<'a> {
    pub(crate) fn new(id: FileId, loader: &'a Loader) -> Self {
        Self { id, loader }
    }

    pub fn id(&self) -> FileId {
        self.id
    }

    /// Borrow the source record. Release this view before loading more NASL sources.
    pub fn source(&self) -> SourceFileRef<'a> {
        SourceFileRef {
            sources: self.loader.source_files(),
            id: self.id,
        }
    }

    pub fn parse(&self) -> ParseResult<'a> {
        ParseResult {
            result: self.source().parse().clone(),
            file: *self,
        }
    }

    pub(crate) fn parse_description_block(&self) -> ParseResult<'a> {
        ParseResult {
            result: self.source().parse_description_block().clone(),
            file: *self,
        }
    }

    pub fn emit_errors<T: IntoDiagnostic>(&self, errors: impl Iterator<Item = T>) {
        emit_errors(&self.source(), errors);
    }
}

impl fmt::Debug for NaslFile<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("NaslFile").field(&self.id).finish()
    }
}

/// An owned parse outcome paired with its registered source handle.
pub struct ParseResult<'a> {
    result: Result<Ast, Vec<ParseError>>,
    file: NaslFile<'a>,
}

impl<'a> ParseResult<'a> {
    pub fn result(self) -> Result<Ast, Vec<ParseError>> {
        self.result
    }

    pub fn file(&self) -> &NaslFile<'a> {
        &self.file
    }

    pub fn emit_errors(self) -> Result<Ast, Vec<ParseError>> {
        let file = self.file;
        self.result
            .inspect_err(|errors| file.emit_errors(errors.iter().cloned()))
    }
}

/// A source record borrowed under the registry's read lock.
pub struct SourceFileRef<'a> {
    sources: RwLockReadGuard<'a, SourceFiles>,
    id: FileId,
}

impl Deref for SourceFileRef<'_> {
    type Target = SourceFile;

    fn deref(&self) -> &SourceFile {
        self.sources.get(self.id).unwrap()
    }
}

/// Source text, diagnostic line information, and lazily cached parse results.
#[derive(Clone, Debug)]
pub struct SourceFile {
    path: PathBuf,
    file: SimpleFile<String, String>,
    parsed: OnceLock<Result<Ast, Vec<ParseError>>>,
    description: OnceLock<Result<Ast, Vec<ParseError>>>,
}

impl SourceFile {
    pub fn new(path: impl Into<PathBuf>, contents: String) -> Self {
        let path = path.into();
        Self {
            file: SimpleFile::new(path.to_string_lossy().into_owned(), contents),
            path,
            parsed: OnceLock::new(),
            description: OnceLock::new(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn name(&self) -> &String {
        self.file.name()
    }

    pub fn source(&self) -> &String {
        self.file.source()
    }

    pub fn parse(&self) -> &Result<Ast, Vec<ParseError>> {
        self.parsed
            .get_or_init(|| Parser::new(Tokenizer::tokenize(self.source())).parse_program())
    }

    pub(crate) fn parse_description_block(&self) -> &Result<Ast, Vec<ParseError>> {
        self.description.get_or_init(|| {
            let mut parser = Parser::new(Tokenizer::tokenize(self.source()));
            parser
                .parse_span::<DescriptionBlock>()
                .map(DescriptionBlock::into_ast)
                .map_err(|error| vec![error.unwrap_as_spanned()])
        })
    }
}

impl AsRef<str> for SourceFile {
    fn as_ref(&self) -> &str {
        self.source()
    }
}

impl<'a> Files<'a> for SourceFile {
    type FileId = ();
    type Name = &'a str;
    type Source = &'a str;

    fn name(&'a self, (): ()) -> Result<Self::Name, Error> {
        Ok(self.name())
    }

    fn source(&'a self, (): ()) -> Result<Self::Source, Error> {
        Ok(self.source())
    }

    fn line_index(&self, (): (), byte_index: usize) -> Result<usize, Error> {
        self.file.line_index((), byte_index)
    }

    fn line_range(&self, (): (), line_index: usize) -> Result<Range<usize>, Error> {
        self.file.line_range((), line_index)
    }
}

/// An append-only NASL source registry that also backs multi-file diagnostics.
/// IDs identify logical loader paths, not canonical filesystem paths.
#[derive(Debug, Default)]
pub struct SourceFiles {
    paths: HashMap<PathBuf, FileId>,
    files: Vec<SourceFile>,
}

impl SourceFiles {
    pub fn get(&self, id: FileId) -> Result<&SourceFile, Error> {
        self.files.get(id.0).ok_or(Error::FileMissing)
    }

    pub(crate) fn id(&self, path: &Path) -> Option<FileId> {
        self.paths.get(path).copied()
    }

    pub(crate) fn get_or_load(
        &mut self,
        path: &Path,
        load: impl FnOnce() -> Result<String, LoadError>,
    ) -> Result<FileId, LoadError> {
        if let Some(id) = self.id(path) {
            return Ok(id);
        }
        let source = SourceFile::new(path, load()?);
        let id = FileId(self.files.len());
        self.files.push(source);
        self.paths.insert(path.to_owned(), id);
        Ok(id)
    }
}

impl<'a> Files<'a> for SourceFiles {
    type FileId = FileId;
    type Name = &'a str;
    type Source = &'a str;

    fn name(&'a self, id: FileId) -> Result<Self::Name, Error> {
        Ok(self.get(id)?.name())
    }

    fn source(&'a self, id: FileId) -> Result<Self::Source, Error> {
        Ok(self.get(id)?.source())
    }

    fn line_index(&self, id: FileId, byte_index: usize) -> Result<usize, Error> {
        self.get(id)?.line_index((), byte_index)
    }

    fn line_range(&self, id: FileId, line_index: usize) -> Result<Range<usize>, Error> {
        self.get(id)?.line_range((), line_index)
    }
}
