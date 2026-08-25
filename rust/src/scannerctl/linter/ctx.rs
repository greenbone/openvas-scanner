use std::collections::HashMap;

use scannerlib::nasl::{
    SourceFile, nasl_std_executor,
    syntax::{
        Visitor,
        grammar::{Ast, FnDecl},
        walk_ast,
    },
};

pub(crate) struct CachedFile {
    file: SourceFile,
    fns: HashMap<String, FnDecl>,
}

impl CachedFile {
    pub(crate) fn new(file: SourceFile, ast: &Ast) -> Self {
        let mut collector = FnDefinitionCollector::default();
        walk_ast(&mut collector, ast);

        CachedFile {
            file,
            fns: collector.functions,
        }
    }

    pub(crate) fn file(&self) -> &SourceFile {
        &self.file
    }

    pub(crate) fn functions(&self) -> impl Iterator<Item = (&str, &FnDecl)> {
        self.fns
            .iter()
            .map(|(name, declaration)| (name.as_str(), declaration))
    }
}

pub struct BuiltinFn;

pub(crate) struct Cache {
    files: HashMap<String, CachedFile>,
    builtin_fns: HashMap<String, BuiltinFn>,
}

impl Default for Cache {
    fn default() -> Self {
        let builtin_fns = nasl_std_executor()
            .iter()
            .map(|name| (name.to_owned(), BuiltinFn))
            .collect();
        Self {
            files: HashMap::new(),
            builtin_fns,
        }
    }
}

impl Cache {
    pub(crate) fn clear_files(&mut self) {
        self.files.clear();
    }

    pub(crate) fn insert(&mut self, rel_path: &str, file: CachedFile) {
        self.files.insert(rel_path.to_owned(), file);
    }

    pub(crate) fn files(&self) -> impl Iterator<Item = (&str, &CachedFile)> {
        self.files.iter().map(|(path, file)| (path.as_str(), file))
    }
}

pub(crate) struct LintCtx<'a> {
    pub cache: &'a mut Cache,
    pub ast: &'a Ast,
    pub file: &'a SourceFile,
}

impl<'a> LintCtx<'a> {
    pub fn new(ast: &'a Ast, file: &'a SourceFile, cache: &'a mut Cache) -> Self {
        Self { cache, ast, file }
    }

    pub fn fn_defined(&self, fn_name: &str) -> bool {
        self.cache
            .files
            .values()
            .any(|file| file.fns.contains_key(fn_name))
    }

    pub(crate) fn builtin_defined(&self, fn_name: &str) -> bool {
        self.cache.builtin_fns.contains_key(fn_name)
    }
}

#[derive(Default)]
pub(crate) struct FnDefinitionCollector {
    pub functions: HashMap<String, FnDecl>,
}

impl<'ast> Visitor<'ast> for FnDefinitionCollector {
    fn visit_fn_decl(&mut self, decl: &'ast FnDecl) {
        let fn_name = decl.fn_name.to_string();
        self.functions
            .entry(fn_name)
            .or_insert_with(|| decl.clone());
    }
}
