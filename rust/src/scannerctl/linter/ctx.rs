use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use scannerlib::nasl::{
    SourceFile, nasl_std_executor,
    syntax::{
        Visitor,
        grammar::{Ast, FnDecl},
        walk_ast,
    },
    utils::Executor,
};

/// Names supplied by the script execution context or accepted for C-linter compatibility,
/// rather than registered as globals by Rust builtin function sets.
const PREDEFINED_VARS: [&str; 5] = [
    "ACT_UNKNOWN",
    "COMMAND_LINE",
    "OPENVAS_VERSION",
    "SCRIPT_NAME",
    "description",
];

fn predefined_vars(executor: &Executor) -> HashSet<String> {
    executor
        .iter_global_var_names()
        .chain(PREDEFINED_VARS)
        .map(str::to_owned)
        .collect()
}

pub(crate) struct CachedFile {
    ast: Ast,
    file: SourceFile,
    fns: HashMap<String, FnDecl>,
}

impl CachedFile {
    pub(crate) fn new(file: SourceFile, ast: &Ast) -> Self {
        let mut collector = FnDefinitionCollector::default();
        walk_ast(&mut collector, ast);

        CachedFile {
            ast: ast.clone(),
            file,
            fns: collector.functions,
        }
    }

    pub(crate) fn ast(&self) -> &Ast {
        &self.ast
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
    files: HashMap<String, Arc<CachedFile>>,
    builtin_fns: HashMap<String, BuiltinFn>,
    predefined_vars: HashSet<String>,
}

impl Default for Cache {
    fn default() -> Self {
        let executor = nasl_std_executor();
        let builtin_fns = executor
            .iter()
            .map(|name| (name.to_owned(), BuiltinFn))
            .collect();
        let predefined_vars = predefined_vars(&executor);
        Self {
            files: HashMap::new(),
            builtin_fns,
            predefined_vars,
        }
    }
}

impl Cache {
    pub(crate) fn clear_files(&mut self) {
        self.files.clear();
    }

    pub(crate) fn insert(&mut self, rel_path: &str, file: Arc<CachedFile>) {
        self.files.insert(rel_path.to_owned(), file);
    }

    pub(crate) fn files(&self) -> impl Iterator<Item = (&str, &CachedFile)> {
        self.files
            .iter()
            .map(|(path, file)| (path.as_str(), file.as_ref()))
    }

    pub(crate) fn file(&self, path: &str) -> Option<&CachedFile> {
        self.files.get(path).map(Arc::as_ref)
    }

    pub(crate) fn predefined_vars(&self) -> impl Iterator<Item = &str> {
        self.predefined_vars.iter().map(String::as_str)
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
