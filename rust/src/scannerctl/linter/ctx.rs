use std::collections::HashMap;

use scannerlib::nasl::syntax::{
    Visitor,
    grammar::{Ast, FnDecl},
    walk_ast,
};

#[derive(Default)]
pub(crate) struct CachedFile {
    fns: HashMap<String, FnDecl>,
}

#[derive(Default)]
pub(crate) struct Cache {
    files: HashMap<String, CachedFile>,
}

impl Cache {
    pub fn add_file_functions(&mut self, file_path: String, ast: &Ast) {
        let mut collector = FnDefinitionCollector::default();
        walk_ast(&mut collector, ast);

        let cached_file = CachedFile {
            fns: collector.functions,
        };
        self.files.insert(file_path, cached_file);
    }
}

pub(crate) struct LintCtx<'a> {
    pub cache: &'a mut Cache,
    pub ast: &'a Ast,
}

impl<'a> LintCtx<'a> {
    pub fn new(ast: &'a Ast, cache: &'a mut Cache) -> Self {
        Self { cache, ast }
    }

    pub fn fn_defined(&self, fn_name: &str) -> bool {
        self.cache
            .files
            .values()
            .any(|file| file.fns.contains_key(fn_name))
    }
}

#[derive(Default)]
pub(crate) struct FnDefinitionCollector {
    pub functions: HashMap<String, FnDecl>,
}

impl<'ast> Visitor<'ast> for FnDefinitionCollector {
    fn visit_fn_decl(&mut self, decl: &'ast FnDecl) {
        let fn_name = decl.fn_name.to_string();
        self.functions.insert(fn_name, decl.clone());
    }
}
