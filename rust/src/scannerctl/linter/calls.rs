use std::collections::{HashMap, HashSet};

use scannerlib::nasl::{
    error::{Span, Spanned},
    syntax::{
        Visitor,
        grammar::{Ast, FnCall, FnDecl},
        walk_ast,
    },
};

use super::ctx::CachedFile;

pub(super) struct Call {
    pub name: String,
    pub span: Span,
}

pub(super) struct FunctionCalls {
    pub name: String,
    pub span: Span,
    pub calls: Vec<Call>,
}

#[derive(Default)]
pub(super) struct FileCalls {
    pub top_level: Vec<Call>,
    pub functions: Vec<FunctionCalls>,
}

impl FileCalls {
    pub fn new(ast: &Ast) -> Self {
        let mut collector = CallCollector::default();
        walk_ast(&mut collector, ast);
        collector.calls
    }
}

#[derive(Default)]
struct CallCollector {
    calls: FileCalls,
    functions: Vec<usize>,
}

impl<'ast> Visitor<'ast> for CallCollector {
    fn visit_fn_decl(&mut self, decl: &'ast FnDecl) {
        self.functions.push(self.calls.functions.len());
        self.calls.functions.push(FunctionCalls {
            name: decl.fn_name.to_string(),
            span: decl.fn_name.span(),
            calls: vec![],
        });
    }

    fn leave_fn_decl(&mut self, _: &'ast FnDecl) {
        self.functions.pop();
    }

    fn visit_fn_call(&mut self, call: &'ast FnCall) {
        let call = Call {
            name: call.fn_name.to_string(),
            span: call.fn_name.span(),
        };
        if let Some(&index) = self.functions.last() {
            self.calls.functions[index].calls.push(call);
        } else {
            self.calls.top_level.push(call);
        }
    }
}

/// Identifies a declaration within a root's ordered list of files.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct FunctionId {
    pub file: usize,
    pub function: usize,
}

pub(super) struct RootCalls<'a> {
    pub files: Vec<&'a CachedFile>,
    pub definitions: HashMap<&'a str, Vec<FunctionId>>,
    pub reachable: HashSet<FunctionId>,
}

impl<'a> RootCalls<'a> {
    pub fn new(files: Vec<&'a CachedFile>) -> Self {
        let mut definitions: HashMap<&str, Vec<FunctionId>> = HashMap::new();
        for (file, cached) in files.iter().enumerate() {
            for (function, decl) in cached.calls.functions.iter().enumerate() {
                definitions
                    .entry(&decl.name)
                    .or_default()
                    .push(FunctionId { file, function });
            }
        }
        let mut pending: Vec<_> = files
            .iter()
            .flat_map(|file| &file.calls.top_level)
            .filter_map(|call| definitions.get(call.name.as_str()))
            .flatten()
            .copied()
            .collect();
        let mut reachable = HashSet::new();
        while let Some(id) = pending.pop() {
            if !reachable.insert(id) {
                continue;
            }
            for call in &files[id.file].calls.functions[id.function].calls {
                if let Some(callees) = definitions.get(call.name.as_str()) {
                    pending.extend(callees);
                }
            }
        }
        Self {
            files,
            definitions,
            reachable,
        }
    }

    pub fn calls_in(&self, file: usize) -> impl Iterator<Item = &Call> {
        let calls = &self.files[file].calls;
        calls.top_level.iter().chain(
            calls
                .functions
                .iter()
                .enumerate()
                .filter(move |(function, _)| {
                    self.reachable.contains(&FunctionId {
                        file,
                        function: *function,
                    })
                })
                .flat_map(|(_, function)| &function.calls),
        )
    }
}
