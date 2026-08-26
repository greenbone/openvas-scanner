use std::{
    collections::{HashMap, HashSet},
    mem,
    ops::Range,
};

use codespan_reporting::diagnostic::{Diagnostic, Label};
use scannerlib::nasl::{
    error::{Span, Spanned},
    syntax::{
        Visitor,
        grammar::{FnCall, FnDecl, Include},
        walk_ast, walk_block,
    },
};

use crate::linter::{
    LintMsg,
    ctx::{Cache, LintCtx},
    paths::{IncludePath, ResolvedPath},
};

const RULE: &str = "undefined_function";
// This a very ugly implementation detail: openvas-nasl-lint would
// explicitly exclude undefined functions of the structure
// `if defined_func("foo") { foo() }`. I find this to be a very ugly
// concept, however it does take care of a few scripts in the feed where
// this would otherwise result in false positives.
// Here, I am explicitly including those exceptions.
// This is ugly too, but makes it a little bit easier to remove this
// in case we can convince feed authors to remove the obsolete functions.
const UNDEFINED_FUNCTION_EXCEPTIONS: [&str; 2] = ["network_targets", "scan_phase"];

struct FunctionDefinition {
    path: ResolvedPath,
    declaration: FnDecl,
}

struct CallSite {
    path: ResolvedPath,
    name: String,
    span: Span,
}

struct ReachableCalls<'cache> {
    cache: &'cache Cache,
    path: ResolvedPath,
    loaded: HashSet<ResolvedPath>,
    calls: Vec<CallSite>,
}

impl<'cache> ReachableCalls<'cache> {
    fn new(cache: &'cache Cache, path: ResolvedPath) -> Self {
        let loaded = HashSet::from([path.clone()]);
        Self {
            cache,
            path,
            loaded,
            calls: vec![],
        }
    }

    fn walk_function(&mut self, definition: &FunctionDefinition) {
        let outer_path = mem::replace(&mut self.path, definition.path.clone());
        walk_block(self, &definition.declaration.block);
        self.path = outer_path;
    }

    fn walk_include(&mut self, include: &Include) {
        let include_path = IncludePath::new(include.path.as_str());
        let Some((path, ast)) = self
            .cache
            .included_file(&self.path, &include_path)
            .map(|(path, file)| (path.clone(), file.ast().clone()))
        else {
            return;
        };
        if !self.loaded.insert(path.clone()) {
            return;
        }

        let outer_path = mem::replace(&mut self.path, path);
        walk_ast(self, &ast);
        self.path = outer_path;
    }
}

impl<'ast> Visitor<'ast> for ReachableCalls<'_> {
    fn visit_fn_call(&mut self, call: &'ast FnCall) {
        self.calls.push(CallSite {
            path: self.path.clone(),
            name: call.fn_name.to_string(),
            span: call.fn_name.span(),
        });
    }

    fn visit_include(&mut self, include: &'ast Include) {
        self.walk_include(include);
    }

    fn should_walk_fn_body(&self, _declaration: &'ast FnDecl) -> bool {
        false
    }
}

fn function_definitions(cache: &Cache) -> HashMap<String, Vec<FunctionDefinition>> {
    let mut definitions: HashMap<String, Vec<FunctionDefinition>> = HashMap::new();
    for (path, file) in cache.files() {
        for (name, declaration) in file.functions() {
            definitions
                .entry(name.to_owned())
                .or_default()
                .push(FunctionDefinition {
                    path: path.clone(),
                    declaration: declaration.clone(),
                });
        }
    }
    definitions
}

pub fn fn_undefined(ctx: &LintCtx) -> Vec<LintMsg> {
    let cache = &*ctx.cache;
    let definitions = function_definitions(cache);
    let mut reachable = ReachableCalls::new(cache, ctx.path.clone());
    walk_ast(&mut reachable, ctx.ast);

    // Here, we build up a collection of all the called functions by
    // starting with the top level function calls and then adding
    // calls from each functions body to a queue.
    let mut reachable_functions = HashSet::new();
    // We do this instead of iterating normally to make borrowck happy
    let mut next_call = 0;
    while let Some(name) = reachable
        .calls
        .get(next_call)
        .map(|call_site| call_site.name.clone())
    {
        next_call += 1;
        if ctx.builtin_defined(&name) || !reachable_functions.insert(name.clone()) {
            continue;
        }
        if let Some(definitions) = definitions.get(&name) {
            for definition in definitions {
                reachable.walk_function(definition);
            }
        }
    }

    let mut undefined = reachable
        .calls
        .into_iter()
        .filter(|call_site| {
            !definitions.contains_key(&call_site.name)
                && !ctx.builtin_defined(&call_site.name)
                && !UNDEFINED_FUNCTION_EXCEPTIONS.contains(&call_site.name.as_str())
        })
        .collect::<Vec<_>>();
    undefined.sort_by(|left, right| {
        let left_span: Range<usize> = left.span.into();
        let right_span: Range<usize> = right.span.into();
        left.path
            .cmp(&right.path)
            .then(left_span.start.cmp(&right_span.start))
    });

    undefined
        .into_iter()
        .filter_map(|call_site| {
            let file = cache.file(&call_site.path)?.file().clone();
            let diagnostic = Diagnostic::error()
                .with_message(format!("Undefined function '{}'", call_site.name))
                .with_labels(vec![
                    Label::primary((), call_site.span).with_message("undefined function"),
                ]);
            Some(LintMsg::new(RULE, file, call_site.span, diagnostic))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::{linter_test, linter_test_multi};

    linter_test!(undefined_fn, "foo();");
    linter_test!(defined_fn, "function foo() {} foo();");
    linter_test!(builtin_fn, "display(\"hello\");");
    linter_test!(
        unreachable_root_function,
        "function unused() { missing(); }"
    );
    linter_test!(
        transitively_reachable_function,
        "function first() { second(); } function second() { missing(); } first();"
    );
    linter_test!(
        defined_func_does_not_declare_function,
        "if (defined_func(\"optional\")) { optional(); }"
    );
    linter_test!(
        undefined_function_exceptions,
        "scan_phase(); network_targets();"
    );
    linter_test!(
        c_compat_builtin_fns,
        "wmi_query(); socket_ssl_do_handshake();"
    );

    linter_test_multi!(
        unreachable_include_function,
        roots: ["root.nasl"],
        files: {
            "root.nasl" => "include(\"library.inc\"); used();",
            "library.inc" => "function used() {} function unused() { missing(); }",
        },
    );

    linter_test_multi!(
        reachable_include_function,
        roots: ["root.nasl"],
        files: {
            "root.nasl" => "include(\"library.inc\"); used();",
            "library.inc" => "function used() { missing(); }",
        },
    );
}
