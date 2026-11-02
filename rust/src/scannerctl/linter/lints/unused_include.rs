use std::{
    collections::{HashMap, HashSet},
    path::Path,
};

use codespan_reporting::diagnostic::{Diagnostic, Label};
use scannerlib::nasl::syntax::{
    Visitor,
    grammar::{Atom, FnDecl, ForEach, PlaceExpr, VarScope, VarScopeDecl},
    walk_ast,
};

use crate::linter::{LintMsgs, calls::RootCalls};

use super::builtins::builtin_functions;

struct GlobalUsage<'a> {
    called: &'a HashSet<&'a str>,
    definitions: HashSet<String>,
    references: HashSet<String>,
    functions: Vec<(bool, HashSet<String>)>,
}

impl GlobalUsage<'_> {
    fn reference(&mut self, name: String) {
        if self
            .functions
            .last()
            .is_none_or(|(active, locals)| *active && !locals.contains(&name))
        {
            self.references.insert(name);
        }
    }
}

impl<'ast> Visitor<'ast> for GlobalUsage<'_> {
    fn visit_fn_decl(&mut self, decl: &'ast FnDecl) {
        let active = self.functions.last().is_none_or(|(active, _)| *active)
            && self.called.contains(decl.fn_name.to_string().as_str());
        self.functions.push((
            active,
            decl.args.items.iter().map(ToString::to_string).collect(),
        ));
    }

    fn leave_fn_decl(&mut self, _: &'ast FnDecl) {
        self.functions.pop();
    }

    fn visit_var_scope_decl(&mut self, decl: &'ast VarScopeDecl) {
        if let Some((_, locals)) = self.functions.last_mut() {
            if matches!(decl.scope, VarScope::Local) {
                locals.extend(decl.idents.iter().map(ToString::to_string));
            }
        } else {
            self.definitions
                .extend(decl.idents.iter().map(ToString::to_string));
        }
    }

    fn visit_for_each(&mut self, stmt: &'ast ForEach) {
        if let Some((_, locals)) = self.functions.last_mut() {
            locals.insert(stmt.var.to_string());
        } else {
            self.definitions.insert(stmt.var.to_string());
        }
    }

    fn visit_place_expr(&mut self, place: &'ast PlaceExpr) {
        if self.functions.is_empty() {
            self.definitions.insert(place.ident.to_string());
        } else {
            self.reference(place.ident.to_string());
        }
    }

    fn visit_atom(&mut self, atom: &'ast Atom) {
        if let Atom::Ident(ident) = atom {
            self.reference(ident.to_string());
        }
    }
}

pub fn unused_includes(root: &RootCalls) -> Vec<LintMsgs> {
    let builtins = builtin_functions();
    let called: HashSet<_> = root
        .files
        .iter()
        .flat_map(|file| {
            file.calls.top_level.iter().chain(
                file.calls
                    .functions
                    .iter()
                    .flat_map(|function| &function.calls),
            )
        })
        .filter(|call| !builtins.contains(&call.name))
        .map(|call| call.name.as_str())
        .collect();
    let globals: Vec<_> = root
        .files
        .iter()
        .map(|file| {
            let mut collector = GlobalUsage {
                called: &called,
                definitions: HashSet::new(),
                references: HashSet::new(),
                functions: vec![],
            };
            walk_ast(&mut collector, &file.ast);
            collector
        })
        .collect();
    let mut definitions: HashMap<&str, Vec<usize>> = HashMap::new();
    for (file, usage) in globals.iter().enumerate() {
        for name in &usage.definitions {
            definitions.entry(name).or_default().push(file);
        }
    }
    let mut used = vec![false; root.files.len()];
    for (caller, usage) in globals.iter().enumerate() {
        for name in &usage.references {
            if let Some(files) = definitions.get(name.as_str()) {
                for &file in files {
                    if caller != file {
                        used[file] = true;
                    }
                }
            }
        }
    }
    for (caller, file) in root.files.iter().enumerate() {
        let calls = file.calls.top_level.iter().map(|call| (0, call)).chain(
            file.calls
                .functions
                .iter()
                .filter(|function| called.contains(function.name.as_str()))
                .flat_map(|function| &function.calls)
                .map(|call| (caller, call)),
        );
        for (caller, call) in calls {
            if let Some(definitions) = root.definitions.get(call.name.as_str()) {
                for definition in definitions {
                    if caller != definition.file {
                        used[definition.file] = true;
                    }
                }
            }
        }
    }

    let mut results: Vec<_> = root
        .files
        .iter()
        .map(|file| LintMsgs {
            file: file.file.clone(),
            msgs: vec![],
        })
        .collect();
    for (index, file) in root.files.iter().enumerate().skip(1) {
        if used[index]
            || globals[index].definitions.is_empty()
                && !file
                    .calls
                    .functions
                    .iter()
                    .any(|function| called.contains(function.name.as_str()))
        {
            continue;
        }
        let path = Path::new(file.file.name());
        let (parent, include) = root
            .files
            .iter()
            .enumerate()
            .find_map(|(parent, file)| {
                file.ast
                    .iter_includes()
                    .zip(&file.includes)
                    .find(|(_, included)| included.as_path() == path)
                    .map(|(include, _)| (parent, include))
            })
            .unwrap();
        results[parent].msgs.push(
            Diagnostic::error()
                .with_message(format!(
                    "The included file '{}' is never used",
                    file.file.name()
                ))
                .with_labels(vec![Label::primary((), include.span)])
                .into(),
        );
    }
    results
}

#[cfg(test)]
mod tests {
    use crate::linter_test_multi;
    use std::path::Path;

    linter_test_multi!(internal_calls,
        files: {
            "root.nasl" => "include(\"internal.inc\");",
            "internal.inc" => "value = 1; function initialize() { initialize(); }",
        },
    );
    linter_test_multi!(included_top_level_call,
        files: {
            "root.nasl" => "include(\"library.inc\");",
            "library.inc" => "function initialize() {} initialize();",
        },
    );
    linter_test_multi!(external_call,
        files: {
            "root.nasl" => "include(\"library.inc\"); exported();",
            "library.inc" => "function exported() {}",
        },
    );
    linter_test_multi!(untracked_includes,
        files: {
            "root.nasl" => "include(\"definitions.inc\"); include(\"constants.inc\");",
            "definitions.inc" => "function never_called() {}",
            "constants.inc" => "constant = 1;",
        },
    );
    linter_test_multi!(transitive_include,
        files: {
            "root.nasl" => "include(\"nested/wrapper.inc\");",
            "nested/wrapper.inc" => "include(\"internal.inc\");",
            "nested/internal.inc" => "function initialize() { initialize(); }",
        },
    );
    linter_test_multi!(root_specific_usage,
        files: {
            "used.nasl" => "include(\"library.inc\"); exported();",
            "unused.nasl" => "include(\"library.inc\");",
            "library.inc" => "function exported() { exported(); }",
        },
    );
    linter_test_multi!(syntactic_calls,
        files: {
            "root.nasl" => "include(\"library.inc\"); function unreachable() { exported(); }",
            "library.inc" => "function exported() {}",
        },
    );
    linter_test_multi!(exported_array,
        files: {
            "root.nasl" => "include(\"data.inc\"); display(values[0]);",
            "data.inc" => "global_var values; values[0] = 1; function internal() { internal(); }",
        },
    );
    linter_test_multi!(global_used_by_function,
        files: {
            "root.nasl" => "include(\"data.inc\"); function show() { display(value); } show();",
            "data.inc" => "value = 1;",
        },
    );
    linter_test_multi!(global_used_by_include,
        files: {
            "root.nasl" => "include(\"data.inc\"); include(\"consumer.inc\"); display(result);",
            "data.inc" => "value = 1;",
            "consumer.inc" => "result = value;",
        },
    );
    linter_test_multi!(shadowed_globals,
        files: {
            "root.nasl" => "include(\"data.inc\"); function show(value) { local_var other; other = 2; display(value, other); } show(value:1);",
            "data.inc" => "value = 1; other = 1;",
        },
    );
    linter_test_multi!(global_only_used_in_uncalled_function,
        files: {
            "root.nasl" => "include(\"data.inc\"); function unused() { display(value); }",
            "data.inc" => "value = 1;",
        },
    );
}
