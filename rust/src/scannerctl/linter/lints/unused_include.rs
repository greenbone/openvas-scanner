use std::collections::{HashMap, HashSet};

use codespan_reporting::diagnostic::{Diagnostic, Label};
use scannerlib::nasl::syntax::grammar::{Include, Statement};

use crate::linter::{
    LintMsg,
    ctx::{Cache, LintCtx},
    paths::{IncludePath, ResolvedPath},
};

const RULE: &str = "unused_include";

// Some include files may contain top level statements
// that are executed when the file is included. Such files
// should never be reported as unused includes. The terminology
// here is that "library" refers to a file that only provides
// function declarations and executes no top level statement.
//
// This function recursively collects all such library files.
fn collect_function_library(
    cache: &Cache,
    path: &ResolvedPath,
    files: &mut HashSet<ResolvedPath>,
    visiting: &mut HashSet<ResolvedPath>,
) -> bool {
    if visiting.contains(path) {
        return false;
    }
    if files.contains(path) {
        return true;
    }
    files.insert(path.clone());
    visiting.insert(path.clone());

    let is_library = cache.file(path).is_some_and(|file| {
        file.ast().iter_root_stmts().all(|statement| {
            matches!(
                statement,
                Statement::FnDecl(_) | Statement::Include(_) | Statement::NoOp
            )
        }) && file.ast().iter_includes().all(|include| {
            let include_path = IncludePath::new(include.path.as_str());
            cache
                .included_path(path, &include_path)
                .is_some_and(|included_path| {
                    collect_function_library(cache, included_path, files, visiting)
                })
        })
    });
    visiting.remove(path);
    is_library
}

fn function_library(cache: &Cache, path: &ResolvedPath) -> Option<HashSet<ResolvedPath>> {
    let mut files = HashSet::new();
    let mut visiting = HashSet::new();
    collect_function_library(cache, path, &mut files, &mut visiting).then_some(files)
}

fn function_callers(cache: &Cache) -> HashMap<String, HashSet<ResolvedPath>> {
    let mut callers = HashMap::<String, HashSet<ResolvedPath>>::new();
    for (path, file) in cache.files() {
        for call in file.ast().iter_fn_calls() {
            callers
                .entry(call.fn_name.to_string())
                .or_default()
                .insert(path.clone());
        }
    }
    callers
}

fn is_used(
    cache: &Cache,
    callers: &HashMap<String, HashSet<ResolvedPath>>,
    library_files: &HashSet<ResolvedPath>,
) -> bool {
    // An include is used when code outside that include chain calls a function
    // it provides. Calls between files in the same include chain do not count.
    library_files
        .iter()
        .filter_map(|path| cache.file(path))
        .flat_map(|file| file.functions())
        .any(|(name, _)| {
            callers.get(name).is_some_and(|caller_files| {
                caller_files
                    .iter()
                    .any(|path| !library_files.contains(path))
            })
        })
}

fn message(file: &scannerlib::nasl::SourceFile, include: &Include) -> LintMsg {
    let text = format!("Included file '{}' is never used", include.path);
    let diagnostic = Diagnostic::warning().with_message(&text).with_labels(vec![
        Label::primary((), include.span).with_message("unused include"),
    ]);
    LintMsg::new(RULE, file.clone(), include.span, diagnostic)
}

pub fn unused_includes(ctx: &LintCtx) -> Vec<LintMsg> {
    let cache = &*ctx.cache;
    let mut files = cache.files().collect::<Vec<_>>();
    files.sort_by(|(left, _), (right, _)| left.cmp(right));
    let callers = function_callers(cache);
    let mut libraries = HashMap::<ResolvedPath, Option<HashSet<ResolvedPath>>>::new();
    let mut messages = vec![];

    for (path, file) in files {
        for include in file.ast().iter_includes() {
            let include_path = IncludePath::new(include.path.as_str());
            let Some(included_path) = cache.included_path(path, &include_path) else {
                continue;
            };
            let library_files = libraries
                .entry(included_path.clone())
                .or_insert_with(|| function_library(cache, included_path));
            if let Some(library_files) = library_files
                && !is_used(cache, &callers, library_files)
            {
                messages.push(message(file.file(), include));
            }
        }
    }
    messages
}

#[cfg(test)]
mod tests {
    use crate::linter_test_multi;

    linter_test_multi!(
        unused_function_include,
        roots: ["root.nasl"],
        files: {
            "root.nasl" => "include(\"helper.inc\");",
            "helper.inc" => "function helper() {}",
        },
    );

    linter_test_multi!(
        used_function_include,
        roots: ["root.nasl"],
        files: {
            "root.nasl" => "include(\"helper.inc\"); helper();",
            "helper.inc" => "function helper() {}",
        },
    );

    linter_test_multi!(
        used_transitive_function_includes,
        roots: ["root.nasl"],
        files: {
            "root.nasl" => "include(\"wrapper.inc\"); wrapper();",
            "wrapper.inc" => "include(\"helper.inc\"); function wrapper() { helper(); }",
            "helper.inc" => "function helper() {}",
        },
    );

    linter_test_multi!(
        include_with_top_level_code_is_not_reported,
        roots: ["root.nasl"],
        files: {
            "root.nasl" => "include(\"constants.inc\"); display(VALUE);",
            "constants.inc" => "VALUE = 1;",
        },
    );

    linter_test_multi!(
        unused_include_in_shared_parent_is_emitted_once,
        roots: ["a.nasl", "b.nasl"],
        files: {
            "a.nasl" => "include(\"common.inc\"); common();",
            "b.nasl" => "include(\"common.inc\"); common();",
            "common.inc" => "include(\"unused.inc\"); function common() {}",
            "unused.inc" => "function unused() {}",
        },
    );
}
