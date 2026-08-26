use std::collections::{HashMap, HashSet};

use codespan_reporting::diagnostic::{Diagnostic, Label};
use scannerlib::nasl::syntax::grammar::{Include, Statement};

use crate::linter::{
    LintMsg,
    ctx::{Cache, LintCtx},
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
    path: &str,
    files: &mut HashSet<String>,
    visiting: &mut HashSet<String>,
) -> bool {
    if visiting.contains(path) {
        return false;
    }
    if files.contains(path) {
        return true;
    }
    files.insert(path.to_owned());
    visiting.insert(path.to_owned());

    let is_library = cache.file(path).is_some_and(|file| {
        file.ast().iter_root_stmts().all(|statement| {
            matches!(
                statement,
                Statement::FnDecl(_) | Statement::Include(_) | Statement::NoOp
            )
        }) && file.ast().iter_includes().all(|include| {
            cache
                .included_path(path, &include.path)
                .is_some_and(|included_path| {
                    collect_function_library(cache, included_path, files, visiting)
                })
        })
    });
    visiting.remove(path);
    is_library
}

fn function_library(cache: &Cache, path: &str) -> Option<HashSet<String>> {
    let mut files = HashSet::new();
    let mut visiting = HashSet::new();
    collect_function_library(cache, path, &mut files, &mut visiting).then_some(files)
}

fn function_callers(cache: &Cache) -> HashMap<String, HashSet<String>> {
    let mut callers = HashMap::<String, HashSet<String>>::new();
    for (path, file) in cache.files() {
        for call in file.ast().iter_fn_calls() {
            callers
                .entry(call.fn_name.to_string())
                .or_default()
                .insert(path.to_owned());
        }
    }
    callers
}

fn is_used(
    cache: &Cache,
    callers: &HashMap<String, HashSet<String>>,
    library_files: &HashSet<String>,
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
    files.sort_by_key(|(path, _)| *path);
    let callers = function_callers(cache);
    let mut libraries = HashMap::<String, Option<HashSet<String>>>::new();
    let mut messages = vec![];

    for (path, file) in files {
        for include in file.ast().iter_includes() {
            let Some(included_path) = cache.included_path(path, &include.path) else {
                continue;
            };
            let library_files = libraries
                .entry(included_path.to_owned())
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
