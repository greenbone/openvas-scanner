use std::{collections::HashSet, path::Path};

use codespan_reporting::diagnostic::{Diagnostic, Label};

use crate::linter::{LintMsgs, calls::RootCalls};

use super::builtins::builtin_functions;

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
    let mut used = vec![false; root.files.len()];
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
            || !file
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
}
