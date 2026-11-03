use codespan_reporting::{
    diagnostic::{Diagnostic, Label},
    files::Files,
};

use crate::linter::{
    LintMsgs,
    calls::{FunctionId, RootCalls},
};

use super::builtins::builtin_functions;

pub fn duplicate_functions(root: &RootCalls) -> Vec<LintMsgs> {
    let builtins = builtin_functions();
    root.files
        .iter()
        .enumerate()
        .map(|(file_index, file)| {
            let mut msgs = vec![];
            for (function, decl) in file.calls.functions.iter().enumerate() {
                let first = root.definitions[decl.name.as_str()][0];
                let diagnostic = if builtins.contains(&decl.name) {
                    Diagnostic::error()
                        .with_message(format!("Function '{}' redefines a builtin", decl.name))
                        .with_labels(vec![
                            Label::primary((), decl.span)
                                .with_message("builtin function redefined"),
                        ])
                } else if first
                    != (FunctionId {
                        file: file_index,
                        function,
                    })
                {
                    let original_file = root.files[first.file];
                    let original = &original_file.calls.functions[first.function];
                    let mut diagnostic = Diagnostic::error()
                        .with_message(format!(
                            "Function '{}' is defined multiple times",
                            decl.name
                        ))
                        .with_labels(vec![
                            Label::primary((), decl.span).with_message("duplicate definition"),
                        ]);
                    if first.file == file_index {
                        diagnostic.labels.push(
                            Label::secondary((), original.span).with_message("first definition"),
                        );
                    } else {
                        let range: std::ops::Range<usize> = original.span.into();
                        let location = original_file.file.location((), range.start).unwrap();
                        diagnostic.notes.push(format!(
                            "First definition: {}:{}:{}",
                            original_file.file.name(),
                            location.line_number,
                            location.column_number
                        ));
                    }
                    diagnostic
                } else {
                    continue;
                };
                msgs.push(diagnostic.into());
            }
            LintMsgs {
                file: file.file.clone(),
                msgs,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::{linter_test, linter_test_multi};

    linter_test!(
        duplicate_unused_functions,
        "function foo() {} function foo() {} function foo() {}"
    );
    linter_test!(
        builtin_redefinitions,
        "function display() {} function win_cmd_exec() {}"
    );

    linter_test_multi!(
        conflicting_includes,
        files: {
            "root.nasl" => "include(\"a.inc\"); include(\"b.inc\");",
            "a.inc" => "function foo() {}",
            "b.inc" => "function foo() {}",
        },
    );
    linter_test_multi!(
        unrelated_roots,
        files: {
            "first.nasl" => "function foo() {}",
            "second.nasl" => "function foo() {}",
        },
    );
    linter_test_multi!(
        shared_include_is_one_definition,
        files: {
            "root.nasl" => "include(\"a.inc\"); include(\"b.inc\");",
            "a.inc" => "include(\"shared.inc\");",
            "b.inc" => "include(\"shared.inc\");",
            "shared.inc" => "function foo() {}",
        },
    );
}
