use codespan_reporting::diagnostic::{Diagnostic, Label};

use crate::linter::{LintMsgs, calls::RootCalls};

use super::builtins::builtin_functions;

#[cfg_attr(not(test), expect(dead_code))]
pub fn strict_include_order(root: &RootCalls) -> Vec<LintMsgs> {
    let builtins = builtin_functions();
    root.files
        .iter()
        .enumerate()
        .skip(1)
        .map(|(caller, file)| {
            let msgs = root
                .calls_in(caller)
                .filter_map(|call| {
                    if builtins.contains(&call.name) {
                        return None;
                    }
                    let definition = root.definitions.get(call.name.as_str())?.first()?;
                    if definition.file <= caller {
                        return None;
                    }
                    Some(
                        Diagnostic::error()
                            .with_message(format!(
                                "{} must be included after {} (usage of {})",
                                file.file.name(),
                                root.files[definition.file].file.name(),
                                call.name,
                            ))
                            .with_labels(vec![
                                Label::primary((), call.span)
                                    .with_message("function is defined in a later include"),
                            ])
                            .into(),
                    )
                })
                .collect();
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

    use crate::{linter::lints::Lint, linter_test_multi};

    use super::strict_include_order;

    linter_test_multi!(later_include,
        lints: vec![Lint::Root(strict_include_order)],
        files: {
            "root.nasl" => "include(\"caller.inc\"); include(\"callee.inc\"); start();",
            "caller.inc" => "function start() { helper(); } helper();",
            "callee.inc" => "function helper() {}",
        },
    );
    linter_test_multi!(earlier_include_and_root_calls,
        lints: vec![Lint::Root(strict_include_order)],
        files: {
            "root.nasl" => "include(\"callee.inc\"); include(\"caller.inc\"); start(); function root_helper() {}",
            "caller.inc" => "function start() { helper(); local_helper(); root_helper(); display(1); } function local_helper() {}",
            "callee.inc" => "function helper() {}",
        },
    );
    linter_test_multi!(transitive_include,
        lints: vec![Lint::Root(strict_include_order)],
        files: {
            "root.nasl" => "include(\"nested/caller.inc\"); start();",
            "nested/caller.inc" => "include(\"callee.inc\"); function start() { helper(); }",
            "nested/callee.inc" => "function helper() {}",
        },
    );
    linter_test_multi!(order_is_root_specific,
        lints: vec![Lint::Root(strict_include_order)],
        files: {
            "ordered.nasl" => "include(\"callee.inc\"); include(\"caller.inc\"); start();",
            "reversed.nasl" => "include(\"caller.inc\"); include(\"callee.inc\"); start();",
            "caller.inc" => "function start() { helper(); }",
            "callee.inc" => "function helper() {}",
        },
    );
}
