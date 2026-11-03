use codespan_reporting::diagnostic::{Diagnostic, Label};
use scannerlib::nasl::{
    error::Spanned,
    syntax::grammar::{Atom, Expr, FnArg},
};

use crate::linter::{LintMsgs, calls::RootCalls};

use super::builtins::builtin_functions;

pub fn fn_undefined(root: &RootCalls) -> Vec<LintMsgs> {
    let mut known_functions = builtin_functions();
    for (index, file) in root.files.iter().enumerate() {
        let checks: Vec<_> = root
            .calls_in(index)
            .filter(|call| call.name == "defined_func")
            .map(|call| call.span)
            .collect();
        if checks.is_empty() {
            continue;
        }
        for call in file
            .ast
            .iter_fn_calls()
            .filter(|call| checks.contains(&call.fn_name.span()))
        {
            let argument = call.args.items.iter().find_map(|arg| match arg {
                FnArg::Anonymous(arg) => Some(arg.expr.as_ref()),
                FnArg::Named(_) => None,
            });
            if let Some(Expr::Atom(Atom::Literal(literal))) = argument
                && let Some(name) = literal.clone().into_string()
            {
                known_functions.insert(name);
            }
        }
    }
    root.files
        .iter()
        .enumerate()
        .map(|(index, file)| {
            let msgs = root
                .calls_in(index)
                .filter(|call| {
                    !root.definitions.contains_key(call.name.as_str())
                        && !known_functions.contains(&call.name)
                })
                .map(|call| {
                    Diagnostic::error()
                        .with_message(format!("Undefined function '{}'", call.name))
                        .with_labels(vec![
                            Label::primary((), call.span).with_message("undefined function"),
                        ])
                        .into()
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

    use crate::{linter_test, linter_test_multi};

    linter_test!(undefined_fn, "foo();");
    linter_test!(defined_fn, "function foo() {} foo();");
    linter_test!(builtin_fn, "display(\"hello\");");
    linter_test!(
        optional_functions,
        "if (defined_func(\"optional\")) optional(); if (!defined_func('another')) exit(0); another();"
    );
    linter_test!(
        unused_or_dynamic_checks,
        "function unused() { defined_func(\"missing\"); } name = \"dynamic\"; defined_func(name); missing(); dynamic();"
    );
    linter_test_multi!(
        optional_function_is_root_specific,
        files: {
            "checked.nasl" => "include(\"shared.inc\"); probe(); optional();",
            "unchecked.nasl" => "include(\"shared.inc\"); optional();",
            "shared.inc" => "function probe() { defined_func(\"optional\"); }",
        },
    );
    linter_test!(
        c_only_builtins,
        "win_cmd_exec(); wmi_connect(); smb_file_SDDL(); socket_ssl_do_handshake(); update_table_driven_lsc_data();"
    );

    linter_test!(
        unused_functions,
        "function unused() { missing(); } function recursive() { recursive(); missing(); }"
    );

    linter_test!(
        recursive_calls,
        "function a() { b(); } function b() { a(); missing(); } a();"
    );

    linter_test!(
        nested_function_calls,
        "function outer() { function inner() { nested_missing(); } outer_missing(); } outer(); top_missing();"
    );

    linter_test!(
        duplicate_definitions_keep_both_bodies,
        "function foo() { missing_a(); } function foo() { missing_b(); } foo();"
    );

    linter_test_multi!(
        reachable_calls_are_root_specific,
        files: {
            "unused.nasl" => "include(\"shared.inc\");",
            "used.nasl" => "include(\"shared.inc\"); start();",
            "shared.inc" => "function start() { helper(); } function helper() { display(missing()); missing(); } function unused() { ignored(); }",
        },
    );

    linter_test_multi!(
        included_top_level_calls_seed_reachability,
        files: {
            "root.nasl" => "include(\"shared.inc\");",
            "shared.inc" => "if (0) { start(); } function start() { missing(); }",
        },
    );

    linter_test_multi!(
        included_fn,
        files: {
            "first.nasl" => "include(\"shared.inc\"); shared();",
            "second.nasl" => "include(\"shared.inc\"); shared();",
            "shared.inc" => "function shared() {}",
        },
    );

    linter_test_multi!(
        unrelated_fn,
        files: {
            "first.nasl" => "include(\"shared.inc\"); shared();",
            "shared.inc" => "function shared() {}",
            "second.nasl" => "shared();",
        },
    );

    linter_test_multi!(
        transitive_fn,
        files: {
            "first.nasl" => "include(\"lib/outer.inc\"); shared();",
            "second.nasl" => "include(\"lib/outer.inc\"); shared();",
            "lib/outer.inc" => "if (0) { include(\"inner.inc\"); }",
            "lib/inner.inc" => "function shared() {}",
        },
    );

    linter_test_multi!(
        shared_and_cyclic_includes,
        files: {
            "root.nasl" => "include(\"left.inc\"); include(\"right.inc\"); shared();",
            "left.inc" => "include(\"shared.inc\");",
            "right.inc" => "include(\"shared.inc\");",
            "shared.inc" => "include(\"left.inc\"); function shared() {}",
        },
    );

    linter_test_multi!(
        undefined_include_call_reported_for_each_root,
        files: {
            "first.nasl" => "include(\"outer.inc\");",
            "second.nasl" => "include(\"outer.inc\");",
            "outer.inc" => "include(\"inner.inc\");",
            "inner.inc" => "missing();",
        },
    );
}
