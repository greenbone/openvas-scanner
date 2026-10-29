use codespan_reporting::diagnostic::{Diagnostic, Label};
use scannerlib::nasl::{
    error::Spanned,
    syntax::grammar::{Ast, FnArg},
};

use crate::linter::LintMsg;

pub fn required_arguments(ast: &Ast) -> Vec<LintMsg> {
    ast.iter_fn_calls()
        .filter(|call| call.fn_name.to_string() == "script_xref")
        .filter_map(|call| {
            let has = |name: &str| {
                call.args
                    .items
                    .iter()
                    .any(|arg| matches!(arg, FnArg::Named(arg) if arg.ident.to_string() == name))
            };
            let mut missing = vec![];
            if !has("name") {
                missing.push("name");
            }
            if !has("value") && !has("csv") {
                missing.push("value or csv");
            }
            if missing.is_empty() {
                return None;
            }
            Some(
                Diagnostic::error()
                    .with_message("script_xref requires name and at least one of value or csv")
                    .with_labels(vec![
                        Label::primary((), call.fn_name.span())
                            .with_message(format!("missing {}", missing.join(" and "))),
                    ])
                    .into(),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::{linter_test, linter_test_multi};

    linter_test!(
        valid_arguments,
        "script_xref(name:\"URL\", value:\"a\"); script_xref(name:\"URL\", csv:\"a,b\"); script_xref(name:\"URL\", value:\"a\", csv:\"b,c\");"
    );
    linter_test!(
        missing_arguments,
        "script_xref(); script_xref(value:\"a\"); script_xref(name:\"URL\"); script_xref(\"URL\", \"a\");"
    );
    linter_test!(
        dynamic_arguments,
        "name = \"URL\"; value = \"a\"; script_xref(name:name, value:value);"
    );
    linter_test_multi!(
        shared_include_reported_once,
        files: {
            "first.nasl" => "include(\"shared.inc\");",
            "second.nasl" => "include(\"shared.inc\");",
            "shared.inc" => "script_xref(name:\"URL\");",
        },
    );
}
