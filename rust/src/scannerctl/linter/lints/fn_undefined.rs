use std::collections::HashSet;

use codespan_reporting::diagnostic::{Diagnostic, Label};
use scannerlib::nasl::{error::Spanned, nasl_std_executor, syntax::grammar::Statement};

use crate::linter::{LintMsg, ctx::LintCtx};

pub fn fn_undefined(ctx: &LintCtx) -> Vec<LintMsg> {
    let mut functions: HashSet<String> = nasl_std_executor().iter().map(str::to_owned).collect();
    for ast in std::iter::once(ctx.ast).chain(ctx.includes.iter().copied()) {
        for stmt in ast.iter_stmts() {
            if let Statement::FnDecl(decl) = stmt {
                functions.insert(decl.fn_name.to_string());
            }
        }
    }
    ctx.ast
        .iter_fn_calls()
        .filter(|call| !functions.contains(&call.fn_name.to_string()))
        .map(|call| {
            Diagnostic::error()
                .with_message(format!("Undefined function '{}'", call.fn_name))
                .with_labels(vec![
                    Label::primary((), call.fn_name.span()).with_message("undefined function"),
                ])
                .into()
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
