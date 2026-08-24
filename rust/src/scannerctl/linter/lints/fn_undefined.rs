use codespan_reporting::diagnostic::{Diagnostic, Label};
use scannerlib::nasl::error::Spanned;

use crate::linter::{LintMsg, ctx::LintCtx};

const RULE: &str = "undefined_function";

pub fn fn_undefined(ctx: &LintCtx) -> Vec<LintMsg> {
    ctx.ast
        .iter_fn_calls()
        .filter(|call| {
            let name = call.fn_name.to_string();
            !ctx.fn_defined(&name) && !ctx.builtin_defined(&name)
        })
        .map(|call| {
            let span = call.fn_name.span();
            let diagnostic = Diagnostic::error()
                .with_message(format!("Undefined function '{}'", call.fn_name))
                .with_labels(vec![
                    Label::primary((), span).with_message("undefined function"),
                ]);
            LintMsg::new(RULE, span, diagnostic)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::linter_test;

    linter_test!(undefined_fn, "foo();");
    linter_test!(defined_fn, "function foo() {} foo();");
    linter_test!(builtin_fn, "display(\"hello\");");
}
