use codespan_reporting::diagnostic::{Diagnostic, Label};
use scannerlib::nasl::error::Spanned;

use crate::linter::{LintMsg, ctx::LintCtx};

pub fn fn_undefined(ctx: &LintCtx) -> Vec<LintMsg> {
    ctx.ast
        .iter_fn_calls()
        .filter(|call| !ctx.fn_defined(&call.fn_name.to_string()))
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
