mod duplicate_function_arg;
mod duplicate_function_declaration;
mod fn_undefined;
mod script_xref;
mod undeclared_variable;
mod unused_include;

use std::ops::Range;

use codespan_reporting::diagnostic::Diagnostic;
use scannerlib::nasl::{
    SourceFile,
    error::{IntoDiagnostic, Span},
};

use super::ctx::LintCtx;

/// A key used to identify the same lint message when it is created
/// multiple times. Getting the same message multiple times happens when
/// a file is included from multiple places.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(super) struct LintMsgKey {
    rule: &'static str,
    file: String,
    span: Range<usize>,
}

pub(super) struct LintMsg {
    rule: &'static str,
    file: SourceFile,
    span: Range<usize>,
    diagnostic: Diagnostic<()>,
}

impl LintMsg {
    pub(super) fn new(
        rule: &'static str,
        file: SourceFile,
        span: Span,
        diagnostic: Diagnostic<()>,
    ) -> Self {
        Self {
            rule,
            file,
            span: span.into(),
            diagnostic,
        }
    }

    pub(super) fn file(&self) -> &SourceFile {
        &self.file
    }

    pub(super) fn message_key(&self) -> LintMsgKey {
        LintMsgKey {
            rule: self.rule,
            file: self.file.name().clone(),
            span: self.span.clone(),
        }
    }
}

impl IntoDiagnostic for LintMsg {
    fn into_diagnostic(self) -> Diagnostic<()> {
        self.diagnostic
    }
}

pub(super) trait Lint {
    fn lint<'a>(&self, ctx: &LintCtx<'a>) -> Vec<LintMsg>;
}

struct FnLint<T>(T);

impl<T> Lint for FnLint<T>
where
    T: Fn(&LintCtx) -> Vec<LintMsg>,
{
    fn lint<'a>(&self, ctx: &LintCtx<'a>) -> Vec<LintMsg> {
        (self.0)(ctx)
    }
}

pub fn all_lints() -> Vec<Box<dyn Lint>> {
    let fn_lint = |f: fn(&LintCtx) -> Vec<LintMsg>| Box::new(FnLint(f)) as Box<dyn Lint>;
    vec![
        fn_lint(duplicate_function_arg::duplicate_function_args),
        fn_lint(duplicate_function_declaration::duplicate_function_declarations),
        fn_lint(fn_undefined::fn_undefined),
        fn_lint(script_xref::script_xref),
        fn_lint(undeclared_variable::undeclared_variables),
        fn_lint(unused_include::unused_includes),
    ]
}
