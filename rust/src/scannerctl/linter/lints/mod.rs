mod duplicate_function_arg;
mod duplicate_function_declaration;
mod fn_undefined;

use std::ops::Range;

use codespan_reporting::diagnostic::Diagnostic;
use scannerlib::nasl::syntax::grammar::Ast;
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
    span: Range<usize>,
    diagnostic: Diagnostic<()>,
}

impl LintMsg {
    pub(super) fn new(rule: &'static str, span: Span, diagnostic: Diagnostic<()>) -> Self {
        Self {
            rule,
            span: span.into(),
            diagnostic,
        }
    }

    pub(super) fn message_key(&self, file: &SourceFile) -> LintMsgKey {
        LintMsgKey {
            rule: self.rule,
            file: file.name().clone(),
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

struct AstLint<T>(T);

impl<T> Lint for AstLint<T>
where
    T: Fn(&Ast) -> Vec<LintMsg>,
{
    fn lint<'a>(&self, ctx: &LintCtx<'a>) -> Vec<LintMsg> {
        (self.0)(ctx.ast)
    }
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
    let ast_lint = |f: fn(&Ast) -> Vec<LintMsg>| Box::new(AstLint(f)) as Box<dyn Lint>;
    let fn_lint = |f| Box::new(FnLint(f)) as Box<dyn Lint>;
    vec![
        ast_lint(duplicate_function_arg::duplicate_function_args),
        ast_lint(duplicate_function_declaration::duplicate_function_declarations),
        fn_lint(fn_undefined::fn_undefined),
    ]
}
