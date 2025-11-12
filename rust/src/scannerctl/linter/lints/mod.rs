pub mod duplicate_function_arg;

use codespan_reporting::diagnostic::Diagnostic;
use scannerlib::nasl::error::IntoDiagnostic;
use scannerlib::nasl::syntax::grammar::Ast;

use super::LintCtx;

pub(super) struct LintMsg {
    diagnostic: Diagnostic<()>,
}

impl From<Diagnostic<()>> for LintMsg {
    fn from(diagnostic: Diagnostic<()>) -> Self {
        Self { diagnostic }
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
    T: Fn(&Ast) -> Vec<LintMsg>,
{
    fn lint<'a>(&self, ctx: &LintCtx<'a>) -> Vec<LintMsg> {
        (self.0)(ctx.ast)
    }
}

pub fn all_lints() -> Vec<Box<dyn Lint>> {
    let mut lints = vec![];
    let mut add_fn_lint = |f| lints.push(Box::new(FnLint(f)) as Box<dyn Lint>);
    add_fn_lint(duplicate_function_arg::duplicate_function_args);
    lints
}
