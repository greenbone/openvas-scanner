mod duplicate_function_arg;
mod fn_undefined;

use codespan_reporting::diagnostic::Diagnostic;
use scannerlib::nasl::error::IntoDiagnostic;
use scannerlib::nasl::syntax::grammar::Ast;

use super::ctx::LintCtx;

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
    let ast_lint = |f| Box::new(AstLint(f)) as Box<dyn Lint>;
    let fn_lint = |f| Box::new(FnLint(f)) as Box<dyn Lint>;
    vec![
        ast_lint(duplicate_function_arg::duplicate_function_args),
        fn_lint(fn_undefined::fn_undefined),
    ]
}
