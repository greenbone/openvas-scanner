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

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum LintScope {
    /// A file-local lint, which checks something that can be
    /// done without looking at the context of how that file
    /// is included. Examples: duplicate_function_args
    File,
    /// A lint that only makes sense in the context of a given
    /// NASL root. Examples: `fn_undefined`, (because the NASL
    /// include semantics are horrifying and `a.inc` using a
    /// function which is defined in `b.inc` works, even if
    /// `b.inc` is included by the top level NASL file, not `a.inc`.)
    Root,
}

pub(super) trait Lint {
    fn scope(&self) -> LintScope;
    fn lint<'a>(&self, ctx: &LintCtx<'a>) -> Vec<LintMsg>;
}

struct AstLint<T>(T);

impl<T> Lint for AstLint<T>
where
    T: Fn(&Ast) -> Vec<LintMsg>,
{
    fn scope(&self) -> LintScope {
        LintScope::File
    }

    fn lint<'a>(&self, ctx: &LintCtx<'a>) -> Vec<LintMsg> {
        (self.0)(ctx.ast)
    }
}

struct FnLint<T>(T);

impl<T> Lint for FnLint<T>
where
    T: Fn(&LintCtx) -> Vec<LintMsg>,
{
    fn scope(&self) -> LintScope {
        LintScope::Root
    }

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
