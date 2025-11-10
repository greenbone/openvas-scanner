pub mod duplicate_function_arg;

use codespan_reporting::diagnostic::Diagnostic;
use scannerlib::nasl::error::IntoDiagnostic;
use scannerlib::nasl::syntax::grammar::Ast;

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
    fn lint(&self, ast: &Ast) -> Vec<LintMsg>;
}

struct FnLint<T>(T);

impl<T> Lint for FnLint<T>
where
    T: Fn(&Ast) -> Vec<LintMsg>,
{
    fn lint(&self, ast: &Ast) -> Vec<LintMsg> {
        (self.0)(ast)
    }
}

pub fn all_lints() -> Vec<Box<dyn Lint>> {
    vec![Box::new(FnLint(
        duplicate_function_arg::duplicate_function_args,
    ))]
}
