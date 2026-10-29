mod builtins;
mod duplicate_function;
mod duplicate_function_arg;
mod fn_undefined;
mod script_xref;

use codespan_reporting::diagnostic::Diagnostic;
use scannerlib::nasl::error::IntoDiagnostic;
use scannerlib::nasl::syntax::grammar::Ast;

use super::{LintMsgs, calls::RootCalls};

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

pub(super) enum Lint {
    /// A file-local lint, which checks something that can be
    /// done without looking at the context of how that file
    /// is included. Examples: duplicate_function_args
    File(fn(&Ast) -> Vec<LintMsg>),
    /// A lint that only makes sense in the context of a given
    /// NASL root. Examples: `fn_undefined`, (because the NASL
    /// include semantics are horrifying and `a.inc` using a
    /// function which is defined in `b.inc` works, even if
    /// `b.inc` is included by the top level NASL file, not `a.inc`.)
    Root(fn(&RootCalls) -> Vec<LintMsgs>),
}

pub fn all_lints() -> Vec<Lint> {
    vec![
        Lint::File(duplicate_function_arg::duplicate_function_args),
        Lint::File(script_xref::required_arguments),
        Lint::Root(fn_undefined::fn_undefined),
        Lint::Root(duplicate_function::duplicate_functions),
    ]
}
