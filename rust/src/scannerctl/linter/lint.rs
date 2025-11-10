use scannerlib::nasl::syntax::grammar::Ast;

use super::LintMsg;

pub(super) trait Lint {
    fn lint(&self, ast: &Ast) -> Option<LintMsg>;
}
