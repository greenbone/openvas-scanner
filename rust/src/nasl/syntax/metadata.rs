use crate::nasl::syntax::parser::Result;

use super::grammar::Ast;
use super::grammar::Atom;
use super::grammar::Expr;
use super::grammar::Statement;
use super::parser::Parse;

pub struct DescriptionBlock {
    stmts: Vec<Statement>,
}

impl DescriptionBlock {
    pub(crate) fn into_ast(self) -> Ast {
        Ast::new(self.stmts)
    }
}

impl Parse for DescriptionBlock {
    fn parse(parser: &mut super::Parser) -> Result<Self> {
        let mut stmts = vec![];
        loop {
            let stmt = parser.parse()?;
            stmts.push(stmt);
            if let Statement::If(if_) = stmts.last().unwrap() {
                let (condition, _) = if_.if_branches.first().unwrap();
                if check_condition(condition) {
                    break;
                }
            }
        }
        Ok(Self { stmts })
    }
}

fn check_condition(condition: &Expr) -> bool {
    if let Expr::Atom(Atom::Ident(ident)) = condition
        && ident.to_string() == "description"
    {
        return true;
    }
    false
}
